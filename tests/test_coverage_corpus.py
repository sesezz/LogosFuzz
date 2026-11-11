"""비-Bazel 커버리지: 커버리지 빌드 바이너리로 최종 코퍼스 재생 → profdata → llvm-cov 요약

가짜 runner 로 명령 순서·인자 확인, clang + compiler-rt + llvm 도구 존재 시 실제 하네스 전체 실행
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from logosfuzz.execute.coverage import (
    DEFAULT_IGNORE_FILENAME_REGEX,
    CmdResult,
    collect_corpus_coverage,
    export_summary_argv,
    replay_corpus_argv,
)

_EXPORT = json.dumps({"data": [{
    "files": [{"filename": "/src/lib.c", "summary": {"lines": {"count": 10, "covered": 4}}}],
    "totals": {
        "functions": {"count": 2, "covered": 1},
        "lines": {"count": 10, "covered": 4},
        "regions": {"count": 6, "covered": 3},
        "branches": {"count": 4, "covered": 1},
    },
}]})


class FakeRunner:
    """재생 명령 시 profraw 생성, export 시 고정 JSON 반환"""

    def __init__(self, *, replay_writes=True, fail_bulk=False):
        self.calls = []
        self.replay_writes = replay_writes
        self.fail_bulk = fail_bulk

    def __call__(self, argv):
        self.calls.append(list(argv))
        if argv[0] == "env":
            profile = next(a.split("=", 1)[1] for a in argv if a.startswith("LLVM_PROFILE_FILE="))
            inputs = argv[argv.index("-runs=0") + 1:]
            bulk = len(inputs) != 1 or Path(inputs[0]).is_dir()
            if self.fail_bulk and bulk:
                return CmdResult(1, "", "==1==ERROR: AddressSanitizer")
            if self.replay_writes:
                Path(profile.replace("%m", "123")).write_bytes(b"raw")
            return CmdResult(0)
        if argv[1] == "merge":
            Path(argv[argv.index("-o") + 1]).write_bytes(b"profdata")
            return CmdResult(0)
        if argv[1] == "export":
            return CmdResult(0, _EXPORT)
        raise AssertionError(argv)


def _corpus(tmp_path, n=2):
    d = tmp_path / "corpus"
    d.mkdir()
    for i in range(n):
        (d / f"in{i}").write_bytes(bytes([i]))
    return d


def test_replay_argv_runs_each_input_once_with_profile_file():
    argv = replay_corpus_argv("/bin/cov", ["/c"], profile_file="/o/g/%m.profraw")
    assert argv[:2] == ["env", "LLVM_PROFILE_FILE=/o/g/%m.profraw"]
    assert argv[-3:] == ["/bin/cov", "-runs=0", "/c"]


def test_export_is_summary_only_and_ignores_harness_sources():
    argv = export_summary_argv("/bin/cov", "/o/g.profdata")
    assert "-summary-only" in argv
    assert f"-ignore-filename-regex={DEFAULT_IGNORE_FILENAME_REGEX}" in argv
    assert argv[-1] == "/bin/cov"
    for path in ("/out/x/harness/g.c", "/src/foo_fuzzer.cc", "/repo/fuzz/a.c"):
        assert re.search(DEFAULT_IGNORE_FILENAME_REGEX, path)
    assert not re.search(DEFAULT_IGNORE_FILENAME_REGEX, "/third_party/libsndfile/src/sndfile.c")


def test_collect_runs_replay_merge_export_and_saves_outputs(tmp_path):
    runner = FakeRunner()
    summary = collect_corpus_coverage(
        tmp_path / "bin-cov" / "g", [_corpus(tmp_path)], tmp_path / "cov",
        group="g", runner=runner)
    assert [c[0] if c[0] == "env" else c[1] for c in runner.calls] == ["env", "merge", "export"]
    assert summary.lines.covered == 4 and summary.lines.count == 10
    assert summary.mode == "llvm-cov"
    assert Path(summary.profdata_path) == tmp_path / "cov" / "g.profdata"
    assert json.loads(Path(summary.export_path).read_text())["data"]


def test_collect_falls_back_to_single_inputs_when_bulk_replay_dies(tmp_path):
    runner = FakeRunner(fail_bulk=True)
    summary = collect_corpus_coverage(
        "/bin/cov", [_corpus(tmp_path, n=3)], tmp_path / "cov", group="g", runner=runner)
    replays = [c for c in runner.calls if c[0] == "env"]
    assert len(replays) == 1 + 3
    assert summary is not None


def test_collect_returns_none_without_corpus_or_profraw(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert collect_corpus_coverage("/bin/cov", [empty], tmp_path / "cov",
                                   group="g", runner=FakeRunner()) is None
    assert collect_corpus_coverage("/bin/cov", [_corpus(tmp_path)], tmp_path / "cov",
                                   group="g", runner=FakeRunner(replay_writes=False)) is None


def test_collect_survives_missing_llvm_tools(tmp_path):
    def runner(argv):
        if argv[0] == "env":
            return FakeRunner()(argv)
        raise FileNotFoundError(argv[0])

    assert collect_corpus_coverage("/bin/cov", [_corpus(tmp_path)], tmp_path / "cov",
                                   group="g", runner=runner) is None


# --------------------------------------------------------------------------- #
# 실제 도구
# --------------------------------------------------------------------------- #
_LIB = r"""
int classify(const unsigned char *d, unsigned long n) {
  if (n > 0 && d[0] == 'A') return 1;
  if (n > 0 && d[0] == 'B') return 2;
  return 0;
}
"""
_HARNESS = r"""
#include <stddef.h>
#include <stdint.h>
int classify(const unsigned char *d, unsigned long n);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { classify(data, size); return 0; }
"""


def _can_build_coverage_fuzzer(tmp_path) -> bool:
    if not all(shutil.which(t) for t in ("clang", "llvm-profdata", "llvm-cov")):
        return False
    probe = tmp_path / "probe.c"
    probe.write_text(_HARNESS.replace("classify(data, size);", ""))
    rc = subprocess.run(["clang", "-fsanitize=fuzzer", str(probe), "-o", str(tmp_path / "probe")],
                        capture_output=True).returncode
    return rc == 0


def test_real_coverage_replay_excludes_harness(tmp_path):
    if not _can_build_coverage_fuzzer(tmp_path):
        pytest.skip("clang libFuzzer 런타임 또는 llvm 도구가 없다")
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.c").write_text(_LIB)
    harness_dir = tmp_path / "harness"
    harness_dir.mkdir()
    (harness_dir / "h.c").write_text(_HARNESS)
    binary = tmp_path / "bin-cov" / "h"
    binary.parent.mkdir()
    subprocess.run(["clang", "-g", "-fsanitize=fuzzer", "-fprofile-instr-generate",
                    "-fcoverage-mapping", str(harness_dir / "h.c"), str(src / "lib.c"),
                    "-o", str(binary)], check=True)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a").write_bytes(b"A")

    summary = collect_corpus_coverage(binary, [corpus], tmp_path / "cov", group="h")

    assert summary is not None
    files = [f.filename for f in summary.files]
    assert any(f.endswith("lib.c") for f in files)
    assert not any("harness" in f for f in files)
    # 코퍼스에 없는 "B" 분기로 인해 리전 일부만 커버
    assert 0 < summary.regions.covered < summary.regions.count
