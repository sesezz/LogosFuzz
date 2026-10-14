"""``logosfuzz run --profile <json> --budget <sec> [--max-round 3] [--no-docker] -o out/<name>``.

- 인자 검증과 SCH 시간 배분은 도구 없이 확인한다.
- 단계 연결은 가짜 LLM·빌드 어댑터·퍼징 세션·커버리지 도구로 확인한다(EXT·ANA 는 실제).
- clang + compiler-rt + cmake 가 있으면 임베디드 샘플로 처음부터 끝까지 실제로 돌린다
  (LLM 자리에는 사람이 쓴 하네스를 돌려주는 가짜를 넣는다).
"""

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from logosfuzz import cli
from logosfuzz.control.generic_run import GenericRun, RunOptions, split_budget
from logosfuzz.execute.coverage import CmdResult
from logosfuzz.generate.build.base import BuildResult

REPO = Path(__file__).resolve().parents[1]
EMBEDDED = REPO / "examples" / "embedded"
MANUAL_HARNESS = (EMBEDDED / "harness" / "fuzz_proto.c").read_text(encoding="utf-8")


class HarnessLLM:
    """생성·수리 프롬프트 모두에 같은 하네스를 돌려준다."""

    def __init__(self, code=MANUAL_HARNESS):
        self.code = code
        self.prompts = []

    def complete(self, prompt, system=""):
        self.prompts.append(prompt)
        return self.code


def _embedded_profile(tmp_path, **overrides):
    src = tmp_path / "embedded"
    shutil.copytree(EMBEDDED, src, ignore=shutil.ignore_patterns("build-fuzz*"))
    data = json.loads((REPO / "targets" / "embedded-sample.json").read_text(encoding="utf-8"))
    data["build"]["source_root"] = str(src)
    data.update(overrides)
    path = tmp_path / "embedded-sample.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# 인자와 시간 배분
# --------------------------------------------------------------------------- #
def _sched(*pairs):
    return [SimpleNamespace(group_name=n, allocated_sec=s) for n, s in pairs]


def test_split_budget_follows_sch_with_floor():
    out = split_budget(_sched(("a", 500), ("b", 100), ("c", 0)), 600)
    assert sum(out.values()) == 600
    assert out["c"] == 30                       # SCH 가 0초를 줘도 바닥값
    assert out["a"] > out["b"] > out["c"]


def test_split_budget_small_budget_is_shared_evenly():
    out = split_budget(_sched(("a", 10), ("b", 0), ("c", 0)), 30)
    assert out == {"a": 10, "b": 10, "c": 10}


def test_split_budget_never_exceeds_budget():
    for budget in (1, 7, 59, 61, 600):
        out = split_budget(_sched(("a", 3), ("b", 2), ("c", 1), ("d", 0)), budget)
        assert sum(out.values()) == budget


def test_run_parser_accepts_spec_flags(tmp_path):
    args = cli._build_parser().parse_args(
        ["run", "--profile", "targets/libsndfile.json", "--budget", "600",
         "--max-round", "3", "--no-docker", "-o", "out/libsndfile"])
    assert args.command == "run"
    assert (args.budget, args.max_round, args.docker) == (600, 3, False)
    assert args.output == Path("out/libsndfile")


def test_run_rejects_bazel_profile(tmp_path, capsys):
    rc = cli.main(["run", "--profile", str(REPO / "targets" / "automotive.json"),
                   "--budget", "10", "-o", str(tmp_path / "o")])
    assert rc == 2
    assert "ctr_06_01_controller --mode bazel" in capsys.readouterr().out


@pytest.mark.parametrize("flags", [["--budget", "0"], ["--budget", "10", "--max-round", "-1"]])
def test_run_rejects_bad_numbers(flags, tmp_path):
    assert cli.main(["run", "--profile", str(REPO / "targets" / "libsndfile.json"), *flags,
                     "-o", str(tmp_path / "o")]) == 2


def test_run_reports_profile_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert cli.main(["run", "--profile", str(bad), "--budget", "10", "-o", str(tmp_path)]) == 2


# --------------------------------------------------------------------------- #
# 단계 연결 (가짜 빌드·퍼징·커버리지)
# --------------------------------------------------------------------------- #
class FakeAdapter:
    build_system = "cmake"

    def __init__(self, root, coverage, fail_link=False):
        self.root = Path(root)
        self.coverage = coverage
        self.fail_link = fail_link
        self.built = []

    def prepare(self, force=False):
        return BuildResult(ok=True, target="lib")

    def _src(self, spec):
        return self.root / "harness" / spec.srcs[0]

    def emit_build_definition(self, spec, source):
        path = self._src(spec)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
        return path

    def build(self, spec):
        if self.fail_link:
            return BuildResult(ok=False, target=spec.name, log="harness.c:1:1: error: boom")
        binary = self.root / ("bin-cov" if self.coverage else "bin") / spec.name
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("#!fake")
        self.built.append(spec.name)
        return BuildResult(ok=True, target=spec.name, binary=binary)

    def remove(self, spec):
        pass


class FakeSession:
    seen = {}

    def __init__(self, config):
        self.config = config

    def run(self, groups, ensure_image=True, timeouts=None):
        FakeSession.seen = {"groups": groups, "timeouts": timeouts, "config": self.config}
        for g in groups:
            (g.corpus_dir / "found").write_bytes(b"new")   # 퍼징이 찾은 입력
        data = {
            "engine": "libfuzzer", "timeout_sec": self.config.timeout_sec,
            "total_groups": len(groups), "total_crashes": 0, "failed_groups": [],
            "groups": [{"group": g.name, "execs": 100, "crashes": [], "failed_to_start": False,
                        "exit_code": 0, "timed_out": True, "crashed": False,
                        "sanitizer_findings": []} for g in groups],
        }
        (self.config.output_dir / "fuzz_summary.json").write_text(json.dumps(data))
        return SimpleNamespace(to_dict=lambda: data)


def _fake_cov_runner(argv):
    if argv[0] == "env":
        prof = next(a.split("=", 1)[1] for a in argv if a.startswith("LLVM_PROFILE_FILE="))
        Path(prof.replace("%m", "1")).write_bytes(b"raw")
        return CmdResult(0)
    if argv[1] == "merge":
        Path(argv[argv.index("-o") + 1]).write_bytes(b"pd")
        return CmdResult(0)
    return CmdResult(0, json.dumps({"data": [{"files": [], "totals": {
        "lines": {"count": 66, "covered": 50}, "functions": {"count": 7, "covered": 7},
        "regions": {"count": 50, "covered": 40}, "branches": {"count": 30, "covered": 20}}}]}))


def _fake_run(tmp_path, *, fail_link=False, llm=None, **opts):
    profile = _embedded_profile(tmp_path)
    out = tmp_path / "out"
    adapters = []

    def factory(p, coverage=False):
        a = FakeAdapter(out / "build", coverage, fail_link=fail_link)
        adapters.append(a)
        return a

    run = GenericRun(
        RunOptions(profile=profile, budget=opts.pop("budget", 120), output=out,
                   use_docker=False, **opts),
        llm=llm or HarnessLLM(), adapter_factory=factory, session_factory=FakeSession,
        coverage_runner=_fake_cov_runner)
    return run, run.run(), out, adapters


def test_stages_run_in_order_and_summary_is_written(tmp_path):
    run, rc, out, adapters = _fake_run(tmp_path)
    assert rc == 0
    summary = json.loads((out / "run_summary.json").read_text())
    assert [s["stage"] for s in summary["stages"]] == \
        ["BUILD", "EXT", "SCH", "GEN", "HEAL", "COVBIN", "EXE", "COV", "ANA"]
    assert all(s["ok"] and s["automatic"] for s in summary["stages"])
    assert summary["totals"]["harness_built"] == summary["totals"]["groups"] >= 1
    for name in ("kb.json", "fuzz_summary.json", "analysis.json", "validation-summary.json"):
        assert (out / name).is_file(), name
    group = summary["groups"][0]
    assert group["coverage"]["lines"] == {"covered": 50, "count": 66, "percent": 75.76}
    assert (out / "gen" / f"{group['group']}.prompt.txt").is_file()


def test_seeds_are_copied_and_sch_time_is_passed_to_exe(tmp_path):
    run, rc, out, _ = _fake_run(tmp_path, budget=100)
    seen = FakeSession.seen
    corpus = seen["groups"][0].corpus_dir
    assert corpus.parent == out / "corpus"
    assert (corpus / "valid_frame.bin").is_file()              # 프로필 seeds
    assert sum(seen["timeouts"].values()) == 100
    assert set(seen["timeouts"]) == {g.name for g in seen["groups"]}
    assert seen["config"].image == "logosfuzz-exec:generic"


def test_generic_domain_prompt_has_no_automotive_wording(tmp_path):
    llm = HarnessLLM()
    _fake_run(tmp_path, llm=llm)
    joined = "\n".join(llm.prompts)
    assert "score::Result" not in joined and "automotive" not in joined.lower()
    assert '#include "proto_parser.h"' in joined


def test_top_limits_groups(tmp_path):
    run, rc, out, _ = _fake_run(tmp_path, top=1)
    assert rc == 0
    assert json.loads((out / "run_summary.json").read_text())["totals"]["groups"] == 1


def test_build_failure_stops_before_fuzzing(tmp_path):
    run, rc, out, _ = _fake_run(tmp_path, fail_link=True, max_round=0)
    assert rc == 1
    summary = json.loads((out / "run_summary.json").read_text())
    assert [s["stage"] for s in summary["stages"]][-1] == "HEAL"
    assert summary["stages"][-1]["ok"] is False
    assert not (out / "fuzz_summary.json").exists()
    assert summary["groups"][0]["outcome"] in ("exhausted", "failed", "escalated", "stagnated")


def test_no_coverage_skips_coverage_stages(tmp_path):
    run, rc, out, adapters = _fake_run(tmp_path, coverage=False)
    stages = [s["stage"] for s in json.loads((out / "run_summary.json").read_text())["stages"]]
    assert "COVBIN" not in stages and "COV" not in stages
    assert not any(a.coverage for a in adapters)


# --------------------------------------------------------------------------- #
# 실제 도구로 끝까지
# --------------------------------------------------------------------------- #
def _toolchain_ready(tmp_path) -> bool:
    if not all(shutil.which(t) for t in ("clang", "cmake", "llvm-profdata", "llvm-cov")):
        return False
    probe = tmp_path / "probe.c"
    probe.write_text("#include <stdint.h>\n#include <stddef.h>\n"
                     "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){return 0;}\n")
    return subprocess.run(["clang", "-fsanitize=address,undefined,fuzzer", str(probe),
                           "-o", str(tmp_path / "probe")], capture_output=True).returncode == 0


def test_real_e2e_embedded_sample_no_docker(tmp_path):
    if not _toolchain_ready(tmp_path):
        pytest.skip("clang + compiler-rt(libFuzzer/ASan) + cmake + llvm 도구가 필요하다")
    profile = _embedded_profile(tmp_path)
    out = tmp_path / "out"

    rc = GenericRun(RunOptions(profile=profile, budget=10, output=out, use_docker=False,
                               top=1), llm=HarnessLLM()).run()

    assert rc == 0
    summary = json.loads((out / "run_summary.json").read_text())
    [group] = summary["groups"]
    assert group["outcome"] == "success"
    assert sorted(group["stubbed_symbols"]) == ["HAL_GetTick", "HAL_UART_Transmit"]
    assert group["execs"] > 0
    assert group["crashes"] >= 1                          # proto_parse 의 의도적 힙 OOB
    cov = group["coverage"]
    assert cov is not None and 0 < cov["lines"]["covered"] <= cov["lines"]["count"]
    export = json.loads((out / "coverage" / f"{group['slug']}.coverage.json").read_text())
    files = [f["filename"] for f in export["data"][0]["files"]]
    assert files and not any("harness" in f for f in files)
    analysis = json.loads((out / "analysis.json").read_text())
    assert analysis["findings"]                           # ANA 까지 크래시가 넘어갔다
