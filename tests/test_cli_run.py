"""``logosfuzz run --profile <json> --budget <sec> [--max-round 3] [--no-docker] -o out/<name>``.

- 인자 검증과 SCH 시간 배분: 도구 없이 확인
- 단계 연결: 가짜 LLM·빌드 어댑터·퍼징 세션·커버리지 도구로 확인 (EXT·ANA 는 실제)
- clang + compiler-rt + cmake 존재 시 임베디드 샘플 전체 실행
  (LLM 자리에 수동 하네스 반환 가짜 사용)
"""

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from logosfuzz import cli
from logosfuzz.control.generic_run import SMOKE_RUNS, GenericRun, RunOptions, split_budget
from logosfuzz.execute.coverage import CmdResult
from logosfuzz.execute.docker_runner import ProcResult
from logosfuzz.generate.build.base import BuildResult

REPO = Path(__file__).resolve().parents[1]
EMBEDDED = REPO / "examples" / "embedded"
MANUAL_HARNESS = (EMBEDDED / "harness" / "fuzz_proto.c").read_text(encoding="utf-8")


class HarnessLLM:
    """생성·수리 프롬프트 모두에 같은 하네스 반환"""

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


class FakeSmoke:
    """dry-run 실행기. ``results`` 를 순서대로 돌려준다 (소진 후 마지막 값 반복)"""

    def __init__(self, *results):
        self.results = list(results) or [ProcResult(0, False, stderr="#2 INITED cov: 120 ft: 130")]
        self.calls = []

    def __call__(self, argv, timeout, on_line):
        self.calls.append(argv)
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]


CRASH = ProcResult(1, False, stderr="#1 INITED cov: 12\n==1==ERROR: AddressSanitizer: SEGV")
LOW_COV = ProcResult(0, False, stderr="#2 INITED cov: 8 ft: 9\nDone 200 runs")
GOOD = ProcResult(0, False, stderr="#2 INITED cov: 450 ft: 900\nDone 200 runs")


def _fake_run(tmp_path, *, fail_link=False, llm=None, smoke_exec=None, profile_overrides=None, **opts):
    profile = _embedded_profile(tmp_path, **(profile_overrides or {}))
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
        coverage_runner=_fake_cov_runner, smoke_executor=smoke_exec or FakeSmoke())
    return run, run.run(), out, adapters


def test_stages_run_in_order_and_summary_is_written(tmp_path):
    run, rc, out, adapters = _fake_run(tmp_path)
    assert rc == 0
    summary = json.loads((out / "run_summary.json").read_text())
    assert [s["stage"] for s in summary["stages"]] == \
        ["BUILD", "EXT", "SCH", "GEN", "HEAL", "SMOKE", "COVBIN", "EXE", "COV", "ANA"]
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


def test_profile_dictionary_is_installed_per_group_and_resolved_by_runner(tmp_path):
    from logosfuzz.execute.docker_runner import DockerIsolationRunner

    dict_file = tmp_path / "proto.dict"
    dict_file.write_text('# 프로토콜 헤더\nmagic="\\xAA\\x55"\n"CMD"\n', encoding="utf-8")
    run, rc, out, _ = _fake_run(tmp_path, profile_overrides={"dictionary": str(dict_file)})
    assert rc == 0
    seen = FakeSession.seen
    assert seen["config"].dict_dir == out / "dict"
    runner = DockerIsolationRunner(seen["config"])
    for group in seen["groups"]:
        installed = out / "dict" / f"{group.name}.dict"
        assert installed.read_bytes() == dict_file.read_bytes()
        assert runner.resolve_dict(group) == installed.resolve()
        assert f"-dict={installed.resolve()}" in runner.libfuzzer_option_args(group, in_docker=False)


def test_run_without_dictionary_creates_no_dict_files(tmp_path):
    run, rc, out, _ = _fake_run(tmp_path)
    assert rc == 0
    assert not (out / "dict").exists()


def test_invalid_profile_dictionary_warns_and_run_continues(tmp_path):
    dict_file = tmp_path / "bad.dict"
    dict_file.write_text('"ok"\nnot a dict line\n', encoding="utf-8")
    run, rc, out, _ = _fake_run(tmp_path, profile_overrides={"dictionary": str(dict_file)})
    assert rc == 0
    assert not (out / "dict").exists()
    assert FakeSession.seen["groups"]


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


def test_smoke_runs_each_harness_with_libfuzzer_runs_flag(tmp_path):
    smoke = FakeSmoke()
    run, rc, out, _ = _fake_run(tmp_path, top=1, smoke_runs=50)
    assert rc == 0
    summary = json.loads((out / "run_summary.json").read_text())
    [group] = summary["groups"]
    assert group["smoke"]["passed"] and group["smoke"]["used"]
    assert group["smoke"]["attempts"][0]["coverage_edges"] == 120
    assert summary["totals"]["smoke_passed"] == 1


def test_smoke_argv_uses_runs_and_libfuzzer_options(tmp_path):
    smoke = FakeSmoke()
    _fake_run(tmp_path, top=1, smoke_exec=smoke, max_len=1024)
    argv = " ".join(smoke.calls[0])
    assert f"-runs={SMOKE_RUNS}" in argv and "-max_len=1024" in argv
    assert "-timeout=1" in argv and "-rss_limit_mb=2048" in argv
    assert "/smoke/" in argv                     # 본 퍼징 crashes/ 와 분리


def test_immediate_crash_is_regenerated_with_reason(tmp_path):
    llm = HarnessLLM()
    smoke = FakeSmoke(CRASH, GOOD)
    run, rc, out, _ = _fake_run(tmp_path, top=1, llm=llm, smoke_exec=smoke)
    assert rc == 0
    [group] = json.loads((out / "run_summary.json").read_text())["groups"]
    assert group["smoke"]["regenerated"] == 1 and group["smoke"]["passed"]
    regen = [p for p in llm.prompts if "dry-run 실패" in p]
    assert regen and "비정상 종료" in regen[0] and "AddressSanitizer: SEGV" in regen[0]
    assert "핸들은" in regen[0] or "생성 API" in regen[0]


def test_low_coverage_harness_is_regenerated(tmp_path):
    smoke = FakeSmoke(LOW_COV, GOOD)
    run, rc, out, _ = _fake_run(tmp_path, top=1, smoke_exec=smoke)
    [group] = json.loads((out / "run_summary.json").read_text())["groups"]
    assert "타겟 API 미도달" in group["smoke"]["attempts"][0]["reason"]
    assert group["smoke"]["passed"]


def test_all_crashing_harnesses_still_fuzz_with_last_regeneration(tmp_path):
    run, rc, out, _ = _fake_run(tmp_path, top=1, smoke_exec=FakeSmoke(CRASH), smoke_retries=1)
    assert rc == 0
    summary = json.loads((out / "run_summary.json").read_text())
    smoke = next(s for s in summary["stages"] if s["stage"] == "SMOKE")
    assert smoke["ok"] and smoke["fallback_crashed"] == 1
    [group] = summary["groups"]
    assert group["smoke"]["regenerated"] == 1 and not group["smoke"]["passed"]
    assert group["smoke"]["used"]
    assert summary["totals"]["smoke_immediate_crash"] == 1
    assert len(FakeSession.seen["groups"]) == 1


TARGET_BUG = ProcResult(1, False, stderr="#1 INITED cov: 40\n"
                        "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1")


def test_target_bug_crash_in_smoke_keeps_harness(tmp_path):
    smoke = FakeSmoke(TARGET_BUG)
    run, rc, out, _ = _fake_run(tmp_path, top=1, smoke_exec=smoke)
    assert rc == 0
    summary = json.loads((out / "run_summary.json").read_text())
    [group] = summary["groups"]
    assert group["smoke"]["passed"] and group["smoke"]["regenerated"] == 0
    assert summary["totals"]["smoke_immediate_crash"] == 0
    assert len(FakeSession.seen["groups"]) == 1


HARNESS_BUG = ProcResult(1, False, stderr=(
    "#1 INITED cov: 40\n"
    "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
    "    #0 0x1 in __asan_memcpy\n"
    "    #1 0x2 in mem_read /tmp/out/build/harness/lg_proto_ctx_t.c:32:5\n"
    "    #2 0x3 in psf_fread /src/file_io.c:349:10\n"))


def test_memory_error_inside_harness_code_is_regenerated(tmp_path):
    smoke = FakeSmoke(HARNESS_BUG, GOOD)
    run, rc, out, _ = _fake_run(tmp_path, top=1, smoke_exec=smoke)
    [group] = json.loads((out / "run_summary.json").read_text())["groups"]
    assert group["smoke"]["regenerated"] == 1
    assert group["smoke"]["attempts"][0]["crashed"]


HARNESS_ALLOC_BUG = ProcResult(1, False, stderr=(
    "#1 INITED cov: 40\n"
    "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
    "    #0 0x1 in strlen\n"
    "    #1 0x2 in psf_get_filelen /src/file_io.c:221:10\n"
    "allocated by thread T0 here:\n"
    "    #0 0x3 in malloc\n"
    "    #1 0x4 in LLVMFuzzerTestOneInput /tmp/out/build/harness/lg_proto_ctx_t.c:66:23\n"))


HARNESS_STACK_BUG = ProcResult(1, False, stderr=(
    "#1 INITED cov: 0\n"
    "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1\n"
    "    #0 0x1 in __asan_memset\n"
    "    #1 0x2 in psf_memset /src/common.c:1297:3\n"
    "    #2 0x3 in sf_readf_float /src/sndfile.c:2039:4\n"
    "Address 0x1 is located in stack of thread T0 at offset 2160 in frame\n"
    "    #0 0x4 in LLVMFuzzerTestOneInput /tmp/out/build/harness/lg_proto_ctx_t.c:42\n"))


def test_overflow_of_harness_stack_buffer_is_regenerated(tmp_path):
    smoke = FakeSmoke(HARNESS_STACK_BUG, GOOD)
    run, rc, out, _ = _fake_run(tmp_path, top=1, smoke_exec=smoke)
    [group] = json.loads((out / "run_summary.json").read_text())["groups"]
    assert group["smoke"]["regenerated"] == 1


def test_overflow_of_harness_allocated_buffer_is_regenerated(tmp_path):
    smoke = FakeSmoke(HARNESS_ALLOC_BUG, GOOD)
    run, rc, out, _ = _fake_run(tmp_path, top=1, smoke_exec=smoke)
    [group] = json.loads((out / "run_summary.json").read_text())["groups"]
    assert group["smoke"]["regenerated"] == 1


@pytest.mark.parametrize("log, expected", [
    ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1", "heap-buffer-overflow"),
    ("==1==ERROR: AddressSanitizer: attempting double-free on 0x1", "attempting double-free"),
    ("==1==ERROR: AddressSanitizer: SEGV on unknown address (pc 0x1)", ""),
    ("==1== ERROR: libFuzzer: deadly signal", ""),
    ("", ""),
])
def test_smoke_target_bug_classification(log, expected):
    from logosfuzz.control.generic_run import smoke_target_bug
    assert smoke_target_bug(log) == expected


def test_low_coverage_only_harness_still_fuzzes_as_fallback(tmp_path):
    run, rc, out, _ = _fake_run(tmp_path, top=1, smoke_exec=FakeSmoke(LOW_COV), smoke_retries=0)
    assert rc == 0
    [group] = json.loads((out / "run_summary.json").read_text())["groups"]
    assert not group["smoke"]["passed"] and group["smoke"]["used"]
    assert len(FakeSession.seen["groups"]) == 1


def test_smoke_threshold_scales_down_for_tiny_targets():
    from logosfuzz.control.generic_run import smoke_threshold

    tiny = "INFO: Loaded 1 modules   (9 inline 8-bit counters): 9 [0x1, 0x2)\n#6 INITED cov: 5"
    big = "INFO: Loaded 1 modules   (25000 inline 8-bit counters): 25000 [0x1, 0x2)"
    assert smoke_threshold(tiny, 30) == 3        # 9 * 0.3 올림
    assert smoke_threshold(big, 30) == 30
    assert smoke_threshold("no info", 30) == 30
    assert smoke_threshold(tiny, 0) == 0


def test_no_smoke_skips_stage(tmp_path):
    smoke = FakeSmoke()
    run, rc, out, _ = _fake_run(tmp_path, smoke_exec=smoke, smoke=False)
    stages = [s["stage"] for s in json.loads((out / "run_summary.json").read_text())["stages"]]
    assert "SMOKE" not in stages and not smoke.calls


def test_run_parser_accepts_smoke_and_libfuzzer_flags(tmp_path):
    from logosfuzz.control.generic_run import options_from_args

    parser = cli._build_parser()
    args = parser.parse_args(["run", "--profile", "p.json", "--budget", "60", "-o", str(tmp_path),
                              "--no-smoke", "--smoke-retries", "1", "--smoke-min-edges", "80",
                              "--max-len", "512", "--rss-limit-mb", "1024",
                              "--dict-dir", str(tmp_path / "d")])
    opts = options_from_args(args)
    assert (opts.smoke, opts.smoke_retries, opts.smoke_min_edges) == (False, 1, 80)
    assert (opts.max_len, opts.rss_limit_mb, opts.dict_dir) == (512, 1024, tmp_path / "d")


# --------------------------------------------------------------------------- #
# 실제 도구 전체 실행
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
    assert analysis["findings"]                           # ANA 까지 크래시 전달


def test_unexpected_llm_error_still_writes_summary(tmp_path):
    class BrokenLLM:
        def complete(self, prompt, system=""):
            raise ConnectionError("Connection error.")

    run, rc, out, _ = _fake_run(tmp_path, llm=BrokenLLM())
    assert rc == 1
    summary = json.loads((out / "run_summary.json").read_text())
    assert summary["ok"] is False
    assert summary["stages"][-1] == {**summary["stages"][-1], "stage": "GEN", "ok": False}
    assert "Connection error" in summary["stages"][-1]["error"]


VULN_HARNESS = """#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "can_label.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *s = malloc(size + 1);
    if (!s) return 0;
    memcpy(s, data, size);
    s[size] = 0;
    copy_can_label(s);
    free(s);
    return 0;
}
"""


def test_real_e2e_vuln_overflow_finds_stack_overflow(tmp_path):
    if not _toolchain_ready(tmp_path):
        pytest.skip("clang + compiler-rt(libFuzzer/ASan) + cmake + llvm 도구가 필요하다")
    src = tmp_path / "vuln_overflow"
    shutil.copytree(REPO / "examples" / "vuln_overflow", src,
                    ignore=shutil.ignore_patterns("build*"))
    data = json.loads((REPO / "targets" / "vuln_overflow.json").read_text(encoding="utf-8"))
    data["build"]["source_root"] = str(src)
    profile = tmp_path / "vuln_overflow.json"
    profile.write_text(json.dumps(data), encoding="utf-8")
    out = tmp_path / "out"

    rc = GenericRun(RunOptions(profile=profile, budget=30, output=out, use_docker=False),
                    llm=HarnessLLM(VULN_HARNESS)).run()

    assert rc == 0
    [group] = json.loads((out / "run_summary.json").read_text())["groups"]
    assert group["smoke"]["passed"]                       # 작은 대상도 비율 임계치로 통과
    assert group["crashes"] >= 1
    analysis = json.loads((out / "analysis.json").read_text())
    assert analysis["summary"]["true_positive"] >= 1
