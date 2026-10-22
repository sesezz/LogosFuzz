"""EXE-04-04 커버리지 계측 단위 테스트 (외부 명령은 ``runner`` 주입으로 대체)"""

import io
import json

from logosfuzz.config import CoverageMode, FuzzConfig, LogicGroup
from logosfuzz.execute.coverage import (
    CmdResult,
    CoverageCollector,
    CoverageMetric,
    bazel_coverage_configs,
    bazel_fuzz_coverage_build_argv,
    bazel_llvm_tool,
    extract_bazel_lcov,
    harness_binary_path,
    instrumentation_flags,
    parse_llvm_cov_export,
    profile_env,
)
from logosfuzz.execute.docker_runner import DockerIsolationRunner, ProcResult
from logosfuzz.execute.fuzz_session import FuzzSession


# --- 실제 llvm-cov export 형태의 샘플 -------------------------------------
_EXPORT_JSON = json.dumps({
    "version": "2.0.1",
    "type": "llvm.coverage.json.export",
    "data": [{
        "files": [
            {"filename": "/harness/uds.c", "summary": {
                "lines": {"count": 100, "covered": 72, "percent": 72.0},
                "functions": {"count": 12, "covered": 9, "percent": 75.0},
            }},
            {"filename": "/harness/can.c", "summary": {
                "lines": {"count": 40, "covered": 10, "percent": 25.0},
            }},
        ],
        "totals": {
            "lines": {"count": 140, "covered": 82, "percent": 58.57},
            "functions": {"count": 12, "covered": 9, "percent": 75.0},
            "regions": {"count": 60, "covered": 40, "percent": 66.67},
            "branches": {"count": 30, "covered": 18, "percent": 60.0},
            "instantiations": {"count": 12, "covered": 9, "percent": 75.0},
        },
    }],
})


def _cfg(tmp_path, **kw):
    return FuzzConfig(harness_dir=tmp_path / "harnesses",
                      output_dir=tmp_path / "out", **kw)


def _group():
    return LogicGroup(name="grpA", harness_path="grpA")


# --- 계측 플래그 계약 ------------------------------------------------------
def test_instrumentation_flags():
    llvm = instrumentation_flags(CoverageMode.LLVM_COV)
    assert "-fprofile-instr-generate" in llvm and "-fcoverage-mapping" in llvm
    assert "-fsanitize-coverage=trace-pc-guard" in instrumentation_flags(CoverageMode.SANITIZER_COV)
    assert instrumentation_flags(CoverageMode.NONE) == ()


# --- Bazel 경로의 계측 config ---------------------------------------------
def test_bazel_coverage_config_for_llvm_cov():
    """Bazel 빌드는 개별 -f 플래그 대신 대상 저장소 config 사용"""
    assert bazel_coverage_configs(CoverageMode.LLVM_COV) == ("llvm_cov",)


def test_bazel_coverage_config_empty_for_sancov():
    """엣지 계측은 퍼징 config(cc_engine_instrumentation)에서 적용"""
    assert bazel_coverage_configs(CoverageMode.SANITIZER_COV) == ()


def test_bazel_coverage_config_empty_when_disabled():
    assert bazel_coverage_configs(CoverageMode.NONE) == ()


# --- 퍼징 쪽 커버리지 빌드 -----------------------------------------------------
def test_fuzz_coverage_build_does_not_use_llvm_cov_config():
    """llvm_cov 는 coverage: 전용이므로 bazel build 에 미사용"""
    argv = bazel_fuzz_coverage_build_argv("//score/json/fuzz:json_parser_fuzz_test")
    assert argv[:3] == ["bazel", "build", "--config=fuzz"]
    assert "--config=llvm_cov" not in argv
    assert "--config=bl-x86_64-linux" not in argv


def test_fuzz_coverage_build_adds_source_based_instrumentation():
    argv = bazel_fuzz_coverage_build_argv("//score/json/fuzz:json_parser_fuzz_test")
    assert "--copt=-fprofile-instr-generate" in argv
    assert "--copt=-fcoverage-mapping" in argv
    assert "--linkopt=-fprofile-instr-generate" in argv


def test_fuzz_coverage_build_is_separated_from_fuzz_outputs():
    """계측 빌드의 퍼징 본 빌드 산출물(k8-fastbuild-fuzz) 덮어쓰기 방지"""
    argv = bazel_fuzz_coverage_build_argv("//score/json/fuzz:json_parser_fuzz_test")
    assert "--platform_suffix=fuzz_cov" in argv
    assert argv[-1] == "//score/json/fuzz:json_parser_fuzz_test_bin"


def test_bazel_llvm_tool_finds_toolchain_binary(tmp_path):
    """툴체인 쪽 llvm-profdata 탐색 (시스템 버전은 clang 22 profraw 미지원)"""
    bin_dir = tmp_path / "external" / "toolchains_llvm++llvm+llvm_toolchain_llvm" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "llvm-profdata").write_text("")
    assert bazel_llvm_tool(tmp_path, "llvm-profdata") == bin_dir / "llvm-profdata"


def test_bazel_llvm_tool_none_before_toolchain_is_fetched(tmp_path):
    assert bazel_llvm_tool(tmp_path, "llvm-profdata") is None


def test_extract_bazel_lcov_from_baselibs_zip(tmp_path):
    """baselibs 리포터의 zip 형식 _coverage_report.dat 처리"""
    import zipfile

    report = tmp_path / "_coverage_report.dat"
    with zipfile.ZipFile(report, "w") as bundle:
        bundle.writestr("html_report/index.html", "<html/>")
        bundle.writestr("lcov_report/lcov.dat", "SF:a.cc\nDA:1,1\nend_of_record\n")
    out = extract_bazel_lcov(report, tmp_path / "unit.lcov")
    assert out.read_text() == "SF:a.cc\nDA:1,1\nend_of_record\n"


def test_extract_bazel_lcov_passes_plain_lcov_through(tmp_path):
    report = tmp_path / "_coverage_report.dat"
    report.write_text("SF:a.cc\nend_of_record\n")
    out = extract_bazel_lcov(report, tmp_path / "unit.lcov")
    assert out.read_text() == "SF:a.cc\nend_of_record\n"


def test_instrumentation_flags_still_available_for_non_bazel_path():
    """CMake 대상·빠른 컴파일 검증 경로의 플래그 직접 사용"""
    assert "-fprofile-instr-generate" in instrumentation_flags(CoverageMode.LLVM_COV)


# --- 환경변수 계산 ---------------------------------------------------------
def test_profile_env_none_is_empty(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.NONE)
    assert profile_env(_group(), cfg, in_docker=True) == {}


def test_profile_env_docker_and_host(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.LLVM_COV)
    d = profile_env(_group(), cfg, in_docker=True)["LLVM_PROFILE_FILE"]
    assert d == "/out/coverage/grpA/%m.profraw"
    h = profile_env(_group(), cfg, in_docker=False)["LLVM_PROFILE_FILE"]
    assert h.endswith("coverage/grpA/%m.profraw") and tmp_path.as_posix() in h


# --- export 파서 -----------------------------------------------------------
def test_parse_llvm_cov_export_totals_and_files():
    s = parse_llvm_cov_export(_EXPORT_JSON, group="grpA", mode="llvm-cov")
    assert s.lines.covered == 82 and s.lines.count == 140
    assert s.lines.percent == 58.57
    assert s.functions.covered == 9 and s.functions.percent == 75.0
    assert s.regions.covered == 40 and s.regions.percent == 66.67
    assert s.branches.covered == 18 and s.branches.percent == 60.0
    assert len(s.files) == 2
    assert s.files[0].filename == "/harness/uds.c" and s.files[0].lines.covered == 72


def test_parse_empty_export_is_zero():
    s = parse_llvm_cov_export('{"data": []}', group="g", mode="llvm-cov")
    assert s.lines.count == 0 and s.lines.percent == 0.0
    assert s.functions.percent == 0.0


def test_metric_percent_zero_safe():
    assert CoverageMetric(0, 0).percent == 0.0
    assert CoverageMetric(3, 4).percent == 75.0


# --- argv 구성 -------------------------------------------------------------
def test_build_merge_argv_docker(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.LLVM_COV, use_docker=True)
    col = CoverageCollector(cfg)
    argv = col.build_merge_argv(_group())
    joined = " ".join(argv)
    assert cfg.image in argv and "bash" in argv
    assert "llvm-profdata merge -sparse" in joined
    assert "/out/coverage/grpA/*.profraw" in joined
    assert "/out/coverage/grpA.profdata" in joined


def test_build_export_argv_docker(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.LLVM_COV, use_docker=True)
    col = CoverageCollector(cfg)
    joined = " ".join(col.build_export_argv(_group()))
    assert "llvm-cov export -format=text" in joined
    assert "-instr-profile=/out/coverage/grpA.profdata" in joined
    assert "/harness/grpA" in joined


# --- 하네스 바이너리 위치 해석 ----------------------------------------------
# GEN 어댑터가 cquery 로 얻은 실제 경로를 harness_path 로 전달 (경로 조립 없음)
def test_harness_binary_path_uses_explicit_path_as_is(tmp_path):
    cfg = _cfg(tmp_path)
    binary = tmp_path / "ws" / "bazel-out" / "fuzz" / "json_parser_fuzz_test_bin"
    group = LogicGroup(name="grpA", harness_path=binary)
    assert harness_binary_path(group, cfg) == binary.resolve()


def test_harness_binary_path_falls_back_to_harness_dir_for_bare_name(tmp_path):
    cfg = _cfg(tmp_path)
    group = LogicGroup(name="grpA", harness_path="grpA")
    assert harness_binary_path(group, cfg) == (cfg.harness_dir / "grpA").resolve()


def test_export_argv_host_uses_explicit_binary_path(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.LLVM_COV, use_docker=False,
               coverage_in_docker=False)
    binary = tmp_path / "ws" / "bazel-out" / "fuzz" / "json_parser_fuzz_test_bin"
    group = LogicGroup(name="grpA", harness_path=binary)
    export = CoverageCollector(cfg).build_export_argv(group)
    assert export[4] == str(binary.resolve())


def test_export_argv_host_falls_back_to_harness_dir(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.LLVM_COV, use_docker=False,
               coverage_in_docker=False)
    export = CoverageCollector(cfg).build_export_argv(_group())
    assert str(cfg.harness_dir.resolve()) in export[4]


def test_build_argv_host(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.LLVM_COV, use_docker=False,
               coverage_in_docker=False)
    (cfg.coverage_dir / "grpA").mkdir(parents=True, exist_ok=True)
    (cfg.coverage_dir / "grpA" / "1.profraw").write_bytes(b"x")
    col = CoverageCollector(cfg)
    merge = col.build_merge_argv(_group())
    assert merge[0] == "llvm-profdata" and "merge" in merge
    assert any(p.endswith("1.profraw") for p in merge)
    export = col.build_export_argv(_group())
    assert export[0] == "llvm-cov" and "export" in export


# --- collect 오케스트레이션 ------------------------------------------------
def test_collect_none_mode_returns_none(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.NONE)
    assert CoverageCollector(cfg).collect(_group()) is None


def test_collect_without_profraw_returns_none(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.LLVM_COV)
    cfg.ensure_dirs()
    assert CoverageCollector(cfg).collect(_group()) is None


def test_collect_happy_path(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.LLVM_COV, use_docker=True)
    cfg.ensure_dirs()
    (cfg.coverage_dir / "grpA").mkdir(parents=True, exist_ok=True)
    (cfg.coverage_dir / "grpA" / "1.profraw").write_bytes(b"profraw-bytes")

    calls = []

    def fake_runner(argv):
        calls.append(argv)
        # merge는 stdout 불필요, export는 JSON 반환
        stdout = _EXPORT_JSON if "export" in " ".join(argv) else ""
        return CmdResult(0, stdout, "")

    col = CoverageCollector(cfg, runner=fake_runner)
    s = col.collect(_group())
    assert s is not None
    assert s.mode == "llvm-cov"
    assert s.lines.percent == 58.57
    assert len(calls) == 2  # merge + export
    # export 원문 보존 여부
    assert (cfg.coverage_dir / "grpA.coverage.json").exists()


def test_collect_tool_failure_returns_none(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.LLVM_COV)
    cfg.ensure_dirs()
    (cfg.coverage_dir / "grpA").mkdir(parents=True, exist_ok=True)
    (cfg.coverage_dir / "grpA" / "1.profraw").write_bytes(b"x")
    col = CoverageCollector(cfg, runner=lambda argv: CmdResult(1, "", "boom"))
    assert col.collect(_group()) is None


# --- docker_runner 통합: 환경변수 주입 -------------------------------------
def test_coverage_env_injected_into_docker_argv(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.LLVM_COV)
    cfg.harness_dir.mkdir(parents=True, exist_ok=True)
    (cfg.harness_dir / "grpA").write_text("#!/bin/sh\n")
    argv = DockerIsolationRunner(cfg).build_run_argv(_group())
    joined = " ".join(argv)
    assert "LLVM_PROFILE_FILE=/out/coverage/grpA/%m.profraw" in joined


def test_no_coverage_env_when_disabled(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.NONE)
    cfg.harness_dir.mkdir(parents=True, exist_ok=True)
    (cfg.harness_dir / "grpA").write_text("#!/bin/sh\n")
    argv = DockerIsolationRunner(cfg).build_run_argv(_group())
    assert "LLVM_PROFILE_FILE" not in " ".join(argv)


# --- fuzz_session 통합: summary에 coverage_report 연결 ---------------------
def test_session_attaches_coverage_report(tmp_path):
    cfg = _cfg(tmp_path, coverage=CoverageMode.LLVM_COV, use_docker=True, timeout_sec=3)
    cfg.harness_dir.mkdir(parents=True, exist_ok=True)
    (cfg.harness_dir / "grpA").write_text("#!/bin/sh\n")
    group = LogicGroup(name="grpA", harness_path="grpA")

    def fake_executor(argv, timeout, on_line):
        on_line("#100 pulse cov: 10 exec/s: 50")
        # 계측 하네스의 profraw 생성 시뮬레이션
        d = cfg.coverage_dir / "grpA"
        d.mkdir(parents=True, exist_ok=True)
        (d / "1.profraw").write_bytes(b"raw")
        return ProcResult(exit_code=0, timed_out=False)

    runner = DockerIsolationRunner(cfg, executor=fake_executor)
    runner.ensure_image = lambda *a, **k: None

    def fake_cmd_runner(argv):
        stdout = _EXPORT_JSON if "export" in " ".join(argv) else ""
        return CmdResult(0, stdout, "")

    collector = CoverageCollector(cfg, runner=fake_cmd_runner)
    session = FuzzSession(cfg, runner=runner, stream=io.StringIO(),
                          coverage_collector=collector)
    summary = session.run([group], ensure_image=False)

    saved = json.loads((cfg.output_dir / "fuzz_summary.json").read_text())
    report = saved["groups"][0]["coverage_report"]
    assert report is not None
    assert report["lines"]["percent"] == 58.57
    assert report["mode"] == "llvm-cov"
    assert (cfg.coverage_dir / "grpA.summary.json").exists()
