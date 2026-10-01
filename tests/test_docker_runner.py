import sys
import time

import pytest

from logosfuzz.config import Engine, FuzzConfig, LogicGroup
from logosfuzz.execute.docker_runner import DockerIsolationRunner, ProcResult, _default_executor
from logosfuzz.execute.errors import HarnessNotFoundError
from logosfuzz.execute.stats import LiveStats, StatsMonitor


def _config(tmp_path, **kw):
    return FuzzConfig(
        harness_dir=tmp_path / "harnesses",
        output_dir=tmp_path / "out",
        **kw,
    )


def _make_harness(cfg, name="grp1"):
    cfg.harness_dir.mkdir(parents=True, exist_ok=True)
    h = cfg.harness_dir / f"{name}"
    h.write_text("#!/bin/sh\n")
    return LogicGroup(name=name, harness_path=h.name)


def test_build_run_argv_isolation_flags(tmp_path):
    cfg = _config(tmp_path)
    runner = DockerIsolationRunner(cfg)
    grp = _make_harness(cfg)
    argv = runner.build_run_argv(grp)
    joined = " ".join(argv)
    assert "--network" in argv and "none" in argv
    assert "--cap-drop" in argv and "ALL" in argv
    assert "no-new-privileges" in joined
    assert "/harness:ro" in joined          # 하네스는 읽기전용
    assert ":/out" in joined                 # 출력은 쓰기 가능
    assert cfg.image in argv
    assert "-max_total_time=60" in joined    # libFuzzer 기본 엔진


def test_build_run_argv_maps_container_to_host_user(tmp_path):
    """/out 바인드 마운트에 크래시 artifact 를 쓸 수 있어야 한다.

    이미지 기본 사용자(uid 1000 fuzzer)로 컨테이너를 돌리면, 호스트 사용자의
    uid 가 다를 때(실측 확인: uid 1003) /out 에 쓰기 권한이 없어 ASAN 이
    결함을 잡아도 크래시 artifact 가 조용히 사라진다(total_crashes=0 으로
    잘못 보고됨). --user 로 호스트 uid:gid 를 그대로 넘겨 이를 막는다.
    """
    import os

    cfg = _config(tmp_path)
    runner = DockerIsolationRunner(cfg)
    grp = _make_harness(cfg)
    argv = runner.build_run_argv(grp)

    if hasattr(os, "getuid"):
        assert "--user" in argv
        idx = argv.index("--user")
        assert argv[idx + 1] == f"{os.getuid()}:{os.getgid()}"
    else:  # pragma: no cover - Windows 등 uid 개념이 없는 플랫폼
        assert "--user" not in argv


def test_build_run_argv_can_keep_the_image_default_user(tmp_path):
    cfg = _config(tmp_path, run_as_host_user=False)
    runner = DockerIsolationRunner(cfg)
    grp = _make_harness(cfg)
    argv = runner.build_run_argv(grp)
    assert "--user" not in argv


def test_local_argv_injects_asan_and_tsan_options(tmp_path):
    """--no-docker 경로도 config.asan_options/tsan_options 를 실제로 넘겨야 한다.

    subprocess.Popen 이 env= 없이 호출되면 부모 셸 환경을 그대로 물려받는다.
    셸에 ASAN_OPTIONS 가 없으면 ASAN 은 자체 기본값(symbolize=1 포함)을 쓰므로,
    config 를 symbolize=0 으로 바꿔도 이 경로에서는 조용히 무시된다(실측으로
    확인된 회귀 - WSL2 에서 크래시 시 ASAN 이 symbolizer 를 내부에서
    fork/exec 하며 무한 대기해, 크래시가 나도 하드 타임아웃까지 멈추고
    crashes/ 가 비었다).
    """
    cfg = _config(tmp_path, use_docker=False,
                  asan_options="abort_on_error=1:symbolize=0")
    runner = DockerIsolationRunner(cfg)
    grp = _make_harness(cfg)
    argv = runner._local_argv(grp)

    assert argv[0] == "env"
    env_pairs = dict(item.split("=", 1) for item in argv[1:] if "=" in item
                     and not item.startswith("-"))
    assert env_pairs.get("ASAN_OPTIONS") == "abort_on_error=1:symbolize=0"
    assert env_pairs.get("TSAN_OPTIONS") == cfg.tsan_options


def test_build_run_argv_aflpp(tmp_path):
    cfg = _config(tmp_path, engine=Engine.AFLPP)
    runner = DockerIsolationRunner(cfg)
    grp = _make_harness(cfg)
    joined = " ".join(runner.build_run_argv(grp))
    assert "afl-fuzz" in joined and "-V 60" in joined


def test_run_group_missing_harness(tmp_path):
    cfg = _config(tmp_path)
    runner = DockerIsolationRunner(cfg)
    grp = LogicGroup(name="ghost", harness_path="nope")
    with pytest.raises(HarnessNotFoundError):
        runner.run_group(grp)


def test_default_executor_separates_stdout_and_stderr():
    """표준 출력/표준 오류를 합치지 않고 각각 모아야 한다.

    사후에 "무엇이 출력됐는지" 재구성하려면 두 스트림이 뒤섞이면 안 된다.
    """
    argv = [sys.executable, "-c",
            "import sys; print('out-1'); print('err-1', file=sys.stderr)"]
    seen = []
    result = _default_executor(argv, timeout=10, on_line=seen.append)

    assert result.stdout == "out-1"
    assert result.stderr == "err-1"
    assert result.timed_out is False
    assert set(seen) == {"out-1", "err-1"}  # 두 스트림 다 on_line 으로도 전달됨


def test_default_executor_times_out_even_when_child_is_completely_silent():
    """자식이 출력을 전혀 안 해도 데드라인이 정확한 시각에 발동해야 한다.

    이전의 `for line in proc.stdout:` 블로킹 순회는 다음 줄이 올 때까지
    데드라인 검사 자체가 실행되지 않아, 자식이 침묵하면 hard timeout까지
    무한정 멈췄다(실측 확인: ASAN이 심볼라이저를 내부에서 fork하며 응답
    없이 대기하는 경우 90초 넘게 멈춘 뒤에야 겨우 빠져나왔다).
    """
    argv = [sys.executable, "-c", "import time; time.sleep(30)"]
    started = time.monotonic()
    result = _default_executor(argv, timeout=0.3, on_line=lambda line: None)
    elapsed = time.monotonic() - started

    assert result.timed_out is True
    assert elapsed < 5.0  # 30초 자식이지만 0.3초 데드라인 근처에서 끊겨야 함


def test_run_group_streams_and_returns(tmp_path):
    cfg = _config(tmp_path)
    grp = _make_harness(cfg)

    def fake_executor(argv, timeout, on_line):
        for line in ["#1 INITED", "#1024 pulse cov: 231 ft: 5 exec/s: 512"]:
            on_line(line)
        return ProcResult(exit_code=0, timed_out=False)

    runner = DockerIsolationRunner(cfg, executor=fake_executor)
    stats = LiveStats(group=grp.name)
    result = runner.run_group(grp, monitor=StatsMonitor(stats, live=False))
    assert result.exit_code == 0
    assert result.stats.exec_per_sec == 512
    assert result.stats.coverage == 231
    assert result.timed_out is False


def test_run_group_saves_stdout_and_stderr_logs(tmp_path):
    """정상/실패 구분 없이 표준 출력·표준 오류가 그룹별 로그로 남아야 한다."""
    cfg = _config(tmp_path)
    grp = _make_harness(cfg)

    def fake_executor(argv, timeout, on_line):
        return ProcResult(exit_code=1, timed_out=False,
                          stdout="normal output line",
                          stderr="ERROR: AddressSanitizer: heap-use-after-free")

    runner = DockerIsolationRunner(cfg, executor=fake_executor)
    result = runner.run_group(grp, monitor=StatsMonitor(LiveStats(group=grp.name), live=False))

    assert result.stdout_log is not None and result.stderr_log is not None
    stdout_path = cfg.logs_dir / grp.name / "run.stdout.log"
    stderr_path = cfg.logs_dir / grp.name / "run.stderr.log"
    assert result.stdout_log == str(stdout_path)
    assert result.stderr_log == str(stderr_path)
    assert stdout_path.read_text(encoding="utf-8") == "normal output line"
    assert "heap-use-after-free" in stderr_path.read_text(encoding="utf-8")


# --- Bazel 산출물 직접 실행 (EXE-04-01, GEN 파트 결정사항 ④) ---------------
#
# cc_fuzz_test 는 `<name>_bin`(계측된 퍼저 바이너리)을 워크스페이스의 bazel
# 출력 트리에 떨군다. harness_dir 밖이므로, 그 바이너리가 있는 디렉토리를
# /harness 로 마운트해야 컨테이너 안에서 실행할 수 있다.
def _make_bazel_binary(tmp_path, name="json_parser_fuzz_test_bin"):
    out = tmp_path / "ws" / "bazel-out" / "fuzz-opt" / "bin" / "score" / "json" / "fuzz"
    out.mkdir(parents=True, exist_ok=True)
    binary = out / name
    binary.write_text("#!/bin/sh\n")
    return binary


def test_harness_binary_path_uses_explicit_path(tmp_path):
    cfg = _config(tmp_path)
    binary = _make_bazel_binary(tmp_path)
    grp = LogicGroup(name="json", harness_path=binary)
    assert DockerIsolationRunner(cfg).harness_binary_path(grp) == binary.resolve()


def test_harness_binary_path_resolves_bare_name_against_harness_dir(tmp_path):
    cfg = _config(tmp_path)
    grp = _make_harness(cfg)
    runner = DockerIsolationRunner(cfg)
    assert runner.harness_binary_path(grp) == (cfg.harness_dir / grp.name).resolve()


def test_build_run_argv_mounts_bazel_output_dir(tmp_path):
    """하네스가 harness_dir 밖에 있으면 그 디렉토리를 /harness 로 마운트한다."""
    cfg = _config(tmp_path)
    binary = _make_bazel_binary(tmp_path)
    grp = LogicGroup(name="json", harness_path=binary)
    joined = " ".join(DockerIsolationRunner(cfg).build_run_argv(grp))
    assert f"{binary.parent.resolve()}:/harness:ro" in joined
    # 컨테이너 안 경로는 두 경우 모두 /harness/<파일명> 이라 내부 커맨드는 동일하다.
    assert "/harness/json_parser_fuzz_test_bin" in joined
    # harness_dir 은 이 경우 마운트되지 않아야 한다(엉뚱한 디렉토리 노출 방지).
    assert f"{cfg.harness_dir.resolve()}:/harness:ro" not in joined


def test_build_run_argv_still_mounts_harness_dir_for_bare_name(tmp_path):
    """기존 흐름(GEN이 harness_dir에 바이너리를 두는 경우)은 그대로 동작한다."""
    cfg = _config(tmp_path)
    grp = _make_harness(cfg)
    joined = " ".join(DockerIsolationRunner(cfg).build_run_argv(grp))
    assert f"{cfg.harness_dir.resolve()}:/harness:ro" in joined
    assert "/harness/grp1" in joined


def test_local_argv_uses_explicit_binary_path(tmp_path):
    cfg = _config(tmp_path, use_docker=False)
    binary = _make_bazel_binary(tmp_path)
    grp = LogicGroup(name="json", harness_path=binary)
    argv = DockerIsolationRunner(cfg)._local_argv(grp)
    # argv 앞에는 env 프리픽스(ASAN_OPTIONS 등)가 붙으므로 위치가 아니라
    # 포함 여부로 확인한다.
    assert str(binary.resolve()) in argv


def test_run_group_finds_harness_outside_harness_dir(tmp_path):
    """harness_dir 밖 바이너리를 '하네스 없음'으로 오판하지 않아야 한다."""
    cfg = _config(tmp_path, timeout_sec=1)
    binary = _make_bazel_binary(tmp_path)
    grp = LogicGroup(name="json", harness_path=binary)

    def fake_executor(argv, timeout, on_line):
        on_line("#1 pulse exec/s: 10")
        return ProcResult(exit_code=0, timed_out=False)

    runner = DockerIsolationRunner(cfg, executor=fake_executor)
    result = runner.run_group(grp)   # HarnessNotFoundError 가 나면 실패
    assert result.exit_code == 0
