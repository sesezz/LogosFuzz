import pytest

from logosfuzz.config import Engine, FuzzConfig, LogicGroup
from logosfuzz.execute.docker_runner import DockerIsolationRunner, ProcResult
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
