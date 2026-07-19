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
