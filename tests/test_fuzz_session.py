import io
import json

from logosfuzz.config import FuzzConfig, LogicGroup
from logosfuzz.execute.docker_runner import DockerIsolationRunner, ProcResult
from logosfuzz.execute.fuzz_session import FuzzSession


def _cfg(tmp_path):
    return FuzzConfig(
        harness_dir=tmp_path / "harnesses",
        output_dir=tmp_path / "out",
        use_docker=True,
        timeout_sec=5,
    )


def _harness(cfg, name):
    cfg.harness_dir.mkdir(parents=True, exist_ok=True)
    (cfg.harness_dir / name).write_text("#!/bin/sh\n")
    return LogicGroup(name=name, harness_path=name)


def test_session_runs_all_groups_and_collects_crash(tmp_path):
    cfg = _cfg(tmp_path)
    g1 = _harness(cfg, "grpA")
    g2 = _harness(cfg, "grpB")

    def fake_executor(argv, timeout, on_line):
        on_line("#100 pulse cov: 10 exec/s: 50")
        # grpB에서만 크래시 산출물 생성
        if "grpB" in " ".join(argv):
            cfg.crashes_dir.mkdir(parents=True, exist_ok=True)
            (cfg.crashes_dir / "crash-deadbeef").write_bytes(b"boom")
            return ProcResult(exit_code=1, timed_out=False)
        return ProcResult(exit_code=0, timed_out=False)

    runner = DockerIsolationRunner(cfg, executor=fake_executor)
    # 이미지 빌드 단계는 테스트에서 우회
    runner.ensure_image = lambda *a, **k: None

    out = io.StringIO()
    session = FuzzSession(cfg, runner=runner, stream=out)
    summary = session.run([g1, g2], ensure_image=False)

    assert len(summary.groups) == 2
    assert summary.total_crashes == 1
    # summary json 저장 확인
    saved = json.loads((cfg.output_dir / "fuzz_summary.json").read_text())
    assert saved["total_crashes"] == 1
    assert saved["total_groups"] == 2
    # 크래시가 crashes/grpB 아래로 보존됐는지
    assert (cfg.crashes_dir / "grpB").exists()
