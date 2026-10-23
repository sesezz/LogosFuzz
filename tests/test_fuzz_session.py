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
    assert saved["groups"][0]["status"] == "passed"
    assert saved["groups"][1]["status"] == "crashed"
    assert "execs" in saved["groups"][0]
    assert saved["groups"][1]["crash_count"] == 1
    # crashes/grpB 아래 크래시 보존 여부
    assert (cfg.crashes_dir / "grpB").exists()


def test_session_writes_sanitizer_events_for_ana(tmp_path):
    cfg = _cfg(tmp_path)
    group = _harness(cfg, "asan-group")

    def fake_executor(argv, timeout, on_line):
        on_line("ERROR: AddressSanitizer: heap-use-after-free")
        on_line("    #0 0x1 in read /src/uds.c:73:4")
        return ProcResult(exit_code=1, timed_out=False)

    runner = DockerIsolationRunner(cfg, executor=fake_executor)
    session = FuzzSession(cfg, runner=runner, stream=io.StringIO())
    summary = session.run([group], ensure_image=False)

    finding = summary.groups[0].sanitizer_findings[0]
    assert finding.signature == "use-after-free_uds_c_73"
    event_file = cfg.logs_dir / "sanitizer" / "asan-group.jsonl"
    event = json.loads(event_file.read_text().strip())
    assert event["category"] == "use-after-free"


# --- 시작 실패 구분 ---------------------------------------------------------
def _run_one(tmp_path, executor):
    cfg = _cfg(tmp_path)
    group = _harness(cfg, "grp")
    out = io.StringIO()
    runner = DockerIsolationRunner(cfg, executor=executor)
    summary = FuzzSession(cfg, runner=runner, stream=out).run([group], ensure_image=False)
    saved = json.loads((cfg.output_dir / "fuzz_summary.json").read_text())
    return summary, saved, out.getvalue()


def test_harness_that_never_runs_is_reported_as_start_failure(tmp_path):
    """libatomic.so.1 부재로 rc=127 종료하는 상황"""
    def executor(argv, timeout, on_line):
        on_line("/harness/grp: error while loading shared libraries: libatomic.so.1")
        return ProcResult(exit_code=127, timed_out=False)

    summary, saved, log = _run_one(tmp_path, executor)
    group = summary.groups[0]
    assert group.failed_to_start is True
    assert group.crashed is False          # 크래시로 미집계
    assert saved["failed_groups"] == ["grp"]
    assert saved["groups"][0]["failed_to_start"] is True
    assert "실행 실패" in log
    assert "=== 완료" not in log


def test_summary_records_exec_count(tmp_path):
    """fuzz_summary.json 의 총 실행 횟수 기록"""
    def executor(argv, timeout, on_line):
        on_line("#4096 pulse  cov: 10 ft: 12 corp: 3/9b exec/s: 2048 rss: 30Mb")
        return ProcResult(exit_code=0, timed_out=False)

    summary, saved, _ = _run_one(tmp_path, executor)
    assert saved["groups"][0]["execs"] == 4096
    assert saved["failed_groups"] == []


def test_crash_on_first_input_is_not_a_start_failure(tmp_path):
    """execs 0 이어도 새니타이저 결함 존재 시 크래시 판정"""
    def executor(argv, timeout, on_line):
        on_line("ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1")
        return ProcResult(exit_code=1, timed_out=False)

    summary, saved, _ = _run_one(tmp_path, executor)
    assert summary.groups[0].failed_to_start is False
    assert summary.groups[0].crashed is True
    assert saved["failed_groups"] == []


def test_reporting_marks_start_failure_as_failed_not_crashed(tmp_path):
    """실행 실패의 failed 상태 보고"""
    from logosfuzz.reporting.summary import _status

    def executor(argv, timeout, on_line):
        return ProcResult(exit_code=127, timed_out=False)

    _, saved, _ = _run_one(tmp_path, executor)
    assert _status(saved["groups"][0]) == "failed"
