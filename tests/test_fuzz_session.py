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


_ASAN_HEAD = ("==7==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1 "
              "at pc 0x2 bp 0x3 sp 0x4")


def test_fork_mode_replays_crashes_for_full_reports(tmp_path):
    """fork 모드 부모 출력의 ERROR 한 줄 결함을 재실행 보고로 대체"""
    cfg = _cfg(tmp_path)
    cfg.fork_jobs = 2
    cfg.fork_replay_limit = 2
    cfg.symbolize_crashes = False
    grp = _harness(cfg, "grpF")
    replays = []

    def fake_executor(argv, timeout, on_line):
        joined = " ".join(argv)
        if "-replay" in joined:
            replays.append(argv)
            for line in (_ASAN_HEAD,
                         "WRITE of size 17 at 0x1 thread T0",
                         "    #0 0x5 in copy_label /src/a.c:13:5",
                         "    #1 0x6 in LLVMFuzzerTestOneInput /src/h.c:19:5",
                         "SUMMARY: AddressSanitizer: stack-buffer-overflow /src/a.c:13:5"):
                on_line(line)
            return ProcResult(exit_code=1, timed_out=False)
        on_line(_ASAN_HEAD)
        on_line("#20: cov: 3 ft: 3 corp: 1 exec/s: 0 oom/timeout/crash: 0/0/3 time: 0s")
        cfg.crashes_dir.mkdir(parents=True, exist_ok=True)
        for i in range(3):
            (cfg.crashes_dir / f"crash-{i}").write_bytes(bytes([i]))
        return ProcResult(exit_code=1, timed_out=False)

    runner = DockerIsolationRunner(cfg, executor=fake_executor)
    session = FuzzSession(cfg, runner=runner, stream=io.StringIO())
    summary = session.run([grp], ensure_image=False)

    result = summary.groups[0]
    assert len(result.crashes) == 3
    assert len(replays) == 2
    assert len(result.sanitizer_findings) == 2
    assert all(f.traceback for f in result.sanitizer_findings)


def test_single_process_mode_does_not_replay(tmp_path):
    cfg = _cfg(tmp_path)
    cfg.symbolize_crashes = False
    grp = _harness(cfg, "grpS")
    calls = []

    def fake_executor(argv, timeout, on_line):
        calls.append(argv)
        cfg.crashes_dir.mkdir(parents=True, exist_ok=True)
        (cfg.crashes_dir / "crash-1").write_bytes(b"x")
        return ProcResult(exit_code=1, timed_out=False)

    runner = DockerIsolationRunner(cfg, executor=fake_executor)
    FuzzSession(cfg, runner=runner, stream=io.StringIO()).run([grp], ensure_image=False)
    assert len(calls) == 1


def test_session_minimizes_corpus_when_enabled(tmp_path):
    cfg = _cfg(tmp_path)
    cfg.minimize_corpus = True
    grp = _harness(cfg, "grpM")
    corpus = tmp_path / "corpus" / "grpM"
    corpus.mkdir(parents=True)
    for i in range(4):
        (corpus / f"c{i}").write_bytes(bytes([i]))
    grp = LogicGroup(name=grp.name, harness_path=grp.harness_path, corpus_dir=corpus)

    def fake_executor(argv, timeout, on_line):
        if "-merge" in " ".join(argv):
            (cfg.output_dir / "corpus_merge" / "grpM" / "m").write_bytes(b"m")
        else:
            on_line("#100 pulse cov: 10 exec/s: 50")
        return ProcResult(exit_code=0, timed_out=False)

    runner = DockerIsolationRunner(cfg, executor=fake_executor)
    out = io.StringIO()
    summary = FuzzSession(cfg, runner=runner, stream=out).run([grp], ensure_image=False)
    assert summary.to_dict()["groups"][0]["corpus_minimized"] == {"before": 4, "after": 1}
    assert "[MERGE] 코퍼스 최소화 4 → 1개" in out.getvalue()


def test_session_skips_minimize_by_default(tmp_path):
    cfg = _cfg(tmp_path)
    grp = _harness(cfg, "grpN")
    calls = []

    def fake_executor(argv, timeout, on_line):
        calls.append(argv)
        return ProcResult(exit_code=0, timed_out=False)

    runner = DockerIsolationRunner(cfg, executor=fake_executor)
    summary = FuzzSession(cfg, runner=runner, stream=io.StringIO()).run([grp], ensure_image=False)
    assert len(calls) == 1
    assert "corpus_minimized" not in summary.to_dict()["groups"][0]
