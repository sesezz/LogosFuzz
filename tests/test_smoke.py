"""시드 스모크 테스트와 런타임 하네스 자가치유 (GENERIC-B, libsndfile 12차 실측 기반)."""
from __future__ import annotations

import stat
from pathlib import Path

import pytest

from logosfuzz.analyze.models import CrashRecord
from logosfuzz.common.target_profile import load_profile
from logosfuzz.execute.sanitizer import SanitizerMonitor
from logosfuzz.generate.smoke import (
    SmokeRun,
    build_runtime_repair_prompt,
    harness_defect,
    run_seed_smoke,
    smoke_repair,
)

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "c_return_code_logs" / "harness_undersized_buffer.txt"

BAD = "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { /* 64 floats */ return 0; }\n"
GOOD = "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { /* channels * frames */ return 0; }\n"


@pytest.fixture(scope="module")
def profile():
    return load_profile(REPO / "targets" / "libsndfile.json", base_dir=REPO)


def _crash_run() -> SmokeRun:
    monitor = SanitizerMonitor()
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        monitor.feed(line)
    records = [CrashRecord.from_finding(f.to_dict()) for f in monitor.finish()]
    return SmokeRun(ok=False, output=FIXTURE.read_text(encoding="utf-8"), returncode=1, records=records)


def _script(tmp_path, body: str) -> Path:
    path = tmp_path / "fake_harness"
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


# --------------------------------------------------------------------------- #
# run_seed_smoke
# --------------------------------------------------------------------------- #
def test_run_seed_smoke_passes_for_a_harness_that_exits_cleanly(tmp_path):
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"x")
    binary = _script(tmp_path, "exit 0\n")

    result = run_seed_smoke(binary, [seed])

    assert result.ok and result.records == []


def test_run_seed_smoke_parses_the_sanitizer_report_of_a_crash(tmp_path):
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"x")
    binary = _script(tmp_path, f"cat '{FIXTURE}' >&2\nexit 77\n")

    result = run_seed_smoke(binary, [seed])

    assert not result.ok and result.returncode == 77
    assert len(result.records) == 1 and result.records[0].category == "buffer-overflow"


def test_run_seed_smoke_does_not_touch_the_original_seed_folder(tmp_path):
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "a.bin").write_bytes(b"a")
    # 하네스가 코퍼스 폴더에 새 파일을 쓰는 상황 (libFuzzer 가 새 입력을 저장하는 동작)
    binary = _script(tmp_path, 'echo new > "$2/new-unit"\nexit 0\n')

    assert run_seed_smoke(binary, [seeds]).ok
    assert sorted(p.name for p in seeds.iterdir()) == ["a.bin"]


def test_run_seed_smoke_accepts_relative_paths(tmp_path, monkeypatch):
    """실측: 상대경로 하네스를 임시 폴더에서 실행하다 127 로 실패해 SMOKE 가 skipped 되었다."""
    (tmp_path / "seeds").mkdir()
    (tmp_path / "seeds" / "a.bin").write_bytes(b"a")
    _script(tmp_path, f"cat '{FIXTURE}' >&2\nexit 77\n")
    monkeypatch.chdir(tmp_path)

    result = run_seed_smoke(Path("fake_harness"), [Path("seeds")])

    assert result.returncode == 77 and len(result.records) == 1       # 실행되었고 크래시를 파싱함


def test_run_seed_smoke_reports_a_missing_binary(tmp_path):
    result = run_seed_smoke(tmp_path / "nope", [tmp_path])
    assert not result.ok and result.returncode == 127


# --------------------------------------------------------------------------- #
# 하네스 결함 증거와 프롬프트
# --------------------------------------------------------------------------- #
def test_harness_defect_found_for_undersized_buffer(profile):
    evidence = harness_defect(_crash_run().records, profile)
    assert evidence is not None and evidence.violation == "harness-buffer-suspect"
    assert evidence.api == "sf_readf_float"


def test_repair_prompt_carries_the_reason_the_log_and_the_source(profile):
    run = _crash_run()
    evidence = harness_defect(run.records, profile)

    prompt = build_runtime_repair_prompt(BAD, evidence, run.output)

    assert "sf_readf_float" in prompt and "channels" in prompt         # 이유
    assert "heap-buffer-overflow" in prompt                              # sanitizer 로그
    assert BAD.strip() in prompt                                         # 현재 소스
    assert "Do not remove API calls" in prompt


# --------------------------------------------------------------------------- #
# smoke_repair
# --------------------------------------------------------------------------- #
class Recorder:
    def __init__(self, runs, reply=f"```c\n{GOOD}```", rebuilt=Path("/bin/fixed")):
        self.runs, self.reply, self.rebuilt = list(runs), reply, rebuilt
        self.prompts, self.sources = [], []

    def run(self, binary, seeds):
        return self.runs.pop(0)

    def complete(self, prompt, system):
        self.prompts.append((prompt, system))
        return self.reply

    def rebuild(self, source):
        self.sources.append(source)
        return self.rebuilt


def _repair(rec, profile, seeds=(Path("seed"),), rounds=2):
    return smoke_repair(Path("/bin/orig"), BAD, seeds=list(seeds), profile=profile,
                        complete=rec.complete, rebuild=rec.rebuild, rounds=rounds, run=rec.run)


def test_clean_harness_is_left_alone(profile):
    rec = Recorder([SmokeRun(ok=True)])
    outcome = _repair(rec, profile)
    assert outcome.status == "clean" and outcome.source == BAD and outcome.binary == Path("/bin/orig")
    assert rec.prompts == []


def test_harness_defect_is_repaired_with_the_llm_and_rebuilt(profile):
    rec = Recorder([_crash_run(), SmokeRun(ok=True)])

    outcome = _repair(rec, profile)

    assert outcome.status == "repaired" and outcome.rounds == 1
    assert outcome.source.strip() == GOOD.strip() and outcome.binary == Path("/bin/fixed")
    assert rec.sources == [GOOD.strip()]
    prompt, system = rec.prompts[0]
    assert "sf_readf_float" in prompt and "C/C++ libraries and embedded firmware" in system


def test_crash_without_harness_defect_evidence_is_not_hidden(profile):
    run = _crash_run()
    run.records[0].raw_log = [line.replace("sf_readf_float", "not_an_api") for line in run.records[0].raw_log]
    rec = Recorder([run])

    outcome = _repair(rec, profile)

    assert outcome.status == "library-crash" and outcome.source == BAD
    assert rec.prompts == []                                             # LLM 으로 고치려 하지 않음


def test_repair_gives_up_after_the_round_limit(profile):
    rec = Recorder([_crash_run(), _crash_run(), _crash_run()])
    outcome = _repair(rec, profile, rounds=2)
    assert outcome.status == "unresolved" and outcome.rounds == 2 and len(rec.prompts) == 2


def test_failed_rebuild_keeps_the_original_harness(profile):
    rec = Recorder([_crash_run()], rebuilt=None)
    outcome = _repair(rec, profile)
    assert outcome.status == "rebuild-failed" and outcome.source == BAD and outcome.binary == Path("/bin/orig")


def test_empty_reply_is_not_built(profile):
    rec = Recorder([_crash_run()], reply="")
    outcome = _repair(rec, profile)
    assert outcome.status == "rebuild-failed" and rec.sources == []


def test_no_seeds_skips_the_smoke_test(profile):
    outcome = _repair(Recorder([]), profile, seeds=())
    assert outcome.status == "skipped"


def test_unrunnable_binary_is_skipped_not_judged(profile):
    rec = Recorder([SmokeRun(ok=False, output="실행할 수 없음", returncode=127)])
    assert _repair(rec, profile).status == "skipped"
