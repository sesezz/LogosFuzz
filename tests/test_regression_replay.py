"""크래시 입력의 GCC+ASan 재생 회귀 경로 단위 테스트"""

from pathlib import Path

from logosfuzz.execute.regression import (
    GCC_REPLAY_PLATFORM_CONFIG,
    RegressionRunner,
    build_replay_manifest,
    gcc_replay_build_argv,
)


# --- 빌드 커맨드 -----------------------------------------------------------
def test_replay_build_uses_gcc_platform_config():
    argv = gcc_replay_build_argv("//score/json/fuzz:json_parser_fuzz_test")
    assert f"--config={GCC_REPLAY_PLATFORM_CONFIG}" in argv
    # 퍼징 config 와 혼용 시 툴체인 충돌
    assert not any(a == "--config=fuzz" for a in argv)


def test_replay_build_swaps_engine_to_replay():
    """GCC libFuzzer 미지원으로 재생 엔진 교체 확인"""
    argv = gcc_replay_build_argv("//score/json/fuzz:json_parser_fuzz_test")
    assert any(
        a.startswith("--@rules_fuzzing//fuzzing:cc_engine=") and a.endswith(":replay")
        for a in argv
    )


def test_replay_build_uses_sanitizer_config():
    """baselibs asan_ubsan_lsan config 그대로 사용"""
    argv = gcc_replay_build_argv("//score/json/fuzz:json_parser_fuzz_test")
    assert "--config=asan_ubsan_lsan" in argv
    assert not any(a.startswith("--features=") for a in argv)


def test_replay_build_relaxes_werror_only_for_abseil():
    """abseil 의 -Wformat-nonliteral 빌드 실패 회피 (외부 저장소 한정)"""
    argv = gcc_replay_build_argv("//score/json/fuzz:json_parser_fuzz_test")
    relax = [a for a in argv if a.startswith("--per_file_copt=")]
    assert relax == ["--per_file_copt=external/abseil-cpp.*@-Wno-error"]
    assert "--copt=-Wno-error" not in argv


def test_replay_build_targets_bin_variant():
    """실제 실행 대상은 cc_fuzz_test 의 <name>_bin"""
    argv = gcc_replay_build_argv("//score/json/fuzz:json_parser_fuzz_test")
    assert argv[-1] == "//score/json/fuzz:json_parser_fuzz_test_bin"


def test_replay_build_does_not_double_suffix_bin():
    argv = gcc_replay_build_argv("//pkg:target_bin")
    assert argv[-1] == "//pkg:target_bin"


# --- 매니페스트 생성 -------------------------------------------------------
def test_manifest_makes_one_case_per_crash(tmp_path):
    crashes = [tmp_path / "crash-aaa", tmp_path / "crash-bbb"]
    for c in crashes:
        c.write_bytes(b"\x00")
    manifest = build_replay_manifest(crashes, replay_binary="/bin/replay_bin")
    assert [c["name"] for c in manifest["cases"]] == ["replay-crash-aaa", "replay-crash-bbb"]


def test_manifest_run_argv_feeds_crash_input_to_binary(tmp_path):
    crash = tmp_path / "crash-aaa"
    crash.write_bytes(b"\x00")
    case = build_replay_manifest([crash], replay_binary="/bin/replay_bin")["cases"][0]
    assert case["run"] == ["/bin/replay_bin", str(crash)]


def test_manifest_expects_reproduction_by_default(tmp_path):
    """크래시 재현 시 통과"""
    crash = tmp_path / "crash-aaa"
    crash.write_bytes(b"\x00")
    case = build_replay_manifest([crash], replay_binary="/bin/x")["cases"][0]
    assert case["expected_status"] == "sanitizer_error"


def test_manifest_expected_status_is_overridable_for_fixed_bugs(tmp_path):
    """수정 후 '크래시 미발생' 회귀 케이스 전환"""
    crash = tmp_path / "crash-aaa"
    crash.write_bytes(b"\x00")
    case = build_replay_manifest(
        [crash], replay_binary="/bin/x", expected_status="passed"
    )["cases"][0]
    assert case["expected_status"] == "passed"


# --- RegressionRunner 연동 --------------------------------------------------
def test_generated_manifest_runs_through_regression_runner(tmp_path):
    """생성 매니페스트의 기존 러너 호환 확인"""
    import json

    crash = tmp_path / "crash-aaa"
    crash.write_bytes(b"\x00")
    manifest = build_replay_manifest([crash], replay_binary="/bin/replay_bin")
    manifest_path = tmp_path / "replay.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    # 크래시 재현 상황을 흉내내는 ASan 출력 가짜 실행기
    def fake_executor(argv, cwd, timeout, env):
        from logosfuzz.execute.regression import CommandResult
        return CommandResult(
            exit_code=1,
            timed_out=False,
            stderr=(
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
                "    #0 0x1 in Dispatch /proc/self/cwd/score/json/json.cc:107:16\n"
            ),
        )

    runner = RegressionRunner(tmp_path / "out", executor=fake_executor)
    summary = runner.run_manifest(manifest_path)

    assert summary["total"] == 1
    assert summary["matched"] == 1          # 재현 = 기대 일치
    group = summary["groups"][0]
    assert group["status"] == "sanitizer_error"
    assert group["sanitizer_findings"][0]["category"] == "buffer-overflow"


def test_replay_that_does_not_reproduce_is_reported_as_mismatch(tmp_path):
    """미재현 케이스 검출 (툴체인 의존성 단서)"""
    import json

    crash = tmp_path / "crash-aaa"
    crash.write_bytes(b"\x00")
    manifest_path = tmp_path / "replay.json"
    manifest_path.write_text(
        json.dumps(build_replay_manifest([crash], replay_binary="/bin/x")),
        encoding="utf-8",
    )

    def clean_executor(argv, cwd, timeout, env):
        from logosfuzz.execute.regression import CommandResult
        return CommandResult(exit_code=0, timed_out=False, stdout="ok\n")

    summary = RegressionRunner(tmp_path / "out", executor=clean_executor).run_manifest(
        manifest_path
    )
    assert summary["failed"] == 1
    assert summary["groups"][0]["status"] == "passed"          # 크래시 미발생
    assert summary["groups"][0]["matched_expected"] is False   # 기대와 다름
