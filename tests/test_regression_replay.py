"""크래시 입력을 GCC+ASan 으로 재생하는 회귀 경로 단위 테스트.

퍼징은 clang + libFuzzer + ASan 으로 돈다. 거기서 나온 크래시를 다른
컴파일러로 다시 재생해 보면, 그 크래시가 대상 코드의 진짜 결함인지 아니면
clang/libFuzzer 쪽 특성이나 하네스 문제인지가 갈린다.
"""

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
    # 퍼징 config 와 섞이면 툴체인이 충돌한다.
    assert not any(a == "--config=fuzz" for a in argv)


def test_replay_build_swaps_engine_to_replay():
    """GCC 에는 libFuzzer 가 없다. 엔진 교체가 없으면 링크에서 죽는다."""
    argv = gcc_replay_build_argv("//score/json/fuzz:json_parser_fuzz_test")
    assert any(
        a.startswith("--@rules_fuzzing//fuzzing:cc_engine=") and a.endswith(":replay")
        for a in argv
    )


def test_replay_build_passes_sanitizer_features_directly():
    """asan_ubsan_lsan 은 test: 로만 정의돼 build 에서 쓸 수 없다.

    그래서 그 config 가 펼치는 것과 같은 --features 를 직접 넘긴다.
    """
    argv = gcc_replay_build_argv("//score/json/fuzz:json_parser_fuzz_test")
    assert "--features=asan" in argv
    assert "--config=asan_ubsan_lsan" not in argv


def test_replay_build_targets_bin_variant():
    """실제 실행 대상은 cc_fuzz_test 가 만드는 <name>_bin 이다."""
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
    """재생의 목적은 크래시가 다시 나는 것이다. 재현되는 쪽이 통과다."""
    crash = tmp_path / "crash-aaa"
    crash.write_bytes(b"\x00")
    case = build_replay_manifest([crash], replay_binary="/bin/x")["cases"][0]
    assert case["expected_status"] == "sanitizer_error"


def test_manifest_expected_status_is_overridable_for_fixed_bugs(tmp_path):
    """수정 후에는 '크래시가 안 나는 것'을 지키는 회귀 케이스가 된다."""
    crash = tmp_path / "crash-aaa"
    crash.write_bytes(b"\x00")
    case = build_replay_manifest(
        [crash], replay_binary="/bin/x", expected_status="passed"
    )["cases"][0]
    assert case["expected_status"] == "passed"


# --- RegressionRunner 와 실제로 물리는지 -----------------------------------
def test_generated_manifest_runs_through_regression_runner(tmp_path):
    """생성한 매니페스트가 기존 러너에서 그대로 돌아야 한다."""
    import json

    crash = tmp_path / "crash-aaa"
    crash.write_bytes(b"\x00")
    manifest = build_replay_manifest([crash], replay_binary="/bin/replay_bin")
    manifest_path = tmp_path / "replay.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    # ASan 출력을 내는 가짜 실행기 - 크래시가 재현된 상황을 흉내낸다.
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
    assert summary["matched"] == 1          # 재현됨 = 기대대로
    group = summary["groups"][0]
    assert group["status"] == "sanitizer_error"
    assert group["sanitizer_findings"][0]["category"] == "buffer-overflow"


def test_replay_that_does_not_reproduce_is_reported_as_mismatch(tmp_path):
    """재현되지 않으면 툴체인 의존성을 의심할 단서가 된다 - 놓치면 안 된다."""
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
    assert summary["groups"][0]["status"] == "passed"          # 크래시 안 남
    assert summary["groups"][0]["matched_expected"] is False   # 기대와 다름
