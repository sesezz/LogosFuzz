"""GEN 빌드 어댑터 테스트 (GENERIC-B). 외부 명령은 FakeRunner 로 대신해서 cmake/clang 없이 돈다."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from logosfuzz.common.target_profile import parse_profile
from logosfuzz.generate.bazel import adapter as bazel_adapter
from logosfuzz.generate.bazel.adapter import BazelAdapter
from logosfuzz.generate.bazel.build_file import FuzzTargetSpec
from logosfuzz.generate.build import (
    CMakeAdapter,
    HarnessSpec,
    PrebuiltAdapter,
    RunResult,
    adapter_for,
)
from logosfuzz.generate.build.__main__ import main
from logosfuzz.generate.build.base import BuildAdapter, BuildResult

SPEC = HarnessSpec(name="sndfile_fuzz", srcs=("sndfile_fuzz.c",))
HARNESS = "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }\n"


class FakeRunner:
    """외부 명령을 실행하지 않고 호출만 기록한다. 빌드가 만드는 파일은 흉내 낸다."""

    def __init__(self, libraries=(), fail=None):
        self.calls = []
        self.libraries = [Path(p) for p in libraries]
        self.fail = fail or (lambda argv: None)          # argv -> RunResult | None

    def __call__(self, argv, cwd, env, timeout):
        argv = list(argv)
        self.calls.append(SimpleNamespace(argv=argv, cwd=cwd, env=dict(env) if env else None))
        failed = self.fail(argv)
        if failed is not None:
            return failed
        if argv[0] == "cmake" and "-B" in argv:                      # configure
            build_dir = Path(argv[argv.index("-B") + 1])
            build_dir.mkdir(parents=True, exist_ok=True)
            (build_dir / "CMakeCache.txt").write_text("", encoding="utf-8")
        elif argv[0] == "cmake" and "--build" in argv:               # 라이브러리 생성 흉내
            for lib in self.libraries:
                lib.parent.mkdir(parents=True, exist_ok=True)
                lib.write_text("", encoding="utf-8")
        elif "-o" in argv:                                           # 링크 -> 실행 파일 생성 흉내
            out = Path(argv[argv.index("-o") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("", encoding="utf-8")
        return RunResult(0, "ok\n", "")


def profile_data(tmp_path, *, system="cmake", language="c", libraries=None, bazel=None):
    root = tmp_path / "third_party" / "lib"
    (root / "include").mkdir(parents=True, exist_ok=True)
    (root / "CMakeLists.txt").write_text("project(x)\n", encoding="utf-8")
    build = {
        "system": system,
        "source_root": "third_party/lib",
        "build_dir": "build-fuzz",
        "configure_args": ["-DBUILD_SHARED_LIBS=OFF", "-DENABLE_EXTERNAL_LIBS=OFF"],
        "libraries": ["build-fuzz/libx.a"] if libraries is None else libraries,
        "include_dirs": ["include"],
        "link_flags": ["-lm"],
        "compile_commands": "build-fuzz/compile_commands.json",
        "bazel": bazel,
    }
    return {"name": "x", "language": language, "domain": "generic", "build": build,
            "error_contract": "c_return_code"}


def make_profile(tmp_path, **kw):
    return parse_profile(profile_data(tmp_path, **kw), base_dir=tmp_path)


def make_adapter(tmp_path, *, profile=None, runner=None, cls=CMakeAdapter, which=None, **kw):
    profile = profile or make_profile(tmp_path)
    runner = runner or FakeRunner(libraries=[profile.abs("build-fuzz/libx.a")])
    adapter = cls(profile, work_dir=tmp_path / "work", runner=runner, jobs=4,
                  which=which or (lambda name: "/usr/bin/ninja"), **kw)
    return adapter, runner


# --------------------------------------------------------------------------- #
# 계약: 승격과 재수출
# --------------------------------------------------------------------------- #
def test_bazel_adapter_reexports_the_promoted_types():
    """승격 뒤에도 기존 import 경로가 같은 객체를 가리킨다 (Bazel 동작 불변)."""
    assert bazel_adapter.BuildResult is BuildResult
    assert bazel_adapter.BuildAdapter is BuildAdapter


def test_short_log_covers_build_tool_errors_compiler_and_linker_lines():
    log = (
        "CMake Error at CMakeLists.txt:3 (add_library):\n  Cannot find source file\n"
        "a.c:3:5: warning: unused variable\n"
        "a.c:9:1: error: expected ';'\n"
        "/usr/bin/ld: b.o: undefined reference to `foo'\n"
        "ld.lld: error: undefined symbol: bar\n"
        "ERROR: bazel style line\n"
    )
    short = BuildResult(ok=False, target="t", log=log).short_log

    assert short.splitlines()[0].startswith("CMake Error")           # 빌드 도구의 오류 줄이 먼저
    assert "ERROR: bazel style line" in short
    assert "expected ';'" in short
    assert "undefined reference to `foo'" in short and "undefined symbol: bar" in short
    assert "unused variable" not in short                            # 경고는 싣지 않는다
    assert "Cannot find source file" not in short                    # 진단이 아닌 줄


# --------------------------------------------------------------------------- #
# adapter_for
# --------------------------------------------------------------------------- #
def test_adapter_for_picks_the_adapter_by_build_system(tmp_path):
    work = tmp_path / "w"
    assert type(adapter_for(make_profile(tmp_path), work_dir=work)) is CMakeAdapter
    assert type(adapter_for(make_profile(tmp_path, system="prebuilt"), work_dir=work)) is PrebuiltAdapter

    bazel_profile = make_profile(tmp_path, system="bazel",
                                 bazel={"workspace": ".", "target": "//pkg:lib"})
    adapter = adapter_for(bazel_profile, bazel="bazelisk", config="fuzz")
    assert type(adapter) is BazelAdapter                              # 기존 어댑터 그대로
    assert adapter.workspace_root == bazel_profile.abs(".") and adapter.bazel == "bazelisk"


def test_adapter_for_rejects_unknown_build_system():
    with pytest.raises(ValueError, match="make"):
        adapter_for(SimpleNamespace(build=SimpleNamespace(system="make")))


# --------------------------------------------------------------------------- #
# CMakeAdapter.prepare
# --------------------------------------------------------------------------- #
def test_prepare_configures_then_builds_with_instrumentation(tmp_path):
    adapter, runner = make_adapter(tmp_path)

    result = adapter.prepare()

    assert result.ok and result.target == "cmake:x"
    configure, build = runner.calls
    assert configure.argv[:5] == ["cmake", "-S", str(adapter.source_dir), "-B", str(adapter.build_dir)]
    assert configure.argv[5:7] == ["-G", "Ninja"]
    assert "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in configure.argv
    assert configure.argv[-2:] == ["-DBUILD_SHARED_LIBS=OFF", "-DENABLE_EXTERNAL_LIBS=OFF"]  # 프로필 인자가 뒤
    env = configure.env
    assert env["CC"] == "clang" and env["CXX"] == "clang++"
    for flag in ("-g", "-O1", "-fno-omit-frame-pointer", "-fsanitize=address,undefined,fuzzer-no-link"):
        assert flag in env["CFLAGS"].split() and flag in env["CXXFLAGS"].split()
    assert build.argv == ["cmake", "--build", str(adapter.build_dir), "--parallel", "4"]


def test_prepare_uses_the_default_generator_without_ninja(tmp_path):
    adapter, runner = make_adapter(tmp_path, which=lambda name: None)
    assert adapter.prepare().ok
    assert "-G" not in runner.calls[0].argv


def test_prepare_is_cached_and_force_reruns(tmp_path):
    adapter, runner = make_adapter(tmp_path)
    assert adapter.prepare().ok and len(runner.calls) == 2

    again = adapter.prepare()
    assert again.ok and "캐시" in again.log and len(runner.calls) == 2   # 명령을 다시 실행하지 않는다

    assert adapter.prepare(force=True).ok and len(runner.calls) == 4
    assert "-G" not in runner.calls[2].argv      # 캐시가 있으면 생성기를 다시 지정하지 않는다(거부당함)


def test_prepare_reports_a_missing_source_tree(tmp_path):
    profile = make_profile(tmp_path)
    (profile.root / "CMakeLists.txt").unlink()
    adapter, runner = make_adapter(tmp_path, profile=profile)

    result = adapter.prepare()

    assert not result.ok and "CMakeLists.txt" in result.log
    assert runner.calls == []


def test_prepare_stops_after_a_failed_configure(tmp_path):
    def fail(argv):
        if "-B" in argv:
            return RunResult(1, "", "CMake Error at CMakeLists.txt:1 (project):\n  boom\n")

    adapter, runner = make_adapter(tmp_path, runner=FakeRunner(fail=fail))

    result = adapter.prepare()

    assert not result.ok and len(runner.calls) == 1                  # build 단계로 가지 않는다
    assert "CMake Error" in result.short_log


def test_prepare_fails_when_the_declared_library_is_not_produced(tmp_path):
    adapter, _ = make_adapter(tmp_path, runner=FakeRunner(libraries=[]))

    result = adapter.prepare()

    assert not result.ok and "libx.a" in result.log


# --- 남이 만들어 둔 캐시 (GENERIC-A 문서의 수동 configure 등) ----------------
#
# CMake 는 캐시가 있으면 CC/CFLAGS 환경변수를 무시한다. 그래서 캐시 판정이
# 컴파일러·플래그까지 보지 않으면 계측 없는 라이브러리가 "(캐시) OK" 로
# 통과하거나, 재빌드돼도 계측 없이 다시 만들어진다. libsndfile 실측에서
# `nm libsndfile.a | grep -c __asan_` 이 0 인 채로 prepare 가 성공했다.

def _write_cache(adapter, *, compiler="/usr/bin/clang", flags=None, language="C"):
    flags = " ".join(adapter.compile_flags()) if flags is None else flags
    adapter.build_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        "# This is the CMakeCache file.",
        "//  컴파일러 경로",
        "CMAKE_{}_COMPILER:FILEPATH={}".format(language, compiler),
        "CMAKE_{}_FLAGS:STRING={}".format(language, flags),
    ]
    (adapter.build_dir / "CMakeCache.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")


def test_prepare_discards_a_cache_built_by_another_compiler(tmp_path):
    profile = make_profile(tmp_path)
    runner = FakeRunner(libraries=[profile.abs("build-fuzz/libx.a")])
    adapter, _ = make_adapter(tmp_path, profile=profile, runner=runner)
    _write_cache(adapter, compiler="/usr/bin/cc", flags="")
    profile.abs("build-fuzz/libx.a").write_text("", encoding="utf-8")   # 라이브러리도 이미 있다

    result = adapter.prepare()

    assert result.ok
    assert "다시 configure" in result.log and "컴파일러가 다르다" in result.log
    assert [c.argv[0] for c in runner.calls] == ["cmake", "cmake"]      # 캐시로 때우지 않았다


def test_prepare_discards_a_cache_without_instrumentation_flags(tmp_path):
    profile = make_profile(tmp_path)
    runner = FakeRunner(libraries=[profile.abs("build-fuzz/libx.a")])
    adapter, _ = make_adapter(tmp_path, profile=profile, runner=runner)
    _write_cache(adapter, flags="-g -O1")          # 컴파일러는 같은데 -fsanitize 가 없다
    profile.abs("build-fuzz/libx.a").write_text("", encoding="utf-8")

    result = adapter.prepare()

    assert result.ok and "계측 플래그가 빠져 있다" in result.log
    assert "-fsanitize=address,undefined,fuzzer-no-link" in result.log
    assert (adapter.build_dir / "CMakeCache.txt").read_text(encoding="utf-8") == ""


def test_prepare_keeps_a_cache_that_already_matches(tmp_path):
    profile = make_profile(tmp_path)
    runner = FakeRunner(libraries=[profile.abs("build-fuzz/libx.a")])
    adapter, _ = make_adapter(tmp_path, profile=profile, runner=runner)
    _write_cache(adapter)                          # 컴파일러·플래그가 모두 일치
    profile.abs("build-fuzz/libx.a").write_text("", encoding="utf-8")

    result = adapter.prepare()

    assert result.ok and "캐시" in result.log
    assert runner.calls == []                      # 아무것도 다시 돌리지 않는다


def test_cache_without_the_keys_is_not_treated_as_a_mismatch(tmp_path):
    """판정은 보수적이어야 한다 — 모르면 지우지 않는다."""
    adapter, _ = make_adapter(tmp_path)
    adapter.build_dir.mkdir(parents=True, exist_ok=True)
    (adapter.build_dir / "CMakeCache.txt").write_text("# 비어 있다", encoding="utf-8")

    assert adapter._cache_mismatch() == ""


def test_cpp_profile_checks_the_cxx_cache_entries(tmp_path):
    profile = make_profile(tmp_path, language="cpp")
    adapter, _ = make_adapter(tmp_path, profile=profile)
    _write_cache(adapter, compiler="/usr/bin/g++", flags="", language="CXX")

    assert "g++" in adapter._cache_mismatch()

    same = make_adapter(tmp_path, profile=profile)[0]
    _write_cache(same, compiler="/usr/bin/cc", flags="", language="C")   # C 쪽은 봐도 의미 없다
    assert same._cache_mismatch() == ""


def test_cache_is_not_removed_when_it_is_the_source_tree(tmp_path):
    """in-source 빌드를 지우면 대상 소스가 날아간다. 지우지 말고 실패해야 한다."""
    data = profile_data(tmp_path)
    data["build"]["build_dir"] = "."            # in-source 빌드
    data["build"]["libraries"] = ["libx.a"]
    profile = parse_profile(data, base_dir=tmp_path)
    adapter, _ = make_adapter(tmp_path, profile=profile)
    _write_cache(adapter, compiler="/usr/bin/cc", flags="")

    result = adapter.prepare()

    assert not result.ok
    assert "source_root 와 같다" in result.log
    assert (profile.root / "CMakeLists.txt").is_file()      # 소스는 그대로다


def test_coverage_variant_uses_a_separate_instrumented_build_dir(tmp_path):
    profile = make_profile(tmp_path)
    runner = FakeRunner(libraries=[profile.abs("build-fuzz-cov/libx.a")])
    adapter, _ = make_adapter(tmp_path, profile=profile, runner=runner, coverage=True)

    assert adapter.build_dir == profile.abs("build-fuzz-cov")
    assert adapter.libraries == [profile.abs("build-fuzz-cov/libx.a")]   # 라이브러리 경로도 -cov 로
    result = adapter.prepare()
    assert result.ok and result.target == "cmake:x:cov"
    cflags = runner.calls[0].env["CFLAGS"]
    assert "-fprofile-instr-generate" in cflags and "-fcoverage-mapping" in cflags
    # configure 검사 프로그램의 profraw 저장소 루트 유출 없음
    assert runner.calls[0].env["LLVM_PROFILE_FILE"].startswith(str(profile.abs("build-fuzz-cov")))

    plain, _ = make_adapter(tmp_path)
    assert "-fprofile-instr-generate" not in " ".join(plain.compile_flags())


# --------------------------------------------------------------------------- #
# CMakeAdapter.emit / build / remove
# --------------------------------------------------------------------------- #
def test_build_links_the_harness_against_the_libraries(tmp_path):
    adapter, runner = make_adapter(tmp_path)
    source = adapter.emit_build_definition(SPEC, HARNESS)

    result = adapter.build(SPEC)

    assert source == tmp_path / "work" / "harness" / "sndfile_fuzz.c"
    assert source.read_text(encoding="utf-8") == HARNESS
    assert result.ok and result.binary == tmp_path / "work" / "bin" / "sndfile_fuzz"
    assert result.binary.is_file() and adapter.binary_path(SPEC) == result.binary

    link = runner.calls[-1].argv                                    # prepare(2회) 다음의 링크 명령
    lib = str(adapter.libraries[0])
    assert link[0] == "clang"
    assert "-fsanitize=address,undefined,fuzzer" in link
    assert f"-I{adapter.profile.abs('include')}" in link
    assert link.index(str(source)) < link.index(lib) < link.index("-lm")   # 소스, 정적 라이브러리, 링크 플래그 순
    assert link[-2:] == ["-o", str(result.binary)]


def test_build_uses_the_cxx_compiler_for_cpp_profiles(tmp_path):
    adapter, runner = make_adapter(tmp_path, profile=make_profile(tmp_path, language="cpp"))
    spec = HarnessSpec(name="h", srcs=("h.cc",))
    adapter.emit_build_definition(spec, HARNESS)

    assert adapter.build(spec).ok
    assert runner.calls[-1].argv[0] == "clang++"


def test_build_requires_the_harness_to_be_emitted_first(tmp_path):
    adapter, runner = make_adapter(tmp_path)

    result = adapter.build(SPEC)

    assert not result.ok and "emit_build_definition" in result.log
    assert runner.calls == []


def test_link_failure_keeps_the_raw_linker_output(tmp_path):
    raw = ("/usr/bin/ld: harness.o: undefined reference to `HAL_GetTick'\n"
           "clang: error: linker command failed with exit code 1 (use -v to see invocation)\n")
    profile = make_profile(tmp_path)
    runner = FakeRunner(libraries=[profile.abs("build-fuzz/libx.a")],
                        fail=lambda argv: RunResult(1, "", raw) if "-o" in argv else None)
    adapter, _ = make_adapter(tmp_path, profile=profile, runner=runner)
    adapter.emit_build_definition(SPEC, HARNESS)

    result = adapter.build(SPEC)

    assert not result.ok and result.binary is None
    assert "undefined reference to `HAL_GetTick'" in result.log      # 원문 그대로 (자가치유 분류기 입력)
    assert "undefined reference" in result.short_log and "linker command failed" in result.short_log


def test_build_does_not_link_when_prepare_fails(tmp_path):
    runner = FakeRunner(fail=lambda argv: RunResult(1, "", "CMake Error: boom") if "-B" in argv else None)
    adapter, _ = make_adapter(tmp_path, runner=runner)
    adapter.emit_build_definition(SPEC, HARNESS)

    result = adapter.build(SPEC)

    assert not result.ok and "CMake Error" in result.log
    assert len(runner.calls) == 1


def test_emit_requires_exactly_one_source(tmp_path):
    adapter, _ = make_adapter(tmp_path)
    with pytest.raises(ValueError, match="1개"):
        adapter.emit_build_definition(HarnessSpec(name="x", srcs=("a.c", "b.c")), HARNESS)


def test_remove_deletes_source_and_binary_and_is_idempotent(tmp_path):
    adapter, _ = make_adapter(tmp_path)
    source = adapter.emit_build_definition(SPEC, HARNESS)
    binary = adapter.build(SPEC).binary
    assert source.is_file() and binary.is_file()

    adapter.remove(SPEC)
    adapter.remove(SPEC)                                              # 두 번째는 오류 없이 지나간다

    assert not source.exists() and not binary.exists() and adapter.binary_path(SPEC) is None


def test_fuzz_target_spec_from_bazel_is_accepted_as_is(tmp_path):
    """Bazel 명세(name/package/srcs)도 그대로 받는다 — 기존 하네스 쌍 코드를 바꾸지 않아도 된다."""
    adapter, _ = make_adapter(tmp_path)
    spec = FuzzTargetSpec(name="lg_x_fuzz_test", package="score/x/fuzz/lg_x",
                          srcs=("lg_x_fuzz.cc",), deps=())

    source = adapter.emit_build_definition(spec, HARNESS)

    assert source == tmp_path / "work" / "harness" / "score/x/fuzz/lg_x" / "lg_x_fuzz.cc"


# --------------------------------------------------------------------------- #
# PrebuiltAdapter
# --------------------------------------------------------------------------- #
def test_prebuilt_requires_the_libraries_to_exist(tmp_path):
    adapter, runner = make_adapter(tmp_path, profile=make_profile(tmp_path, system="prebuilt"),
                                   cls=PrebuiltAdapter)

    result = adapter.prepare()

    assert not result.ok and "libx.a" in result.log and "prebuilt" in result.log
    assert runner.calls == []


def test_prebuilt_rejects_an_empty_library_list(tmp_path):
    profile = make_profile(tmp_path, system="prebuilt", libraries=[])
    adapter, _ = make_adapter(tmp_path, profile=profile, cls=PrebuiltAdapter)

    result = adapter.prepare()

    assert not result.ok and "비어" in result.log


def test_prebuilt_only_links(tmp_path):
    profile = make_profile(tmp_path, system="prebuilt")
    lib = profile.abs("build-fuzz/libx.a")
    lib.parent.mkdir(parents=True, exist_ok=True)
    lib.write_text("", encoding="utf-8")
    adapter, runner = make_adapter(tmp_path, profile=profile, cls=PrebuiltAdapter,
                                   runner=FakeRunner())

    assert adapter.prepare().ok and runner.calls == []                # configure/build 없음
    adapter.emit_build_definition(SPEC, HARNESS)
    result = adapter.build(SPEC)

    assert result.ok and len(runner.calls) == 1                       # 링크 1회뿐
    assert runner.calls[0].argv[0] == "clang" and str(lib) in runner.calls[0].argv


# --------------------------------------------------------------------------- #
# 확인용 진입점
# --------------------------------------------------------------------------- #
def _write_profile(tmp_path, **kw):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile_data(tmp_path, **kw)), encoding="utf-8")
    return path


def test_cli_builds_a_manual_harness(tmp_path, capsys):
    profile = make_profile(tmp_path)
    harness = tmp_path / "manual_fuzz.c"
    harness.write_text(HARNESS, encoding="utf-8")
    runner = FakeRunner(libraries=[profile.abs("build-fuzz/libx.a")])

    code = main(["--profile", str(_write_profile(tmp_path)), "--base-dir", str(tmp_path),
                 "--harness", str(harness), "--work-dir", str(tmp_path / "work")], runner=runner)

    out = capsys.readouterr().out
    assert code == 0 and "[PREPARE] OK" in out and "[BUILD] OK manual_fuzz" in out
    assert str(tmp_path / "work" / "bin" / "manual_fuzz") in out


def test_cli_prepare_only_does_not_need_a_harness(tmp_path, capsys):
    profile = make_profile(tmp_path)
    runner = FakeRunner(libraries=[profile.abs("build-fuzz/libx.a")])

    code = main(["--profile", str(_write_profile(tmp_path)), "--base-dir", str(tmp_path),
                 "--prepare-only", "--work-dir", str(tmp_path / "work")], runner=runner)

    assert code == 0 and "[PREPARE] OK" in capsys.readouterr().out


def test_cli_says_when_it_threw_away_a_stale_cache(tmp_path, capsys):
    """조용히 지나가면 2분이 더 걸린 이유를 아무도 모른다."""
    profile = make_profile(tmp_path)
    runner = FakeRunner(libraries=[profile.abs("build-fuzz/libx.a")])
    build_dir = profile.abs("build-fuzz")
    build_dir.mkdir(parents=True, exist_ok=True)
    (build_dir / "CMakeCache.txt").write_text(      # 남이 gcc 로 만들어 둔 캐시
        "CMAKE_C_COMPILER:FILEPATH=/usr/bin/cc", encoding="utf-8")

    code = main(["--profile", str(_write_profile(tmp_path)), "--base-dir", str(tmp_path),
                 "--prepare-only", "--work-dir", str(tmp_path / "work")], runner=runner)

    assert code == 0

    out = capsys.readouterr().out
    assert "[PREPARE] OK" in out
    assert "기존 캐시를 버리고 다시 configure" in out


def test_cli_reports_a_failed_build_and_returns_nonzero(tmp_path, capsys):
    profile = make_profile(tmp_path)
    harness = tmp_path / "bad_fuzz.c"
    harness.write_text(HARNESS, encoding="utf-8")
    runner = FakeRunner(
        libraries=[profile.abs("build-fuzz/libx.a")],
        fail=lambda argv: RunResult(1, "", "bad_fuzz.c:1:5: error: boom\n") if "-o" in argv else None)

    code = main(["--profile", str(_write_profile(tmp_path)), "--base-dir", str(tmp_path),
                 "--harness", str(harness), "--work-dir", str(tmp_path / "work")], runner=runner)

    captured = capsys.readouterr()
    assert code == 1 and "[BUILD] FAIL" in captured.out and "error: boom" in captured.err


def test_cli_rejects_bad_profiles_and_bazel_profiles(tmp_path, capsys):
    assert main(["--profile", str(tmp_path / "missing.json"), "--prepare-only"]) == 2

    code = main(["--profile", str(_write_profile(tmp_path, system="bazel",
                                                 bazel={"workspace": ".", "target": "//pkg:lib"})),
                 "--base-dir", str(tmp_path), "--prepare-only"])
    assert code == 2 and "bazel" in capsys.readouterr().err
