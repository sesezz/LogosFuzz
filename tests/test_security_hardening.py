"""시큐어코딩 가이드 대응 회귀 테스트.

각 테스트는 보안약점 하나의 "완료 조건"을 그대로 옮긴 것이다
(docs/security/secure-coding.md 의 F01~F10 표 참고). 실제 악성 동작은 하지 않고,
임시 디렉터리 안에서 무해한 marker 파일·가짜 비밀 문자열로만 확인한다.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from logosfuzz.common.security import (
    UnsafePathError, cap_text, minimal_env, redact_secrets, safe_component, safe_join,
)

FAKE_SECRET = "sk-proj-THISISAFAKETESTSECRET0123456789"


# --------------------------------------------------------------------------- #
# 경로 검증 (F04, CWE-22)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["sf_open", "json_parse.c", "LG-can-parse", "grp1", "a+b"])
def test_safe_component_accepts_normal_names(name):
    assert safe_component(name) == name


@pytest.mark.parametrize("name", [
    "", "..", ".", "../x", "a/b", "a\\b", "/etc/passwd", "C:evil", "C:\\x",
    "\\\\server\\share", ".hidden", "a\x00b", "x" * 200, "name with space",
])
def test_safe_component_rejects_traversal_and_separators(name):
    with pytest.raises(UnsafePathError):
        safe_component(name)


@pytest.mark.parametrize("rel", ["../sibling", "a/../../x", "/abs", "C:/x", "a\\..\\b"])
def test_safe_join_rejects_escape(tmp_path, rel):
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path / "root", rel)


def test_safe_join_rejects_symlink_escape(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafePathError):
        safe_join(root, "link/marker")
    assert safe_join(root, "pkg/fuzz") == root / "pkg" / "fuzz"


# --------------------------------------------------------------------------- #
# 실행 환경 최소화 (F03, CWE-526)
# --------------------------------------------------------------------------- #
def test_minimal_env_drops_secrets_and_keeps_toolchain_basics():
    source = {"PATH": "/usr/bin", "HOME": "/home/u", "OPENAI_API_KEY": FAKE_SECRET,
              "AWS_SECRET_ACCESS_KEY": "x" * 20, "HTTPS_PROXY": "http://proxy:3128",
              "CCACHE_DIR": "/c", "LOGOSFUZZ_ENV_PASSTHROUGH": "CCACHE_DIR,GITHUB_TOKEN",
              "GITHUB_TOKEN": "ghp_x"}
    env = minimal_env({"CC": "clang"}, source=source)
    assert env["PATH"] == "/usr/bin" and env["CC"] == "clang"
    assert env["CCACHE_DIR"] == "/c"                     # 운영자가 명시한 변수는 통과
    assert "OPENAI_API_KEY" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert "GITHUB_TOKEN" not in env                     # 비밀 이름은 명시해도 차단
    assert "HTTPS_PROXY" not in env                      # 네트워크 단계가 아니면 프록시도 없음
    assert minimal_env(source=source, network=True)["HTTPS_PROXY"] == "http://proxy:3128"


def test_redact_secrets_masks_tokens_env_values_and_assignments():
    text = (f"key={FAKE_SECRET}\nOPENAI_API_KEY=abc123def456ghi\n"
            "int token_len = sizeof(x);\nleaked DBVALUE-zzzzzzzzzz here")
    out = redact_secrets(text, env={"DB_PASSWORD": "DBVALUE-zzzzzzzzzz"})
    assert FAKE_SECRET not in out and "abc123def456ghi" not in out
    assert "DBVALUE-zzzzzzzzzz" not in out
    assert "int token_len = sizeof(x);" in out            # 정상 C 코드는 건드리지 않는다


def test_cap_text_keeps_head_and_tail():
    text = "HEAD" + "x" * 10_000 + "TAIL"
    capped = cap_text(text, 200)
    assert len(capped) <= 200 and capped.startswith("HEAD") and capped.endswith("TAIL")


# --------------------------------------------------------------------------- #
# CMake 어댑터 (F01·F03·F04·F05·F10)
# --------------------------------------------------------------------------- #
from logosfuzz.common.target_profile import parse_profile          # noqa: E402
from logosfuzz.generate.build import CMakeAdapter, HarnessSpec     # noqa: E402
from logosfuzz.generate.build.cmake import DEFAULT_TIMEOUT_S, RunResult  # noqa: E402


class _Recorder:
    def __init__(self, libs):
        self.calls = []
        self.libs = libs

    def __call__(self, argv, cwd, env, timeout):
        argv = list(argv)
        self.calls.append(SimpleNamespace(argv=argv, env=dict(env) if env else None,
                                          timeout=timeout))
        if argv[0] == "cmake" and "-B" in argv:
            d = Path(argv[argv.index("-B") + 1])
            d.mkdir(parents=True, exist_ok=True)
            (d / "CMakeCache.txt").write_text("", encoding="utf-8")
        elif argv[0] == "cmake":
            for lib in self.libs:
                lib.parent.mkdir(parents=True, exist_ok=True)
                lib.write_text("", encoding="utf-8")
        elif "-o" in argv:
            out = Path(argv[argv.index("-o") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("", encoding="utf-8")
        return RunResult(0, "", "")


def _cmake(tmp_path, configure_args=("-DX=1",)):
    root = tmp_path / "src"
    root.mkdir(exist_ok=True)
    (root / "CMakeLists.txt").write_text("project(x)\n", encoding="utf-8")
    profile = parse_profile({
        "name": "x", "language": "c", "domain": "generic", "error_contract": "c_return_code",
        "build": {"system": "cmake", "source_root": "src", "build_dir": "build-fuzz",
                  "configure_args": list(configure_args), "libraries": ["build-fuzz/libx.a"],
                  "include_dirs": [], "link_flags": []},
    }, base_dir=tmp_path)
    runner = _Recorder([profile.abs("build-fuzz/libx.a")])
    adapter = CMakeAdapter(profile, work_dir=tmp_path / "work", runner=runner, jobs=1,
                           which=lambda name: None)
    return adapter, runner


def test_cmake_build_env_has_no_parent_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_SECRET)
    adapter, runner = _cmake(tmp_path)
    spec = HarnessSpec(name="h", srcs=("h.c",))
    adapter.emit_build_definition(spec, "int x;\n")
    assert adapter.build(spec).ok
    assert len(runner.calls) == 3                         # configure, build, link
    for call in runner.calls:
        assert call.env is not None and "OPENAI_API_KEY" not in call.env
        assert FAKE_SECRET not in json.dumps(call.env)
        assert call.timeout == DEFAULT_TIMEOUT_S          # 상한 없는 실행이 없다


@pytest.mark.parametrize("spec", [
    HarnessSpec(name="h", srcs=("../../escape.c",)),
    HarnessSpec(name="h", srcs=("h.c",), package="../../outside"),
    HarnessSpec(name="h", srcs=("/tmp/abs.c",)),
])
def test_cmake_rejects_harness_paths_outside_work_dir(tmp_path, spec):
    adapter, _ = _cmake(tmp_path)
    with pytest.raises(UnsafePathError):
        adapter.emit_build_definition(spec, "int x;\n")
    assert not (tmp_path / "escape.c").exists() and not (tmp_path / "outside").exists()


def test_cmake_rejects_binary_name_traversal(tmp_path):
    adapter, _ = _cmake(tmp_path)
    spec = HarnessSpec(name="../../evil", srcs=("h.c",))
    adapter.emit_build_definition(spec, "int x;\n")
    with pytest.raises(UnsafePathError):
        adapter.build(spec)


def test_cmake_cache_is_invalidated_when_flags_change(tmp_path):
    adapter, runner = _cmake(tmp_path)
    assert adapter.prepare().ok and len(runner.calls) == 2
    assert "캐시" in adapter.prepare().log                # 같은 설정이면 재사용

    changed, runner2 = _cmake(tmp_path, configure_args=("-DX=2",))
    result = changed.prepare()
    assert result.ok and "캐시" not in result.log and len(runner2.calls) == 2


# --------------------------------------------------------------------------- #
# Bazel 어댑터 (F04)
# --------------------------------------------------------------------------- #
from logosfuzz.generate.bazel.adapter import BazelAdapter             # noqa: E402
from logosfuzz.generate.bazel.build_file import FuzzTargetSpec        # noqa: E402


def _bazel_spec(package="pkg/fuzz", name="t_fuzz_test", srcs=("t_fuzz.cc",), deps=("//pkg:t",)):
    return FuzzTargetSpec(name=name, package=package, srcs=srcs, deps=deps)


def test_bazel_package_outside_workspace_is_rejected(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    adapter = BazelAdapter(ws)
    with pytest.raises(UnsafePathError):
        adapter.emit_build_definition(_bazel_spec(package="../sibling"), "x")
    with pytest.raises(UnsafePathError):
        adapter.remove(_bazel_spec(package="../sibling"))
    assert not (tmp_path / "sibling").exists()


def test_bazel_rejects_build_literal_injection(tmp_path):
    adapter = BazelAdapter(tmp_path)
    bad = _bazel_spec(deps=('//pkg:t"],\n)\ngenrule(name="x', ))
    with pytest.raises(UnsafePathError):
        adapter.emit_build_definition(bad, "x")


def test_bazel_remove_only_deletes_generated_files(tmp_path):
    adapter = BazelAdapter(tmp_path)
    spec = _bazel_spec()
    adapter.emit_build_definition(spec, "int x;\n")
    user_file = tmp_path / "pkg" / "fuzz" / "keep_me.txt"
    user_file.write_text("user data", encoding="utf-8")

    adapter.remove(spec)

    assert user_file.read_text(encoding="utf-8") == "user data"
    assert not (tmp_path / "pkg" / "fuzz" / "BUILD.bazel").exists()
    assert not (tmp_path / "pkg" / "fuzz" / "t_fuzz.cc").exists()


def test_bazel_does_not_overwrite_user_build_file(tmp_path):
    pkg = tmp_path / "pkg" / "fuzz"
    pkg.mkdir(parents=True)
    (pkg / "BUILD.bazel").write_text('cc_library(name = "orig")\n', encoding="utf-8")
    with pytest.raises(FileExistsError):
        BazelAdapter(tmp_path).emit_build_definition(_bazel_spec(), "x")
    assert "orig" in (pkg / "BUILD.bazel").read_text(encoding="utf-8")


def test_bazel_reemit_overwrites_its_own_build_file(tmp_path):
    adapter = BazelAdapter(tmp_path)
    adapter.emit_build_definition(_bazel_spec(), "v1")
    adapter.emit_build_definition(_bazel_spec(), "v2")      # 자가치유 루프의 재작성
    assert (tmp_path / "pkg" / "fuzz" / "t_fuzz.cc").read_text(encoding="utf-8") == "v2"


# --------------------------------------------------------------------------- #
# SubprocessCompiler (F04)
# --------------------------------------------------------------------------- #
from logosfuzz.generate.compiler import SubprocessCompiler    # noqa: E402
from logosfuzz.generate.models import HarnessDraft            # noqa: E402


def test_compiler_rejects_logic_group_traversal(tmp_path, monkeypatch):
    work = tmp_path / "work"
    compiler = SubprocessCompiler(cc="cc", workdir=str(work))
    monkeypatch.setattr(compiler, "available", lambda: True)
    result = compiler.compile(HarnessDraft(logic_group="../marker", source="int x;"))
    assert not result.ok and "로직 그룹" in result.stderr
    assert not (tmp_path / "marker.c").exists()


# --------------------------------------------------------------------------- #
# Docker 실행기 (F02·F03·F05·F07)
# --------------------------------------------------------------------------- #
from logosfuzz.config import FuzzConfig, LogicGroup                     # noqa: E402
from logosfuzz.execute.coverage import CoverageCollector                # noqa: E402
from logosfuzz.execute.docker_runner import (                           # noqa: E402
    DockerIsolationRunner, ProcResult, _default_executor,
)


def _cfg(tmp_path, **kw):
    return FuzzConfig(harness_dir=tmp_path / "h", output_dir=tmp_path / "out", **kw)


def test_run_group_rejects_group_name_traversal(tmp_path):
    cfg = _cfg(tmp_path, use_docker=False)
    cfg.harness_dir.mkdir(parents=True)
    (cfg.harness_dir / "bin").write_text("", encoding="utf-8")
    runner = DockerIsolationRunner(cfg, executor=lambda *a: ProcResult(0, False))
    with pytest.raises(UnsafePathError):
        runner.run_group(LogicGroup(name="../log-marker", harness_path="bin"))
    assert not (tmp_path / "out" / "log-marker").exists()


def test_log_write_failure_is_reported_not_swallowed(tmp_path):
    cfg = _cfg(tmp_path, use_docker=False)
    cfg.harness_dir.mkdir(parents=True)
    (cfg.harness_dir / "bin").write_text("", encoding="utf-8")
    cfg.ensure_dirs()
    (cfg.logs_dir / "g").write_text("not a dir", encoding="utf-8")   # mkdir 실패 유도
    runner = DockerIsolationRunner(cfg, executor=lambda *a: ProcResult(0, False))
    result = runner.run_group(LogicGroup(name="g", harness_path="bin"))
    assert result.stdout_log is None and not result.evidence_complete and result.log_error


def test_coverage_container_uses_same_isolation_policy(tmp_path):
    cfg = _cfg(tmp_path)
    argv = CoverageCollector(cfg)._docker_prefix()
    joined = " ".join(argv)
    for flag in ("--network none", "--cap-drop ALL", "no-new-privileges",
                 f"--memory {cfg.memory_limit}", f"--pids-limit {cfg.pids_limit}"):
        assert flag in joined


@pytest.mark.skipif(os.name != "posix", reason="POSIX 프로세스 그룹 동작")
def test_executor_hides_parent_secrets(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_SECRET)
    code = "import os; print(os.environ.get('OPENAI_API_KEY', 'absent'))"
    result = _default_executor([sys.executable, "-c", code], 30, lambda line: None)
    assert result.stdout.strip() == "absent"


@pytest.mark.skipif(os.name != "posix", reason="POSIX 프로세스 그룹 동작")
def test_executor_bounds_captured_output_but_monitor_sees_all():
    seen = []
    code = "import sys\nfor i in range(60000): print(i)\nprint('LAST')"
    result = _default_executor([sys.executable, "-c", code], 60, seen.append)
    assert len(seen) == 60001                                # 모니터는 모든 줄을 본다
    kept = result.stdout.splitlines()
    assert len(kept) < 30000 and kept[0] == "0" and kept[-1] == "LAST"
    assert any("생략" in line for line in kept)


@pytest.mark.skipif(os.name != "posix", reason="POSIX 프로세스 그룹 동작")
def test_executor_timeout_kills_descendants(tmp_path):
    marker = tmp_path / "child.pid"
    # 자식이 손자를 띄우고 침묵한다. 타임아웃 뒤 손자도 남지 않아야 한다.
    code = (
        "import subprocess, sys, time\n"
        f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        f"open({str(marker)!r}, 'w').write(str(p.pid))\n"
        "time.sleep(120)\n"
    )
    started = time.monotonic()
    result = _default_executor([sys.executable, "-c", code], 2, lambda line: None)
    assert result.timed_out and time.monotonic() - started < 30
    pid = int(marker.read_text())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        # 좀비로 남았다면 init 이 거둘 때까지 잠깐 기다린다.
        if Path(f"/proc/{pid}/stat").exists() and ") Z" in Path(f"/proc/{pid}/stat").read_text():
            break
        time.sleep(0.1)
    else:
        pytest.fail("타임아웃 뒤에도 손자 프로세스가 살아 있다")


# --------------------------------------------------------------------------- #
# HITL 저장소 (F07)
# --------------------------------------------------------------------------- #
from logosfuzz.control.hitl.models import Checkpoint, ReviewItem     # noqa: E402
from logosfuzz.control.hitl.store import JsonReviewStore             # noqa: E402


def test_two_store_instances_do_not_lose_each_others_items(tmp_path):
    path = tmp_path / "reviews.json"
    a, b = JsonReviewStore(path), JsonReviewStore(path)      # 두 프로세스를 흉내 낸다
    a.list()
    b.list()                                                 # 둘 다 빈 상태를 읽어 둔 뒤
    a.add(ReviewItem(checkpoint=Checkpoint.CRASH_TRIAGE, target="one"))
    b.add(ReviewItem(checkpoint=Checkpoint.CRASH_TRIAGE, target="two"))
    targets = {it.target for it in JsonReviewStore(path).list()}
    assert targets == {"one", "two"}
    if os.name == "posix":
        assert (path.stat().st_mode & 0o077) == 0              # 소유자만 읽고 쓴다
    assert not list(tmp_path.glob("*.tmp"))


def test_concurrent_processes_do_not_lose_items(tmp_path):
    path = tmp_path / "reviews.json"
    code = (
        "import sys\n"
        "from logosfuzz.control.hitl.models import Checkpoint, ReviewItem\n"
        "from logosfuzz.control.hitl.store import JsonReviewStore\n"
        "s = JsonReviewStore(sys.argv[1])\n"
        "for i in range(15):\n"
        "    s.add(ReviewItem(checkpoint=Checkpoint.CRASH_TRIAGE, target=sys.argv[2] + str(i)))\n"
    )
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    procs = [subprocess.Popen([sys.executable, "-c", code, str(path), tag], env=env)
             for tag in ("a", "b", "c")]
    assert all(p.wait(timeout=60) == 0 for p in procs)
    assert len(JsonReviewStore(path).list()) == 45


# --------------------------------------------------------------------------- #
# LLM 전송 (F06)
# --------------------------------------------------------------------------- #
from logosfuzz.generate.llm import (                         # noqa: E402
    MAX_CODE_CHARS, RepairPromptBuilder, extract_code, prepare_outbound,
)
from logosfuzz.generate.models import CompileResult         # noqa: E402


def test_prompt_and_outbound_payload_are_masked(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_SECRET)
    log = f"error: env dump OPENAI_API_KEY={FAKE_SECRET}\n"
    prompt = RepairPromptBuilder().build(
        HarnessDraft(logic_group="g", source="int x;"), "int x;",
        CompileResult(ok=False, returncode=1, stderr=log), round_idx=1)
    assert FAKE_SECRET not in prompt
    assert FAKE_SECRET not in prepare_outbound(f"raw {FAKE_SECRET}")
    assert len(prepare_outbound("x" * 500_000)) <= 60_000


def test_system_prompt_marks_inputs_as_untrusted():
    assert "untrusted data" in RepairPromptBuilder(domain="generic").system_prompt()


def test_oversized_llm_response_is_not_accepted_as_code():
    assert extract_code("```c\n" + "x" * (MAX_CODE_CHARS + 1) + "\n```") == ""
    assert extract_code("```c\nint x;\n```") == "int x;"


# --------------------------------------------------------------------------- #
# 공급망·비밀정보 (F08·O01)
# --------------------------------------------------------------------------- #
REPO = Path(__file__).resolve().parents[1]


def test_dockerfiles_require_download_digest_and_pinned_base():
    for name in ("Dockerfile", "Dockerfile.selfheal"):
        text = (REPO / "docker" / name).read_text(encoding="utf-8")
        assert "FROM ubuntu:24.04@sha256:" in text
        assert "sha256sum -c -" in text
        assert 'ARG BAZELISK_SHA256=""' not in text            # 빈 값으로 검증을 건너뛰지 않는다


def test_no_secret_like_values_are_committed():
    from logosfuzz.common import security

    try:
        files = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True,
                               text=True, check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git 저장소가 아니다")
    hits = []
    for rel in files:
        path = REPO / rel
        if path.suffix in {".png", ".jpg", ".pdf", ".zip", ".gz", ".hwpx"} or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in security._SECRET_VALUE_PATTERNS:
            hits += [f"{rel}: {m.group(0)[:12]}..." for m in pattern.finditer(text)
                     if "FAKE" not in m.group(0)]
    assert not hits, hits
