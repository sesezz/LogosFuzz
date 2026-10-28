"""EXE-04-02 크래시 후처리 심볼라이즈 테스트.

입력으로 쓰는 ASAN 프레임 원문은 추측이 아니다 — clang 18.1.3 /
``symbolize=0`` 으로 돌린 실제 캠페인(examples/stage1) 출력에서 가져왔다.
"""

import io

from logosfuzz.config import FuzzConfig, LogicGroup
from logosfuzz.execute.coverage import CmdResult
from logosfuzz.execute.docker_runner import DockerIsolationRunner, ProcResult
from logosfuzz.execute.fuzz_session import FuzzSession
from logosfuzz.execute.sanitizer import SanitizerMonitor
from logosfuzz.execute.symbolize import CrashSymbolizer

# symbolize=0 ASAN 출력. #1/#2 가 대상 코드, #0 은 ASAN 런타임(ASAN 이 이미
# 함수명을 붙였지만 파일:줄은 없다), #3 은 컨테이너의 libc.
RAW_CRASH = """==8184==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f78469da5a8 at pc 0x59c7003d9d18 bp 0x7ffe75f1e770 sp 0x7ffe75f1df30
WRITE of size 13 at 0x7f78469da5a8 thread T0
    #0 0x59c7003d9d17 in __asan_memcpy (/harness/stage1_fuzz+0xfed17) (BuildId: 1c73e4)
    #1 0x59c70041a726  (/harness/stage1_fuzz+0x13f726) (BuildId: 1c73e4)
    #2 0x59c70041a3b4  (/harness/stage1_fuzz+0x13f3b4) (BuildId: 1c73e4)
    #3 0x7f784882a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a799)
SUMMARY: AddressSanitizer: stack-buffer-overflow
"""


def _findings(text=RAW_CRASH):
    monitor = SanitizerMonitor()
    for line in text.splitlines():
        monitor.feed(line)
    return monitor.finish()


def _cfg(tmp_path, **kwargs):
    cfg = FuzzConfig(
        harness_dir=tmp_path / "harnesses",
        output_dir=tmp_path / "out",
        use_docker=False,
        **kwargs,
    )
    cfg.harness_dir.mkdir(parents=True, exist_ok=True)
    (cfg.harness_dir / "stage1_fuzz").write_bytes(b"\x7fELF")
    return cfg


def _runner(mapping, calls=None):
    """오프셋 → "함수\n파일:행:열" 응답을 흉내내는 가짜 llvm-symbolizer."""
    def run(argv):
        if calls is not None:
            calls.append(argv)
        blocks = []
        for offset in [a for a in argv if a.startswith("0x")]:
            blocks.append(mapping.get(offset, "??\n??:0:0"))
        return CmdResult(0, "\n\n".join(blocks) + "\n")
    return run


OFFSETS = {
    "0xfed17": "__asan_memcpy\n??:0:0",
    "0x13f726": "vulnerable\n/src/fuzz_target.c:16:13",
    "0x13f3b4": "LLVMFuzzerTestOneInput\n/src/fuzz_target.c:23:5",
}


# ---------------------------------------------------------------------------
# 복원
# ---------------------------------------------------------------------------

def test_unsymbolized_frames_get_file_and_line(tmp_path):
    findings = _findings()
    assert findings[0].traceback == []          # 복원 전: 위치를 모른다

    report = CrashSymbolizer(_cfg(tmp_path), runner=_runner(OFFSETS)).symbolize(findings)

    # 미해결 프레임은 #1·#2·#3 셋이다. #0 은 ASAN 이 함수명을 이미 붙였으니
    # 복원 대상이 아니고, #3(libc)은 호스트에 모듈이 없어 건너뛴다.
    assert (report.resolved, report.attempted) == (2, 3)
    locations = [(loc.file, loc.line) for loc in findings[0].traceback]
    assert locations == [("/src/fuzz_target.c", 16), ("/src/fuzz_target.c", 23)]
    # 원래 줄의 들여쓰기까지 ASAN 의 symbolize=1 출력과 같은 모양으로 남는다.
    assert ("    #1 0x59c70041a726 in vulnerable /src/fuzz_target.c:16:13"
            in findings[0].raw_log)


def test_signature_stops_being_unknown(tmp_path):
    """시그니처가 뭉개지면 서로 다른 버그가 한 클러스터로 합쳐진다."""
    findings = _findings()
    assert findings[0].signature == "buffer-overflow_unknown"

    CrashSymbolizer(_cfg(tmp_path), runner=_runner(OFFSETS)).symbolize(findings)

    assert findings[0].signature == "buffer-overflow_fuzz_target_c_16"


def test_already_symbolized_frames_are_left_alone(tmp_path):
    """ASAN 이 직접 심볼라이즈한 로그(symbolize=1)는 건드릴 것이 없다."""
    text = RAW_CRASH.replace(
        "    #1 0x59c70041a726  (/harness/stage1_fuzz+0x13f726) (BuildId: 1c73e4)",
        "    #1 0x59c70041a726 in vulnerable /src/fuzz_target.c:16:13",
    )
    findings = _findings(text)
    before = list(findings[0].raw_log)

    report = CrashSymbolizer(_cfg(tmp_path), runner=_runner(OFFSETS)).symbolize(findings)

    assert findings[0].raw_log[3] == before[3]
    assert report.resolved == 1                 # #2 만 복원 대상


def test_unknown_location_keeps_the_line_unchanged(tmp_path):
    """``??`` 응답에 엉뚱한 위치를 써 넣지 않는다."""
    findings = _findings()
    before = list(findings[0].raw_log)

    report = CrashSymbolizer(_cfg(tmp_path), runner=_runner({})).symbolize(findings)

    assert findings[0].raw_log == before
    assert findings[0].traceback == []
    assert report.resolved == 0 and report.unresolved == 3


def test_missing_module_is_skipped(tmp_path):
    """컨테이너의 libc 처럼 호스트에 없는 모듈은 조용히 건너뛴다."""
    calls = []
    CrashSymbolizer(_cfg(tmp_path), runner=_runner(OFFSETS, calls)).symbolize(_findings())

    modules = [a for argv in calls for a in argv if a.startswith("--obj=")]
    assert modules == ["--obj=" + str((tmp_path / "harnesses" / "stage1_fuzz").resolve())]


def test_tool_missing_is_reported_not_raised(tmp_path):
    """llvm-symbolizer 가 없어도 결함을 잃지 않는다."""
    def boom(argv):
        raise FileNotFoundError("llvm-symbolizer")

    findings = _findings()
    before = list(findings[0].raw_log)
    report = CrashSymbolizer(_cfg(tmp_path), runner=boom).symbolize(findings)

    assert report.tool_available is False
    assert report.resolved == 0 and report.unresolved == 3
    assert findings[0].raw_log == before


def test_no_frames_to_resolve_calls_nothing(tmp_path):
    calls = []
    findings = _findings("some unrelated line\n")
    report = CrashSymbolizer(_cfg(tmp_path), runner=_runner({}, calls)).symbolize(findings)

    assert calls == [] and report.attempted == 0


# ---------------------------------------------------------------------------
# argv / 경로 규약
# ---------------------------------------------------------------------------

def test_host_argv_uses_configured_tool(tmp_path):
    cfg = _cfg(tmp_path, llvm_symbolizer="/opt/llvm/bin/llvm-symbolizer")
    argv = CrashSymbolizer(cfg).build_argv("/harness/stage1_fuzz", ["0x1"])

    assert argv[0] == "/opt/llvm/bin/llvm-symbolizer"
    assert "--obj=/harness/stage1_fuzz" in argv and argv[-1] == "0x1"


def test_docker_campaign_uses_the_host_tool_by_default(tmp_path):
    """퍼징 이미지에는 llvm-symbolizer 가 없다. 바이너리는 호스트에도 있다."""
    cfg = _cfg(tmp_path)
    cfg.use_docker = True
    argv = CrashSymbolizer(cfg).build_argv("/harness/stage1_fuzz", ["0x1"])

    assert argv[0] == "llvm-symbolizer"


def test_docker_argv_mounts_harness_and_keeps_container_path(tmp_path):
    """컨테이너 안에서 돌릴 때는 로그의 ``/harness/...`` 경로가 그대로 맞다."""
    cfg = _cfg(tmp_path, symbolize_in_docker=True)
    cfg.use_docker = True
    sym = CrashSymbolizer(cfg)

    assert sym.resolve_module("/harness/stage1_fuzz") == "/harness/stage1_fuzz"
    argv = sym.build_argv("/harness/stage1_fuzz", ["0x1"])
    assert argv[0] == "docker" and "--network" in argv
    assert f"{cfg.harness_dir.resolve()}:/harness:ro" in argv
    assert argv[argv.index(cfg.image) + 1] == "llvm-symbolizer"


def test_falls_back_to_the_image_when_the_host_has_no_tool(tmp_path):
    """호스트에 도구가 없으면 이미지 안에서 한 번 더 시도한다."""
    cfg = _cfg(tmp_path)
    cfg.use_docker = True
    inner = _runner(OFFSETS)

    def host_missing(argv):
        if argv[0] != "docker":
            raise FileNotFoundError("llvm-symbolizer")
        return inner(argv)

    findings = _findings()
    report = CrashSymbolizer(cfg, runner=host_missing).symbolize(findings)

    assert report.tool_available is True and report.resolved == 2
    assert findings[0].signature == "buffer-overflow_fuzz_target_c_16"


def test_tool_missing_on_both_sides_is_reported(tmp_path):
    cfg = _cfg(tmp_path)
    cfg.use_docker = True

    def boom(argv):
        raise FileNotFoundError(argv[0])

    report = CrashSymbolizer(cfg, runner=boom).symbolize(_findings())

    assert report.tool_available is False and report.resolved == 0


def test_log_path_module_falls_back_to_harness_dir(tmp_path):
    """컨테이너에서 돈 캠페인의 로그를 호스트 도구로 복원하는 경우."""
    cfg = _cfg(tmp_path)
    resolved = CrashSymbolizer(cfg).resolve_module("/harness/stage1_fuzz")

    assert resolved == str((cfg.harness_dir / "stage1_fuzz").resolve())
    assert CrashSymbolizer(cfg).resolve_module("/harness/nope") is None


# ---------------------------------------------------------------------------
# 세션 연동
# ---------------------------------------------------------------------------

def _session_run(tmp_path, out, **cfg_kwargs):
    cfg = _cfg(tmp_path, **cfg_kwargs)

    def fake_executor(argv, timeout, on_line):
        for line in RAW_CRASH.splitlines():
            on_line(line)
        return ProcResult(exit_code=1, timed_out=False)

    runner = DockerIsolationRunner(cfg, executor=fake_executor)
    session = FuzzSession(
        cfg, runner=runner, stream=out,
        symbolizer=CrashSymbolizer(cfg, runner=_runner(OFFSETS)),
    )
    group = LogicGroup(name="stage1_fuzz", harness_path="stage1_fuzz")
    return cfg, session.run([group], ensure_image=False)


def test_session_symbolizes_before_writing_ana_input(tmp_path):
    """ANA 입력 JSONL 에 복원된 위치가 들어가야 한다."""
    out = io.StringIO()
    cfg, summary = _session_run(tmp_path, out)

    jsonl = (cfg.logs_dir / "sanitizer" / "stage1_fuzz.jsonl").read_text(encoding="utf-8")
    assert "/src/fuzz_target.c" in jsonl
    assert '"signature": "buffer-overflow_fuzz_target_c_16"' in jsonl
    assert "[SYMBOLIZE] 프레임 2/3개" in out.getvalue()
    assert summary.groups[0].sanitizer_findings[0].traceback


def test_session_can_skip_symbolization(tmp_path):
    out = io.StringIO()
    cfg, summary = _session_run(tmp_path, out, symbolize_crashes=False)

    assert summary.groups[0].sanitizer_findings[0].traceback == []
    assert "SYMBOLIZE" not in out.getvalue()


def test_session_survives_a_broken_symbolizer(tmp_path):
    """심볼라이즈 실패가 캠페인을 깨뜨리지 않는다."""
    cfg = _cfg(tmp_path)

    def fake_executor(argv, timeout, on_line):
        for line in RAW_CRASH.splitlines():
            on_line(line)
        return ProcResult(exit_code=1, timed_out=False)

    class Broken(CrashSymbolizer):
        def symbolize(self, findings):
            raise RuntimeError("출력 형식이 바뀌었다")

    out = io.StringIO()
    session = FuzzSession(
        cfg, runner=DockerIsolationRunner(cfg, executor=fake_executor),
        stream=out, symbolizer=Broken(cfg),
    )
    summary = session.run([LogicGroup(name="stage1_fuzz", harness_path="stage1_fuzz")],
                          ensure_image=False)

    assert summary.groups[0].sanitizer_findings          # 결함은 그대로 남는다
    assert "심볼라이즈 실패(RuntimeError)" in out.getvalue()
