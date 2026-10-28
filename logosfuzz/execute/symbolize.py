"""EXE-04-02: 크래시 후처리 심볼라이즈(파일:줄 복원).

왜 "후처리"인가
--------------
``FuzzConfig.asan_options`` 는 ``symbolize=0`` 이다. ASAN 이 크래시 시그널
핸들러 **안에서** llvm-symbolizer 를 fork/exec 하면 WSL2 에서 그 자식이
응답 없이 멈추고, 하드 타임아웃까지 간 뒤 크래시 산출물도 저장되지 않는다
(근거는 ``config.py`` 의 ``asan_options`` 주석). 그래서 실행 중에는 심볼라이즈를
끄고, 프로세스가 **죽은 뒤** 별도 프로세스로 파일:줄을 복원한다.

복원하지 않으면 무슨 일이 생기나
--------------------------------
심볼라이즈를 끈 ASAN 프레임은 함수도 파일도 없이 모듈+오프셋만 남는다.

    #1 0x57a665aa3726  (/harness/rec_fuzz+0x13f726) (BuildId: 1c73e4...)

:class:`~logosfuzz.execute.sanitizer.SanitizerMonitor` 는 이 로그에서
``*.c:<행>`` 을 하나도 찾지 못해 ``traceback=[]`` 로 결함을 넘긴다. 그러면
ANA 쪽에서 연쇄로 어긋난다 — 크래시 시그니처가 ``<분류>_unknown`` 으로 뭉개져
서로 다른 버그가 한 클러스터로 합쳐지고, ``triage.rule_triage`` 는 대상 코드
프레임을 찾지 못해 ``harness-only-frame`` (-0.35) 을 매겨 **진짜 메모리 오류를
오탐으로 판정한다**(실측: examples/stage1 의 stack-buffer-overflow 가
``false_positive`` 로 떨어졌다). 즉 이 모듈이 없으면 정/오탐 수치 자체를
신뢰할 수 없다.

무엇을 하는가
------------
``llvm-symbolizer --obj=<모듈> <오프셋>...`` 을 모듈별로 한 번씩 돌려, 미해결
프레임 줄을 ASAN 이 ``symbolize=1`` 에서 내는 것과 같은 형태로 다시 쓴다.

    #1 0x57a665aa3726 in parse_record /src/lib.c:9:9

그 뒤 ``raw_log`` 를 다시 훑어 ``traceback`` 을 채운다. 결함 객체를 제자리에서
고치므로, 세션 요약·ANA 입력 JSONL 모두 복원된 위치를 그대로 받는다.

원칙
----
- **증명된 것만 고친다.** 도구가 없거나(``llvm-symbolizer`` 미설치), 모듈을
  못 찾거나, 결과가 ``??`` 면 그 줄은 손대지 않는다. 심볼라이즈 실패가 결함을
  잃는 쪽으로 번지면 안 된다 — 복원 못 한 결함은 복원 전과 똑같이 남는다.
- 외부 프로세스 실행은 ``runner`` 콜러블로 주입할 수 있어 실제 llvm 도구 없이
  단위 테스트가 가능하다(``coverage``/``docker_runner`` 의 주입 패턴과 동일).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from logosfuzz.config import FuzzConfig
# CmdResult/CommandRunner 는 llvm 도구 실행 공통 계약이다(coverage 가 먼저
# 정의했다). 같은 모양을 또 만들지 않고 그대로 쓴다.
from logosfuzz.execute.coverage import CmdResult, CommandRunner
from logosfuzz.execute.sanitizer import source_locations


def _default_runner(argv: list) -> CmdResult:
    """subprocess 기반 기본 실행기. 도구가 없으면 OSError 가 그대로 올라간다."""
    proc = subprocess.run(argv, capture_output=True, text=True)
    return CmdResult(proc.returncode, proc.stdout, proc.stderr)

# 심볼라이즈되지 않은 sanitizer 스택 프레임.
#
#     #1 0x57a665aa3726  (/harness/rec_fuzz+0x13f726) (BuildId: 1c73e4...)
#
# 심볼라이즈된 프레임은 PC 와 모듈 사이에 ``in <함수>`` 가 들어간다. PC 뒤에
# 곧바로 ``(`` 가 오도록 묶어서, 이미 복원된 줄은 아예 매칭되지 않게 한다.
_UNSYMBOLIZED_FRAME = re.compile(
    r"^(?P<head>\s*#\d+\s+0x[0-9a-fA-F]+)\s+"
    r"\((?P<module>[^()]+)\+0x(?P<offset>[0-9a-fA-F]+)\)"
)


@dataclass
class SymbolizeReport:
    """한 그룹의 복원 결과(로그와 테스트 단정용)."""

    resolved: int = 0          # 파일:줄까지 복원한 프레임 수
    unresolved: int = 0        # 미해결로 남은 프레임 수(모듈 없음·?? 포함)
    tool_available: bool = True  # llvm-symbolizer 를 실행할 수 있었는가

    @property
    def attempted(self) -> int:
        return self.resolved + self.unresolved


class CrashSymbolizer:
    """``llvm-symbolizer`` 로 sanitizer 결함의 파일:줄을 복원한다.

    도구를 호스트에서 돌릴지, 이미지 안에서 돌릴지
    ------------------------------------------------
    기본은 **호스트** 다. 하네스 바이너리는 ``harness_dir`` 에 있어 Docker 로
    돈 캠페인의 로그도 호스트에서 복원할 수 있고, 반대로 퍼징 이미지
    (``docker/Dockerfile``)에는 llvm-symbolizer 가 없다 — clang/llvm 을 apt 로
    깔지 않고 Bazel 의 ``@llvm_toolchain`` 에서 받기 때문이다(그 이미지가 들고
    있는 심볼라이저는 GCC 새니타이저용 ``binutils`` 의 addr2line 뿐이다).

    그래도 호스트에 도구가 없고 이미지에는 있는 환경(심볼라이저를 넣은 커스텀
    이미지)이 있을 수 있어서, 한쪽에서 도구를 찾지 못하면 다른 쪽으로 한 번
    넘어간다. ``cfg.symbolize_in_docker=True`` 는 그 순서를 뒤집는다.
    """

    def __init__(self, cfg: FuzzConfig, runner: Optional[CommandRunner] = None,
                 docker_bin: str = "docker", use_docker: Optional[bool] = None):
        self.cfg = cfg
        self.runner = runner or _default_runner
        self.docker_bin = docker_bin
        self.use_docker = cfg.use_docker if use_docker is None else use_docker

    # ---- 컨테이너 내부에서 도구를 돌릴지 여부 ------------------------
    def _in_docker(self) -> bool:
        """기본 실행 위치. 공개 헬퍼(``build_argv``/``resolve_module``)의 기본값."""
        return self.use_docker and self.cfg.symbolize_in_docker

    def _attempts(self) -> list:
        """시도 순서. 첫 선택지에 도구가 없으면 다음으로 넘어간다."""
        first = self._in_docker()
        if self.use_docker:
            return [first, not first]
        return [False]

    # ---- 모듈 경로 ----------------------------------------------------
    def resolve_module(self, module: str, in_docker: Optional[bool] = None) -> Optional[str]:
        """로그의 모듈 경로를 도구에 넘길 경로로 바꾼다. 못 찾으면 None.

        컨테이너 안에서 돌릴 때는 로그 경로가 이미 컨테이너 경로라 그대로 쓴다
        (존재 확인은 할 수 없으니 도구의 실패로 판단한다). 호스트에서는 경로가
        그대로 있으면 쓰고, 없으면 같은 이름의 파일을 ``harness_dir`` 에서
        찾는다 — 컨테이너에서 돈 캠페인의 로그를 호스트에서 복원하는 경우다.
        """
        if self._in_docker() if in_docker is None else in_docker:
            return module
        p = Path(module)
        if p.exists():
            return str(p)
        candidate = self.cfg.harness_dir / p.name
        if candidate.exists():
            return str(candidate.resolve())
        return None

    # ---- argv 구성 ----------------------------------------------------
    def build_argv(self, module: str, offsets: list,
                   in_docker: Optional[bool] = None) -> list:
        """``llvm-symbolizer`` argv. 오프셋을 인자로 넘겨 stdin 을 쓰지 않는다."""
        tool_args = ["--obj=" + module, "--functions=short", "--demangle",
                     "--no-inlines", *offsets]
        if self._in_docker() if in_docker is None else in_docker:
            c = self.cfg
            return [
                self.docker_bin, "run", "--rm", "--network", "none",
                "-v", f"{c.harness_dir.resolve()}:/harness:ro",
                c.image, c.llvm_symbolizer, *tool_args,
            ]
        return [self.cfg.llvm_symbolizer, *tool_args]

    # ---- 실행 ---------------------------------------------------------
    def _symbolize_offsets(self, module: str, offsets: list, in_docker: bool) -> list:
        """오프셋 목록 → ``(함수, 파일, 행, 열)`` 목록. 실패하면 빈 목록.

        도구가 아예 없을 때(FileNotFoundError)는 호출자가 다음 시도로 넘어가거나
        "도구 없음" 으로 처리할 수 있게 그대로 올려 보낸다.
        """
        result: CmdResult = self.runner(self.build_argv(module, offsets, in_docker))
        if result.returncode != 0:
            return []
        return _parse_symbolizer_output(result.stdout, expected=len(offsets))

    def _symbolize_module(self, module: str, offsets: list) -> list:
        """시도 순서대로 돌려 첫 성공 결과를 쓴다. 모두 도구를 못 찾으면 OSError."""
        last_error: Optional[OSError] = None
        for in_docker in self._attempts():
            resolved = self.resolve_module(module, in_docker)
            if resolved is None:
                continue
            try:
                return self._symbolize_offsets(resolved, offsets, in_docker)
            except OSError as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        return []

    def symbolize(self, findings: list) -> SymbolizeReport:
        """결함들의 ``raw_log``·``traceback`` 을 제자리에서 복원한다."""
        report = SymbolizeReport()
        # 모듈별로 모아서 도구를 한 번만 부른다. (결함, 줄 번호) 를 함께 들고
        # 있어야 응답을 원래 줄에 되돌려 쓸 수 있다.
        pending: dict = {}
        for finding in findings:
            for index, line in enumerate(finding.raw_log):
                match = _UNSYMBOLIZED_FRAME.match(line)
                if match:
                    pending.setdefault(match.group("module"), []).append(
                        (finding, index, match)
                    )

        touched = set()
        total = sum(len(frames) for frames in pending.values())
        for module, frames in pending.items():
            offsets = ["0x" + m.group("offset") for _, _, m in frames]
            try:
                # 모듈을 찾지 못하면(컨테이너 안의 libc 처럼) 빈 목록이 와서
                # 아래 길이 비교에서 미해결로 떨어진다 — 대상 코드가 아니라
                # 복원 가치도 없으니 조용히 넘기는 쪽이 맞다.
                entries = self._symbolize_module(module, offsets)
            except OSError:
                # llvm-symbolizer 미설치. 아직 보지 못한 프레임까지 모두 미해결로
                # 세고, 호출자가 한 번만 경고할 수 있게 tool_available 을 내린다.
                report.tool_available = False
                report.unresolved = total - report.resolved
                break
            if len(entries) != len(frames):
                report.unresolved += len(frames)
                continue
            for (finding, index, match), (func, file, line, col) in zip(frames, entries):
                if not file or file == "??":
                    report.unresolved += 1
                    continue
                location = f"{file}:{line}" + (f":{col}" if col else "")
                name = func if func and func != "??" else "??"
                finding.raw_log[index] = f"{match.group('head')} in {name} {location}"
                touched.add(id(finding))
                report.resolved += 1

        # 복원한 결함은 traceback 을 다시 계산한다. 시그니처(파일_행)도 여기에
        # 매달려 있으므로, 이 단계를 빠뜨리면 로그만 고치고 ANA 입력은 그대로다.
        for finding in findings:
            if id(finding) in touched:
                finding.traceback = source_locations(finding.raw_log)
        return report


def _parse_symbolizer_output(stdout: str, *, expected: int) -> list:
    """llvm-symbolizer 출력 → ``(함수, 파일, 행, 열)`` 목록.

    주소 하나당 "함수 이름" 줄과 "파일:행:열" 줄이 나오고 빈 줄로 끊긴다.
    ``--no-inlines`` 로 레코드가 주소당 하나임을 보장한다. 블록 수가 기대와
    다르면(도구 버전이 형식을 바꾼 경우) 빈 목록을 돌려 "복원하지 않음" 으로
    떨어뜨린다 — 엉뚱한 줄에 엉뚱한 위치를 써 넣는 것보다 낫다.
    """
    blocks: list = []
    current: list = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            if current:
                blocks.append(current)
                current = []
            continue
        current.append(line)
    if current:
        blocks.append(current)

    if len(blocks) != expected:
        return []

    entries = []
    for block in blocks:
        func = block[0] if block else "??"
        loc = block[1] if len(block) > 1 else "??"
        file, line, col = _split_location(loc)
        entries.append((func, file, line, col))
    return entries


_LOCATION = re.compile(r"^(?P<file>.+?):(?P<line>\d+)(?::(?P<col>\d+))?$")


def _split_location(text: str) -> tuple:
    """``파일:행:열`` 문자열을 쪼갠다. 해석 불가면 파일을 ``??`` 로 둔다."""
    match = _LOCATION.match(text.strip())
    if not match:
        return ("??", 0, 0)
    file = match.group("file")
    if file in ("??", ""):
        return ("??", 0, 0)
    return (file, int(match.group("line")), int(match.group("col") or 0))
