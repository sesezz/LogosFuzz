"""GENERIC-C 링크 실패 미정의 심볼 → weak 스텁 자동 생성.

왜 필요한가
-----------
임베디드 펌웨어 모듈은 벤더 HAL(``HAL_UART_Transmit``, ``HAL_GetTick`` 등)을 부른다.
호스트에서 퍼징 바이너리를 만들면 그 정의가 없어서 **링크 단계**에서 실패한다.
이건 하네스 소스 결함이 아니므로 LLM 에게 하네스를 다시 쓰게 해도 풀리지 않는다
(LLM 은 대개 호출을 지우거나 같은 이름을 하네스에 재정의해서 다른 문제를 만든다).

그래서 링커 로그에서 미정의 심볼을 읽고, 프로필이 허용한 심볼만 **결정적으로**
스텁을 만들어 다시 링크한다. LLM 호출이 없다.

    embedded.stub_undefined  true 일 때만 동작한다.
    embedded.stub_allowlist  glob 목록(예: ``["HAL_*"]``). 여기에 맞는 심볼만 스텁을 만든다.
                             비어 있으면 제한 없음(프로필 계약 그대로).

스텁 모양
---------
* 모든 스텁은 ``__attribute__((weak))`` 다. 나중에 실제 정의가 링크되면 그쪽이 이긴다.
* KB 에 그 함수 문서(반환형·파라미터)가 있으면 그 시그니처로 만들고, 문서의 파일이
  헤더면 ``#include`` 해서 타입을 맞춘다. 반환 값은 0 으로 채운 값이다.
* KB 에 없으면 ``int X() { return 0; }`` 다. C 에서 빈 괄호는 "인자 미지정"이라
  어떤 호출과도 링크된다. 반환형이 다른 함수(``uint32_t`` 등)도 정수 레지스터로
  0 을 돌려받는다.

스텁은 하네스와 **다른 번역 단위**(별도 .c 파일)로 만든다. 하네스가 ``hal.h`` 를
include 하고 있으면 같은 파일 안의 ``int HAL_GetTick()`` 이 선언과 충돌하기 때문이다.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from .errors import classify_toolchain_log, undefined_symbols

# C 식별자만 스텁을 만든다. C++ 심볼(``ns::f(int)``)은 맹글링과 오버로드 때문에
# 이름만으로 정의를 쓸 수 없다.
_C_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".hxx")


def parse_undefined_symbols(log: str) -> List[str]:
    """링커 로그에서 미정의 심볼을 등장 순서대로(중복 없이) 뽑는다.

    GNU ld ``undefined reference to `X'`` 와 lld ``undefined symbol: X`` 를 모두 읽는다.
    """
    return undefined_symbols(classify_toolchain_log(log))


@dataclass(frozen=True)
class StubPolicy:
    """스텁을 만들지, 어떤 심볼까지 만들지."""

    enabled: bool = False
    allowlist: Tuple[str, ...] = ()

    @classmethod
    def from_profile(cls, profile) -> "StubPolicy":
        embedded = getattr(profile, "embedded", None)
        if embedded is None:
            return cls()
        return cls(enabled=bool(embedded.stub_undefined),
                   allowlist=tuple(embedded.stub_allowlist))

    def allows(self, symbol: str) -> bool:
        if not self.enabled or not _C_IDENTIFIER_RE.match(symbol):
            return False
        if not self.allowlist:
            return True
        return any(fnmatch.fnmatchcase(symbol, pattern) for pattern in self.allowlist)


@dataclass
class StubPlan:
    """미정의 심볼을 스텁 대상과 나머지로 나눈 결과."""

    stub: List[str] = field(default_factory=list)
    """허용목록에 맞아서 스텁을 만들 심볼."""

    rejected: List[str] = field(default_factory=list)
    """허용목록 밖이거나 C 식별자가 아니어서 스텁을 만들지 않는 심볼."""

    @property
    def only_rejected(self) -> bool:
        """스텁으로 풀 수 있는 게 없고, 남은 미정의 심볼은 전부 허용목록 밖이다."""
        return not self.stub and bool(self.rejected)


def plan_stubs(symbols: Iterable[str], policy: StubPolicy,
               already: Iterable[str] = ()) -> StubPlan:
    """심볼을 스텁 대상/거부로 나눈다. ``already`` 에 있는 심볼은 다시 만들지 않는다."""
    done = set(already)
    plan = StubPlan()
    for symbol in symbols:
        if symbol in done or symbol in plan.stub or symbol in plan.rejected:
            continue
        (plan.stub if policy.allows(symbol) else plan.rejected).append(symbol)
    return plan


# --------------------------------------------------------------------------- #
# 스텁 소스
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class StubSignature:
    """스텁 하나의 시그니처. ``header`` 가 있으면 그 헤더를 include 한다."""

    name: str
    return_type: str = "int"
    params: Tuple[str, ...] = ()
    header: str = ""
    from_kb: bool = False


def _kb_document(kb, name: str) -> Optional[dict]:
    if kb is None:
        return None
    try:
        return kb.api(name)
    except Exception:
        return None


def signature_for(name: str, kb=None) -> StubSignature:
    """KB 에 문서가 있으면 그 반환형·파라미터, 없으면 ``int name()``."""
    document = _kb_document(kb, name)
    if not document:
        return StubSignature(name=name)
    return_type = str(document.get("return_type") or "").strip() or "int"
    params = []
    for param in document.get("params") or []:
        ptype = str(param.get("type") or "").strip()
        pname = str(param.get("name") or "").strip()
        params.append(f"{ptype} {pname}".strip())
    file = str(document.get("file") or "")
    header = Path(file).name if file.endswith(_HEADER_SUFFIXES) else ""
    return StubSignature(name=name, return_type=return_type, params=tuple(params),
                         header=header, from_kb=True)


def _render_one(sig: StubSignature) -> str:
    if not sig.from_kb:
        return f"__attribute__((weak)) int {sig.name}() {{ return 0; }}\n"
    params = ", ".join(sig.params) or "void"
    if sig.return_type == "void":
        body = "{\n}"
    else:
        body = (f"{{\n    {sig.return_type} ret;\n"
                f"    __builtin_memset(&ret, 0, sizeof(ret));\n    return ret;\n}}")
    return f"__attribute__((weak)) {sig.return_type} {sig.name}({params})\n{body}\n"


def render_stub_source(symbols: Sequence[str], kb=None) -> str:
    """스텁 C 소스 1개를 만든다."""
    signatures = [signature_for(name, kb) for name in symbols]
    headers = sorted({sig.header for sig in signatures if sig.header})
    lines = [
        "/* LogosFuzz 자동 생성 스텁 (GENERIC-C generate/stubs.py).",
        " * 링크 단계 미정의 심볼 중 embedded.stub_allowlist 에 맞는 것만 weak 로 정의한다.",
        " * 실제 정의가 링크되면 그쪽이 우선한다. 손으로 고치지 않는다. */",
    ]
    lines += [f'#include "{h}"' for h in headers]
    lines.append("")
    source = "\n".join(lines) + "\n"
    return source + "\n".join(_render_one(sig) for sig in signatures)


@dataclass
class StubSet:
    """지금까지 만든 스텁 묶음. 자가치유 라운드를 거치며 누적된다."""

    symbols: List[str] = field(default_factory=list)
    kb: object = None

    def add(self, symbols: Iterable[str]) -> List[str]:
        added = [s for s in symbols if s not in self.symbols]
        self.symbols.extend(added)
        return added

    @property
    def source(self) -> str:
        return render_stub_source(self.symbols, self.kb) if self.symbols else ""

    def write(self, path: Path) -> Optional[Path]:
        """스텁 소스를 쓴다. 스텁이 없으면 아무것도 쓰지 않고 None."""
        if not self.symbols:
            return None
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.source, encoding="utf-8")
        return path


__all__ = [
    "StubPolicy",
    "StubPlan",
    "StubSet",
    "StubSignature",
    "parse_undefined_symbols",
    "plan_stubs",
    "render_stub_source",
    "signature_for",
]
