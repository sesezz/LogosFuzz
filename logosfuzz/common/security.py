"""
공통 보안 유틸 (시큐어코딩 가이드 대응)
=======================================

행정안전부·KISA 「소프트웨어 개발보안 가이드」(2021.12) 구현단계 보안약점 중
이 도구가 직접 마주치는 항목을 한곳에서 처리한다. 모듈마다 제각각 막으면
빠뜨린 경로 하나로 전체가 뚫리므로, 파일을 쓰거나 외부 명령을 실행하는
모든 계층이 이 함수들을 거치게 한다.

- 경로 조작 및 자원 삽입(CWE-22/99)     : :func:`safe_component`, :func:`safe_join`
- 중요정보 노출 / 환경변수 상속(CWE-526) : :func:`minimal_env`
- 오류 메시지·로그를 통한 정보노출(CWE-532): :func:`redact_secrets`
- 자원의 부적절한 관리(CWE-400)        : :func:`cap_text`

대상 프로젝트 소스, 프로필, 코퍼스, LLM 응답은 모두 **비신뢰 입력**으로 본다.
여기 함수들은 그런 값이 파일 이름·경로·환경으로 흘러들 때의 마지막 검사다.
"""
from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Dict, Iterable, Mapping, Optional


class UnsafePathError(ValueError):
    """허용 루트를 벗어나거나 허용되지 않은 문자를 포함한 경로."""


# --------------------------------------------------------------------------- #
# 경로 검증
# --------------------------------------------------------------------------- #
# 파일·디렉터리 이름 한 칸에 허용하는 문자. 슬래시·역슬래시·콜론(Windows 드라이브)·
# NUL 은 들어갈 수 없다. 첫 글자로 '.' 을 막아 '.', '..', 숨김 파일을 거른다.
_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]*$")
MAX_COMPONENT_LEN = 128


def safe_component(name: str, *, what: str = "이름") -> str:
    """경로 한 칸(파일·디렉터리 이름)으로 써도 안전한지 검사하고 그대로 돌려준다.

    ``..``, 절대경로, 슬래시·역슬래시, 드라이브 문자, 제어문자는 거부한다.
    정상 이름(``sf_open``, ``json_parse.c``, ``grp-1``)은 바뀌지 않고 통과한다.
    """
    if not isinstance(name, str) or not name:
        raise UnsafePathError(f"{what}이(가) 비어 있다")
    if len(name) > MAX_COMPONENT_LEN:
        raise UnsafePathError(f"{what}이(가) 너무 길다({len(name)}자 > {MAX_COMPONENT_LEN})")
    if not _COMPONENT_RE.match(name):
        raise UnsafePathError(f"{what}에 허용되지 않은 문자가 있다: {name!r}")
    return name


def safe_relpath(rel: str, *, what: str = "상대경로", allow_empty: bool = True) -> PurePosixPath:
    """``a/b/c`` 형태의 상대경로를 칸마다 검사한다(Bazel 패키지 경로 등).

    빈 문자열은 ``allow_empty`` 일 때 루트 자신을 뜻한다.
    """
    if rel in ("", None):
        if allow_empty:
            return PurePosixPath()
        raise UnsafePathError(f"{what}이(가) 비어 있다")
    if "\\" in rel or PureWindowsPath(rel).drive or rel.startswith("/"):
        raise UnsafePathError(f"{what}은(는) 상대 POSIX 경로여야 한다: {rel!r}")
    parts = [p for p in rel.split("/") if p != ""]
    if not parts:
        raise UnsafePathError(f"{what}이(가) 올바르지 않다: {rel!r}")
    for part in parts:
        safe_component(part, what=what)
    return PurePosixPath(*parts)


def is_within(path: Path, root: Path) -> bool:
    """``path`` 를 끝까지 해석(심볼릭 링크 포함)했을 때 ``root`` 안에 있는가."""
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def safe_join(root: Path | str, *parts: str, what: str = "경로") -> Path:
    """``root`` 아래에 ``parts`` 를 붙이고, 결과가 ``root`` 밖이면 거부한다.

    각 칸은 :func:`safe_relpath` 로 검사한 뒤, 이미 존재하는 심볼릭 링크를 따라가도
    루트를 벗어나지 않는지 resolve 로 한 번 더 확인한다.
    """
    base = Path(root)
    joined = base
    for part in parts:
        for piece in safe_relpath(str(part), what=what).parts:
            joined = joined / piece
    if not is_within(joined, base):
        raise UnsafePathError(f"{what}이(가) 허용 루트를 벗어난다: {joined} (루트: {base})")
    return joined


# --------------------------------------------------------------------------- #
# 실행 환경 최소화
# --------------------------------------------------------------------------- #
# 빌드·퍼징·재생 작업자가 물려받아도 되는 변수. 대상 프로젝트의 CMake 스크립트나
# 하네스는 비신뢰 코드라 부모 환경 전체(OPENAI_API_KEY, 클라우드 자격증명 등)를
# 주면 안 된다.
BASE_ENV_ALLOWLIST = (
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE",
    "TMPDIR", "TEMP", "TMP", "TERM", "TZ", "SHELL",
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",   # Windows 에서 실행 파일을 찾는 데 필요
    "ASAN_SYMBOLIZER_PATH", "LLVM_SYMBOLIZER_PATH",
    "CC", "CXX", "BAZEL_CC", "BAZEL_CXX",            # 운영자가 고른 컴파일러(Bazel cc 자동설정이 읽는다)
)
# 승인된 네트워크 단계(Bazel 외부 저장소 받기 등)에서만 넘기는 변수.
NETWORK_ENV_ALLOWLIST = (
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "BAZELISK_HOME", "XDG_CACHE_HOME",
)
# 운영자가 추가로 넘길 변수 이름을 쉼표로 적는다(예: CCACHE_DIR).
PASSTHROUGH_ENV_VAR = "LOGOSFUZZ_ENV_PASSTHROUGH"

# 이름이 이 패턴이면 허용 목록·운영자 지정과 무관하게 절대 넘기지 않는다.
_SECRET_NAME_RE = re.compile(
    r"(KEY|TOKEN|SECRET|PASSW|PASSWD|CREDENTIAL|SESSION|AUTH|COOKIE|PRIVATE)",
    re.IGNORECASE,
)


def is_secret_name(name: str) -> bool:
    return bool(_SECRET_NAME_RE.search(name))


def minimal_env(
    extra: Optional[Mapping[str, str]] = None,
    *,
    network: bool = False,
    source: Optional[Mapping[str, str]] = None,
    allow: Iterable[str] = (),
) -> Dict[str, str]:
    """비밀값을 뺀 최소 실행 환경을 새로 만든다.

    Args:
        extra: 그대로 덮어쓸 값(CC, CFLAGS, ASAN_OPTIONS 처럼 도구가 정한 값).
        network: 프록시·CA 변수까지 넘길지(승인된 네트워크 단계 전용).
        source: 원본 환경(기본 ``os.environ``). 테스트에서 주입한다.
        allow: 호출부가 추가로 넘길 변수 이름.
    """
    src = os.environ if source is None else source
    names = list(BASE_ENV_ALLOWLIST)
    if network:
        names += NETWORK_ENV_ALLOWLIST
    names += list(allow)
    names += [n.strip() for n in src.get(PASSTHROUGH_ENV_VAR, "").split(",") if n.strip()]

    env: Dict[str, str] = {}
    for name in names:
        if name in src and not is_secret_name(name):
            env[name] = src[name]
    env.setdefault("PATH", os.defpath)
    if extra:
        env.update({k: str(v) for k, v in extra.items()})
    return env


# --------------------------------------------------------------------------- #
# 비밀정보 마스킹
# --------------------------------------------------------------------------- #
_REDACTED = "[REDACTED]"
_SECRET_VALUE_PATTERNS = (
    re.compile(r"sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{16,}"),             # OpenAI / Anthropic 키
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),                          # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),                         # GitHub 토큰
    re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),                       # Slack 토큰
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
               re.DOTALL),
)
# OPENAI_API_KEY=..., "password": "...", token: ... 형태의 대입. 값은 공백·괄호·세미콜론 없는
# 8자 이상만 본다(C 코드의 ``token_len = sizeof(x);`` 같은 문장을 건드리지 않게).
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:api[_-]?key|secret|token|passw(?:or)?d|credential)[A-Z0-9_]*)"
    r"([\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9_\-+/.=@:]{8,})(?=[\s\"',}]|$)"
)
# 이 길이 미만의 환경변수 값은 일반 단어와 겹칠 수 있어 값 치환 대상에서 뺀다.
_MIN_ENV_SECRET_LEN = 8


def redact_secrets(text: str, *, env: Optional[Mapping[str, str]] = None,
                   assignments: bool = True) -> str:
    """로그·프롬프트·보고서에 실리기 전에 비밀값으로 보이는 문자열을 가린다.

    알려진 토큰 형식과 ``KEY=value`` 대입을 가리고, 현재 환경에서 이름이 비밀처럼
    보이는 변수(``*_API_KEY`` 등)의 **실제 값**이 본문에 있으면 그것도 가린다.
    ``assignments=False`` 는 소스 코드처럼 대입문 패턴이 정상 코드와 겹칠 수 있는
    본문에 쓴다(토큰 형식·환경변수 값만 가린다).
    """
    if not text:
        return text
    out = text
    src = os.environ if env is None else env
    for name, value in src.items():
        if value and len(value) >= _MIN_ENV_SECRET_LEN and is_secret_name(name):
            out = out.replace(value, _REDACTED)
    for pattern in _SECRET_VALUE_PATTERNS:
        out = pattern.sub(_REDACTED, out)
    if assignments:
        out = _ASSIGNMENT_PATTERN.sub(lambda m: m.group(1) + m.group(2) + _REDACTED, out)
    return out


# --------------------------------------------------------------------------- #
# 출력 크기 상한
# --------------------------------------------------------------------------- #
def cap_text(text: str, limit: int, *, marker: str = "\n... (출력 상한 초과로 생략) ...\n") -> str:
    """``limit`` 자를 넘으면 머리와 꼬리만 남긴다(로그 메모리·디스크 폭주 방지)."""
    if limit <= 0 or len(text) <= limit:
        return text
    keep = max(limit - len(marker), 0)
    head = keep // 2
    tail = keep - head
    return text[:head] + marker + (text[-tail:] if tail else "")
