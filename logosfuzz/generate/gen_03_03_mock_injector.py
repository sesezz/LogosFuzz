"""
GEN-03-03 : 하네스 외부 의존성 Mocking 코드 삽입 (팀원 B/D 지원, 목업)

전제
----
GEN-03-01(하네스 골격 생성)/GEN-03-02(입력 매핑)가 로직 그룹 대상 API에 대한
퍼징 하네스 골격을 이미 만들었다고 가정한다. 실제 자동차 오픈소스(dlt-daemon,
Eclipse S-CORE 등)의 대상 함수는 하드웨어·드라이버·다른 모듈의 함수를 호출하는데,
그 정의가 빌드 단위 안에 없으면 하네스가 **컴파일/링크되지 않거나** 실행 시
정의되지 않은 심볼을 호출해 퍼징이 시작조차 되지 않는다.

이 모듈(GEN-03-03)은 대상이 "호출하지만 정의가 없는" 외부 의존성 함수를 찾아,
컴파일·실행 가능한 mock/stub 코드를 생성하고 **하네스 소스에 삽입**한다. 입력은
EXT(AST 분석, `src/ast_analyzer.py`)가 뽑은 "정의된 함수"와 "호출된 함수" 목록 +
시그니처이고, 출력은 삽입된 하네스 소스, 별도 mocks.c, 그리고 추적용 매니페스트다.

'B/D 지원'의 의미 (설계서 미명시 → 팀 확인 후 확정. 근거는 개발 보고서에 기록)
----------------------------------------------------------------------
팀 4인(A/B/C/D) 중 **B와 D가 모두 GEN(하네스 생성)** 담당이고, C(EXE, 임세은)가
이 mocking 기능을 지원 개발한다. 따라서 이 기능은 특정 역할로 나뉘는 것이 아니라
**두 GEN 팀원(B·D)이 공통으로 사용하는 하네스 생성 유틸리티**로 설계한다.
  - 공통 삽입 API: `build_mock_plan(...)` → `insert_mocks(harness_src, plan)` 로
    어떤 GEN 하네스에도 동일하게 mock을 끼워 넣는다(대상/모듈이 달라도 재사용).
  - 빌드 산출물: `mock_source()`(mocks.c) · `mock_header()`(선언부)로 링크 에러 제거.
  - 추적 매니페스트: `manifest()` — 무엇을 어떤 기본값 정책으로 모킹했는지 기록.
    C(EXE) 파트와의 연결점으로, 선택적 마커(`instrumented`)가 실행 로그에 남으면
    EXE-04-02가 이를 'mocking-fail-fp'로 분류해 "모킹 부작용 vs 실제 결함"을
    가려낼 수 있게 한다.

의존성 최소화 원칙(프로젝트 공통)에 따라 표준 라이브러리만 사용하고, C/C++
파싱은 EXT가 넘겨준 시그니처 문자열을 경량 정규식으로 처리한다(clang 재파싱 X).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------
# 1. 시그니처 모델 및 파서
# ---------------------------------------------------------------------

# C 문법 구성요소. 함수 호출처럼 생겼지만 함수가 아니라서 절대 모킹 대상이
# 되면 안 된다. 호출 심볼 목록을 넘겨주는 쪽(EXT/KB)이 걸러 주기를 기대하지
# 않고 여기서도 막는다 - 실제로 can-utils 검증에서 `sizeof`가 모킹 후보로
# 올라왔다.
_C_CONSTRUCTS = {
    "sizeof", "alignof", "_Alignof", "offsetof", "typeof", "__typeof__",
    "va_start", "va_arg", "va_end", "va_copy",
    "static_assert", "_Static_assert", "defined",
    "if", "for", "while", "switch", "do", "else", "case", "goto", "return",
}

# libc 등 표준 런타임이 이미 제공하는 심볼은 모킹 대상에서 제외한다
# (printf/malloc 등을 stub으로 덮으면 오히려 하네스가 깨진다).
#
# 왜 소켓/POSIX 계열까지 넣나
# ---------------------------
# 3단계 검증(linux-can/can-utils)에서 실제 SocketCAN 유틸리티 `isotpsend.c`를
# 대상으로 돌리자 `socket`/`bind`/`setsockopt`/`close`/`write`/`if_nametoindex`
# 같은 표준 POSIX 함수가 전부 "정의되지 않은 심볼"로 잡혀 stub 생성 대상이
# 됐다. 목록이 stdio/string/stdlib 계열만 담고 있었기 때문이다.
#
# 이대로 하네스에 적용하면 두 가지가 터진다.
#   1) 진짜 libc `socket()`과 시그니처가 다른 가짜 stub이 함께 컴파일되면서
#      링크 충돌
#   2) 링크가 통과하더라도 진짜 소켓 호출이 stub으로 조용히 대체되어, 대상이
#      실제로는 아무 통신도 하지 않는 채 "정상 동작"으로 보임
#
# 자동차 오픈소스는 대부분 SocketCAN(`socket(PF_CAN,...)`,
# `ioctl(SIOCGIFINDEX)`, `bind`, `setsockopt`)에 의존하므로, 이 목록을
# 넓히지 않으면 "CAN/UDS 모킹이 실제 프로토콜에서 통하는가"의 답이 "아니오"가
# 된다. 모킹해야 할 것은 libc가 아니라 **대상 라이브러리가 정의하지 않은
# 프로토콜/장치 API**다.
LIBC_ALLOWLIST = {
    # stdio
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "puts", "putchar", "putc", "fputc", "fputs",
    "getc", "fgetc", "gets", "fgets", "scanf", "fscanf", "sscanf",
    "fopen", "fdopen", "freopen", "fclose", "fread", "fwrite", "fflush",
    "fseek", "ftell", "rewind", "feof", "ferror", "clearerr", "perror",
    "setbuf", "setvbuf", "remove", "rename", "tmpfile",
    # string / memory
    "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset",
    "memcmp", "memchr", "strlen", "strnlen", "strcmp", "strncmp",
    "strcasecmp", "strncasecmp", "strcpy", "strncpy", "strcat", "strncat",
    "strdup", "strndup", "strchr", "strrchr", "strstr", "strcasestr",
    "strtok", "strtok_r", "strspn", "strcspn", "strpbrk", "strerror",
    "strerror_r", "strsignal", "bzero", "bcopy",
    # stdlib
    "abort", "exit", "_exit", "atexit", "getenv", "setenv", "unsetenv",
    "atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtoll",
    "strtoull", "strtod", "strtof", "abs", "labs", "llabs", "div",
    "qsort", "bsearch", "rand", "srand", "random", "srandom", "system",
    # ctype
    "isalpha", "isdigit", "isalnum", "isspace", "isxdigit", "isupper",
    "islower", "isprint", "ispunct", "iscntrl", "isgraph", "toupper",
    "tolower",
    # POSIX 파일/디스크립터
    "open", "close", "read", "write", "pread", "pwrite", "lseek", "fcntl",
    "ioctl", "dup", "dup2", "pipe", "unlink", "stat", "fstat", "lstat",
    "access", "mkdir", "rmdir", "chdir", "getcwd", "readlink", "fsync",
    "mmap", "munmap", "isatty", "fileno",
    # POSIX 소켓 / 네트워크 - SocketCAN 대상에 필수
    "socket", "socketpair", "bind", "connect", "listen", "accept",
    "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg",
    "setsockopt", "getsockopt", "getsockname", "getpeername", "shutdown",
    "getaddrinfo", "freeaddrinfo", "gai_strerror", "getnameinfo",
    "inet_ntop", "inet_pton", "inet_addr", "inet_ntoa",
    "htons", "htonl", "ntohs", "ntohl",
    "if_nametoindex", "if_indextoname", "if_nameindex", "if_freenameindex",
    "select", "pselect", "poll", "ppoll",
    "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait",
    # 시간
    "time", "clock", "clock_gettime", "clock_nanosleep", "gettimeofday",
    "settimeofday", "localtime", "localtime_r", "gmtime", "gmtime_r",
    "mktime", "strftime", "difftime", "nanosleep", "sleep", "usleep",
    "alarm",
    # 프로세스 / 시그널 / 스레드
    "getpid", "getppid", "fork", "execv", "execvp", "execl", "execlp",
    "waitpid", "wait", "kill", "signal", "sigaction", "sigemptyset",
    "sigfillset", "sigaddset", "sigprocmask", "raise",
    "pthread_create", "pthread_join", "pthread_mutex_init",
    "pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_destroy",
    "pthread_cond_init", "pthread_cond_wait", "pthread_cond_signal",
    # 기타 유틸
    "getopt", "getopt_long", "basename", "dirname", "assert",
    "__assert_fail", "syslog", "openlog", "closelog",
    "LLVMFuzzerTestOneInput",  # 하네스 진입점은 GEN-03-01이 정의한다
}


@dataclass
class Param:
    type: str
    name: str = ""

    def render(self) -> str:
        return f"{self.type} {self.name}".strip() if self.name else self.type


@dataclass
class FunctionSignature:
    name: str
    return_type: str = "int"
    params: list[Param] = field(default_factory=list)
    variadic: bool = False

    def render_decl(self) -> str:
        """C 함수 정의 헤더(예: `int uds_send(uds_ctx_t *ctx, uint8_t sid)`)."""
        parts = [p.render() for p in self.params]
        if self.variadic:
            parts.append("...")
        args = ", ".join(parts) if parts else "void"
        return f"{self.return_type} {self.name}({args})"


_SIG_RE = re.compile(
    r"^\s*(?P<ret>[A-Za-z_][\w\s\*]*?)\s*"      # 반환 타입(포인터 * 포함)
    r"(?P<name>[A-Za-z_]\w*)\s*"                # 함수명
    r"\(\s*(?P<params>[^)]*)\)\s*;?\s*$"        # 파라미터 목록
)


def parse_signature(signature: str) -> FunctionSignature:
    """C 함수 시그니처 문자열을 :class:`FunctionSignature`로 파싱한다.

    파싱 실패(정규식 불일치) 시 이름만 살리고 기본 반환형 int로 폴백한다.
    파라미터명은 없을 수 있으므로(선언만 있는 경우) 타입만 있어도 처리한다.
    """
    m = _SIG_RE.match(signature.strip())
    if not m:
        # "name" 또는 "name()"만 온 경우: 이름만 추출
        name = re.findall(r"[A-Za-z_]\w*", signature)
        return FunctionSignature(name=name[-1] if name else "unknown_fn")

    ret = re.sub(r"\s+", " ", m.group("ret")).strip() or "int"
    name = m.group("name")
    raw_params = m.group("params").strip()
    params: list[Param] = []
    variadic = False
    if raw_params and raw_params != "void":
        for chunk in raw_params.split(","):
            chunk = chunk.strip()
            if chunk == "...":
                variadic = True
                continue
            # 마지막 식별자를 파라미터명 후보로 보되, 포인터/타입만 있으면 이름 생략.
            tokens = re.findall(r"[A-Za-z_]\w*|\*", chunk)
            if len(tokens) >= 2 and not chunk.endswith("*"):
                pname = tokens[-1]
                ptype = chunk[: chunk.rfind(pname)].strip()
                params.append(Param(type=ptype or chunk, name=pname))
            else:
                params.append(Param(type=chunk))
    return FunctionSignature(name=name, return_type=ret, params=params, variadic=variadic)


# ---------------------------------------------------------------------
# 2. 기본값 반환 정책 (임의 결정 — 근거는 보고서에 기록)
# ---------------------------------------------------------------------

_PTR_RE = re.compile(r"\*\s*$")
_FLOAT_RE = re.compile(r"\b(float|double)\b")
_BOOL_RE = re.compile(r"\b(bool|_Bool)\b")
_INT_RE = re.compile(
    r"\b(char|short|int|long|unsigned|signed|size_t|ssize_t|"
    r"u?int(?:8|16|32|64)_t|enum)\b"
)


def default_return(return_type: str) -> str | None:
    """반환 타입별 안전 기본값을 돌려준다(void면 None).

    정책 근거(자동차 오픈소스 퍼징 하네스 관례):
      - 포인터: `NULL`  → 대부분의 호출자는 반환 포인터를 NULL 검사하므로 가장 안전.
                 쓰레기 포인터를 돌려주면 하네스 자체가 오탐 크래시를 낸다.
      - 정수/열거형: `0` → 상태 코드에서 0을 성공/중립으로 쓰는 관례가 많음.
      - 부동소수점: `0.0`, 불리언: 0(false).
      - 구조체 등 집계형: `(T){0}` 제로 초기화 → 값 반환도 컴파일되게 함.
      - void: 반환문 없음.
    """
    t = return_type.strip()
    if t in ("void", ""):
        return None
    if _PTR_RE.search(t):
        return "NULL"
    if _BOOL_RE.search(t):
        return "0"
    if _FLOAT_RE.search(t):
        return "0.0"
    if _INT_RE.search(t):
        return "0"
    # 알 수 없는 타입(대개 구조체/타입def 값 반환): 제로 초기화 복합 리터럴.
    return f"({t}){{0}}"


# ---------------------------------------------------------------------
# 3. Mock stub 생성
# ---------------------------------------------------------------------

# 모킹된 경로가 실제로 실행됐음을 알리는 마커. EXE-04-02 sanitizer가 'mock'/
# 'unimplemented' 문자열을 'mocking-fail-fp'로 분류하므로, C(EXE)/ANA가 크래시와
# 모킹 경로의 상관을 추적할 수 있다. (기본 OFF — 남용 시 로그 오탐을 유발)
_MARKER_MACRO = (
    "#ifndef LOGOSFUZZ_MOCK_MARK\n"
    "#include <stdio.h>\n"
    "#define LOGOSFUZZ_MOCK_MARK(name) "
    "fprintf(stderr, \"LOGOSFUZZ-MOCK-HIT: %s (unimplemented dependency)\\n\", name)\n"
    "#endif\n"
)

# 삽입 지점 표식: 재삽입(idempotent) 판정과 사람이 읽는 경계 표시.
_BEGIN = "/* >>> GEN-03-03 mock injection begin <<< */"
_END = "/* >>> GEN-03-03 mock injection end <<< */"


@dataclass
class MockStub:
    symbol: str
    signature: FunctionSignature
    default_return: str | None
    emits_marker: bool = False

    def render(self) -> str:
        sig = self.signature.render_decl()
        lines = [f"{sig} {{"]
        # 이름 있는 파라미터는 (void) 캐스팅으로 미사용 경고(-Wunused-parameter,
        # 팀 빌드가 -Werror일 수 있음)를 없앤다.
        for p in self.signature.params:
            if p.name:
                lines.append(f"    (void){p.name};")
        if self.emits_marker:
            lines.append(f'    LOGOSFUZZ_MOCK_MARK("{self.symbol}");')
        if self.default_return is not None:
            lines.append(f"    return {self.default_return};")
        lines.append("}")
        return "\n".join(lines)

    def render_prototype(self) -> str:
        return f"{self.signature.render_decl()};"


@dataclass
class MockPlan:
    harness: str
    stubs: list[MockStub] = field(default_factory=list)
    skipped_libc: list[str] = field(default_factory=list)
    strategy: str = "buildable"

    # ---- 삽입 소스 (GEN 하네스 생성이 링크할 mocks.c) ----
    def mock_source(self) -> str:
        """컴파일 가능한 mock 정의 소스(하네스와 함께 빌드/링크)."""
        header = [f"/* GEN-03-03 auto-generated mocks for harness: {self.harness} */"]
        if any(s.emits_marker for s in self.stubs):
            header.append(_MARKER_MACRO)
        body = "\n\n".join(s.render() for s in self.stubs)
        return "\n".join(header) + "\n\n" + body + "\n"

    def mock_header(self) -> str:
        """모킹 심볼 선언부(하네스가 mock 정의 전에도 컴파일되도록)."""
        protos = "\n".join(s.render_prototype() for s in self.stubs)
        guard = f"LOGOSFUZZ_MOCKS_{re.sub(r'[^A-Za-z0-9]', '_', self.harness).upper()}_H"
        return f"#ifndef {guard}\n#define {guard}\n{protos}\n#endif\n"

    # ---- 추적 매니페스트 (GEN + EXE/ANA) ----
    def manifest(self) -> dict:
        """무엇을 어떻게 모킹했는지 구조화 기록."""
        return {
            "harness": self.harness,
            "strategy": self.strategy,
            "mock_count": len(self.stubs),
            "mocked_symbols": [
                {
                    "symbol": s.symbol,
                    "return_type": s.signature.return_type,
                    "default_return": s.default_return,
                    "emits_marker": s.emits_marker,
                }
                for s in self.stubs
            ],
            "skipped_libc": sorted(self.skipped_libc),
            # 이 마커 문자열이 로그에 보이면 EXE-04-02가 'mocking-fail-fp'로 분류한다.
            "marker_hint": "LOGOSFUZZ-MOCK-HIT",
        }

    def manifest_json(self) -> str:
        return json.dumps(self.manifest(), ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------
# 4. Mock 후보 탐지 및 계획 수립
# ---------------------------------------------------------------------


def find_mock_candidates(defined: list[str], called: list[str]) -> list[str]:
    """호출됐지만 정의가 없는 심볼(= 모킹 대상)을 찾는다.

    `called - defined`에서 libc 허용목록을 제외한다. 호출 순서를 보존하고
    중복을 제거한다.
    """
    defined_set = set(defined)
    seen: set[str] = set()
    candidates: list[str] = []
    for name in called:
        if name in defined_set or name in LIBC_ALLOWLIST or name in _C_CONSTRUCTS:
            continue
        if name in seen:
            continue
        seen.add(name)
        candidates.append(name)
    return candidates


def build_mock_plan(harness: str,
                    defined: list[str],
                    called: list[str],
                    signatures: dict[str, str] | None = None,
                    *,
                    strategy: str = "buildable") -> MockPlan:
    """하네스 하나에 대한 모킹 계획을 만든다.

    Args:
        harness: 하네스 이름(로직 그룹 단위).
        defined: 빌드 단위 안에 정의된 함수명 목록.
        called: 대상이 호출하는 함수명 목록.
        signatures: 심볼명 → 시그니처 문자열(EXT AST 분석 산출물). 없으면
            `int name(void)`로 폴백한다.
        strategy: "buildable"(기본, 조용한 stub) 또는 "instrumented"
            (마커를 출력해 모킹 경로 실행을 알림 — EXE/ANA 추적용).

    Returns:
        :class:`MockPlan`.
    """
    signatures = signatures or {}
    emits = strategy == "instrumented"
    candidates = find_mock_candidates(defined, called)
    skipped = [c for c in called if c in LIBC_ALLOWLIST]

    stubs: list[MockStub] = []
    for name in candidates:
        sig_str = signatures.get(name, f"int {name}(void)")
        sig = parse_signature(sig_str)
        sig.name = name  # 시그니처 파싱이 흔들려도 심볼명은 강제 고정
        stubs.append(MockStub(
            symbol=name,
            signature=sig,
            default_return=default_return(sig.return_type),
            emits_marker=emits,
        ))
    return MockPlan(harness=harness, stubs=stubs,
                    skipped_libc=sorted(set(skipped)), strategy=strategy)


# ---------------------------------------------------------------------
# 5. 하네스 소스에 mock 코드 삽입 ("Mocking 코드 삽입"의 핵심)
# ---------------------------------------------------------------------


def insert_mocks(harness_source: str, plan: MockPlan, *, style: str = "append") -> str:
    """GEN 하네스 소스 문자열에 mock 코드를 삽입한 결과를 돌려준다.

    - style="append" : 하네스 끝에 mock 정의 블록을 덧붙인다(단일 파일 빌드).
    - style="include": 하네스 상단에 `#include "mocks_<harness>.h"`를 넣는다
        (mocks.c를 별도 컴파일해 링크하는 빌드).

    이미 삽입된 소스면(경계 표식 존재) 중복 삽입하지 않고 그대로 돌려준다(idempotent).
    """
    if _BEGIN in harness_source:
        return harness_source

    if style == "include":
        include_line = f'#include "mocks_{plan.harness}.h"'
        block = f"{_BEGIN}\n{include_line}\n{_END}\n"
        return block + harness_source

    block = f"\n{_BEGIN}\n{plan.mock_source()}{_END}\n"
    return harness_source.rstrip() + "\n" + block


# ---------------------------------------------------------------------
# 6. 목업 실행 예시
# ---------------------------------------------------------------------

if __name__ == "__main__":
    # EXT AST 분석이 넘겨줬다고 가정한 입력(dlt-daemon 류 대상 예시).
    defined = ["dlt_user_log_write_start", "LLVMFuzzerTestOneInput"]
    called = [
        "dlt_user_log_write_start",   # 정의됨 → 모킹 제외
        "dlt_get_hw_timestamp",       # 외부 의존성 → 모킹
        "can_hal_read_frame",         # 하드웨어 드라이버 → 모킹
        "uds_session_lookup",         # 외부 모듈 → 모킹
        "malloc",                     # libc → 제외
    ]
    signatures = {
        "dlt_get_hw_timestamp": "uint32_t dlt_get_hw_timestamp(void)",
        "can_hal_read_frame": "int can_hal_read_frame(can_frame_t *out, int bus)",
        "uds_session_lookup": "uds_ctx_t *uds_session_lookup(uint8_t id)",
    }

    plan = build_mock_plan("lg_1_uds", defined, called, signatures,
                           strategy="instrumented")

    harness = (
        "#include <stdint.h>\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        "    return 0;\n}\n"
    )

    print("=== 삽입된 하네스 (GEN B/D 공통) ===")
    print(insert_mocks(harness, plan))
    print("=== manifest.json (추적/EXE·ANA 연계) ===")
    print(plan.manifest_json())
