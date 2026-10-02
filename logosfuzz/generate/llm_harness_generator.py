"""
GEN-03-01 : Context-based Harness Generation

Generates fuzzing harness code using LLM based on API context
retrieved from Vector DB (mock: dict) or the knowledge base.

3주차 (B 송서원) — 프롬프트를 C++ / FuzzedDataProvider 로
------------------------------------------------------------
S-CORE(baselibs) 대상은 C++ 이고 Bazel `cc_fuzz_test` 로 빌드된다. 그래서
``language="cpp"`` 프롬프트를 새로 추가했다. 기본값은 기존 호출부(C 경로)가
바뀌지 않도록 ``"c"`` 로 두었고, C++ 경로(gen_03_01_harness_generator)가
``language="cpp"`` 를 명시해서 넘긴다.

- 진입점은 ``extern "C" int LLVMFuzzerTestOneInput(...)`` — C++ 에서 extern "C"
  를 빠뜨리면 이름이 맹글링돼 libFuzzer 가 진입점을 못 찾는다.
- 인자가 여러 개인 API 는 ``FuzzedDataProvider`` 로 입력을 쪼갠다.
- 헤더는 **Bazel include 루트 기준 경로**(``score/json/json_parser.h``)로
  include 한다. extern 선언을 쓰지 않는다 — C++ 선언을 흉내 내면 ODR 위반이다.
- 1주차에 손으로 써서 실제 빌드·퍼징까지 통과시킨
  ``generate/bazel/overlay/score/json/fuzz/json_parser_fuzz.cc`` 를 few-shot
  예시로 넣는다(그 파일 주석에 적어 둔 용도 그대로).
- ``score::Result`` 에러 반환은 정상 동작이다. A 파트의 에러계약(error_contract)
  이 컨텍스트로 들어오면 "에러 경로에서 abort 하지 말 것" 을 근거와 함께 준다.

기존 C 프롬프트는 이전과 똑같이 남긴다(dlt/can-utils 용 ``logosfuzz/pipeline.py``
가 인자 없이 호출해도 그대로 C 프롬프트를 받는다).
"""

from __future__ import annotations
import os
import re
from pathlib import Path
from dotenv import load_dotenv
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

load_dotenv()  # cwd부터 상위로 .env 자동 탐색 (팀원 환경마다 경로가 다르므로 하드코딩 금지)

from logosfuzz.schedule.sch_02_02_synergy_scheduler import (
    ApiMetadata, Constraint,
    compute_pairwise_synergy, rank_logic_groups,
)
from logosfuzz.schedule.sch_02_03_resource_allocator import (
    FuzzingRun, allocate_resources, ScheduleResult
)

# 지원 언어. "cpp" 가 기본(S-CORE/Bazel), "c" 는 기존 pipeline.py 경로.
LANG_CPP = "cpp"
LANG_C = "c"
SUPPORTED_LANGUAGES = (LANG_CPP, LANG_C)

DEFAULT_MODEL = "gpt-4o-mini"

# 1주차 수동 하네스 = C++ 프롬프트의 few-shot 예시.
REFERENCE_HARNESS_PATH = (
    Path(__file__).resolve().parent
    / "bazel" / "overlay" / "score" / "json" / "fuzz" / "json_parser_fuzz.cc"
)


# ---------------------------------------------------------------------
# 1. Data Models
# ---------------------------------------------------------------------

@dataclass
class ApiContext:
    api_id: int
    func_signature: str
    call_order: list[str]
    constraints: list[str]
    source_type: str


@dataclass
class FuzzDriver:
    group_name: str
    code: str
    prompt_used: str = ""
    language: str = LANG_C
    # 빌드 단위(Bazel 라벨). C++/Bazel 경로에서 BUILD 룰 짝을 만들 때 쓴다.
    build_target: str = ""


# ---------------------------------------------------------------------
# 2. Vector DB Mock
# ---------------------------------------------------------------------

VECTOR_DB_MOCK: dict[int, ApiContext] = {
    101: ApiContext(
        api_id=101,
        func_signature="int can_open(can_ctx_t *ctx)",
        call_order=["can_open", "uds_session_start", "uds_read_did"],
        constraints=["must be called before any UDS API"],
        source_type="CAN_SPEC"
    ),
    102: ApiContext(
        api_id=102,
        func_signature="int uds_session_start(uds_ctx_t *ctx, uint8_t level)",
        call_order=["can_open", "uds_session_start", "uds_read_did"],
        constraints=["session start must precede read_did"],
        source_type="UDS_SPEC"
    ),
    103: ApiContext(
        api_id=103,
        func_signature="int uds_read_did(uds_ctx_t *ctx, uint16_t did)",
        call_order=["uds_session_start", "uds_read_did"],
        constraints=["read_did requires active session"],
        source_type="UDS_SPEC"
    ),
    201: ApiContext(
        api_id=201,
        func_signature="int json_parse(const char *buf, size_t len)",
        call_order=["json_parse", "json_free"],
        constraints=["buf must not be NULL", "len must match actual buffer size"],
        source_type="INTERNAL"
    ),
    202: ApiContext(
        api_id=202,
        func_signature="void json_free(json_val_t *v)",
        call_order=["json_parse", "json_free"],
        constraints=["must be called after json_parse"],
        source_type="INTERNAL"
    ),
}


# ---------------------------------------------------------------------
# 3. Context Collection
# ---------------------------------------------------------------------

def collect_context(api_ids: list[int],
                    db: Mapping[int, ApiContext] | None = None) -> list[ApiContext]:
    """Logic Group 의 API ID 로 컨텍스트를 꺼낸다.

    ``db`` 를 주면 그 매핑(KB 에서 만든 것)을 쓰고, 없으면 기존 목업을 쓴다.
    """
    source = VECTOR_DB_MOCK if db is None else db
    return [source[aid] for aid in api_ids if aid in source]


# ---------------------------------------------------------------------
# 4. Prompt Builder
# ---------------------------------------------------------------------

def build_prompt(group_name: str, contexts: list[ApiContext],
                 header_content: str = "",
                 header_filenames: list[str] | None = None,
                 *,
                 language: str = LANG_C,
                 includes: Sequence[str] | None = None,
                 build_target: str = "",
                 build_deps: Sequence[str] | None = None,
                 context_blocks: Sequence[str] | None = None,
                 error_contracts: Sequence[str] | None = None,
                 reference_harness: str | None = None) -> str:
    """언어에 맞는 하네스 생성 프롬프트를 만든다.

    기본은 C(``language="c"``)라 기존 호출부는 이전과 똑같은 프롬프트를 받는다.
    C++/Bazel 경로는 ``language="cpp"`` 를 명시한다.
    """
    if language == LANG_C:
        return _build_c_prompt(group_name, contexts,
                               header_content=header_content,
                               header_filenames=header_filenames)
    if language != LANG_CPP:
        raise ValueError(f"지원하지 않는 언어: {language!r} (지원: {SUPPORTED_LANGUAGES})")
    return build_cpp_prompt(
        group_name, contexts,
        includes=includes if includes is not None else (header_filenames or []),
        header_content=header_content,
        build_target=build_target,
        build_deps=build_deps,
        context_blocks=context_blocks,
        error_contracts=error_contracts,
        reference_harness=reference_harness,
    )


def load_reference_harness(path: Path | str | None = None) -> str:
    """few-shot 예시 하네스를 읽는다. 라이선스 블록 주석은 떼고 넘긴다.

    라이선스 블록까지 넣으면 LLM 이 그걸 그대로 따라 쓰는데, 프롬프트 토큰만
    먹고 생성 품질에는 아무 도움이 안 된다. 파일이 없으면 빈 문자열.
    """
    target = Path(path) if path else REFERENCE_HARNESS_PATH
    try:
        text = target.read_text(encoding="utf-8")
    except OSError:
        return ""
    return re.sub(r"\A\s*/\*.*?\*/\s*", "", text, count=1, flags=re.DOTALL).strip()


def build_cpp_prompt(group_name: str, contexts: Sequence[ApiContext],
                     *,
                     includes: Sequence[str] = (),
                     header_content: str = "",
                     build_target: str = "",
                     build_deps: Sequence[str] | None = None,
                     context_blocks: Sequence[str] | None = None,
                     error_contracts: Sequence[str] | None = None,
                     reference_harness: str | None = None) -> str:
    """C++ / FuzzedDataProvider / Bazel cc_fuzz_test 용 프롬프트."""
    api_block = ""
    for ctx in contexts:
        api_block += f"""
- Signature   : {ctx.func_signature}
  Call order  : {" -> ".join(ctx.call_order) or "(none observed)"}
  Constraints : {"; ".join(ctx.constraints) or "(none extracted)"}
  Spec source : {ctx.source_type}
"""

    include_lines = "\n".join(f'#include "{h}"' for h in includes)
    include_section = (
        f"""
PROJECT HEADERS (Bazel include root relative — use EXACTLY these paths):
{include_lines}
"""
        if include_lines else
        """
PROJECT HEADERS: not resolved. Include the public header of each API using
its path relative to the Bazel workspace root (e.g. "score/json/json_parser.h").
"""
    )

    header_section = ""
    if header_content:
        header_section = f"""
Header content for reference (READ ONLY — do not copy or redeclare anything):
```cpp
{header_content}
```
"""

    build_section = ""
    if build_target:
        deps_text = ", ".join(build_deps or ()) or "(resolved by the BUILD generator)"
        build_section = f"""
BUILD UNIT:
  The harness is compiled by a generated Bazel `cc_fuzz_test` rule in a
  subpackage of the build unit {build_target}.
  deps: {deps_text}
  Only use headers exported by these deps. A header of a target that is not
  a direct dep fails with layering_check.
"""

    kb_section = ""
    blocks = [b for b in (context_blocks or ()) if b and b.strip()]
    if blocks:
        kb_section = "\nKNOWLEDGE-BASE CONTEXT:\n" + "\n\n".join(blocks) + "\n"

    contract_section = ""
    contracts = [c for c in (error_contracts or ()) if c and c.strip()]
    if contracts:
        contract_lines = "\n".join(f"  - {c}" for c in contracts)
        contract_section = f"""
ERROR CONTRACTS (score::Result — returning an error is EXPECTED behaviour):
{contract_lines}
  When a call returns an error, stop using that object and `return 0;`.
  NEVER abort()/assert()/__builtin_trap() on an error result.
"""

    reference = load_reference_harness() if reference_harness is None else reference_harness
    reference_section = ""
    if reference:
        reference_section = f"""
REFERENCE HARNESS (verified to build and fuzz with cc_fuzz_test — follow its STYLE only, not its API usage: call YOUR APIs exactly as the declarations above show them):
```cpp
{reference}
```
"""

    return f"""You are a C++ security testing expert.
Write ONE libFuzzer fuzz target in C++17 for the following APIs.

[Logic Group: {group_name}]
{api_block}
{build_section}{include_section}{header_section}{kb_section}{contract_section}{reference_section}
STRICT RULES:
1. The entry point MUST be exactly:
   extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
   `extern "C"` is mandatory (C++ name mangling hides the symbol otherwise).
   It MUST return 0.
2. Include <fuzzer/FuzzedDataProvider.h>, <cstddef>, <cstdint> and the project
   headers listed above. Do not include anything that does not exist.
3. When an API takes more than one fuzzable argument, split the input with
   `FuzzedDataProvider fdp(data, size);` and ConsumeIntegral<T>(),
   ConsumeIntegralInRange<T>(lo, hi), ConsumeBool(), ConsumeEnum<E>(),
   ConsumeRandomLengthString(max), ConsumeBytes<uint8_t>(n),
   ConsumeRemainingBytesAsString(). Consume fixed-size values FIRST and the
   variable-length remainder LAST.
   ConsumeBytes<T> is only valid for a 1-byte T (uint8_t/char); for text use
   ConsumeRandomLengthString(max) or ConsumeRemainingBytesAsString().
   When an API takes a single byte buffer / std::string_view, pass
   `std::string_view{{reinterpret_cast<const char*>(data), size}}` directly
   like the reference harness.
4. Respect the call order and constraints above. Construct objects with the
   real public constructors/factories declared in the headers.
   Call ONLY members declared `public` in the header excerpts. A `static`
   member function is called as `ClassName::Func(...)` with NO instance; do
   not construct a class whose public constructors are not shown (a private
   or inherited constructor means the class is used through its static
   functions). Never build helper objects you have not seen declared.
5. CONSUME every result so the optimizer cannot delete the call (discarding
   it lets -O1 remove the path) — but only with what the REAL return type
   offers. Read the return type in the signatures / header excerpts above:
   - score::Result<T> / expected: check has_value(), then read value().
   - a reference such as `Foo&` (fluent/chained API): bind it with `auto&`,
     NEVER `auto` (that copies; many project classes are non-copyable), and do
     NOT call has_value()/value() on it. Observe it through a real accessor
     (e.g. a state/validity query) or simply chain the next call.
   - void: nothing to consume; make the call directly.
   Never invent members such as has_value() for a type that does not declare it.
6. An error result is NOT a bug. Never abort/assert/throw on API errors.
   Crashes are detected by ASan/UBSan, not by the harness.
7. Do NOT redeclare, forward-declare or re-implement any project class,
   function or type. Do NOT write `extern` declarations for project APIs.
   Do NOT invent functions that are not declared in the headers.
8. Do NOT define `main`. Do NOT use try/catch/throw (targets may be built
   with -fno-exceptions). No global mutable state carried across calls.
9. No file, network, thread, sleep or environment access. If an API needs a
   file path (e.g. FromFile, ReadFile, Load), do NOT call it — fuzz the
   in-memory / buffer variant (e.g. FromBuffer) instead.
10. NEVER const_cast the input. If an API needs a mutable buffer, copy into
    a std::vector<uint8_t> / std::string first.
11. Comments in English only.
12. Output ONLY raw C++ source code — no markdown fences, no explanation.
"""


def _build_c_prompt(group_name: str, contexts: list[ApiContext],
                    header_content: str = "",
                    header_filenames: list[str] | None = None) -> str:

    api_block = ""
    extern_decls = ""
    for ctx in contexts:
        api_block += f"""
- Function signature : {ctx.func_signature}
  Call order        : {" -> ".join(ctx.call_order)}
  Constraints       : {", ".join(ctx.constraints)}
  Spec source       : {ctx.source_type}
"""
        extern_decls += f"extern {ctx.func_signature};\n"

    # 헤더 include 지시 — 내용을 복붙하는 게 아니라 #include 한 줄로 쓰도록 명시
    # "복붙하라"고 시키면 LLM이 구조체를 중복 정의하는 원인이 됐음
    header_include_lines = ""
    header_section = ""
    if header_filenames:
        header_include_lines = "\n".join(f'#include "{h}"' for h in header_filenames)
        header_section = f"""
HEADER FILES:
The target source is compiled with these headers available.
Start your harness with EXACTLY these lines (in this order, nothing else before them):

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
{header_include_lines}

The headers above already define all necessary types (structs, typedefs, etc).
DO NOT redefine or redeclare any type — just use them directly after the includes.

For reference, the header content is shown below (READ ONLY — do not copy-paste structs):
```c
{header_content}
```
"""

    prompt = f"""You are a C/C++ security testing expert.
Write a libFuzzer fuzz driver in C for the following APIs.

[Logic Group: {group_name}]
{api_block}

These functions are REAL functions that already exist in the target source
file. At compile time, your driver file will be compiled together with the
original target source file, so the real implementation will be linked in.
{header_section}
Use exactly these extern declarations AFTER the includes (copy verbatim):
{extern_decls}

STRICT RULES:
1. Return type of LLVMFuzzerTestOneInput MUST be int, NEVER void
2. All comments MUST be in English only, NEVER use Korean
3. Reflect API call order and constraints
4. Map input data(data, size) to API parameters appropriately
5. Handle memory allocation/deallocation explicitly
6. Output ONLY raw C code, no markdown, no explanation
7. Do NOT write a function body for any extern function listed above.
   Their real implementation is linked from the original target source.
8. Do NOT invent or call any function not explicitly listed above.
9. Do NOT define `main`. The fuzzing runtime provides its own `main`.
10. Do NOT redefine or redeclare any struct, typedef, or function already
    declared in the included headers. No duplicate typedefs. No empty structs.
11. The FIRST lines of your output must be the #include lines shown above.
    Do not add any code or comments before them.
12. NEVER cast the fuzzer input (const uint8_t *data) directly to a mutable
    pointer and pass it to a function that writes through that pointer.
    Always malloc() + memcpy() a separate buffer first.
    Direct const-cast causes libFuzzer to abort with
    "fuzz target overwrites its const input".
"""
    return prompt



# ---------------------------------------------------------------------
# 5. Harness Generator
# ---------------------------------------------------------------------

_FENCE_RE = re.compile(r"```[A-Za-z0-9_+\-]*\s*\n(?P<body>.*?)```", re.DOTALL)
_ENTRY_RE = re.compile(r"(?P<prefix>^|\n)(?P<decl>[ \t]*int\s+LLVMFuzzerTestOneInput\s*\()")
# 진입점 선언 **자체**에 붙은 extern "C". 파일 다른 곳(다른 함수, extern "C" { } 블록
# 등)의 extern "C" 는 진입점 링크에 아무 영향이 없으므로 세지 않는다.
_ENTRY_EXTERN_RE = re.compile(r'extern\s+"C"\s+int\s+LLVMFuzzerTestOneInput\s*\(')
_FDP_INCLUDE = "#include <fuzzer/FuzzedDataProvider.h>"
# 주석에서 이름만 언급한 경우(참조 하네스가 그렇다)는 제외하고, 실제로
# `FuzzedDataProvider fdp(data, size);` 처럼 객체를 만들 때만 include 를 넣는다.
_FDP_USE_RE = re.compile(r"\bFuzzedDataProvider\s+[A-Za-z_]\w*\s*[({]")


def strip_code_fences(text: str) -> str:
    """LLM 응답에서 코드만 남긴다. 펜스가 있으면 첫 블록 본문을 쓴다."""
    text = text or ""
    m = _FENCE_RE.search(text)
    if m:
        body = m.group("body")
    else:
        # 닫는 펜스 없이 잘린 응답: 여는 펜스의 언어 태그 줄까지 같이 뗀다.
        body = re.sub(r"^\s*```[A-Za-z0-9_+\-]*[ \t]*\n?", "", text)
    return body.replace("```", "").strip()


def normalize_cpp_harness(code: str) -> str:
    """C++ 하네스에서 자주 나오는 **기계적** 실수만 고친다.

    - 마크다운 펜스 제거
    - ``int LLVMFuzzerTestOneInput(`` 에 ``extern "C"`` 가 빠졌으면 붙인다
      (C++ 에서 이게 없으면 링크 단계에서 진입점을 못 찾는다)
    - FuzzedDataProvider 를 쓰는데 include 가 없으면 넣는다

    의미가 걸린 수정은 하지 않는다. 그건 selfheal 루프(D) 의 몫이다.
    """
    code = strip_code_fences(code)
    if _ENTRY_RE.search(code) and not _ENTRY_EXTERN_RE.search(code):
        code = _ENTRY_RE.sub(
            lambda m: f'{m.group("prefix")}extern "C" {m.group("decl").lstrip()}',
            code, count=1,
        )
    if _FDP_USE_RE.search(code) and "FuzzedDataProvider.h" not in code:
        code = f"{_FDP_INCLUDE}\n{code}"
    return code.rstrip() + "\n"


def _default_llm(model: str, max_tokens: int):
    """OpenAI 호출 함수를 만든다. openai 는 여기서만 import 한다.

    모듈 import 시점에 openai 를 요구하지 않아야 프롬프트·정규화만 쓰는 쪽
    (테스트, --dry-run) 이 API 키 없이 돈다.
    """
    from openai import OpenAI

    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

    def complete(prompt: str) -> str:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.2,
        )
        return (response.choices[0].message.content or "").strip()

    return complete


def generate_harness(schedule: list[ScheduleResult],
                     logic_groups: dict[str, list[int]],
                     header_content: str = "",
                     header_filenames: list[str] | None = None,
                     *,
                     language: str = LANG_C,
                     context_db: Mapping[int, ApiContext] | None = None,
                     group_meta: Mapping[str, Mapping[str, Any]] | None = None,
                     llm: Optional[Any] = None,
                     model: str = DEFAULT_MODEL,
                     max_tokens: int = 1500) -> list[FuzzDriver]:
    """스케줄 순서대로 Logic Group 마다 하네스를 생성한다.

    Parameters
    ----------
    language    : "c"(기본, 기존 pipeline.py) 또는 "cpp"(S-CORE/Bazel)
    context_db  : {api_id: ApiContext}. 없으면 VECTOR_DB_MOCK
    group_meta  : {group_name: {...}} — C++ 프롬프트에 넣을 그룹별 부가 정보.
                  키: build_target, build_deps, includes, context_blocks,
                  error_contracts, header_content
    llm         : ``prompt -> str`` 호출 가능 객체. 없으면 OpenAI 를 쓴다.
                  테스트에서는 가짜 함수를 주입한다.
    """
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"지원하지 않는 언어: {language!r}")
    complete = llm or _default_llm(model, max_tokens)
    drivers = []

    for result in schedule:
        group_name = result.group_name
        api_ids = logic_groups.get(group_name, [])

        print(f"\n[GEN] {group_name} generating {language} harness... "
              f"(budget={result.allocated_sec}s)")

        contexts = collect_context(api_ids, context_db)
        if not contexts:
            print(f"  [WARN] {group_name} no context found, skipping")
            continue

        meta = dict((group_meta or {}).get(group_name) or {})
        prompt = build_prompt(
            group_name, contexts,
            header_content=meta.get("header_content", header_content),
            header_filenames=header_filenames,
            language=language,
            includes=meta.get("includes"),
            build_target=str(meta.get("build_target") or ""),
            build_deps=meta.get("build_deps"),
            context_blocks=meta.get("context_blocks"),
            error_contracts=meta.get("error_contracts"),
        )
        raw = complete(prompt)
        code = normalize_cpp_harness(raw) if language == LANG_CPP else raw.strip()

        drivers.append(FuzzDriver(
            group_name=group_name,
            code=code,
            prompt_used=prompt,
            language=language,
            build_target=str(meta.get("build_target") or ""),
        ))
        print(f"  [DONE] {group_name} harness generated ({len(code)} chars)")

    return drivers


# ---------------------------------------------------------------------
# 6. Mock Run
# ---------------------------------------------------------------------

if __name__ == "__main__":
    apis = [
        ApiMetadata(101, "int can_open(can_ctx_t *ctx)",
                    ["101", "102", "103", "101", "102"]),
        ApiMetadata(102, "int uds_session_start(uds_ctx_t *ctx, uint8_t level)",
                    ["101", "102", "103"]),
        ApiMetadata(103, "int uds_read_did(uds_ctx_t *ctx, uint16_t did)",
                    ["102", "103"]),
        ApiMetadata(201, "int json_parse(const char *buf, size_t len)",
                    ["201", "202"]),
        ApiMetadata(202, "void json_free(json_val_t *v)",
                    ["201", "202"]),
    ]
    constraints = [
        Constraint(1, 102, "session start must precede read_did", "UDS_SPEC"),
        Constraint(2, 103, "read_did requires active session", "UDS_SPEC"),
        Constraint(3, 101, "can_open must be called before any UDS API", "CAN_SPEC"),
    ]
    logic_groups = {
        "lg_1_uds": [101, 102, 103],
        "lg_2_json": [201, 202],
    }
    fuzzing_runs = [
        FuzzingRun(1, "lg_1_uds", total_branches=1000, covered_branches=400),
        FuzzingRun(2, "lg_2_json", total_branches=500, covered_branches=0),
    ]

    synergy_results = compute_pairwise_synergy(apis, constraints)
    synergy_ranking = rank_logic_groups(logic_groups, synergy_results)
    schedule = allocate_resources(synergy_ranking, fuzzing_runs, budget_sec=3600)

    print("=== GEN-03-01 Harness Generation Start ===")
    # 목업 API 가 C 시그니처라 C 프롬프트로 돌린다.
    drivers = generate_harness(schedule, logic_groups, language="c")

    print("\n=== Generated Harness Code ===")
    for d in drivers:
        print(f"\n--- {d.group_name} ---")
        print(d.code)