import shutil
import subprocess

import pytest

from src.kb_adapters import (
    configuration_apis,
    render_configuration_apis,
    api_reference,
    as_include_path,
    call_sequences_by_file,
    constraints_for_triage,
    default_source_type,
    harness_context,
    suggest_fixes,
    to_synergy_inputs,
)
from src.knowledge_base import KnowledgeBase

HEADER = """
#ifndef UDS_H
#define UDS_H
#include <stddef.h>
#include <stdint.h>

typedef struct uds_ctx { int fd; } uds_ctx_t;

/**
 * 세션을 시작한다.
 * @param ctx 열린 컨텍스트. must not be NULL.
 */
int uds_session_start(uds_ctx_t *ctx, uint8_t level);

int uds_read_did(uds_ctx_t *ctx, uint16_t did, char *out, size_t len);

void uds_close(uds_ctx_t *ctx);
#endif
"""

IMPL = """
#include "uds.h"
#include <stdlib.h>

int uds_session_start(uds_ctx_t *ctx, uint8_t level)
{
    if (!ctx) {
        return -1;
    }
    if (level == 0 || level > 3) {
        return -1;
    }
    return 0;
}

int uds_read_did(uds_ctx_t *ctx, uint16_t did, char *out, size_t len)
{
    if (ctx == NULL || out == NULL) {
        return -1;
    }
    if (len == 0) {
        return -1;
    }
    memcpy(out, &did, len);
    return 0;
}

void uds_close(uds_ctx_t *ctx) { free(ctx); }
"""

CLIENT = """
#include "uds.h"

int read_vin(uds_ctx_t *ctx, char *out, size_t len)
{
    if (uds_session_start(ctx, 1) != 0) {
        return -1;
    }
    if (uds_read_did(ctx, 0xF190, out, len) != 0) {
        return -1;
    }
    uds_close(ctx);
    return 0;
}
"""


@pytest.fixture
def kb(tmp_path):
    (tmp_path / "uds.h").write_text(HEADER, encoding="utf-8")
    (tmp_path / "uds.c").write_text(IMPL, encoding="utf-8")
    (tmp_path / "client.c").write_text(CLIENT, encoding="utf-8")
    return KnowledgeBase.build(paths=[str(tmp_path)])


# ---------------------------------------------------------------------------
# B (SCH-02-02 / SCH-02-03) 지원
# ---------------------------------------------------------------------------


def test_to_synergy_inputs_produces_the_real_sch_dataclasses(kb):
    sch = pytest.importorskip("sch_02_02_synergy_scheduler")
    apis, constraints = to_synergy_inputs(kb)

    assert apis and constraints
    assert isinstance(apis[0], sch.ApiMetadata)
    assert isinstance(constraints[0], sch.Constraint)


def test_synergy_api_fields_are_populated(kb):
    apis, _ = to_synergy_inputs(kb)
    entry = next(a for a in apis if "uds_session_start" in a.func_signature)

    assert isinstance(entry.api_id, int)
    assert entry.func_signature.startswith("int uds_session_start")
    assert entry.dep_graph_ref.endswith("uds.c")


def test_synergy_constraints_carry_rule_text_and_api_id(kb):
    _, constraints = to_synergy_inputs(kb)
    target_id = kb.api("uds_session_start")["api_id"]
    mine = [c for c in constraints if c.api_id == target_id]

    assert mine
    assert all(c.rule_text for c in mine)
    assert len({c.constraint_id for c in constraints}) == len(constraints)


def test_min_confidence_filters_weak_constraints(kb):
    _, all_constraints = to_synergy_inputs(kb)
    _, strong = to_synergy_inputs(kb, min_confidence=0.85)

    assert len(strong) < len(all_constraints)


def test_default_source_type_separates_doc_and_code(kb):
    document = kb.api("uds_session_start")
    doc_constraint = {"kind": "doc"}
    code_constraint = {"kind": "null_check"}

    assert default_source_type(doc_constraint, document).startswith("DOC:")
    assert default_source_type(code_constraint, document).startswith("CODE:")


def test_source_type_can_be_overridden(kb):
    _, constraints = to_synergy_inputs(kb, source_type=lambda c, d: "UDS_SPEC")

    assert {c.source_type for c in constraints} == {"UDS_SPEC"}


def test_synergy_pipeline_runs_on_real_b_modules(kb):
    """어댑터 출력이 B의 실제 계산 함수를 그대로 통과해야 한다."""
    sch = pytest.importorskip("sch_02_02_synergy_scheduler")
    apis, constraints = to_synergy_inputs(kb)

    results = sch.compute_pairwise_synergy(apis, constraints)

    assert results
    assert all(0.0 <= r.score <= 1.0 for r in results)


def test_call_adjacency_is_actually_scored(kb):
    """call_seq 에 자기 api_id 가 없으면 이 점수가 항상 0 이 된다 (회귀 방지)."""
    sch = pytest.importorskip("sch_02_02_synergy_scheduler")
    apis, constraints = to_synergy_inputs(kb)

    results = sch.compute_pairwise_synergy(apis, constraints)

    assert any(r.detail["call_adjacency"] > 0 for r in results), \
        "인접도가 전부 0 이면 call_seq 형식이 SCH-02-02 와 맞지 않는 것"


def test_adjacent_calls_score_higher_than_distant_ones(kb):
    sch = pytest.importorskip("sch_02_02_synergy_scheduler")
    apis, constraints = to_synergy_inputs(kb)
    results = {(r.api_a, r.api_b): r for r in sch.compute_pairwise_synergy(apis, constraints)}

    start = kb.api("uds_session_start")["api_id"]
    read = kb.api("uds_read_did")["api_id"]
    pair = results.get((start, read)) or results.get((read, start))

    assert pair is not None
    assert pair.detail["call_adjacency"] > 0


def test_resource_allocator_consumes_the_ranking(kb):
    sch = pytest.importorskip("sch_02_02_synergy_scheduler")
    alloc = pytest.importorskip("sch_02_03_resource_allocator")
    apis, constraints = to_synergy_inputs(kb)
    results = sch.compute_pairwise_synergy(apis, constraints)

    groups = {"g1": [a.api_id for a in apis]}
    ranking = sch.rank_logic_groups(groups, results)
    schedule = alloc.allocate_resources(ranking, [], budget_sec=3600)

    assert schedule
    assert schedule[0].allocated_sec > 0


def test_call_sequences_by_file(kb):
    sequences = call_sequences_by_file(kb)

    assert any(path.endswith("client.c") for path in sequences)
    client = next(v for k, v in sequences.items() if k.endswith("client.c"))
    assert client.index("uds_session_start") < client.index("uds_read_did")


# ---------------------------------------------------------------------------
# B (GEN-03-01 하네스 초안 생성) 지원
# ---------------------------------------------------------------------------


def test_harness_context_includes_build_information(kb):
    block = harness_context(kb, "uds_read_did")

    assert "## uds_read_did" in block
    assert "api_id=" in block
    assert "signature:" in block
    assert '#include "' in block
    assert "constraints:" in block


def test_harness_context_emits_header_name_not_full_path(kb):
    """`#include "a/b/uds.h"` 는 포함하는 파일 기준으로 해석되어 컴파일이 깨진다.

    하네스는 KB 와 다른 폴더에 생성되므로 헤더 이름 + -I 여야 한다.
    """
    block = harness_context(kb, "uds_read_did")

    assert 'include: #include "uds.h"' in block
    assert "/uds.h" not in block.split("constraints:")[0].replace("defined in:", "")


def test_harness_context_supplies_the_include_directory(kb):
    block = harness_context(kb, "uds_read_did")

    assert "compile flags: -I" in block


def test_harness_context_include_actually_compiles(kb, tmp_path):
    """제안한 include + 플래그로 실제 컴파일되는지 확인한다."""
    gcc = shutil.which("gcc") or shutil.which("clang")
    if gcc is None:
        pytest.skip("C 컴파일러가 없음")

    block = harness_context(kb, "uds_read_did")
    include_line = next(l for l in block.splitlines() if l.startswith("include:"))
    flag_line = next(l for l in block.splitlines() if l.startswith("compile flags:"))
    include_stmt = include_line.split("include: ", 1)[1]
    flags = flag_line.split("compile flags: ", 1)[1].split()

    # 하네스는 KB 소스와 다른 폴더에 생성된다
    harness = tmp_path / "harness.c"
    harness.write_text(
        f"{include_stmt}\nint LLVMFuzzerTestOneInput(const char *d, long s) "
        "{ (void)d; (void)s; return 0; }\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [gcc, "-c", str(harness), "-o", str(tmp_path / "harness.o"), *flags],
        capture_output=True, text=True, errors="ignore",
    )

    assert result.returncode == 0, result.stderr


def test_harness_context_lists_call_relationships(kb):
    block = harness_context(kb, "uds_session_start")

    assert "called by: read_vin" in block


def test_harness_context_falls_back_to_search(kb):
    assert "uds_read_did" in harness_context(kb, "read did")


def test_harness_context_reports_no_match(kb):
    assert "no knowledge-base entry matched" in harness_context(kb, "zzz_widget")


def test_harness_context_limits_constraints(kb):
    block = harness_context(kb, "uds_read_did", max_constraints=1)

    assert block.count("  - (") == 1


# ---------------------------------------------------------------------------
# D (GEN-03-02 컴파일 에러 자가치유) 지원
# ---------------------------------------------------------------------------


def test_as_include_path_normalizes_backslashes():
    # `#include "a\b.h"` 는 C 에서 이스케이프로 해석된다
    assert as_include_path(r"examples\uds\uds.h") == "examples/uds/uds.h"


def test_implicit_declaration_suggests_the_header(kb):
    output = ("harness.c:12:9: error: implicit declaration of function "
              "'uds_session_start' [-Wimplicit-function-declaration]")
    fixes = suggest_fixes(kb, output)

    assert fixes
    fix = fixes[0]
    assert fix["error"] == "implicit_declaration"
    assert fix["action"] == "add_include"
    assert fix["detail"] == '#include "uds.h"'


def test_include_suggestion_carries_the_directory_flag(kb):
    fixes = suggest_fixes(
        kb, "error: implicit declaration of function 'uds_close'"
    )

    assert fixes[0]["compile_flag"].startswith("-I")


def test_unknown_type_suggests_the_defining_header(kb):
    fixes = suggest_fixes(kb, "harness.c:9:5: error: unknown type name 'uds_ctx_t'")

    assert fixes
    assert fixes[0]["error"] == "unknown_type"
    assert fixes[0]["detail"] == '#include "uds.h"'


def test_argument_count_error_returns_the_signature(kb):
    output = "harness.c:16:5: error: too few arguments to function call 'uds_read_did'"
    fixes = suggest_fixes(kb, output)

    assert fixes
    assert fixes[0]["action"] == "fix_call_signature"
    assert "uds_read_did" in fixes[0]["detail"]
    assert "size_t len" in fixes[0]["detail"]


def test_undefined_reference_points_at_the_source_file(kb):
    fixes = suggest_fixes(kb, "undefined reference to `uds_close'")

    assert fixes
    assert fixes[0]["action"] == "link_source"
    assert "uds.c" in fixes[0]["detail"]


def test_undefined_reference_for_declared_only_symbol(tmp_path):
    # 헤더만 색인된 라이브러리: 선언은 있고 정의는 지식베이스에 없다
    (tmp_path / "ext.h").write_text("int ext_api(int a);\n", encoding="utf-8")
    kb = KnowledgeBase.build(paths=[str(tmp_path)])

    fixes = suggest_fixes(kb, "undefined reference to `ext_api'")

    assert fixes
    assert fixes[0]["action"] == "link_library"
    assert "ext.h" in fixes[0]["detail"]


def test_missing_header_error_is_recognised(kb):
    fixes = suggest_fixes(kb, "harness.c:3:10: fatal error: uds.h: No such file or directory")

    assert fixes
    assert fixes[0]["error"] == "missing_header"
    assert fixes[0]["action"] == "add_include_path"


def test_multiple_errors_are_all_reported(kb):
    output = (
        "error: unknown type name 'uds_ctx_t'\n"
        "error: implicit declaration of function 'uds_session_start'\n"
        "error: implicit declaration of function 'uds_read_did'\n"
    )
    fixes = suggest_fixes(kb, output)

    assert {f["symbol"] for f in fixes} == {
        "uds_ctx_t", "uds_session_start", "uds_read_did"
    }


def test_duplicate_errors_are_deduplicated(kb):
    output = "\n".join(
        ["error: implicit declaration of function 'uds_close'"] * 5
    )

    assert len(suggest_fixes(kb, output)) == 1


def test_unknown_symbols_produce_no_suggestions(kb):
    fixes = suggest_fixes(kb, "error: implicit declaration of function 'totally_unknown'")

    assert fixes == []


def test_clean_compiler_output_produces_no_suggestions(kb):
    assert suggest_fixes(kb, "") == []


# ---------------------------------------------------------------------------
# D (ANA-05-02 / ANA-05-01) 지원
# ---------------------------------------------------------------------------


def test_api_reference_has_join_keys_for_reporting(kb):
    reference = api_reference(kb, "uds_read_did")

    assert reference["api_id"] == kb.api("uds_read_did")["api_id"]
    assert reference["function"] == "uds_read_did"
    assert reference["file"].endswith("uds.c")
    assert reference["header"].endswith("uds.h")
    assert reference["constraint_count"] > 0


def test_api_reference_returns_none_for_unknown(kb):
    assert api_reference(kb, "nope") is None


def test_constraints_for_triage_filters_by_confidence(kb):
    high = constraints_for_triage(kb, "uds_read_did", min_confidence=0.85)
    everything = constraints_for_triage(kb, "uds_read_did", min_confidence=0.0)

    assert everything
    assert len(high) <= len(everything)
    assert all(c["confidence"] >= 0.85 for c in high)


def test_constraints_for_triage_unknown_api(kb):
    assert constraints_for_triage(kb, "nope") == []


# -- 코드 경로를 여는 설정 API ----------------------------------------------
#
# 2단계 검증(Magma libpng)에서 자동 생성 하네스 커버리지가 823, 사람이 쓴
# OSS-Fuzz 드라이버가 1454 였다. 차이는 하나였다 - 사람 쪽은 png_set_expand 같은
# 변환 설정 API 를 켜서 디코딩 코드의 큰 덩어리를 연다.

CONFIG_HEADER = """
#ifndef LIB_H
#define LIB_H
typedef struct dec_ctx { int mode; } dec_ctx_t;

int dec_open(dec_ctx_t *ctx, const char *path);
void dec_set_expand(dec_ctx_t *ctx);
void dec_set_scale(dec_ctx_t *ctx, int factor);
void dec_enable_checks(dec_ctx_t *ctx);
#endif
"""

CONFIG_PRIVATE_HEADER = """
#ifndef LIB_PRIV_H
#define LIB_PRIV_H
void dec_internal_set_state(dec_ctx_t *ctx, int state);
#endif
"""

CONFIG_IMPL = """
#include "lib.h"
#include "libpriv.h"

int dec_open(dec_ctx_t *ctx, const char *path) { return ctx ? 0 : -1; }
void dec_set_expand(dec_ctx_t *ctx) { ctx->mode |= 1; }
void dec_set_scale(dec_ctx_t *ctx, int factor) { ctx->mode += factor; }
void dec_enable_checks(dec_ctx_t *ctx) { ctx->mode |= 2; }
void dec_internal_set_state(dec_ctx_t *ctx, int state) { ctx->mode = state; }
static void dec_set_hidden(dec_ctx_t *ctx) { ctx->mode = 0; }
"""


@pytest.fixture
def config_kb(tmp_path):
    (tmp_path / "lib.h").write_text(CONFIG_HEADER, encoding="utf-8")
    (tmp_path / "libpriv.h").write_text(CONFIG_PRIVATE_HEADER, encoding="utf-8")
    (tmp_path / "lib.c").write_text(CONFIG_IMPL, encoding="utf-8")
    return KnowledgeBase.build(paths=[str(tmp_path)])


def test_configuration_apis_finds_path_opening_setters(config_kb):
    names = [a["function"] for a in configuration_apis(config_kb, "dec_ctx_t")]

    assert "dec_set_expand" in names
    assert "dec_set_scale" in names
    assert "dec_enable_checks" in names


def test_configuration_apis_excludes_the_main_entry_point(config_kb):
    """`dec_open` 은 설정이 아니라 진입점이다."""
    names = [a["function"] for a in configuration_apis(config_kb, "dec_ctx_t")]

    assert "dec_open" not in names


def test_configuration_apis_excludes_private_header_declarations(config_kb):
    """비공개 헤더(libpriv.h)에만 선언된 내부 헬퍼는 제외한다."""
    names = [a["function"] for a in configuration_apis(config_kb, "dec_ctx_t")]

    assert "dec_internal_set_state" not in names


def test_configuration_apis_excludes_static_functions(config_kb):
    names = [a["function"] for a in configuration_apis(config_kb, "dec_ctx_t")]

    assert "dec_set_hidden" not in names


def test_configuration_apis_needs_the_handle_as_first_parameter(config_kb):
    """다른 핸들 타입을 물으면 아무것도 나오면 안 된다."""
    assert configuration_apis(config_kb, "other_ctx_t") == []


def test_configuration_apis_returns_nothing_without_a_handle(config_kb):
    assert configuration_apis(config_kb, "") == []


def test_render_configuration_apis_lists_signatures(config_kb):
    rendered = render_configuration_apis(configuration_apis(config_kb, "dec_ctx_t"))

    assert "dec_set_expand" in rendered
    assert "새 코드 경로" in rendered


def test_render_is_empty_when_there_is_nothing_to_say():
    assert render_configuration_apis([]) == ""
