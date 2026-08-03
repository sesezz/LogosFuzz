"""EXT → SCH → GEN 파이프라인 연계 테스트.

GEN 단계의 LLM 호출은 openai 의존성이 필요하므로, 여기서는 EXT→SCH 구간과
GEN 에 주입되는 컨텍스트까지만 검증한다.
"""
import pytest

import pipeline
from src.kb_adapters import to_api_contexts, to_synergy_inputs
from src.knowledge_base import KnowledgeBase

HEADER = """
#ifndef UDS_H
#define UDS_H
#include <stdint.h>
typedef struct uds_ctx { int fd; } uds_ctx_t;

/** @param ctx 열린 컨텍스트. must not be NULL. */
int uds_open(uds_ctx_t *ctx, const char *path);
int uds_read(uds_ctx_t *ctx, char *out, int len);
void uds_close(uds_ctx_t *ctx);
#endif
"""

IMPL = """
#include "uds.h"
int uds_open(uds_ctx_t *ctx, const char *path)
{
    if (ctx == NULL || path == NULL) { return -1; }
    return 0;
}
int uds_read(uds_ctx_t *ctx, char *out, int len)
{
    if (!ctx || !out) { return -1; }
    if (len <= 0) { return -1; }
    return 0;
}
void uds_close(uds_ctx_t *ctx) { ctx->fd = -1; }
"""

CLIENT = """
#include "uds.h"
int run(const char *path, char *buf)
{
    uds_ctx_t ctx;
    if (uds_open(&ctx, path) != 0) { return -1; }
    uds_read(&ctx, buf, 16);
    uds_close(&ctx);
    return 0;
}
"""


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "uds.h").write_text(HEADER, encoding="utf-8")
    (tmp_path / "uds.c").write_text(IMPL, encoding="utf-8")
    (tmp_path / "client.c").write_text(CLIENT, encoding="utf-8")
    return tmp_path


@pytest.fixture
def kb(tree):
    return KnowledgeBase.build(paths=[str(tree)])


# -- Logic Group 구성 -------------------------------------------------------


def test_auto_group_groups_by_source_file(kb):
    groups = pipeline.auto_group(kb)

    assert set(groups) == {"lg_uds.c", "lg_client.c"}
    assert len(groups["lg_uds.c"]) == 3
    assert len(groups["lg_client.c"]) == 1


def test_auto_group_fixed_size_still_available(kb):
    groups = pipeline.auto_group(kb, group_size=2)

    assert all(len(v) <= 2 for v in groups.values())
    assert sum(len(v) for v in groups.values()) == len(kb.documents)


def test_auto_group_covers_every_api(kb):
    grouped = {i for ids in pipeline.auto_group(kb).values() for i in ids}

    assert grouped == {d["api_id"] for d in kb.documents}


# -- EXT → SCH 연결 ---------------------------------------------------------


def test_scheduler_receives_real_constraints(kb):
    """예전 파이프라인은 constraints=[] 를 넘겨 제약조건이 전혀 반영되지 않았다."""
    _, constraints = to_synergy_inputs(kb)

    assert constraints, "제약조건이 비면 constraint_overlap 이 항상 0 이 된다"


def test_synergy_uses_all_three_components(kb):
    sch = pytest.importorskip("sch_02_02_synergy_scheduler")
    apis, constraints = to_synergy_inputs(kb)

    results = sch.compute_pairwise_synergy(apis, constraints)

    assert any(r.detail["call_adjacency"] > 0 for r in results)
    assert any(r.detail["type_coupling"] > 0 for r in results)
    assert any(r.detail["constraint_overlap"] > 0 for r in results)


def test_signature_is_not_guessed_as_int(kb):
    """예전에는 반환형을 무조건 int 로 지어냈다."""
    apis, _ = to_synergy_inputs(kb)
    close = next(a for a in apis if "uds_close" in a.func_signature)

    assert close.func_signature.startswith("void ")


# -- GEN 에 주입되는 컨텍스트 -----------------------------------------------


def test_to_api_contexts_keyed_by_api_id(kb):
    contexts = to_api_contexts(kb)

    assert set(contexts) == {d["api_id"] for d in kb.documents}
    entry = contexts[kb.api("uds_open")["api_id"]]
    assert entry.func_signature.startswith("int uds_open")


def test_api_context_carries_real_constraints(kb):
    contexts = to_api_contexts(kb)
    entry = contexts[kb.api("uds_open")["api_id"]]

    assert entry.constraints
    assert any("NULL" in c for c in entry.constraints)
    assert "must be called with valid parameters" not in entry.constraints


def test_api_context_call_order_uses_function_names(kb):
    contexts = to_api_contexts(kb)
    entry = contexts[kb.api("uds_open")["api_id"]]

    assert "uds_open" in entry.call_order
    assert all(isinstance(name, str) for name in entry.call_order)


def test_api_contexts_can_be_filtered(kb):
    wanted = [kb.api("uds_open")["api_id"]]

    assert list(to_api_contexts(kb, api_ids=wanted)) == wanted


def test_api_context_min_confidence_filter(kb):
    strict = to_api_contexts(kb, min_confidence=0.9)
    entry = strict[kb.api("uds_open")["api_id"]]

    assert all("NULL" in c or "assert" in c.lower() for c in entry.constraints)


# -- CLI --------------------------------------------------------------------


def test_cli_requires_a_source():
    with pytest.raises(SystemExit):
        pipeline.parse_args([])


def test_cli_accepts_source(tree):
    args = pipeline.parse_args(["--source", str(tree)])

    assert args.source == str(tree)
    assert args.output == "harness_output.c"
    assert args.dry_run is False


def test_cli_accepts_compile_db():
    args = pipeline.parse_args(["--compile-db", "cc.json", "--dry-run"])

    assert args.compile_db == "cc.json"
    assert args.dry_run is True


# -- 전체 실행 (dry-run) ----------------------------------------------------


def test_dry_run_succeeds_without_llm(tree, capsys):
    code = pipeline.run_pipeline(str(tree), "unused.c", dry_run=True)
    out = capsys.readouterr().out

    assert code == 0
    assert "[EXT]" in out and "[SCH]" in out and "[GEN]" in out
    assert "uds_open" in out


def test_dry_run_prints_include_and_constraints(tree, capsys):
    pipeline.run_pipeline(str(tree), "unused.c", dry_run=True)
    out = capsys.readouterr().out

    assert '#include "uds.h"' in out
    assert "must not be NULL" in out


def test_empty_source_reports_error(tmp_path, capsys):
    (tmp_path / "empty.c").write_text("/* no functions */\n", encoding="utf-8")

    code = pipeline.run_pipeline(str(tmp_path), "unused.c", dry_run=True)

    assert code == 1
    assert "추출된 API가 없습니다" in capsys.readouterr().out


def test_load_env_is_safe_without_dotenv_or_file():
    # 하드코딩된 개인 경로 대신 저장소 기준으로 찾고, 없으면 그냥 넘어가야 한다
    pipeline.load_env()
