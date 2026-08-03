import json

import pytest

from src.knowledge_base import (
    KnowledgeBase,
    header_declaration_docs,
    scan_file,
)

HEADER = """
#ifndef LIB_H
#define LIB_H
#include <stddef.h>

typedef struct lib_ctx {
    int fd;
} lib_ctx_t;

typedef enum { LIB_OK, LIB_ERR } lib_status_t;

/**
 * 컨텍스트를 연다.
 * @param ctx 초기화할 컨텍스트. must not be NULL.
 */
int lib_open(lib_ctx_t *ctx, const char *path);

int lib_read(lib_ctx_t *ctx, char *buf, size_t len);

void lib_close(lib_ctx_t *ctx);

#endif
"""

IMPL = """
#include "lib.h"
#include <stdlib.h>

int lib_open(lib_ctx_t *ctx, const char *path)
{
    if (ctx == NULL) {
        return -1;
    }
    return 0;
}

int lib_read(lib_ctx_t *ctx, char *buf, size_t len)
{
    if (!ctx || !buf) {
        return -1;
    }
    if (len == 0) {
        return -1;
    }
    return 0;
}

void lib_close(lib_ctx_t *ctx)
{
    free(ctx);
}
"""

CLIENT = """
#include "lib.h"

int run(const char *path)
{
    lib_ctx_t ctx;
    char buf[32];

    if (lib_open(&ctx, path) != 0) {
        return -1;
    }
    lib_read(&ctx, buf, sizeof(buf));
    lib_close(&ctx);
    return 0;
}
"""


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "lib.h").write_text(HEADER, encoding="utf-8")
    (tmp_path / "lib.c").write_text(IMPL, encoding="utf-8")
    (tmp_path / "client.c").write_text(CLIENT, encoding="utf-8")
    return tmp_path


@pytest.fixture
def kb(tree):
    return KnowledgeBase.build(paths=[str(tree)])


# -- 파일 스캔 --------------------------------------------------------------


def test_scan_file_collects_includes_declarations_and_types(tmp_path):
    path = tmp_path / "lib.h"
    path.write_text(HEADER, encoding="utf-8")

    info = scan_file(str(path))

    assert "stddef.h" in info.includes
    assert {"lib_open", "lib_read", "lib_close"} <= set(info.declares)
    assert "lib_ctx_t" in info.types
    assert "lib_status_t" in info.types
    assert "lib_ctx" in info.types


def test_header_declaration_docs_extracts_prototype_docs():
    docs = header_declaration_docs(HEADER)

    assert "lib_open" in docs
    assert "must not be NULL" in docs["lib_open"]
    assert "lib_close" not in docs  # 문서 주석이 없는 선언


# -- 구축 -------------------------------------------------------------------


def test_build_requires_a_source():
    with pytest.raises(ValueError, match="either paths or compile_db"):
        KnowledgeBase.build()


def test_build_indexes_every_definition(kb):
    assert {d["function"] for d in kb.documents} == {
        "lib_open", "lib_read", "lib_close", "run"
    }


def test_api_ids_are_unique_and_deterministic(tree):
    first = KnowledgeBase.build(paths=[str(tree)])
    second = KnowledgeBase.build(paths=[str(tree)])

    ids = [d["api_id"] for d in first.documents]
    assert len(ids) == len(set(ids))
    assert ids == sorted(ids)
    assert {d["function"]: d["api_id"] for d in first.documents} == \
        {d["function"]: d["api_id"] for d in second.documents}


def test_lookup_by_name_and_by_id(kb):
    document = kb.api("lib_open")

    assert document is not None
    assert kb.api(document["api_id"])["function"] == "lib_open"
    assert kb.api("does_not_exist") is None


# -- 헤더 문서 결합 ---------------------------------------------------------


def test_header_doc_is_merged_into_the_implementation(kb):
    # 문서는 lib.h 선언에 달려 있고 lib.c 정의에는 없다
    document = kb.api("lib_open")

    assert "컨텍스트를 연다" in document["doc"]


def test_constraints_are_derived_from_the_merged_header_doc(kb):
    kinds = [(c["kind"], c["target"]) for c in kb.api("lib_open")["constraints"]]

    assert ("doc", "ctx") in kinds


def test_definition_doc_is_not_overwritten_by_header_doc(tmp_path):
    (tmp_path / "a.h").write_text("/** header doc */\nint f(int x);\n", encoding="utf-8")
    (tmp_path / "a.c").write_text(
        '#include "a.h"\n/** definition doc */\nint f(int x) { return x; }\n',
        encoding="utf-8",
    )
    kb = KnowledgeBase.build(paths=[str(tmp_path)])

    assert "definition doc" in kb.api("f")["doc"]


# -- 호출 그래프 ------------------------------------------------------------


def test_call_graph_records_callees_and_callers(kb):
    assert set(kb.callees_of("run")) >= {"lib_open", "lib_read", "lib_close"}
    assert "run" in kb.callers_of("lib_open")


def test_call_graph_excludes_external_calls(kb):
    # free() 는 지식베이스에 없는 외부 함수이므로 내부 호출로 세지 않는다
    assert "free" not in kb.callees_of("lib_close")


def test_call_seq_contains_the_api_itself(kb):
    """SCH-02-02 의 call_adjacency_score 는 시퀀스에서 자기 api_id 를 찾는다."""
    open_id = str(kb.api("lib_open")["api_id"])
    sequence = kb.call_sequence_ids("lib_open")

    assert sequence, "호출자가 있는 API 는 call_seq 가 비면 안 된다"
    assert open_id in sequence


def test_call_seq_holds_neighbours_in_call_order(kb):
    sequence = kb.call_sequence_ids("lib_open")
    open_id = str(kb.api("lib_open")["api_id"])
    read_id = str(kb.api("lib_read")["api_id"])

    assert sequence.index(open_id) < sequence.index(read_id)


def test_uncalled_api_has_empty_call_seq(kb):
    assert kb.call_sequence_ids("run") == []


# -- 헤더/타입 해석 ---------------------------------------------------------


def test_header_for_symbol_prefers_the_matching_header(kb, tree):
    assert kb.header_for("lib_open").endswith("lib.h")


def test_declaring_files_finds_the_prototype(kb):
    assert any(p.endswith("lib.h") for p in kb.declaring_files("lib_read"))


def test_defines_type_locates_the_typedef(kb):
    assert any(p.endswith("lib.h") for p in kb.defines_type("lib_ctx_t"))


def test_defines_type_accepts_a_struct_tag(kb):
    assert any(p.endswith("lib.h") for p in kb.defines_type("struct lib_ctx"))


def test_defines_type_returns_empty_for_unknown(kb):
    assert kb.defines_type("nope_t") == []


# -- compile_commands 연동 --------------------------------------------------


def test_compile_flags_come_from_the_compile_database(tree, tmp_path):
    db = tmp_path / "compile_commands.json"
    db.write_text(json.dumps([{
        "directory": str(tree),
        "command": "gcc -Iinclude -DDEBUG=1 -std=c11 -c lib.c -o lib.o",
        "file": "lib.c",
    }]), encoding="utf-8")

    kb = KnowledgeBase.build(paths=[str(tree)], compile_db=str(db))
    flags = kb.api("lib_open")["compile_flags"]

    assert "-Iinclude" in flags
    assert "-DDEBUG=1" in flags
    assert "-std=c11" in flags


def test_build_from_compile_db_alone(tree, tmp_path):
    db = tmp_path / "compile_commands.json"
    db.write_text(json.dumps([{
        "directory": str(tree), "command": "gcc -c lib.c", "file": "lib.c",
    }]), encoding="utf-8")

    kb = KnowledgeBase.build(compile_db=str(db))

    assert {d["function"] for d in kb.documents} == {"lib_open", "lib_read", "lib_close"}


# -- 검색 / 통계 / 저장 -----------------------------------------------------


def test_search_still_works_on_the_unified_kb(kb):
    hits = kb.search("buffer length check", top_k=3)

    assert hits
    assert any(h["document"]["function"] == "lib_read" for h in hits)


def test_stats_reports_integration_specific_counters(kb):
    stats = kb.stats()

    assert stats["apis"] == 4
    assert stats["headers"] == 1
    assert stats["call_edges"] >= 3
    assert stats["apis_with_header"] >= 3
    assert 0 < stats["constraint_coverage"] <= 1


def test_save_and_load_roundtrip(kb, tmp_path):
    path = tmp_path / "kb.json"
    kb.save(str(path))
    restored = KnowledgeBase.load(str(path))

    assert restored.stats() == kb.stats()
    assert restored.api("lib_open")["api_id"] == kb.api("lib_open")["api_id"]
    assert restored.call_sequence_ids("lib_open") == kb.call_sequence_ids("lib_open")
    assert restored.header_for("lib_open") == kb.header_for("lib_open")


def test_load_rejects_unknown_version(tmp_path):
    path = tmp_path / "kb.json"
    path.write_text(json.dumps({"version": 99}), encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported knowledge base version"):
        KnowledgeBase.load(str(path))


def test_saved_kb_keeps_korean_text(kb, tmp_path):
    path = tmp_path / "kb.json"
    kb.save(str(path))

    payload = json.loads(path.read_text(encoding="utf-8"))
    document = next(d for d in payload["documents"] if d["function"] == "lib_open")
    assert "컨텍스트를 연다" in document["doc"]
