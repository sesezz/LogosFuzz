import json

import pytest

from src.rag_constraints import ConstraintKB, build_document, build_kb
from src.constraint_extractor import extract_from_text

SOURCE = """
#include <stdlib.h>
#include <string.h>

/**
 * @param buf 파싱할 입력 버퍼. must not be NULL.
 */
int parse_record(const char *buf, size_t len, int *out)
{
    if (buf == NULL || out == NULL) {
        return -1;
    }
    if (len > 4096) {
        return -1;
    }
    memcpy(out, buf, sizeof(int));
    return 0;
}

char *clone_record(const char *buf, size_t len)
{
    if (!buf) {
        return NULL;
    }
    char *copy = malloc(len);
    memcpy(copy, buf, len);
    return copy;
}
"""


@pytest.fixture
def source_tree(tmp_path):
    (tmp_path / "record.c").write_text(SOURCE, encoding="utf-8")
    return tmp_path


@pytest.fixture
def kb(source_tree):
    return ConstraintKB.from_paths([str(source_tree)])


def test_build_document_contains_searchable_text():
    facts = extract_from_text(SOURCE, path="record.c")
    document = build_document(next(f for f in facts if f.name == "parse_record"))

    assert document["function"] == "parse_record"
    assert document["id"].startswith("record.c::parse_record")
    assert "parse_record" in document["text"]
    assert "null_check" in document["text"]
    assert document["params"][0]["name"] == "buf"


def test_build_document_sorts_constraints_by_priority():
    facts = extract_from_text(SOURCE, path="record.c")
    document = build_document(next(f for f in facts if f.name == "parse_record"))
    kinds = [c["kind"] for c in document["constraints"]]

    assert kinds.index("null_check") < kinds.index("risky_call")


def test_kb_indexes_every_function(kb):
    assert {d["function"] for d in kb.documents} == {"parse_record", "clone_record"}
    assert len(kb.index) == len(kb.documents)


def test_kb_search_finds_function_by_natural_language(kb):
    hits = kb.search("who must free the returned pointer", top_k=2)

    assert hits
    assert hits[0]["document"]["function"] == "clone_record"


def test_kb_search_finds_function_by_korean_ownership_query(kb):
    hits = kb.search("메모리 해제 책임", top_k=2)

    assert hits
    assert hits[0]["document"]["function"] == "clone_record"


def test_kb_search_returns_both_candidates_for_broad_query(kb):
    hits = kb.search("buffer NULL", top_k=5)

    assert {hit["document"]["function"] for hit in hits} == {"parse_record", "clone_record"}


def test_kb_search_finds_function_by_korean_query(kb):
    hits = kb.search("널 체크가 있는 함수", top_k=2)

    assert hits
    assert any(h["document"]["function"] == "parse_record" for h in hits)


def test_kb_search_filter_by_file_returns_only_that_file(kb, tmp_path):
    hits = kb.search("buffer", top_k=5, where={"file": "does-not-exist.c"})

    assert hits == []


def test_constraints_of_returns_flat_list(kb):
    constraints = kb.constraints_of("parse_record")

    assert constraints
    assert {c["kind"] for c in constraints} >= {"null_check", "buffer_size"}


def test_get_function_returns_empty_for_unknown(kb):
    assert kb.get_function("nope") == []


def test_stats_reports_coverage_and_kinds(kb):
    stats = kb.stats()

    assert stats["functions"] == 2
    assert stats["files"] == 1
    assert stats["constraints"] > 0
    assert 0 < stats["coverage"] <= 1
    assert "null_check" in stats["by_kind"]
    assert stats["dense_backend"] is False


def test_context_for_known_function_is_prompt_ready(kb):
    block = kb.context_for("parse_record")

    assert "## parse_record" in block
    assert "signature:" in block
    assert "constraints:" in block
    assert "must not be NULL" in block
    assert "evidence:" in block


def test_context_limits_number_of_constraints(kb):
    block = kb.context_for("parse_record", max_constraints=1)

    assert block.count("  - (") == 1


def test_context_falls_back_to_search_for_unknown_function(kb):
    block = kb.context_for("clone", top_k=1)

    assert "clone_record" in block


def test_context_reports_no_match(kb):
    block = kb.context_for("zzz_quantum_widget", top_k=1)

    assert "no knowledge-base entry matched" in block


def test_save_and_load_roundtrip(kb, tmp_path):
    path = tmp_path / "kb.json"
    kb.save(str(path))
    restored = ConstraintKB.load(str(path))

    assert len(restored.documents) == len(kb.documents)
    assert restored.stats()["constraints"] == kb.stats()["constraints"]
    assert restored.search("buffer", top_k=1)[0]["document"]["function"] == \
        kb.search("buffer", top_k=1)[0]["document"]["function"]


def test_saved_kb_keeps_korean_text(kb, tmp_path):
    path = tmp_path / "kb.json"
    kb.save(str(path))

    payload = json.loads(path.read_text(encoding="utf-8"))
    document = next(d for d in payload["documents"] if d["function"] == "parse_record")
    assert "파싱할 입력 버퍼" in document["doc"]


def test_load_rejects_unknown_version(tmp_path):
    path = tmp_path / "kb.json"
    path.write_text(json.dumps({"version": 99, "documents": [], "index": {}}), encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported knowledge base version"):
        ConstraintKB.load(str(path))


def test_build_kb_writes_output(source_tree, tmp_path):
    output = tmp_path / "out" / "kb.json"
    kb = build_kb(paths=[str(source_tree)], output_path=str(output))

    assert output.exists()
    assert kb.stats()["functions"] == 2


def test_build_kb_requires_a_source():
    with pytest.raises(ValueError, match="either paths or compile_db"):
        build_kb()


def test_build_kb_from_compile_db(tmp_path):
    (tmp_path / "record.c").write_text(SOURCE, encoding="utf-8")
    compile_commands = [
        {"directory": str(tmp_path), "command": "gcc -c record.c -o record.o", "file": "record.c"}
    ]
    db_path = tmp_path / "compile_commands.json"
    db_path.write_text(json.dumps(compile_commands), encoding="utf-8")

    kb = build_kb(compile_db=str(db_path))

    assert {d["function"] for d in kb.documents} == {"parse_record", "clone_record"}


def test_build_kb_skips_missing_compile_db_entries(tmp_path):
    compile_commands = [
        {"directory": str(tmp_path), "command": "gcc -c gone.c", "file": "gone.c"}
    ]
    db_path = tmp_path / "compile_commands.json"
    db_path.write_text(json.dumps(compile_commands), encoding="utf-8")

    kb = build_kb(compile_db=str(db_path))

    assert kb.documents == []
    assert kb.stats()["coverage"] == 0.0


def test_build_kb_deduplicates_overlapping_sources(source_tree, tmp_path):
    compile_commands = [
        {"directory": str(source_tree), "command": "gcc -c record.c", "file": "record.c"}
    ]
    db_path = tmp_path / "compile_commands.json"
    db_path.write_text(json.dumps(compile_commands), encoding="utf-8")

    kb = build_kb(paths=[str(source_tree)], compile_db=str(db_path))

    assert kb.stats()["functions"] == 2
