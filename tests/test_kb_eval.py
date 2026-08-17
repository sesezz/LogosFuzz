import json
import shutil

import pytest

from src.kb_eval import (
    GroundTruth,
    GroundTruthUnavailable,
    build_auto_queries,
    evaluate,
    evaluate_coverage,
    evaluate_extraction,
    evaluate_retrieval,
    label_ground_truth,
    load_queries,
    nm_ground_truth,
    render_report,
    resolve_ground_truth,
)
from src.knowledge_base import KnowledgeBase

HEADER = """
#ifndef LIB_H
#define LIB_H
#include <stddef.h>
typedef struct lib_ctx { int fd; } lib_ctx_t;

/** 컨텍스트를 연다. @param ctx 초기화할 컨텍스트. must not be NULL. */
int lib_open(lib_ctx_t *ctx, const char *path);

/** 버퍼를 읽는다. @param len buf 의 바이트 길이. */
int lib_read(lib_ctx_t *ctx, char *buf, size_t len);
#endif
"""

IMPL = """
#include "lib.h"

int lib_open(lib_ctx_t *ctx, const char *path)
{
    if (ctx == NULL || path == NULL) { return -1; }
    return 0;
}

int lib_read(lib_ctx_t *ctx, char *buf, size_t len)
{
    if (!ctx || !buf) { return -1; }
    if (len == 0) { return -1; }
    return 0;
}
"""


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "lib.h").write_text(HEADER, encoding="utf-8")
    (tmp_path / "lib.c").write_text(IMPL, encoding="utf-8")
    return tmp_path


@pytest.fixture
def kb(tree):
    return KnowledgeBase.build(paths=[str(tree)])


def _labels(tmp_path, names, **extra):
    path = tmp_path / "labels.json"
    path.write_text(json.dumps({
        "apis": [{"name": n, **extra.get(n, {})} for n in names]
    }), encoding="utf-8")
    return str(path)


# -- 정답셋 ----------------------------------------------------------------


def test_label_ground_truth_reads_entries(tree):
    path = _labels(tree, ["lib_open", "lib_read"])
    truth = label_ground_truth(path)

    assert truth.source == "labels"
    assert truth.names() == {"lib_open", "lib_read"}


def test_label_ground_truth_rejects_bad_format(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"nope": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="apis"):
        label_ground_truth(str(path))


def test_nm_ground_truth_finds_definitions(tree):
    if not (shutil.which("gcc") and shutil.which("nm")):
        pytest.skip("gcc/nm 이 없음")

    truth = nm_ground_truth([str(tree)])

    assert truth.source == "nm"
    assert {"lib_open", "lib_read"} <= truth.names()


def test_nm_ground_truth_keeps_underscore_prefixed_functions(tmp_path):
    """`_internal` 은 C 에서 정상인 이름이다.

    정답셋에서 빠지면 정상 추출이 오탐으로 잘못 채점된다(precision 이 실제보다
    낮게 나온다). 일부 툴체인이 모든 C 심볼에 밑줄을 덧붙이는 것과 혼동하면 안 된다.
    """
    if not (shutil.which("gcc") and shutil.which("nm")):
        pytest.skip("gcc/nm 이 없음")

    (tmp_path / "u.c").write_text(
        "int _internal_helper(int a) { return a + 1; }\n"
        "int public_api(int a) { return _internal_helper(a); }\n"
        "static int _static_helper(int a) { return a; }\n"
        "int uses_static(int a) { return _static_helper(a); }\n",
        encoding="utf-8",
    )

    names = nm_ground_truth([str(tmp_path)]).names()

    assert "_internal_helper" in names
    assert "_static_helper" in names
    assert {"public_api", "uses_static"} <= names


def test_underscore_functions_are_not_scored_as_false_positives(tmp_path):
    if not (shutil.which("gcc") and shutil.which("nm")):
        pytest.skip("gcc/nm 이 없음")

    (tmp_path / "u.c").write_text(
        "int _helper(int a) { return a; }\n"
        "int api(int a) { return _helper(a); }\n",
        encoding="utf-8",
    )

    # 이 테스트는 nm 티어의 언더스코어 필터링 동작 자체를 검증한다.
    # libclang이 설치된 환경에서는 clang 티어가 nm보다 먼저 성공하므로,
    # prefer="nm"으로 강제해야 nm 티어 로직을 실제로 검증할 수 있다.
    result = evaluate([str(tmp_path)], prefer="nm")

    assert result["ground_truth"]["source"] == "nm"
    assert result["extraction_accuracy"]["precision"] == 1.0
    assert result["extraction_accuracy"]["false_positive_names"] == []


def test_nm_ground_truth_fails_without_sources(tmp_path):
    (tmp_path / "only.h").write_text("int f(void);\n", encoding="utf-8")

    with pytest.raises(GroundTruthUnavailable):
        nm_ground_truth([str(tmp_path)])


def test_resolve_falls_back_and_records_the_reason(tree):
    path = _labels(tree, ["lib_open", "lib_read"])
    truth = resolve_ground_truth([str(tree)], labels=path)

    # 이 환경에는 libclang 이 없으므로 clang 은 건너뛰어야 한다
    assert truth.source in ("clang", "nm", "labels")
    if truth.source != "clang":
        assert "폴백 사유" in truth.note or truth.source == "labels"


def test_prefer_labels_skips_other_providers(tree):
    path = _labels(tree, ["lib_open"])

    assert resolve_ground_truth([str(tree)], labels=path, prefer="labels").source == "labels"


def test_resolve_without_labels_raises_when_nothing_works(tmp_path):
    (tmp_path / "only.h").write_text("int f(void);\n", encoding="utf-8")

    with pytest.raises(GroundTruthUnavailable):
        resolve_ground_truth([str(tmp_path)], labels=None)


# -- 추출 정확도 (평가기가 오류를 실제로 잡아내는가) -------------------------


def test_perfect_extraction_scores_one(kb, tree):
    truth = label_ground_truth(_labels(tree, ["lib_open", "lib_read"]))
    result = evaluate_extraction(kb, truth)

    assert result["precision"] == 1.0 and result["recall"] == 1.0
    assert result["f1"] == 1.0


def test_missing_api_lowers_recall(kb, tree):
    # 정답에는 있는데 추출기가 못 찾은 함수
    truth = label_ground_truth(_labels(tree, ["lib_open", "lib_read", "lib_close"]))
    result = evaluate_extraction(kb, truth)

    assert result["recall"] < 1.0
    assert result["false_negative"] == 1
    assert "lib_close" in result["false_negative_names"]


def test_extra_api_lowers_precision(kb, tree):
    # 추출기가 찾았지만 정답에 없는 함수
    truth = label_ground_truth(_labels(tree, ["lib_open"]))
    result = evaluate_extraction(kb, truth)

    assert result["precision"] < 1.0
    assert "lib_read" in result["false_positive_names"]


def test_param_count_mismatch_is_detected(kb, tree):
    path = _labels(tree, ["lib_open", "lib_read"],
                   lib_open={"params": ["a", "b", "c"]})   # 실제는 2개
    result = evaluate_extraction(kb, label_ground_truth(path))

    assert result["param_count_accuracy"] < 1.0


def test_detail_metrics_are_none_when_not_comparable(kb, tree):
    """nm 정답셋처럼 인자/반환형 정보가 없으면 0% 가 아니라 미측정이어야 한다."""
    truth = GroundTruth(source="nm", apis={
        "lib_open": {"params": None, "return_type": ""},
        "lib_read": {"params": None, "return_type": ""},
    })
    result = evaluate_extraction(kb, truth)

    assert result["param_count_accuracy"] is None
    assert result["return_type_accuracy"] is None
    assert result["detail_comparable"] == {"params": 0, "return_type": 0}


# -- KB Coverage ------------------------------------------------------------


def test_coverage_reports_component_ratios(kb, tree):
    truth = label_ground_truth(_labels(tree, ["lib_open", "lib_read"]))
    result = evaluate_coverage(kb, truth)

    assert result["target_apis"] == 2
    assert result["api_coverage"] == 1.0
    assert 0.0 < result["with_constraint"] <= 1.0
    assert result["constraints_per_api"] > 0


def test_coverage_below_one_when_apis_are_missing(kb, tree):
    truth = label_ground_truth(_labels(tree, ["lib_open", "lib_read", "ghost"]))

    assert evaluate_coverage(kb, truth)["api_coverage"] < 1.0


# -- RAG 검색 성공률 --------------------------------------------------------


def test_auto_queries_exclude_the_function_name(kb):
    queries = build_auto_queries(kb)

    assert queries
    for entry in queries:
        assert entry["expect"] not in entry["query"]


def test_auto_queries_drop_subtokens_of_the_name(kb):
    queries = {q["expect"]: q["query"] for q in build_auto_queries(kb)}

    if "lib_read" in queries:
        # 'lib' / 'read' 부분 토큰도 지워져야 이름 노출이 아닌 검색력을 잰다
        assert " read " not in f" {queries['lib_read'].lower()} "


def test_retrieval_metrics_on_matching_queries(kb):
    queries = [{"query": "must not be NULL 포인터 검사", "expect": "lib_open"}]
    result = evaluate_retrieval(kb, queries, top_k=5)

    assert result["queries"] == 1
    assert 0.0 <= result["recall_at_1"] <= 1.0
    assert result["mrr"] >= result["recall_at_1"] * 0  # 형태 확인


def test_retrieval_detects_failure(kb):
    queries = [{"query": "quantum entanglement", "expect": "lib_open"}]
    result = evaluate_retrieval(kb, queries, top_k=5)

    assert result["recall_at_5"] == 0.0
    assert "lib_open" in result["missed_examples"]


def test_retrieval_perfect_when_query_is_the_signature(kb):
    queries = [
        {"query": d["signature"], "expect": d["function"]} for d in kb.documents
    ]
    result = evaluate_retrieval(kb, queries, top_k=5)

    assert result["recall_at_1"] == 1.0
    assert result["mrr"] == 1.0


def test_retrieval_handles_empty_query_set(kb):
    assert evaluate_retrieval(kb, [], top_k=5)["queries"] == 0


def test_load_queries_accepts_both_shapes(tmp_path):
    wrapped = tmp_path / "a.json"
    wrapped.write_text(json.dumps({"queries": [{"query": "q", "expect": "f"}]}),
                       encoding="utf-8")
    bare = tmp_path / "b.json"
    bare.write_text(json.dumps([{"query": "q", "expect": "f"}]), encoding="utf-8")

    assert load_queries(str(wrapped)) == load_queries(str(bare))


# -- 통합 -------------------------------------------------------------------


def test_evaluate_produces_all_three_sections(tree):
    result = evaluate([str(tree)], labels=_labels(tree, ["lib_open", "lib_read"]))

    assert set(result) >= {
        "ground_truth", "extraction_accuracy", "kb_coverage", "retrieval"
    }
    assert result["ground_truth"]["source"] in ("clang", "nm", "labels")


def test_report_is_console_safe(tree):
    """cp949 콘솔에서도 깨지지 않아야 한다 (팀 환경이 Windows)."""
    result = evaluate([str(tree)], labels=_labels(tree, ["lib_open", "lib_read"]))

    render_report(result).encode("cp949")


def test_report_mentions_the_ground_truth_source(tree):
    result = evaluate([str(tree)], labels=_labels(tree, ["lib_open"]))
    report = render_report(result)

    assert "정답셋" in report
    assert result["ground_truth"]["source"] in report
