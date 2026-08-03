import json

import pytest

from src.rag_index import (
    BM25Index,
    HybridRetriever,
    expand_query,
    reciprocal_rank_fusion,
    split_identifier,
    tokenize,
)

DOCUMENTS = [
    {"id": "1", "function": "parse_header", "file": "a.c",
     "text": "function parse_header buffer length must not be NULL bounds checked"},
    {"id": "2", "function": "readAllBytes", "file": "b.c",
     "text": "function readAllBytes opens a file with fopen and the caller must free the result"},
    {"id": "3", "function": "add", "file": "c.c",
     "text": "function add returns the sum of two integers"},
]


@pytest.fixture
def index():
    bm25 = BM25Index()
    bm25.add_documents(DOCUMENTS)
    return bm25


def test_split_identifier_handles_snake_and_camel():
    assert split_identifier("parse_http_header") == ["parse", "http", "header"]
    assert split_identifier("readAllBytes") == ["read", "all", "bytes"]
    assert split_identifier("HTTPParser") == ["http", "parser"]


def test_tokenize_keeps_full_identifier_and_subtokens():
    tokens = tokenize("parse_header(buf)")

    assert "parse_header" in tokens
    assert "parse" in tokens and "header" in tokens
    assert "buf" in tokens


def test_tokenize_drops_stopwords():
    assert "the" not in tokenize("the buffer")
    assert "buffer" in tokenize("the buffer")


def test_expand_query_adds_korean_synonyms():
    expanded = expand_query("버퍼 크기")

    assert "buffer" in expanded
    assert "size" in expanded


def test_expand_query_handles_korean_with_particles():
    expanded = expand_query("버퍼의 길이는")

    assert "buffer" in expanded
    assert "length" in expanded


def test_search_ranks_relevant_document_first(index):
    hits = index.search("buffer length", top_k=3)

    assert hits
    assert hits[0]["document"]["function"] == "parse_header"


def test_search_matches_subtokens_of_identifier(index):
    hits = index.search("read bytes", top_k=3)

    assert hits[0]["document"]["function"] == "readAllBytes"


def test_search_respects_top_k(index):
    assert len(index.search("function", top_k=2)) == 2


def test_search_filters_by_field(index):
    hits = index.search("function", top_k=5, where={"file": "b.c"})

    assert len(hits) == 1
    assert hits[0]["document"]["file"] == "b.c"


def test_search_returns_nothing_for_unknown_terms(index):
    assert index.search("quantum entanglement") == []


def test_scores_are_positive_and_sorted(index):
    hits = index.search("free file caller", top_k=3)

    scores = [hit["score"] for hit in hits]
    assert all(score > 0 for score in scores)
    assert scores == sorted(scores, reverse=True)


def test_roundtrip_serialization_preserves_ranking(index, tmp_path):
    path = tmp_path / "index.json"
    index.save(str(path))
    restored = BM25Index.load(str(path))

    assert len(restored) == len(index)
    assert restored.search("buffer length", top_k=1) == index.search("buffer length", top_k=1)


def test_saved_index_is_valid_utf8_json(index, tmp_path):
    path = tmp_path / "index.json"
    index.save(str(path))

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["type"] == "bm25"
    assert len(payload["documents"]) == 3


def test_add_document_accepts_explicit_text():
    bm25 = BM25Index()
    bm25.add_document({"id": "x"}, text="custom searchable body")

    assert bm25.search("custom", top_k=1)[0]["document"]["id"] == "x"


def test_empty_index_search_is_empty():
    assert BM25Index().search("anything") == []


def test_reciprocal_rank_fusion_merges_rankings():
    sparse = [{"score": 5.0, "document": DOCUMENTS[0]}, {"score": 1.0, "document": DOCUMENTS[2]}]
    dense = [{"score": 0.9, "document": DOCUMENTS[2]}, {"score": 0.8, "document": DOCUMENTS[0]}]

    fused = reciprocal_rank_fusion([sparse, dense], top_k=2)

    assert {hit["document"]["id"] for hit in fused} == {"1", "3"}
    assert fused[0]["score"] >= fused[1]["score"]


def test_hybrid_retriever_falls_back_to_bm25_without_dense(index):
    retriever = HybridRetriever(index, dense=None)
    hits = retriever.search("buffer length", top_k=2)

    assert hits[0]["document"]["function"] == "parse_header"
    assert len(hits) <= 2
