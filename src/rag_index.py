"""EXT-01-02: 제약조건 문서를 위한 경량 RAG 검색 인덱스.

외부 의존성 없이 동작하는 BM25 희소 검색기를 기본으로 쓴다. 코드 식별자를
잘 다루기 위해 `snake_case`/`camelCase`를 부분 토큰으로 쪼개고, 한국어 질의를
영문 제약조건 문서에 연결하기 위한 소규모 동의어 사전을 둔다.

`sentence-transformers`가 설치되어 있으면 `DenseIndex`가 활성화되어 RRF
(reciprocal rank fusion)로 BM25와 결합된다. 설치되어 있지 않으면 BM25만
사용하며, 이는 저장소의 다른 모듈(clang optional 패턴)과 같은 방식이다.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[가-힣]+")
CAMEL_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|\d+")

STOPWORDS = {
    "a", "an", "the", "of", "to", "is", "are", "be", "and", "or", "in", "on",
    "at", "by", "it", "this", "that", "as", "with", "from",
}

# 한국어 질의 -> 문서에 등장하는 영문 토큰
SYNONYMS: Dict[str, Sequence[str]] = {
    "널": ("null", "nullptr"),
    "널체크": ("null", "check"),
    "포인터": ("pointer", "ptr"),
    "버퍼": ("buffer", "buf"),
    "크기": ("size", "len", "length"),
    "길이": ("length", "len", "size"),
    "범위": ("range", "bounds"),
    "경계": ("bounds", "range"),
    "메모리": ("memory", "malloc", "free"),
    "할당": ("alloc", "malloc", "allocate"),
    "해제": ("free", "release", "close"),
    "자원": ("resource", "handle"),
    "제약": ("constraint", "precondition"),
    "제약조건": ("constraint", "precondition"),
    "사전조건": ("precondition", "assert"),
    "인자": ("param", "argument"),
    "매개변수": ("param", "argument"),
    "반환": ("return", "result"),
    "반환값": ("return", "value"),
    "함수": ("function",),
    "검증": ("check", "validate", "assert"),
    "파일": ("file", "fopen"),
    "문자열": ("string", "str", "char"),
    "위험": ("risky", "unsafe"),
    "초기화": ("init", "initialize"),
}


def split_identifier(token: str) -> List[str]:
    """`parse_http_header` / `parseHttpHeader` -> ['parse', 'http', 'header']"""
    parts: List[str] = []
    for chunk in token.split("_"):
        if not chunk:
            continue
        parts.extend(m.group(0).lower() for m in CAMEL_RE.finditer(chunk))
    return [p for p in parts if p]


def tokenize(text: str) -> List[str]:
    """식별자 원형과 부분 토큰을 함께 담은 토큰 목록."""
    tokens: List[str] = []
    for raw in TOKEN_RE.findall(text or ""):
        lowered = raw.lower()
        if lowered in STOPWORDS:
            continue
        tokens.append(lowered)
        for part in split_identifier(raw):
            if part != lowered and part not in STOPWORDS:
                tokens.append(part)
    return tokens


def expand_query(text: str) -> List[str]:
    """질의 토큰에 한국어 동의어를 덧붙인다."""
    tokens = tokenize(text)
    expanded = list(tokens)
    for token in tokens:
        for alias in SYNONYMS.get(token, ()):  # 정확히 일치하는 경우
            expanded.append(alias)
        for korean, aliases in SYNONYMS.items():
            # '버퍼크기' 처럼 조사가 붙거나 합성된 경우
            if len(korean) > 1 and korean in token and korean != token:
                expanded.extend(aliases)
    return expanded


class BM25Index:
    """Okapi BM25 색인. 직렬화 가능하며 파일로 저장/로드된다."""

    def __init__(self, k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.documents: List[dict] = []
        self._term_freqs: List[Dict[str, int]] = []
        self._lengths: List[int] = []
        self._df: Counter = Counter()
        self._avgdl: float = 0.0

    # -- 색인 구성 ---------------------------------------------------------
    def add_document(self, document: dict, text: Optional[str] = None) -> int:
        """문서를 추가하고 doc index를 반환한다.

        `text`를 주지 않으면 document['text']를 색인 대상으로 삼는다.
        """
        body = text if text is not None else document.get("text", "")
        tokens = tokenize(body)
        frequencies = Counter(tokens)
        self.documents.append(document)
        self._term_freqs.append(dict(frequencies))
        self._lengths.append(len(tokens))
        for term in frequencies:
            self._df[term] += 1
        self._avgdl = sum(self._lengths) / len(self._lengths) if self._lengths else 0.0
        return len(self.documents) - 1

    def add_documents(self, documents: Iterable[dict]) -> None:
        for document in documents:
            self.add_document(document)

    def __len__(self) -> int:
        return len(self.documents)

    # -- 검색 --------------------------------------------------------------
    def _idf(self, term: str) -> float:
        n = len(self.documents)
        df = self._df.get(term, 0)
        if df == 0:
            return 0.0
        return math.log(1 + (n - df + 0.5) / (df + 0.5))

    def score(self, query_tokens: Sequence[str], doc_index: int) -> float:
        frequencies = self._term_freqs[doc_index]
        length = self._lengths[doc_index] or 1
        total = 0.0
        for term in set(query_tokens):
            tf = frequencies.get(term, 0)
            if tf == 0:
                continue
            denominator = tf + self.k1 * (1 - self.b + self.b * length / (self._avgdl or 1))
            total += self._idf(term) * (tf * (self.k1 + 1)) / denominator
        return total

    def search(self, query: str, top_k: int = 5,
               where: Optional[Dict[str, str]] = None) -> List[dict]:
        """상위 `top_k` 문서를 [{score, document}] 형태로 반환한다."""
        query_tokens = expand_query(query)
        scored: List[dict] = []
        for index, document in enumerate(self.documents):
            if where and any(str(document.get(key)) != str(value) for key, value in where.items()):
                continue
            value = self.score(query_tokens, index)
            if value <= 0:
                continue
            scored.append({"score": round(value, 6), "document": document})
        scored.sort(key=lambda item: item["score"], reverse=True)
        return scored[:top_k]

    # -- 직렬화 ------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "type": "bm25",
            "k1": self.k1,
            "b": self.b,
            "documents": self.documents,
            "term_freqs": self._term_freqs,
            "lengths": self._lengths,
            "df": dict(self._df),
            "avgdl": self._avgdl,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "BM25Index":
        index = cls(k1=payload.get("k1", 1.5), b=payload.get("b", 0.75))
        index.documents = payload.get("documents", [])
        index._term_freqs = payload.get("term_freqs", [])
        index._lengths = payload.get("lengths", [])
        index._df = Counter(payload.get("df", {}))
        index._avgdl = payload.get("avgdl", 0.0)
        return index

    def save(self, path: str) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), ensure_ascii=False), encoding="utf-8")
        return str(target)

    @classmethod
    def load(cls, path: str) -> "BM25Index":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


class DenseIndex:
    """`sentence-transformers`가 있을 때만 동작하는 선택적 밀집 검색기."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        from sentence_transformers import SentenceTransformer  # 지연 임포트

        self._model = SentenceTransformer(model_name)
        self.documents: List[dict] = []
        self._vectors: List[List[float]] = []

    @staticmethod
    def available() -> bool:
        try:
            import sentence_transformers  # noqa: F401
        except Exception:
            return False
        return True

    def add_documents(self, documents: Sequence[dict]) -> None:
        texts = [document.get("text", "") for document in documents]
        if not texts:
            return
        vectors = self._model.encode(texts, normalize_embeddings=True)
        self.documents.extend(documents)
        self._vectors.extend([list(map(float, vector)) for vector in vectors])

    def search(self, query: str, top_k: int = 5) -> List[dict]:
        if not self._vectors:
            return []
        query_vector = list(map(float, self._model.encode([query], normalize_embeddings=True)[0]))
        scored = [
            {"score": sum(a * b for a, b in zip(query_vector, vector)),
             "document": self.documents[index]}
            for index, vector in enumerate(self._vectors)
        ]
        scored.sort(key=lambda item: item["score"], reverse=True)
        return scored[:top_k]


def reciprocal_rank_fusion(rankings: Sequence[Sequence[dict]], key: str = "id",
                           k: int = 60, top_k: int = 5) -> List[dict]:
    """여러 검색기의 순위를 RRF로 합친다."""
    fused: Dict[str, dict] = {}
    for ranking in rankings:
        for rank, hit in enumerate(ranking):
            document = hit["document"]
            identifier = str(document.get(key))
            entry = fused.setdefault(identifier, {"score": 0.0, "document": document})
            entry["score"] += 1.0 / (k + rank + 1)
    merged = sorted(fused.values(), key=lambda item: item["score"], reverse=True)
    for item in merged:
        item["score"] = round(item["score"], 6)
    return merged[:top_k]


class HybridRetriever:
    """BM25 + (가능하면) 밀집 검색을 RRF로 결합한다."""

    def __init__(self, bm25: BM25Index, dense: Optional[DenseIndex] = None) -> None:
        self.bm25 = bm25
        self.dense = dense

    def search(self, query: str, top_k: int = 5,
               where: Optional[Dict[str, str]] = None) -> List[dict]:
        sparse_hits = self.bm25.search(query, top_k=max(top_k * 3, top_k), where=where)
        if self.dense is None:
            return sparse_hits[:top_k]
        dense_hits = self.dense.search(query, top_k=max(top_k * 3, top_k))
        if where:
            dense_hits = [
                hit for hit in dense_hits
                if all(str(hit["document"].get(k)) == str(v) for k, v in where.items())
            ]
        return reciprocal_rank_fusion([sparse_hits, dense_hits], top_k=top_k)
