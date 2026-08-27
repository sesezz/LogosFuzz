"""EXT-01-02: RAG 제약조건 지식베이스 구축/검색.

파이프라인:
  1. `compile_commands.json`(EXT-01-03) 또는 경로 목록에서 소스를 모은다.
  2. `src.constraint_extractor`로 함수별 제약조건을 추출한다.
  3. 함수 하나를 문서 하나로 만들어 `src.rag_index`에 색인한다.
  4. 하네스 생성기(GEN-03-01)가 질의하면 프롬프트에 넣을 컨텍스트를 돌려준다.

사용법:
  python -m src.rag_constraints build --paths examples --output build/kb.json
  python -m src.rag_constraints build --compile-db build/compile_commands.json \
      --output build/kb.json
  python -m src.rag_constraints query --kb build/kb.json "buffer length check" --top-k 3
  python -m src.rag_constraints context --kb build/kb.json --function parse_header
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from logosfuzz.extract.constraint_extractor import (
    FunctionFacts,
    extract_from_paths,
    iter_source_files,
)
from logosfuzz.knowledge.rag_index import BM25Index, DenseIndex, HybridRetriever

KB_VERSION = 1

# 하네스 생성 시 우선적으로 보여줄 제약조건 순서
KIND_PRIORITY = {
    "assert": 0,
    "null_check": 1,
    "buffer_size": 2,
    "range_check": 3,
    "resource": 4,
    "return_value": 5,
    "doc": 6,
    "risky_call": 7,
    "nullable": 8,
}


def _sources_from_compile_db(compile_db: str) -> List[str]:
    """compile_commands.json에서 소스 경로를 뽑아 실제 존재하는 것만 남긴다."""
    from logosfuzz.extract.compile_commands import load_compile_commands
    from logosfuzz.extract.compile_db_analyzer import normalize_path

    sources: List[str] = []
    for entry in load_compile_commands(compile_db):
        file_path = entry.get("file")
        if not file_path:
            continue
        if entry.get("directory") and not os.path.isabs(file_path):
            file_path = os.path.join(entry["directory"], file_path)
        file_path = normalize_path(file_path)
        if os.path.exists(file_path):
            sources.append(file_path)
    return sources


def build_document(facts: FunctionFacts) -> dict:
    """함수 하나를 검색 문서로 변환한다."""
    constraints = sorted(
        facts.constraints,
        key=lambda c: (KIND_PRIORITY.get(c.kind, 99), -c.confidence),
    )
    param_text = ", ".join(
        f"{p.type} {p.name}".strip() for p in facts.params
    ) or "void"

    lines = [
        f"function {facts.name}",
        f"signature {facts.signature}",
        f"params {param_text}",
        f"returns {facts.return_type}",
    ]
    if facts.doc:
        lines.append(f"doc {facts.doc}")
    for constraint in constraints:
        lines.append(f"{constraint.kind} {constraint.target} {constraint.description}")
    if facts.calls:
        lines.append("calls " + " ".join(facts.calls))

    return {
        "id": f"{facts.file}::{facts.name}:{facts.line}",
        "function": facts.name,
        "file": facts.file,
        "line": facts.line,
        "signature": facts.signature,
        "return_type": facts.return_type,
        "params": [p.to_dict() for p in facts.params],
        "doc": facts.doc,
        "calls": facts.calls,
        "constraints": [c.to_dict() for c in constraints],
        "text": "\n".join(lines),
    }


class ConstraintKB:
    """제약조건 문서 + 검색 인덱스를 함께 들고 다니는 지식베이스."""

    def __init__(self, documents: Optional[Sequence[dict]] = None,
                 index: Optional[BM25Index] = None,
                 use_dense: bool = False) -> None:
        self.documents: List[dict] = list(documents or [])
        if index is None:
            index = BM25Index()
            index.add_documents(self.documents)
        self.index = index
        self._dense: Optional[DenseIndex] = None
        if use_dense and DenseIndex.available():
            self._dense = DenseIndex()
            self._dense.add_documents(self.documents)
        self.retriever = HybridRetriever(self.index, self._dense)

    # -- 구축 --------------------------------------------------------------
    @classmethod
    def from_paths(cls, paths: Iterable[str], use_dense: bool = False) -> "ConstraintKB":
        facts = extract_from_paths(paths)
        documents = [build_document(f) for f in facts]
        return cls(documents=documents, use_dense=use_dense)

    @classmethod
    def from_compile_db(cls, compile_db: str, use_dense: bool = False) -> "ConstraintKB":
        return cls.from_paths(_sources_from_compile_db(compile_db), use_dense=use_dense)

    # -- 조회 --------------------------------------------------------------
    def search(self, query: str, top_k: int = 5,
               where: Optional[Dict[str, str]] = None) -> List[dict]:
        return self.retriever.search(query, top_k=top_k, where=where)

    def get_function(self, name: str) -> List[dict]:
        return [d for d in self.documents if d["function"] == name]

    def constraints_of(self, name: str) -> List[dict]:
        constraints: List[dict] = []
        for document in self.get_function(name):
            constraints.extend(document["constraints"])
        return constraints

    def stats(self) -> dict:
        by_kind: Dict[str, int] = {}
        for document in self.documents:
            for constraint in document["constraints"]:
                by_kind[constraint["kind"]] = by_kind.get(constraint["kind"], 0) + 1
        covered = sum(1 for d in self.documents if d["constraints"])
        return {
            "functions": len(self.documents),
            "files": len({d["file"] for d in self.documents}),
            "constraints": sum(by_kind.values()),
            "by_kind": dict(sorted(by_kind.items())),
            "functions_with_constraints": covered,
            "coverage": round(covered / len(self.documents), 4) if self.documents else 0.0,
            "dense_backend": self._dense is not None,
        }

    # -- 하네스 생성기용 컨텍스트 -------------------------------------------
    def context_for(self, target: str, top_k: int = 3, max_constraints: int = 12) -> str:
        """GEN-03-01 프롬프트에 그대로 붙일 수 있는 텍스트 블록을 만든다."""
        documents = self.get_function(target)
        if not documents:
            documents = [hit["document"] for hit in self.search(target, top_k=top_k)]
        if not documents:
            return f"# no knowledge-base entry matched '{target}'"

        blocks: List[str] = []
        for document in documents[:top_k]:
            lines = [
                f"## {document['function']}  ({document['file']}:{document['line']})",
                f"signature: {document['signature']}",
            ]
            if document["doc"]:
                lines.append(f"doc: {document['doc']}")
            constraints = document["constraints"][:max_constraints]
            if constraints:
                lines.append("constraints:")
                for constraint in constraints:
                    target_note = f" [{constraint['target']}]" if constraint["target"] else ""
                    repeats = constraint.get("occurrences", 1)
                    repeat_note = f" (x{repeats})" if repeats > 1 else ""
                    lines.append(
                        f"  - ({constraint['kind']}, conf={constraint['confidence']})"
                        f"{target_note} {constraint['description']}{repeat_note}"
                    )
                    if constraint["expression"]:
                        lines.append(f"      evidence: {constraint['expression']}")
            else:
                lines.append("constraints: none extracted")
            blocks.append("\n".join(lines))
        return "\n\n".join(blocks)

    # -- 저장/로드 ---------------------------------------------------------
    def save(self, path: str) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": KB_VERSION,
            "documents": self.documents,
            "index": self.index.to_dict(),
        }
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(target)

    @classmethod
    def load(cls, path: str, use_dense: bool = False) -> "ConstraintKB":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("version") != KB_VERSION:
            raise ValueError(
                f"unsupported knowledge base version: {payload.get('version')} "
                f"(expected {KB_VERSION})"
            )
        index = BM25Index.from_dict(payload["index"])
        return cls(documents=payload["documents"], index=index, use_dense=use_dense)


def build_kb(paths: Optional[Sequence[str]] = None, compile_db: Optional[str] = None,
             output_path: Optional[str] = None, use_dense: bool = False) -> ConstraintKB:
    """경로 또는 compile_commands.json으로부터 지식베이스를 만든다."""
    if not paths and not compile_db:
        raise ValueError("either paths or compile_db must be provided")

    sources: List[str] = list(iter_source_files(paths or []))
    if compile_db:
        sources.extend(_sources_from_compile_db(compile_db))

    kb = ConstraintKB.from_paths(sorted(set(sources)), use_dense=use_dense)
    if output_path:
        kb.save(output_path)
    return kb


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="RAG constraint knowledge base for harness generation (EXT-01-02)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="Build the knowledge base")
    build_parser.add_argument("--paths", nargs="*", default=[], help="Source files or directories")
    build_parser.add_argument("--compile-db", help="Path to compile_commands.json")
    build_parser.add_argument("--output", "-o", required=True, help="Knowledge base JSON path")
    build_parser.add_argument("--dense", action="store_true",
                              help="Use the optional sentence-transformers backend")

    query_parser = subparsers.add_parser("query", help="Search the knowledge base")
    query_parser.add_argument("query", help="Natural language or identifier query")
    query_parser.add_argument("--kb", required=True, help="Knowledge base JSON path")
    query_parser.add_argument("--top-k", type=int, default=5)
    query_parser.add_argument("--file", help="Restrict results to a single source file")
    query_parser.add_argument("--dense", action="store_true")

    context_parser = subparsers.add_parser(
        "context", help="Render a prompt-ready constraint block for a function"
    )
    context_parser.add_argument("--kb", required=True)
    context_parser.add_argument("--function", required=True)
    context_parser.add_argument("--top-k", type=int, default=3)
    context_parser.add_argument("--dense", action="store_true")

    stats_parser = subparsers.add_parser("stats", help="Show knowledge base statistics")
    stats_parser.add_argument("--kb", required=True)

    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.command == "build":
        kb = build_kb(
            paths=args.paths,
            compile_db=args.compile_db,
            output_path=args.output,
            use_dense=args.dense,
        )
        print(json.dumps({"output": args.output, **kb.stats()}, indent=2, ensure_ascii=False))
        return

    if args.command == "stats":
        kb = ConstraintKB.load(args.kb)
        print(json.dumps(kb.stats(), indent=2, ensure_ascii=False))
        return

    kb = ConstraintKB.load(args.kb, use_dense=args.dense)

    if args.command == "query":
        where = {"file": args.file} if args.file else None
        hits = kb.search(args.query, top_k=args.top_k, where=where)
        print(json.dumps(
            [
                {
                    "score": hit["score"],
                    "function": hit["document"]["function"],
                    "file": hit["document"]["file"],
                    "line": hit["document"]["line"],
                    "signature": hit["document"]["signature"],
                    "constraints": hit["document"]["constraints"],
                }
                for hit in hits
            ],
            indent=2,
            ensure_ascii=False,
        ))
        return

    if args.command == "context":
        print(kb.context_for(args.function, top_k=args.top_k))


if __name__ == "__main__":
    main()
