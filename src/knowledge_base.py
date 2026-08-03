"""EXT-01-04: A파트 산출물을 하나로 묶는 통합 지식베이스 (B/D 지원).

지금까지 A파트가 만든 세 가지를 하나의 아티팩트로 합친다.

  EXT-01-01 AST 분석        -> 함수/포함 헤더/타입 정의
  EXT-01-03 bear 빌드 통합  -> 파일별 컴파일 플래그(-I/-D/-std)
  EXT-01-02 RAG 제약조건    -> 함수별 제약조건 + BM25 검색

여기에 통합 단계에서만 얻을 수 있는 정보를 더한다.

  * `api_id`  : 파일·줄 기준으로 결정적으로 매겨지는 정수 ID.
                B(SCH)와 D(ANA)가 서로 조인할 때 쓰는 키.
  * 호출 그래프 : 어떤 API가 어떤 API를 부르는지(정방향/역방향)와
                호출 순서(call_sequence).
  * 심볼 -> 헤더 : 이 API를 쓰려면 어떤 헤더를 include 해야 하는지.
                D의 GEN-03-02(컴파일 에러 자가치유)가 쓴다.

B/D가 실제로 소비하는 형태로 바꾸는 어댑터는 `src.kb_adapters`에 있다.

사용법:
  python -m src.knowledge_base build --paths examples --output build/kb_full.json
  python -m src.knowledge_base show --kb build/kb_full.json --api parse_header
  python -m src.knowledge_base stats --kb build/kb_full.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from src.constraint_extractor import (
    FunctionFacts,
    doc_constraints,
    extract_doc_comment,
    extract_from_text,
    iter_source_files,
    mask_source,
)
from src.rag_constraints import build_document
from src.rag_index import BM25Index, DenseIndex, HybridRetriever

KB_VERSION = 1

HEADER_SUFFIXES = (".h", ".hh", ".hpp")

INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.M)
# 헤더가 "선언"하는 함수: 본문 없이 세미콜론으로 끝나는 프로토타입
DECL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;{)]*(?:\)[^;{)]*)*\)\s*;")
TYPEDEF_ALIAS_RE = re.compile(r"\btypedef\b[^;{]*?\b([A-Za-z_]\w*)\s*;")
TYPEDEF_BLOCK_RE = re.compile(
    r"\btypedef\s+(?:struct|union|enum)\b[^{;]*\{.*?\}\s*([A-Za-z_]\w*)\s*;", re.S
)
TAG_RE = re.compile(r"\b(?:struct|union|enum)\s+([A-Za-z_]\w*)\s*\{")

# 함수 정의가 아니라 선언으로만 잡히면 안 되는 이름들
_NON_SYMBOLS = {
    "if", "for", "while", "switch", "return", "sizeof", "defined", "typedef",
    "else", "do", "case", "static", "extern", "inline", "const", "struct",
    "union", "enum", "void", "int", "char", "long", "short", "unsigned",
    "signed", "float", "double", "attribute", "__attribute__",
}


@dataclass
class FileInfo:
    """소스 파일 하나에 대한 빌드/구조 정보."""

    path: str
    includes: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    directory: str = ""
    declares: List[str] = field(default_factory=list)
    types: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def header_declaration_docs(text: str) -> Dict[str, str]:
    """헤더의 함수 선언 위에 붙은 문서 주석을 {함수이름: 문서} 로 뽑는다.

    C 프로젝트는 보통 `.h` 의 프로토타입에 문서를 달고 `.c` 의 정의에는 달지
    않는다. 통합 단계에서 둘을 이어 줘야 제약조건이 살아난다.
    """
    masked = mask_source(text)
    docs: Dict[str, str] = {}
    for match in DECL_RE.finditer(masked):
        name = match.group(1)
        if name in _NON_SYMBOLS:
            continue
        start = match.start()
        cut = max(masked.rfind(ch, 0, start) for ch in ";}{")
        decl_start = start if cut < 0 else cut + 1
        # 마스킹된 주석은 공백이므로 lstrip 하면 선언 첫 글자로 간다
        offset = len(masked[decl_start:start]) - len(masked[decl_start:start].lstrip())
        doc = extract_doc_comment(text, decl_start + offset)
        if doc:
            docs.setdefault(name, doc)
    return docs


def scan_file(path: str, text: Optional[str] = None) -> FileInfo:
    """파일에서 include / 선언 심볼 / 타입 이름을 뽑는다."""
    if text is None:
        text = _read(path)
    masked = mask_source(text)

    declares = {
        name for name in DECL_RE.findall(masked) if name not in _NON_SYMBOLS
    }
    types = set(TYPEDEF_BLOCK_RE.findall(masked))
    types |= {n for n in TYPEDEF_ALIAS_RE.findall(masked) if n not in _NON_SYMBOLS}
    types |= set(TAG_RE.findall(masked))

    return FileInfo(
        path=path,
        includes=INCLUDE_RE.findall(text),
        declares=sorted(declares),
        types=sorted(types),
    )


def _compile_db_entries(compile_db: str) -> Dict[str, dict]:
    """compile_commands.json 을 파일 경로 -> {flags, directory} 로 정리한다."""
    from src.compile_commands import load_compile_commands
    from src.compile_db_analyzer import extract_clang_args, normalize_path

    entries: Dict[str, dict] = {}
    for entry in load_compile_commands(compile_db):
        file_path = entry.get("file")
        if not file_path:
            continue
        directory = entry.get("directory", "")
        if directory and not os.path.isabs(file_path):
            file_path = os.path.join(directory, file_path)
        file_path = normalize_path(file_path)
        entries[file_path] = {
            "flags": extract_clang_args(entry.get("command", "")),
            "directory": directory,
        }
    return entries


class KnowledgeBase:
    """A파트 통합 지식베이스."""

    def __init__(self, documents: Optional[Sequence[dict]] = None,
                 files: Optional[Dict[str, dict]] = None,
                 index: Optional[BM25Index] = None,
                 use_dense: bool = False) -> None:
        self.documents: List[dict] = list(documents or [])
        self.files: Dict[str, dict] = dict(files or {})
        if index is None:
            index = BM25Index()
            index.add_documents(self.documents)
        self.index = index
        self._by_id = {d["api_id"]: d for d in self.documents}
        self._by_name: Dict[str, List[dict]] = {}
        for document in self.documents:
            self._by_name.setdefault(document["function"], []).append(document)

        dense = None
        if use_dense and DenseIndex.available():
            dense = DenseIndex()
            dense.add_documents(self.documents)
        self.retriever = HybridRetriever(self.index, dense)
        self._dense_enabled = dense is not None

    # -- 구축 --------------------------------------------------------------
    @classmethod
    def build(cls, paths: Optional[Sequence[str]] = None,
              compile_db: Optional[str] = None,
              use_dense: bool = False) -> "KnowledgeBase":
        if not paths and not compile_db:
            raise ValueError("either paths or compile_db must be provided")

        build_info = _compile_db_entries(compile_db) if compile_db else {}

        sources: List[str] = list(iter_source_files(paths or []))
        sources.extend(p for p in build_info if os.path.exists(p))
        sources = sorted(set(sources))

        file_infos: Dict[str, FileInfo] = {}
        facts: List[FunctionFacts] = []
        header_docs: Dict[str, str] = {}
        for source in sources:
            try:
                text = _read(source)
            except OSError:
                continue
            info = scan_file(source, text)
            entry = build_info.get(source)
            if entry:
                info.flags = entry["flags"]
                info.directory = entry["directory"]
            file_infos[source] = info
            if source.endswith(HEADER_SUFFIXES):
                for name, doc in header_declaration_docs(text).items():
                    header_docs.setdefault(name, doc)
            facts.extend(extract_from_text(text, path=source))

        _merge_header_docs(facts, header_docs)
        documents = cls._assemble(facts, file_infos)
        files = {path: info.to_dict() for path, info in file_infos.items()}
        return cls(documents=documents, files=files, use_dense=use_dense)

    @staticmethod
    def _assemble(facts: Sequence[FunctionFacts],
                  file_infos: Dict[str, FileInfo]) -> List[dict]:
        """FunctionFacts 를 api_id·호출그래프·헤더 정보가 붙은 문서로 만든다."""
        # api_id 는 (파일, 줄) 정렬 기준으로 결정적으로 매긴다. 같은 입력이면
        # 항상 같은 ID 가 나와야 B/D 가 저장해 둔 ID 로 다시 조인할 수 있다.
        ordered = sorted(facts, key=lambda f: (f.file, f.line, f.name))

        documents: List[dict] = []
        for api_id, fact in enumerate(ordered, start=1):
            document = build_document(fact)
            document["api_id"] = api_id
            document["call_sequence"] = list(fact.call_sequence)
            documents.append(document)

        known = {d["function"] for d in documents}
        name_to_ids: Dict[str, List[int]] = {}
        for document in documents:
            name_to_ids.setdefault(document["function"], []).append(document["api_id"])

        # 호출 그래프: 알려진 API 만 남긴다 (libc 호출은 제외)
        callers: Dict[str, List[str]] = {}
        for document in documents:
            internal = [c for c in document["call_sequence"] if c in known]
            document["calls_internal"] = internal
            # 이 함수의 본문에서 관찰된 호출 순서(api_id)
            document["body_call_ids"] = [
                str(api_id) for name in internal for api_id in name_to_ids.get(name, [])
            ]
            for callee in set(internal):
                if callee != document["function"]:
                    callers.setdefault(callee, []).append(document["function"])

        # SCH-02-02 의 call_seq: "소비자 코드에서 뽑힌 호출 순서"를 이어붙인 것.
        # B의 call_adjacency_score 는 시퀀스 안에서 자기 자신의 api_id 를 찾아
        # 이웃을 세므로, 이 API를 *호출하는* 함수들의 시퀀스를 모아야 한다.
        # 자기 자신의 호출 목록을 주면 자기 id 가 없어 점수가 항상 0이 된다.
        for document in documents:
            own_id = str(document["api_id"])
            observed: List[str] = []
            for other in documents:
                if own_id in other["body_call_ids"]:
                    observed.extend(other["body_call_ids"])
            document["call_seq_ids"] = observed

        headers = {
            path: info for path, info in file_infos.items()
            if path.endswith(HEADER_SUFFIXES)
        }
        for document in documents:
            document["called_by"] = sorted(set(callers.get(document["function"], [])))
            info = file_infos.get(document["file"])
            document["includes"] = list(info.includes) if info else []
            document["compile_flags"] = list(info.flags) if info else []
            document["header"] = _declaring_header(document["function"], document["file"],
                                                   headers)
        return documents

    # -- 조회 --------------------------------------------------------------
    def api(self, key) -> Optional[dict]:
        """api_id(int) 또는 함수 이름(str)으로 단일 API를 찾는다."""
        if isinstance(key, int):
            return self._by_id.get(key)
        matches = self._by_name.get(str(key))
        return matches[0] if matches else None

    def apis(self, name: Optional[str] = None) -> List[dict]:
        if name is None:
            return list(self.documents)
        return list(self._by_name.get(name, []))

    def search(self, query: str, top_k: int = 5,
               where: Optional[Dict[str, str]] = None) -> List[dict]:
        return self.retriever.search(query, top_k=top_k, where=where)

    def callees_of(self, name: str) -> List[str]:
        document = self.api(name)
        return list(document["calls_internal"]) if document else []

    def callers_of(self, name: str) -> List[str]:
        document = self.api(name)
        return list(document["called_by"]) if document else []

    def call_sequence_ids(self, name: str) -> List[str]:
        """SCH-02-02 의 call_seq 형식(api_id 문자열 목록)."""
        document = self.api(name)
        return list(document["call_seq_ids"]) if document else []

    def header_for(self, name: str) -> Optional[str]:
        document = self.api(name)
        return document.get("header") if document else None

    def flags_for(self, path: str) -> List[str]:
        info = self.files.get(path)
        return list(info["flags"]) if info else []

    def defines_type(self, type_name: str) -> List[str]:
        """해당 타입 이름을 정의하는 파일 목록."""
        bare = type_name.replace("struct ", "").replace("union ", "").strip()
        return sorted(
            path for path, info in self.files.items() if bare in info.get("types", [])
        )

    def declaring_files(self, name: str) -> List[str]:
        return sorted(
            path for path, info in self.files.items() if name in info.get("declares", [])
        )

    def stats(self) -> dict:
        by_kind: Dict[str, int] = {}
        for document in self.documents:
            for constraint in document["constraints"]:
                by_kind[constraint["kind"]] = by_kind.get(constraint["kind"], 0) + 1
        with_header = sum(1 for d in self.documents if d.get("header"))
        with_flags = sum(1 for d in self.documents if d.get("compile_flags"))
        edges = sum(len(d.get("calls_internal", [])) for d in self.documents)
        covered = sum(1 for d in self.documents if d["constraints"])
        return {
            "apis": len(self.documents),
            "files": len(self.files),
            "headers": sum(1 for p in self.files if p.endswith(HEADER_SUFFIXES)),
            "constraints": sum(by_kind.values()),
            "by_kind": dict(sorted(by_kind.items())),
            "call_edges": edges,
            "apis_with_header": with_header,
            "apis_with_compile_flags": with_flags,
            "constraint_coverage": (
                round(covered / len(self.documents), 4) if self.documents else 0.0
            ),
            "dense_backend": self._dense_enabled,
        }

    # -- 저장/로드 ---------------------------------------------------------
    def save(self, path: str) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": KB_VERSION,
            "documents": self.documents,
            "files": self.files,
            "index": self.index.to_dict(),
        }
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(target)

    @classmethod
    def load(cls, path: str, use_dense: bool = False) -> "KnowledgeBase":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("version") != KB_VERSION:
            raise ValueError(
                f"unsupported knowledge base version: {payload.get('version')} "
                f"(expected {KB_VERSION})"
            )
        return cls(
            documents=payload["documents"],
            files=payload.get("files", {}),
            index=BM25Index.from_dict(payload["index"]),
            use_dense=use_dense,
        )


def _merge_header_docs(facts: Sequence[FunctionFacts], header_docs: Dict[str, str]) -> None:
    """헤더 선언부 문서를 구현 함수에 결합하고, 거기서 제약조건을 다시 뽑는다."""
    for fact in facts:
        doc = header_docs.get(fact.name)
        if not doc or fact.doc:
            continue
        fact.doc = doc
        existing = {(c.kind, c.target, c.description) for c in fact.constraints}
        for constraint in doc_constraints(doc, fact.line):
            key = (constraint.kind, constraint.target, constraint.description)
            if key not in existing:
                fact.constraints.append(constraint)
                existing.add(key)


def _declaring_header(name: str, definition_file: str,
                      headers: Dict[str, FileInfo]) -> Optional[str]:
    """해당 API를 선언하는 헤더를 고른다.

    같은 basename 의 헤더(foo.c <-> foo.h)를 우선하고, 없으면 선언을 담고
    있는 헤더 중 경로가 가장 짧은 것을 고른다.
    """
    candidates = [path for path, info in headers.items() if name in info.declares]
    if not candidates:
        # 헤더 자체에 정의된 static inline 함수라면 그 헤더가 답이다.
        if definition_file.endswith(HEADER_SUFFIXES):
            return definition_file
        return None

    stem = Path(definition_file).stem
    for path in sorted(candidates):
        if Path(path).stem == stem:
            return path
    return sorted(candidates, key=lambda p: (len(p), p))[0]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Unified A-track knowledge base (EXT-01-04)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="Build the unified knowledge base")
    build_parser.add_argument("--paths", nargs="*", default=[])
    build_parser.add_argument("--compile-db", help="Path to compile_commands.json")
    build_parser.add_argument("--output", "-o", required=True)
    build_parser.add_argument("--dense", action="store_true")

    show_parser = subparsers.add_parser("show", help="Show a single API entry")
    show_parser.add_argument("--kb", required=True)
    show_parser.add_argument("--api", required=True, help="Function name or api_id")

    stats_parser = subparsers.add_parser("stats", help="Show knowledge base statistics")
    stats_parser.add_argument("--kb", required=True)

    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.command == "build":
        kb = KnowledgeBase.build(
            paths=args.paths, compile_db=args.compile_db, use_dense=args.dense
        )
        kb.save(args.output)
        print(json.dumps({"output": args.output, **kb.stats()}, indent=2, ensure_ascii=False))
        return

    kb = KnowledgeBase.load(args.kb)

    if args.command == "stats":
        print(json.dumps(kb.stats(), indent=2, ensure_ascii=False))
        return

    if args.command == "show":
        key = int(args.api) if args.api.isdigit() else args.api
        document = kb.api(key)
        if document is None:
            print(json.dumps({"error": f"no API named {args.api!r}"}, ensure_ascii=False))
            return
        print(json.dumps(document, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
