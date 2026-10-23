"""EXT-01-04: A파트 산출물을 하나로 묶는 통합 지식베이스 (B/D 지원)

  EXT-01-01 AST 분석        -> 함수/포함 헤더/타입 정의
  EXT-01-02 RAG 제약조건    -> 함수별 제약조건 + BM25 검색

빌드 정보 출처
  * Bazel(S-CORE): `extract/bazel_query.py` 의 타깃·deps·include 경로
  * 대상 프로필(`targets/*.json`) cmake/prebuilt: compile_commands.json
    (`extract/compile_db.py`) 기반 파일별 플래그, 라이브러리 전체를 빌드 단위 1개로 기록
  * `profile.apis` 지정 시 해당 API 만 수록

통합 단계 추가 정보
  * `api_id`  : 파일·줄 기준 결정적 정수 ID (B(SCH)·D(ANA) 조인 키)
  * 호출 그래프 : 정방향/역방향 호출 관계와 호출 순서(call_sequence)
  * 심볼 -> 헤더 : API 사용에 필요한 include 헤더 (GEN-03-02 자가치유용)

B/D가 실제로 소비하는 형태로 바꾸는 어댑터는 `logosfuzz.knowledge.kb_adapters`에 있다.

사용법:
  python -m logosfuzz.knowledge.knowledge_base build --paths examples --output build/kb_full.json
  python -m logosfuzz.knowledge.knowledge_base build --profile targets/libsndfile.json --output build/sndfile-kb.json
  python -m logosfuzz.knowledge.knowledge_base show --kb build/kb_full.json --api parse_header
  python -m logosfuzz.knowledge.knowledge_base stats --kb build/kb_full.json
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Sequence

if TYPE_CHECKING:  # pragma: no cover
    from logosfuzz.common.target_profile import TargetProfile

from logosfuzz.extract.bazel_query import BazelGraph, query_bazel
from logosfuzz.extract.constraint_extractor import (
    FunctionFacts,
    destructure_macro_declaration,
    doc_constraints,
    extract_doc_comment,
    extract_from_text,
    iter_source_files,
    mask_source,
    score_result_enabled,
)
from logosfuzz.knowledge.rag_constraints import build_document
from logosfuzz.knowledge.rag_index import BM25Index, DenseIndex, HybridRetriever

logger = logging.getLogger(__name__)

KB_VERSION = 2
SUPPORTED_KB_VERSIONS = {1, KB_VERSION}

HEADER_SUFFIXES = (".h", ".hh", ".hpp")

INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.M)
# 헤더가 "선언"하는 함수: 본문 없이 세미콜론으로 끝나는 프로토타입
DECL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;{)]*(?:\)[^;{)]*)*\)\s*;")
TYPEDEF_ALIAS_RE = re.compile(r"\btypedef\b[^;{]*?\b([A-Za-z_]\w*)\s*;")
TYPEDEF_BLOCK_RE = re.compile(
    r"\btypedef\s+(?:struct|union|enum)\b[^{;]*\{.*?\}\s*([A-Za-z_]\w*)\s*;", re.S
)
TAG_RE = re.compile(r"\b(?:struct|union|enum)\s+([A-Za-z_]\w*)\s*\{")
# 구조체/공용체를 감싼 타입만 별도 집계 (`typedef struct _object PyObject;` 형태 포함)
# SCH-02-01 상태 핸들 선정 시 스칼라 별칭(Py_ssize_t 등)과 구분용
STRUCT_BLOCK_RE = re.compile(
    r"\btypedef\s+(?:struct|union)\b[^{;]*\{.*?\}\s*([A-Za-z_]\w*)\s*;", re.S
)
STRUCT_ALIAS_RE = re.compile(
    r"\btypedef\s+(?:struct|union)\s+[A-Za-z_]\w*\s+([A-Za-z_]\w*)\s*;"
)
STRUCT_TAG_RE = re.compile(r"\b(?:struct|union)\s+([A-Za-z_]\w*)\s*\{")

# 테스트/예제 코드 경로 표지 (S-CORE `logging` 기준 API 48.2%가 테스트 코드)
# KB 는 is_test 사실만 기록, 제외 여부는 소비자(SCH/GEN) 결정
# 경로 세그먼트 단위 비교 (부분 문자열 비교 시 상위 디렉토리 이름으로 오판)
_TEST_DIR_SEGMENTS = {
    "test", "tests", "testing", "ut", "it", "mock", "mocks",
    "gtest", "gmock", "example", "examples", "benchmark", "benchmarks",
    "fuzz", "fuzzing",
    # Eclipse S-CORE 관례 (`unit_test/` 아래 gtest 픽스처)
    "unit_test", "unit_tests", "component_test", "component_tests",
}

# 파일 이름 자체의 테스트 표지: `x_test.cpp`, `test_x.c`, `x.test.ts`
# `ut_`/`ct_` 접두사는 S-CORE 단위/컴포넌트 테스트 관례 (`ut_number.cpp`)
_TEST_FILE_RE = re.compile(
    r"(^|[._-])(test|tests|mock|benchmark|ut|ct|example|examples)([._-]|$)"
)

# 함수 선언으로 잡히면 안 되는 이름 목록
_NON_SYMBOLS = {
    "if", "for", "while", "switch", "return", "sizeof", "defined", "typedef",
    "else", "do", "case", "static", "extern", "inline", "const", "struct",
    "union", "enum", "void", "int", "char", "long", "short", "unsigned",
    "signed", "float", "double", "attribute", "__attribute__",
}


@dataclass
class FileInfo:
    """소스 파일 하나의 빌드/구조 정보"""

    path: str
    includes: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    directory: str = ""
    declares: List[str] = field(default_factory=list)
    types: List[str] = field(default_factory=list)
    # types 중 구조체/공용체를 감싼 것만. 상태 핸들 판정용(SCH-02-01)
    struct_types: List[str] = field(default_factory=list)
    build_system: str = ""
    build_target: str = ""
    build_rule_kind: str = ""
    build_deps: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def is_test_path(path: str, root: Optional[str] = None) -> bool:
    """테스트/예제 코드 여부 판별 (디렉토리 세그먼트·파일 이름 기준)

    ``root`` 지정 시 프로젝트 루트 기준 상대 경로로 판별
    (저장소 이름이 ``fuzz`` 등 테스트 표지와 겹치는 오판 방지)

    >>> is_test_path("score/datarouter/test/ut/ut_logging/x.cpp")
    True
    >>> is_test_path("score/mw/log/detail/common/dlt_format.cpp")
    False
    """
    candidate = str(path)
    if root:
        try:
            candidate = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
        except (OSError, ValueError):
            # 드라이브가 다른 Windows 경로 등은 절대 경로 판별로 폴백
            candidate = str(path)
    parts = [p.lower() for p in candidate.replace("\\", "/").split("/") if p]
    if not parts:
        return False
    if any(segment in _TEST_DIR_SEGMENTS for segment in parts[:-1]):
        return True
    return bool(_TEST_FILE_RE.search(Path(parts[-1]).stem))


def _is_test_path_under_roots(path: str, roots: Sequence[str]) -> bool:
    """Classify a source relative to its input root, not the checkout's name."""
    resolved = Path(path).resolve()
    matching = []
    for root in roots:
        candidate = Path(root).resolve()
        if resolved.is_relative_to(candidate):
            matching.append(candidate)
    if matching:
        root = max(matching, key=lambda candidate: len(candidate.parts))
        return is_test_path(str(resolved), root=str(root))
    return is_test_path(path)


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def header_declaration_docs(text: str) -> Dict[str, str]:
    """헤더 함수 선언 위 문서 주석을 {함수이름: 문서} 로 추출

    C 프로젝트는 `.h` 프로토타입에만 문서를 다는 경우가 많아 `.c` 정의와 결합 필요
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
        # 마스킹된 주석은 공백이므로 lstrip 시 선언 첫 글자 위치
        offset = len(masked[decl_start:start]) - len(masked[decl_start:start].lstrip())
        doc = extract_doc_comment(text, decl_start + offset)
        if doc:
            docs.setdefault(name, doc)
    return docs


def macro_declared_symbols(masked: str) -> Dict[str, str]:
    """매크로로 선언된 함수 이름 -> 반환 타입 문자열

    libpng `PNG_EXPORT(idx, rettype, name, (params));` 형태 대응
    (일반 프로토타입 정규식은 매크로 이름만 인식)
    """
    found: Dict[str, str] = {}
    for match in re.finditer(r"\b([A-Z][A-Z0-9_]{2,})\s*\(", masked):
        open_paren = match.end() - 1
        depth, close = 0, None
        for i in range(open_paren, len(masked)):
            if masked[i] == "(":
                depth += 1
            elif masked[i] == ")":
                depth -= 1
                if depth == 0:
                    close = i
                    break
        if close is None:
            continue
        parsed = destructure_macro_declaration(masked[open_paren + 1:close])
        if parsed and parsed["name"] not in _NON_SYMBOLS:
            found.setdefault(parsed["name"], parsed["return_type"])
    return found


def scan_file(path: str, text: Optional[str] = None) -> FileInfo:
    """파일의 include / 선언 심볼 / 타입 이름 추출"""
    if text is None:
        text = _read(path)
    masked = mask_source(text)

    declares = {
        name for name in DECL_RE.findall(masked) if name not in _NON_SYMBOLS
    }
    # 매크로로 선언되는 API 도 헤더 선언으로 집계
    declares |= set(macro_declared_symbols(masked))
    types = set(TYPEDEF_BLOCK_RE.findall(masked))
    types |= {n for n in TYPEDEF_ALIAS_RE.findall(masked) if n not in _NON_SYMBOLS}
    types |= set(TAG_RE.findall(masked))

    struct_types = set(STRUCT_BLOCK_RE.findall(masked))
    struct_types |= set(STRUCT_ALIAS_RE.findall(masked))
    struct_types |= set(STRUCT_TAG_RE.findall(masked))
    types |= struct_types

    return FileInfo(
        path=path,
        includes=INCLUDE_RE.findall(text),
        declares=sorted(declares),
        types=sorted(types),
        struct_types=sorted(struct_types),
    )


class KnowledgeBase:
    """A파트 통합 지식베이스"""

    def __init__(self, documents: Optional[Sequence[dict]] = None,
                 files: Optional[Dict[str, dict]] = None,
                 build_units: Optional[Sequence[dict]] = None,
                 index: Optional[BM25Index] = None,
                 use_dense: bool = False,
                 profile: Optional[dict] = None) -> None:
        self.documents: List[dict] = list(documents or [])
        self.files: Dict[str, dict] = dict(files or {})
        self.build_units: List[dict] = list(build_units or [])
        # 프로필 기반 KB 면 {name, domain, build_system, apis, apis_missing}
        # 없으면 None (기존 KB 와 같은 형태로 저장)
        self.profile: Optional[dict] = dict(profile) if profile else None
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
              use_dense: bool = False,
              bazel_graph: Optional[BazelGraph] = None,
              bazel_workspace: Optional[str] = None,
              bazel_targets: Optional[Sequence[str]] = None,
              bazel: Optional[str] = None,
              profile: Optional["TargetProfile"] = None) -> "KnowledgeBase":
        if profile is not None and not profile.is_bazel:
            return cls._build_from_profile(profile, paths=paths, use_dense=use_dense)
        if (profile is not None and bazel_graph is None
                and not (bazel_workspace or bazel_targets)):
            # Bazel 프로필은 기존 bazel query 경로 사용
            bazel_workspace = str(profile.abs(profile.build.bazel.workspace))
            bazel_targets = [profile.build.bazel.target]
        if bazel_graph is None and bazel_workspace and bazel_targets:
            bazel_graph = query_bazel(
                bazel_workspace, bazel_targets, bazel=bazel
            )
        if not paths and bazel_graph is not None:
            paths = sorted({
                path
                for target in bazel_graph.targets.values()
                for path in target.sources + target.headers
                if Path(path).exists()
            })
        if not paths:
            raise ValueError("paths must be provided")

        # Test and fuzzing harness files must not enter API groups or header
        # selection. Classify paths relative to the supplied project roots so
        # a checkout named "Fuzz" does not hide every production source.
        if bazel_graph is not None:
            test_roots = [str(Path(bazel_graph.workspace).resolve())]
        else:
            entries = [Path(entry).resolve() for entry in paths or []]
            directories = [str(entry) for entry in entries if entry.is_dir()]
            if directories:
                test_roots = directories
            elif entries:
                try:
                    common = Path(os.path.commonpath(entries))
                    test_roots = [str(common if common.is_dir() else common.parent)]
                except ValueError:  # Files on different Windows drives.
                    test_roots = [str(entry.parent) for entry in entries]
            else:
                test_roots = []
        sources: List[str] = sorted(set(iter_source_files(
            paths,
            exclude=lambda source: _is_test_path_under_roots(source, test_roots),
        )))

        file_infos: Dict[str, FileInfo] = {}
        facts: List[FunctionFacts] = []
        header_docs: Dict[str, str] = {}
        for source in sources:
            try:
                text = _read(source)
            except OSError:
                continue
            info = scan_file(source, text)
            if bazel_graph is not None:
                context = bazel_graph.compile_context(source)
                info.flags = list(context.get("compile_flags", []))
                info.directory = str(context.get("directory", ""))
                info.build_system = str(context.get("build_system", ""))
                info.build_target = str(context.get("build_target", ""))
                info.build_rule_kind = str(context.get("build_rule_kind", ""))
                info.build_deps = list(context.get("build_deps", []))
            file_infos[source] = info
            if source.endswith(HEADER_SUFFIXES):
                for name, doc in header_declaration_docs(text).items():
                    header_docs.setdefault(name, doc)
            # score::Result 계약은 S-CORE 전용: 프로필 있으면 domain 기준,
            # 없으면 Bazel 경로(=S-CORE)일 때만 활성화
            use_score = (
                score_result_enabled(profile) if profile is not None
                else bazel_graph is not None
            )
            facts.extend(extract_from_text(text, path=source, score_result=use_score))

        _merge_header_docs(facts, header_docs)
        meta = None
        if profile is not None:
            facts, meta = _select_profile_apis(facts, profile)
        documents = cls._assemble(facts, file_infos, test_roots=test_roots)
        files = {path: info.to_dict() for path, info in file_infos.items()}
        build_units = bazel_graph.build_units() if bazel_graph is not None else []
        return cls(
            documents=documents,
            files=files,
            build_units=build_units,
            use_dense=use_dense,
            profile=meta,
        )

    @classmethod
    def _build_from_profile(cls, profile: "TargetProfile",
                            paths: Optional[Sequence[str]] = None,
                            use_dense: bool = False) -> "KnowledgeBase":
        """비-Bazel(cmake/prebuilt) 프로필 기반 KB 구축

        * 파일별 플래그: compile_commands.json 항목의 clang 인자, 없으면(헤더 등)
          전체 합집합에서 ``-std`` 제외. ``include_dirs`` 항상 추가.
          compile_commands.json 부재 시 경고 후 ``include_dirs`` 만 사용
        * 빌드 단위: 라이브러리 전체 1개 (``build_target`` = ``profile.name``,
          ``build_deps`` = ``libraries`` 절대경로)
        * 대상 파일: ``paths`` 없으면 compile_db 소스 + ``include_dirs``,
          compile_db 도 없으면 ``source_root`` 전체(테스트·예제 트리 제외)
        """
        from logosfuzz.extract.compile_db import (
            CompileDbError, CompileFlags, compile_db_path, flags_for_profile,
        )

        root = profile.root
        try:
            by_file = flags_for_profile(profile)
            db_path = str(compile_db_path(profile))
        except CompileDbError as exc:
            logger.warning("compile_commands.json 없이 include_dirs 만 사용합니다: %s", exc)
            by_file, db_path = {}, ""
        merged = CompileFlags()
        for flags in by_file.values():
            merged.merge(flags)
        merged.std = ""
        include_dirs = [str(profile.abs(d)) for d in profile.build.include_dirs]
        include_args = [f"-I{d}" for d in include_dirs]

        if not paths:
            db_sources = [path for path in sorted(by_file) if os.path.exists(path)]
            if db_sources:
                paths = db_sources + [d for d in include_dirs if os.path.isdir(d)]
            else:
                # compile_db 부재 시 source_root 전체 대상
                # (테스트·예제 트리는 test_roots 기준 제외)
                paths = [str(root)]
        test_roots = [str(root)]
        sources: List[str] = sorted(set(iter_source_files(
            paths,
            exclude=lambda source: _is_test_path_under_roots(source, test_roots),
        )))

        unit_target = profile.name
        unit_deps = [str(profile.abs(lib)) for lib in profile.build.libraries]
        use_score = score_result_enabled(profile)

        file_infos: Dict[str, FileInfo] = {}
        facts: List[FunctionFacts] = []
        header_docs: Dict[str, str] = {}
        for source in sources:
            try:
                text = _read(source)
            except OSError:
                continue
            info = scan_file(source, text)
            flags = by_file.get(os.path.normpath(os.path.abspath(source)), merged).clang_args()
            flags.extend(arg for arg in include_args if arg not in flags)
            info.flags = flags
            info.directory = str(root)
            info.build_system = profile.build.system
            info.build_target = unit_target
            info.build_rule_kind = f"{profile.build.system}_library"
            info.build_deps = list(unit_deps)
            file_infos[source] = info
            if source.endswith(HEADER_SUFFIXES):
                for name, doc in header_declaration_docs(text).items():
                    header_docs.setdefault(name, doc)
            facts.extend(extract_from_text(text, path=source, score_result=use_score))

        _merge_header_docs(facts, header_docs)
        facts, meta = _select_profile_apis(facts, profile)
        documents = cls._assemble(facts, file_infos, test_roots=test_roots)
        files = {path: info.to_dict() for path, info in file_infos.items()}
        unit_flags = merged.clang_args()
        unit_flags.extend(arg for arg in include_args if arg not in unit_flags)
        build_unit = {
            "build_system": profile.build.system,
            "build_target": unit_target,
            "build_rule_kind": f"{profile.build.system}_library",
            "build_deps": unit_deps,
            "compile_flags": unit_flags,
            "include_dirs": include_dirs,
            "link_flags": list(profile.build.link_flags),
            "sources": [p for p in sources if not p.endswith(HEADER_SUFFIXES)],
            "headers": [p for p in sources if p.endswith(HEADER_SUFFIXES)],
            "visibility": [],
            "build_file": db_path,
        }
        return cls(
            documents=documents,
            files=files,
            build_units=[build_unit],
            use_dense=use_dense,
            profile=meta,
        )

    @staticmethod
    def _assemble(facts: Sequence[FunctionFacts],
                  file_infos: Dict[str, FileInfo],
                  test_roots: Optional[Sequence[str]] = None) -> List[dict]:
        """FunctionFacts 를 api_id·호출그래프·헤더 정보가 붙은 문서로 변환"""
        # api_id 는 (파일, 줄) 정렬 기준 결정적 부여 (B/D 저장 ID 재조인용)
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

        # 호출 그래프: 알려진 API 만 유지 (libc 호출 제외)
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

        # SCH-02-02 call_seq: 이 API 를 호출하는 함수들의 호출 순서 연결
        # (call_adjacency_score 가 시퀀스 내 자기 api_id 이웃을 세므로 자기 호출 목록은 부적합)
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
            # 내부 링키지 여부: 하네스에서 `static` 함수 호출 시 링크 실패
            # ("undefined reference", 자가 치유로 복구 불가)
            document["is_static"] = (
                document.get("signature", "").lstrip().startswith("static")
            )
            document["is_test"] = any(
                is_test_path(document["file"], root=root)
                for root in (test_roots or [])
            ) if test_roots else is_test_path(document["file"])
            document["called_by"] = sorted(set(callers.get(document["function"], [])))
            info = file_infos.get(document["file"])
            document["includes"] = list(info.includes) if info else []
            document["compile_flags"] = list(info.flags) if info else []
            document["build_system"] = info.build_system if info else ""
            document["build_target"] = info.build_target if info else ""
            document["build_rule_kind"] = info.build_rule_kind if info else ""
            document["build_deps"] = list(info.build_deps) if info else []
            document["header"] = _declaring_header(
                document["function"], document["file"], headers, test_roots
            )
        return documents

    # -- 조회 --------------------------------------------------------------
    def api(self, key) -> Optional[dict]:
        """api_id(int) 또는 함수 이름(str) 기준 단일 API 조회"""
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
        """SCH-02-02 의 call_seq 형식(api_id 문자열 목록)"""
        document = self.api(name)
        return list(document["call_seq_ids"]) if document else []

    def header_for(self, name: str) -> Optional[str]:
        document = self.api(name)
        return document.get("header") if document else None

    def flags_for(self, path: str) -> List[str]:
        info = self.files.get(path)
        return list(info["flags"]) if info else []

    def defines_type(self, type_name: str) -> List[str]:
        """해당 타입 이름을 정의하는 파일 목록"""
        bare = type_name.replace("struct ", "").replace("union ", "").strip()
        return sorted(
            path for path, info in self.files.items() if bare in info.get("types", [])
        )

    def defines_struct_type(self, type_name: str) -> List[str]:
        """구조체/공용체를 감싼 타입의 정의 파일 목록 (스칼라 별칭 제외)"""
        bare = type_name.replace("struct ", "").replace("union ", "").strip()
        return sorted(
            path for path, info in self.files.items()
            if bare in info.get("struct_types", [])
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
        build_systems: Dict[str, int] = {}
        for unit in self.build_units:
            system = str(unit.get("build_system", "unknown"))
            build_systems[system] = build_systems.get(system, 0) + 1
        return {
            "apis": len(self.documents),
            "files": len(self.files),
            "headers": sum(1 for p in self.files if p.endswith(HEADER_SUFFIXES)),
            "constraints": sum(by_kind.values()),
            "by_kind": dict(sorted(by_kind.items())),
            "call_edges": edges,
            "apis_with_header": with_header,
            "apis_with_compile_flags": with_flags,
            "apis_with_build_unit": sum(
                1 for document in self.documents if document.get("build_target")
            ),
            "build_units": len(self.build_units),
            "build_units_by_system": dict(sorted(build_systems.items())),
            "constraint_coverage": (
                round(covered / len(self.documents), 4) if self.documents else 0.0
            ),
            "dense_backend": self._dense_enabled,
            **({"profile": dict(self.profile)} if self.profile else {}),
        }

    # -- 저장/로드 ---------------------------------------------------------
    def save(self, path: str) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": KB_VERSION,
            "documents": self.documents,
            "files": self.files,
            "build_units": self.build_units,
            "index": self.index.to_dict(),
        }
        if self.profile:
            payload["profile"] = self.profile
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(target)

    @classmethod
    def load(cls, path: str, use_dense: bool = False) -> "KnowledgeBase":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("version") not in SUPPORTED_KB_VERSIONS:
            raise ValueError(
                f"unsupported knowledge base version: {payload.get('version')} "
                f"(expected one of {sorted(SUPPORTED_KB_VERSIONS)})"
            )
        return cls(
            documents=payload["documents"],
            files=payload.get("files", {}),
            build_units=payload.get("build_units", []),
            index=BM25Index.from_dict(payload["index"]),
            use_dense=use_dense,
            profile=payload.get("profile"),
        )


def _merge_header_docs(facts: Sequence[FunctionFacts], header_docs: Dict[str, str]) -> None:
    """헤더 선언부 문서를 구현 함수에 결합 후 제약조건 재추출"""
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


def _select_profile_apis(facts: Sequence[FunctionFacts],
                         profile: "TargetProfile") -> tuple:
    """``profile.apis`` 지정 시 해당 API 정의만 선별

    동명 정의가 여럿이면 공개 함수(non-static) 우선, 정의 없는 API 는 ``apis_missing`` 기록
    반환: (선별된 facts, KB 저장용 프로필 메타데이터)
    """
    meta = {
        "name": profile.name,
        "domain": profile.domain,
        "build_system": profile.build.system,
        "apis": list(profile.apis),
        "apis_missing": [],
    }
    if not profile.apis:
        return list(facts), meta
    wanted = set(profile.apis)
    by_name: Dict[str, List[FunctionFacts]] = {}
    for fact in facts:
        if fact.name in wanted:
            by_name.setdefault(fact.name, []).append(fact)
    selected: List[FunctionFacts] = []
    for name in profile.apis:
        candidates = by_name.get(name, [])
        public = [
            fact for fact in candidates
            if not fact.signature.lstrip().startswith("static")
        ]
        selected.extend(public or candidates)
        if not candidates:
            meta["apis_missing"].append(name)
    return selected, meta


def _declaring_header(name: str, definition_file: str,
                      headers: Dict[str, FileInfo],
                      test_roots: Sequence[str] = ()) -> Optional[str]:
    """해당 API 선언 헤더 선택

    같은 basename 헤더(foo.c <-> foo.h) 우선, 없으면 선언 헤더 중 최단 경로
    """
    candidates = [
        path for path, info in headers.items()
        if name in info.declares
        and not _is_test_path_under_roots(path, test_roots)
    ]
    if not candidates:
        # 헤더 자체에 정의된 static inline 함수면 해당 헤더 반환
        if definition_file.endswith(HEADER_SUFFIXES) and not _is_test_path_under_roots(
            definition_file, test_roots
        ):
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
    build_parser.add_argument("--output", "-o", required=True)
    build_parser.add_argument("--dense", action="store_true")
    build_parser.add_argument("--bazel-workspace")
    build_parser.add_argument("--bazel-target", action="append", default=[])
    build_parser.add_argument("--bazel", help="bazel/bazelisk executable")
    build_parser.add_argument(
        "--profile",
        help="targets/*.json 대상 프로필. bazel 이면 기존 경로, cmake/prebuilt 이면 compile_db 사용",
    )

    show_parser = subparsers.add_parser("show", help="Show a single API entry")
    show_parser.add_argument("--kb", required=True)
    show_parser.add_argument("--api", required=True, help="Function name or api_id")

    stats_parser = subparsers.add_parser("stats", help="Show knowledge base statistics")
    stats_parser.add_argument("--kb", required=True)

    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.command == "build":
        profile = None
        if args.profile:
            from logosfuzz.common.target_profile import load_profile
            profile = load_profile(args.profile)
        kb = KnowledgeBase.build(
            paths=args.paths,
            use_dense=args.dense,
            bazel_workspace=args.bazel_workspace,
            bazel_targets=args.bazel_target,
            bazel=args.bazel,
            profile=profile,
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
