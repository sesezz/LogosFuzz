"""6주차 평가: KB Coverage / API 추출 정확도 / RAG 검색 성공률

정답셋(ground truth) 경로

  A. clang 기준 대조 (기본): libclang 으로 파싱한 함수 정의 목록
  B. 라벨 파일 폴백: libclang 부재 시 수작업 라벨 JSON

A 실패 시 B 로 폴백, 사용한 경로는 ``ground_truth.source`` 에 기록

사용법
------
  python -m logosfuzz.knowledge.kb_eval run --paths examples/uds --labels examples/uds/labels.json \
      --output build/eval.json
  python -m logosfuzz.knowledge.kb_eval run --paths examples/uds --labels examples/uds/labels.json --report
  python -m logosfuzz.knowledge.kb_eval run --profile targets/libsndfile.json \
      --labels targets/labels/libsndfile.json --prefer labels --report

``--profile`` 지정 시 프로필 기반 KB 생성 및 정답셋을 ``profile.apis`` 로 제한
(미제한 시 라이브러리 내부 함수가 전부 미탐으로 집계)
"""
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from logosfuzz.extract.ast_analyzer import clang_args_for_path, qualified_name
from logosfuzz.extract.constraint_extractor import iter_source_files
from logosfuzz.knowledge.knowledge_base import KnowledgeBase
from logosfuzz.knowledge.rag_index import split_identifier

EVAL_VERSION = 1


# ---------------------------------------------------------------------------
# 정답셋
# ---------------------------------------------------------------------------


@dataclass
class GroundTruth:
    """평가 기준 함수 정의 목록"""

    source: str                       # "clang" | "labels"
    apis: Dict[str, dict] = field(default_factory=dict)
    note: str = ""

    def names(self) -> set:
        return set(self.apis)


class GroundTruthUnavailable(RuntimeError):
    pass


def clang_ground_truth(paths: Sequence[str],
                       clang_args: Optional[Sequence[str]] = None) -> GroundTruth:
    """libclang 기반 함수 '정의' 수집 (사용 불가 시 예외)"""
    try:
        from clang import cindex
    except Exception as exc:  # pragma: no cover - 바인딩 자체가 없는 환경
        raise GroundTruthUnavailable(f"clang 바인딩 없음: {exc}") from exc

    try:
        index = cindex.Index.create()
    except Exception as exc:
        raise GroundTruthUnavailable(f"libclang 바이너리 없음: {exc}") from exc

    apis: Dict[str, dict] = {}
    parsed = 0
    argument_sets: set[tuple[str, ...]] = set()

    for source in iter_source_files(paths):
        args = clang_args_for_path(source, clang_args)
        try:
            source_text = Path(source).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            source_text = ""
        try:
            unit = index.parse(source, args=args)
        except Exception:
            continue
        parsed += 1
        argument_sets.add(tuple(args))
        source_key = os.path.normcase(os.path.abspath(source))
        for cursor in unit.cursor.walk_preorder():
            if cursor.kind.name not in {
                "FUNCTION_DECL", "CXX_METHOD", "CONSTRUCTOR", "FUNCTION_TEMPLATE",
            }:
                continue
            is_definition = cursor.is_definition()
            if cursor.kind.name == "FUNCTION_TEMPLATE" and not is_definition:
                # Some libclang versions report function templates as declarations
                # even when the cursor owns the template body.  Depending on the
                # libclang build, COMPOUND_STMT may also be omitted, so inspect
                # the cursor's own token extent as the final source of truth.
                is_definition = any(
                    child.kind.name == "COMPOUND_STMT"
                    for child in cursor.get_children()
                )
                if not is_definition:
                    try:
                        is_definition = any(
                            token.spelling == "{" for token in cursor.get_tokens()
                        )
                    except Exception:
                        pass
                if not is_definition and source_text:
                    try:
                        head = source_text[:cursor.extent.end.offset].rstrip()
                        tail = source_text[cursor.extent.end.offset:].lstrip()
                        is_definition = head.endswith("{") or tail.startswith("{")
                    except Exception:
                        pass
            if not is_definition:
                continue
            location = cursor.location
            if not location.file:
                continue
            # 시스템 헤더에서 딸려온 정의 제외
            if os.path.normcase(os.path.abspath(location.file.name)) != source_key:
                continue
            name = qualified_name(cursor) or cursor.spelling
            try:
                return_type = (
                    "" if cursor.kind.name == "CONSTRUCTOR"
                    else cursor.result_type.spelling
                )
            except Exception:
                return_type = ""
            apis.setdefault(name, {
                "name": cursor.spelling,
                "qualified_name": name,
                "kind": cursor.kind.name,
                "file": source,
                "line": location.line,
                "return_type": return_type,
                "params": [a.spelling for a in cursor.get_arguments()],
            })

    if parsed == 0:
        raise GroundTruthUnavailable("clang 이 파싱한 파일이 없음")
    if not apis:
        raise GroundTruthUnavailable(
            f"clang 이 {parsed}개 파일을 파싱했지만 함수 정의를 찾지 못함 "
            f"(선언만 있는 헤더거나 소스에 정의가 없는 경우)"
        )
    rendered_args = "; ".join(" ".join(args) for args in sorted(argument_sets))
    return GroundTruth(
        source="clang",
        apis=apis,
        note=f"libclang, {parsed} files, args={rendered_args}",
    )


def nm_ground_truth(paths: Sequence[str], cc: str = "gcc",
                    cc_args: Optional[Sequence[str]] = None) -> GroundTruth:
    """소스 컴파일 후 `nm` 으로 '정의된 함수 심볼' 수집

    추출기와 독립적인 정답셋, 단 대상이 실제로 컴파일 가능해야 함
    """
    import shutil
    import subprocess
    import tempfile

    compiler = shutil.which(cc)
    reader = shutil.which("nm")
    if not compiler or not reader:
        raise GroundTruthUnavailable(f"{cc}/nm 을 찾을 수 없음")

    sources = [s for s in iter_source_files(paths) if not s.endswith(HEADER_ONLY)]
    if not sources:
        raise GroundTruthUnavailable("컴파일할 .c/.cpp 소스가 없음")

    underscore_prefixed = _toolchain_prefixes_underscore(compiler, reader)

    # 소스 디렉터리를 포함 경로로 추가 (헤더가 옆에 있는 흔한 배치)
    include_flags = [f"-I{d}" for d in sorted({os.path.dirname(s) or "." for s in sources})]
    args = list(cc_args or []) + include_flags

    apis: Dict[str, dict] = {}
    compiled = failed = 0

    with tempfile.TemporaryDirectory() as workdir:
        for index, source in enumerate(sources):
            obj = os.path.join(workdir, f"obj{index}.o")
            build = subprocess.run(
                [compiler, "-c", source, "-o", obj, *args],
                capture_output=True, text=True, errors="ignore",
            )
            if build.returncode != 0 or not os.path.exists(obj):
                failed += 1
                continue
            compiled += 1
            listing = subprocess.run(
                [reader, obj], capture_output=True, text=True, errors="ignore",
            )
            for name in _nm_defined_symbols(listing.stdout, underscore_prefixed):
                apis.setdefault(name, {"file": source, "line": 0,
                                       "return_type": "", "params": None})

    if compiled == 0:
        raise GroundTruthUnavailable(
            f"{cc} 로 컴파일된 파일이 없음 (실패 {failed}건)"
        )
    return GroundTruth(
        source="nm", apis=apis,
        note=f"{cc}+nm, 컴파일 {compiled}건" + (f", 실패 {failed}건" if failed else ""),
    )


HEADER_ONLY = (".h", ".hh", ".hpp")

_PROBE_SYMBOL = "logosfuzz_nm_probe"


def _nm_defined_symbols(listing: str, underscore_prefixed: bool) -> List[str]:
    """`nm` 출력의 '정의된 함수' 심볼 이름 추출

    밑줄 시작 이름(`_internal`)은 유지, C 심볼에 밑줄을 덧붙이는 툴체인
    (32비트 Windows, macOS)에서만 밑줄 1개 제거
    """
    names: List[str] = []
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        symbol_type, name = parts[-2], parts[-1]
        if symbol_type not in ("T", "t"):
            continue
        if name.startswith((".", "$")):        # 섹션 이름 등
            continue
        if underscore_prefixed and name.startswith("_"):
            name = name[1:]
        if name:
            names.append(name)
    return names


def _toolchain_prefixes_underscore(compiler: str, reader: str) -> bool:
    """툴체인의 C 심볼 밑줄 접두 여부 실측"""
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as workdir:
        source = os.path.join(workdir, "probe.c")
        obj = os.path.join(workdir, "probe.o")
        with open(source, "w", encoding="utf-8") as handle:
            handle.write(f"int {_PROBE_SYMBOL}(void) {{ return 0; }}\n")
        build = subprocess.run([compiler, "-c", source, "-o", obj],
                               capture_output=True, text=True, errors="ignore")
        if build.returncode != 0 or not os.path.exists(obj):
            return False
        listing = subprocess.run([reader, obj], capture_output=True, text=True,
                                 errors="ignore").stdout
        return f"_{_PROBE_SYMBOL}" in listing and _PROBE_SYMBOL not in listing.replace(
            f"_{_PROBE_SYMBOL}", ""
        )


def label_ground_truth(path: str) -> GroundTruth:
    """수작업 라벨 JSON 의 정답셋 로드

    형식: {"apis": [{"name": "uds_open", "file": "...", "return_type": "int",
                     "params": ["ctx", "path"]}, ...]}
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = payload.get("apis")
    if not isinstance(entries, list):
        raise ValueError(f"라벨 파일에 'apis' 목록이 없습니다: {path}")

    apis: Dict[str, dict] = {}
    for entry in entries:
        name = entry.get("name")
        if not name:
            continue
        apis[name] = {
            "file": entry.get("file", ""),
            "line": entry.get("line", 0),
            "return_type": entry.get("return_type", ""),
            "params": entry.get("params", []),
        }
    return GroundTruth(source="labels", apis=apis, note=os.path.basename(path))


def resolve_ground_truth(paths: Sequence[str], labels: Optional[str] = None,
                         prefer: str = "auto",
                         clang_args: Optional[Sequence[str]] = None) -> GroundTruth:
    """정답셋 결정: clang -> nm -> 라벨 파일 순 폴백

    사용 경로와 폴백 사유는 `GroundTruth.note` 에 기록
    """
    if prefer == "labels":
        if not labels:
            raise GroundTruthUnavailable("labels 경로가 필요합니다")
        return label_ground_truth(labels)
    if prefer in ("clang", "nm"):
        return (clang_ground_truth(paths, clang_args=clang_args) if prefer == "clang"
                else nm_ground_truth(paths, cc_args=clang_args))

    reasons: List[str] = []
    for provider in (
        lambda: clang_ground_truth(paths, clang_args=clang_args),
        # 프로필의 compile_db 플래그(-I 등)는 nm 경로 컴파일에도 필요
        lambda: nm_ground_truth(paths, cc_args=clang_args),
    ):
        try:
            truth = provider()
        except GroundTruthUnavailable as exc:
            reasons.append(str(exc))
            continue
        if reasons:
            truth.note = f"{truth.note} (폴백 사유: {reasons[0]})"
        return truth

    if not labels:
        raise GroundTruthUnavailable(
            "clang/nm 을 쓸 수 없고 라벨 파일도 없습니다: " + " | ".join(reasons)
        )
    truth = label_ground_truth(labels)
    truth.note = f"{truth.note} (폴백 사유: {'; '.join(reasons)})"
    return truth


# ---------------------------------------------------------------------------
# 1. API 추출 정확도
# ---------------------------------------------------------------------------


def _prf(true_positive: int, false_positive: int, false_negative: int) -> dict:
    precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) else 0.0
    recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
    }


def evaluate_extraction(kb: KnowledgeBase, truth: GroundTruth) -> dict:
    """추출 API 집합과 정답 대조 (precision/recall/F1)"""
    extracted = {d["function"] for d in kb.documents}
    expected = truth.names()

    matched = sorted(extracted & expected)
    spurious = sorted(extracted - expected)
    missed = sorted(expected - extracted)

    result = _prf(len(matched), len(spurious), len(missed))
    result["false_positive_names"] = spurious[:20]
    result["false_negative_names"] = missed[:20]

    # 이름 일치 항목에 한해 시그니처 세부 비교
    # 분모는 정답셋에 해당 정보가 있는 항목만 (nm 정답셋은 이름만 있어 제외)
    by_name = {d["function"]: d for d in kb.documents}
    param_ok = param_comparable = 0
    return_ok = return_comparable = 0
    for name in matched:
        expected_entry = truth.apis[name]
        document = by_name[name]
        if expected_entry.get("params") is not None:
            param_comparable += 1
            if len(document["params"]) == len(expected_entry["params"]):
                param_ok += 1
        expected_return = (expected_entry.get("return_type") or "").replace(" ", "")
        if expected_return:
            return_comparable += 1
            actual_return = document["return_type"].replace(" ", "")
            # 'static int' 처럼 한정자 포함 가능
            if expected_return in actual_return or actual_return.endswith(expected_return):
                return_ok += 1

    result["param_count_accuracy"] = (
        round(param_ok / param_comparable, 4) if param_comparable else None
    )
    result["return_type_accuracy"] = (
        round(return_ok / return_comparable, 4) if return_comparable else None
    )
    result["detail_comparable"] = {
        "params": param_comparable, "return_type": return_comparable,
    }
    return result


# ---------------------------------------------------------------------------
# 2. KB Coverage
# ---------------------------------------------------------------------------


def evaluate_coverage(kb: KnowledgeBase, truth: GroundTruth) -> dict:
    """지식베이스의 대상 API 포함 정도"""
    documents = kb.documents
    total = len(documents)
    expected = truth.names()
    covered = sum(1 for d in documents if d["function"] in expected)

    def ratio(count: int) -> float:
        return round(count / total, 4) if total else 0.0

    return {
        "target_apis": len(expected),
        "indexed_apis": total,
        "api_coverage": round(covered / len(expected), 4) if expected else 0.0,
        "with_constraint": ratio(sum(1 for d in documents if d["constraints"])),
        "with_doc": ratio(sum(1 for d in documents if d.get("doc"))),
        "with_header": ratio(sum(1 for d in documents if d.get("header"))),
        "with_compile_flags": ratio(sum(1 for d in documents if d.get("compile_flags"))),
        "in_call_graph": ratio(sum(
            1 for d in documents
            if d.get("calls_internal") or d.get("called_by")
        )),
        "constraints_per_api": round(
            sum(len(d["constraints"]) for d in documents) / total, 2
        ) if total else 0.0,
    }


# ---------------------------------------------------------------------------
# 3. RAG 검색 성공률
# ---------------------------------------------------------------------------


def _strip_identifier(text: str, name: str) -> str:
    """질의에서 함수 이름과 부분 토큰 제거

    이름이 남으면 검색기 성능 대신 이름 노출 여부를 측정하게 됨
    """
    tokens = {name.lower(), *split_identifier(name)}
    def replace(match: re.Match) -> str:
        return " " if match.group(0).lower() in tokens else match.group(0)
    return re.sub(r"[A-Za-z_]\w*", replace, text)


def build_auto_queries(kb: KnowledgeBase, max_queries: int = 200) -> List[dict]:
    """문서/제약조건 텍스트 기반 질의 생성 (함수 이름 제거)"""
    queries: List[dict] = []
    for document in kb.documents:
        parts: List[str] = []
        if document.get("doc"):
            parts.append(document["doc"])
        parts.extend(
            c["description"] for c in document.get("constraints", [])
            if c["kind"] in ("doc", "null_check", "buffer_size", "range_check", "resource")
        )
        if not parts:
            continue
        text = _strip_identifier(" ".join(parts), document["function"])
        if len(text.split()) < 3:
            continue
        queries.append({"query": text, "expect": document["function"]})
        if len(queries) >= max_queries:
            break
    return queries


def load_queries(path: str) -> List[dict]:
    """질의 파일 로드 (`{"queries": [...]}` 와 최상위 배열 모두 지원)"""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        entries = payload.get("queries", [])
    else:
        entries = payload
    if not isinstance(entries, list):
        raise ValueError(f"질의 파일 형식이 올바르지 않습니다: {path}")
    return [
        e for e in entries
        if isinstance(e, dict) and e.get("query") and e.get("expect")
    ]


def evaluate_retrieval(kb: KnowledgeBase, queries: Sequence[dict],
                       top_k: int = 5) -> dict:
    """recall@1 / recall@k / MRR 측정"""
    if not queries:
        return {"queries": 0, "note": "질의를 만들 수 없었습니다(문서/제약조건 부족)"}

    hit_at_1 = hit_at_k = 0
    reciprocal_total = 0.0
    misses: List[str] = []

    for entry in queries:
        hits = kb.search(entry["query"], top_k=top_k)
        names = [h["document"]["function"] for h in hits]
        expected = entry["expect"]
        if names[:1] == [expected]:
            hit_at_1 += 1
        if expected in names:
            hit_at_k += 1
            reciprocal_total += 1.0 / (names.index(expected) + 1)
        elif len(misses) < 10:
            misses.append(expected)

    total = len(queries)
    return {
        "queries": total,
        "top_k": top_k,
        "recall_at_1": round(hit_at_1 / total, 4),
        f"recall_at_{top_k}": round(hit_at_k / total, 4),
        "mrr": round(reciprocal_total / total, 4),
        "missed_examples": misses,
    }


# ---------------------------------------------------------------------------
# 통합 실행
# ---------------------------------------------------------------------------


def restrict_to_apis(truth: GroundTruth, apis: Sequence[str]) -> GroundTruth:
    """정답셋을 프로필의 대상 API 로 제한 (``apis`` 가 비면 그대로)"""
    if not apis:
        return truth
    wanted = set(apis)
    kept = {name: entry for name, entry in truth.apis.items() if name in wanted}
    note = f"{truth.note} (profile.apis {len(wanted)}개로 제한)".strip()
    return GroundTruth(source=truth.source, apis=kept, note=note)


def evaluate(paths: Sequence[str], labels: Optional[str] = None,
             queries_path: Optional[str] = None,
             prefer: str = "auto", top_k: int = 5,
             profile=None) -> dict:
    kb = KnowledgeBase.build(paths=list(paths) or None, profile=profile)
    truth_paths = list(paths)
    clang_args = None
    if profile is not None:
        unit = kb.build_units[0] if kb.build_units else {}
        if not truth_paths:
            truth_paths = list(unit.get("sources") or [str(profile.root)])
        clang_args = list(unit.get("compile_flags") or []) or None
    truth = resolve_ground_truth(truth_paths, labels=labels, prefer=prefer,
                                 clang_args=clang_args)
    if profile is not None:
        truth = restrict_to_apis(truth, profile.apis)

    queries = load_queries(queries_path) if queries_path else build_auto_queries(kb)

    return {
        "version": EVAL_VERSION,
        "target": list(paths) or ([profile.name] if profile is not None else []),
        "ground_truth": {
            "source": truth.source,
            "apis": len(truth.apis),
            "note": truth.note,
        },
        "extraction_accuracy": evaluate_extraction(kb, truth),
        "kb_coverage": evaluate_coverage(kb, truth),
        "retrieval": evaluate_retrieval(kb, queries, top_k=top_k),
        "query_source": "file" if queries_path else "auto",
    }


def render_report(result: dict) -> str:
    """사람이 읽는 요약"""
    truth = result["ground_truth"]
    accuracy = result["extraction_accuracy"]
    coverage = result["kb_coverage"]
    retrieval = result["retrieval"]
    top_k = retrieval.get("top_k", 5)

    lines = [
        "=" * 58,
        "6주차 평가 결과",
        "=" * 58,
        f"대상        : {', '.join(result['target'])}",
        f"정답셋      : {truth['source']} ({truth['apis']}개) - {truth['note']}",
        "",
        "[1] API 추출 정확도",
        f"  precision {accuracy['precision']:.3f} / recall {accuracy['recall']:.3f}"
        f" / F1 {accuracy['f1']:.3f}",
        f"  정탐 {accuracy['true_positive']} · 오탐 {accuracy['false_positive']}"
        f" · 미탐 {accuracy['false_negative']}",
    ]
    if accuracy.get("param_count_accuracy") is not None:
        lines.append(f"  인자 개수 일치율 {accuracy['param_count_accuracy']:.3f}")
    if accuracy.get("return_type_accuracy") is not None:
        lines.append(f"  반환형 일치율   {accuracy['return_type_accuracy']:.3f}")
    if accuracy["false_positive_names"]:
        lines.append(f"  오탐 예: {', '.join(accuracy['false_positive_names'][:5])}")
    if accuracy["false_negative_names"]:
        lines.append(f"  미탐 예: {', '.join(accuracy['false_negative_names'][:5])}")

    lines += [
        "",
        "[2] KB Coverage",
        f"  대상 API {coverage['target_apis']}개 중 색인 {coverage['indexed_apis']}개"
        f" (coverage {coverage['api_coverage']:.3f})",
        f"  제약조건 보유 {coverage['with_constraint']:.3f}"
        f" · 문서 보유 {coverage['with_doc']:.3f}"
        f" · 헤더 해석 {coverage['with_header']:.3f}",
        f"  호출그래프 편입 {coverage['in_call_graph']:.3f}"
        f" · API당 제약조건 {coverage['constraints_per_api']}",
        "",
        "[3] RAG 검색 성공률",
    ]
    if retrieval.get("queries"):
        lines += [
            f"  질의 {retrieval['queries']}개 ({result['query_source']})",
            f"  recall@1 {retrieval['recall_at_1']:.3f}"
            f" · recall@{top_k} {retrieval[f'recall_at_{top_k}']:.3f}"
            f" · MRR {retrieval['mrr']:.3f}",
        ]
        if retrieval.get("missed_examples"):
            lines.append(f"  실패 예: {', '.join(retrieval['missed_examples'][:5])}")
    else:
        lines.append(f"  {retrieval.get('note', '질의 없음')}")

    lines.append("=" * 58)
    return "\n".join(lines)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="KB Coverage / API 추출 정확도 / RAG 검색 성공률 평가 (6주차)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="평가 실행")
    run_parser.add_argument("--paths", nargs="*", default=[])
    run_parser.add_argument("--profile", help="targets/*.json — 프로필로 KB 를 만들고 정답을 apis 로 제한")
    run_parser.add_argument("--labels", help="clang 을 쓸 수 없을 때 사용할 라벨 JSON")
    run_parser.add_argument("--queries", help="RAG 질의 JSON (없으면 자동 생성)")
    run_parser.add_argument("--prefer", choices=["auto", "clang", "labels"],
                            default="auto")
    run_parser.add_argument("--top-k", type=int, default=5)
    run_parser.add_argument("--output", "-o", help="결과 JSON 경로")
    run_parser.add_argument("--report", action="store_true", help="요약을 사람이 읽게 출력")

    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.command != "run":
        return
    if not args.paths and not args.profile:
        raise SystemExit("--paths 또는 --profile 이 필요합니다")
    profile = None
    if args.profile:
        from logosfuzz.common.target_profile import load_profile
        profile = load_profile(args.profile)

    try:
        result = evaluate(
            args.paths, labels=args.labels,
            queries_path=args.queries, prefer=args.prefer, top_k=args.top_k,
            profile=profile,
        )
    except GroundTruthUnavailable as exc:
        raise SystemExit(
            f"정답셋을 만들 수 없습니다.\n  사유: {exc}\n\n"
            "다음 중 하나가 필요합니다:\n"
            "  1) libclang 설치 후 재시도 (가장 정확)\n"
            "  2) 컴파일 가능한 .c 소스를 대상으로 지정 (gcc+nm 사용)\n"
            "  3) --labels 로 정답 JSON 지정 "
            "(형식은 examples/uds/labels.json 참고)"
        ) from exc

    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(result, indent=2, ensure_ascii=False),
                          encoding="utf-8")

    if args.report or not args.output:
        print(render_report(result))
    if args.output:
        print(f"\nWrote {args.output}")


if __name__ == "__main__":
    main()
