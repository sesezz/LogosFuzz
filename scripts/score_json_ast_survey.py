"""`//score/json` 을 현행 `logosfuzz.extract.ast_analyzer` 로 파싱해 C++ 실패 케이스를 목록화한다.

1주차 A(추출·KB) 과제의 산출물 생성기다. 목적은 "고치는 것"이 아니라
**현행 분석기가 C++ 에서 정확히 어디서 무너지는지**를 재현 가능한 수치로
남기는 것이다. 따라서 `src.ast_analyzer.analyze_file()` 을 기본 인자 그대로
호출한다(= 파이프라인이 실제로 부르는 경로).

수집 항목:
  1. 파싱 실패 — libclang 진단(error/fatal)을 원인별로 분류
  2. 추출 실패 — 파싱은 됐는데 FUNCTION_DECL 만 보는 탓에 놓치는 C++ 엔티티
     (CXX_METHOD / FUNCTION_TEMPLATE / CLASS_TEMPLATE / NAMESPACE ...)
  3. 다운스트림 영향 — `logosfuzz.pipeline.ext_to_api_metadata` 규칙을 그대로 적용했을 때
     남는 API 개수

사용법:
  python -m scripts.score_json_ast_survey \
      --source-root third_party/score-baselibs/score/json \
      --output report/score-json-ast-survey.json \
      --markdown docs/EXT-01-01-SCORE-JSON-CPP-FAILURES.md
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logosfuzz.extract.ast_analyzer import analyze_file  # noqa: E402

try:
    from clang import cindex
    HAVE_CLANG = True
except Exception:  # pragma: no cover - libclang 없으면 진단 수집 불가
    HAVE_CLANG = False

SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".h", ".hpp")

# S-CORE 테스트 관례: *_test.cc, ut_*.cpp, ct_*.cpp
TEST_NAME_RE = re.compile(r"(^(ut|ct)_|_test$|_test_suite$|_benchmark$)")

# 진단 메시지 -> 실패 원인 분류. 위에서부터 먼저 맞는 것을 채택한다.
DIAGNOSTIC_RULES = [
    ("cxx_keyword_under_c_std", re.compile(
        r"unknown type name '(namespace|class|template|constexpr|noexcept|using)'"
        r"|expected identifier or '\('"
        r"|'namespace' does not name"
    )),
    ("missing_include", re.compile(r"'[^']+' file not found")),
    ("host_stl_rejects_c_mode", re.compile(
        r"STL1003|Unexpected compiler|Unknown standard C\+\+ library variant"
    )),
    ("cascade_from_unresolved_dep", re.compile(
        r"expected class name"
        r"|only virtual member functions can be marked"
        r"|invalid operands to binary expression"
        r"|static assertion expression is not an integral constant"
    )),
    ("cxx_template_syntax", re.compile(
        r"expected '>'|expected expression|expected unqualified-id"
        r"|expected ';' after top level declarator"
    )),
    ("unknown_type", re.compile(r"unknown type name|use of undeclared identifier|no type named")),
    ("cxx_only_construct", re.compile(
        r"expected parameter declarator|expected function body|redefinition of|expected '\)'"
    )),
]

# ast_analyzer 가 FUNCTION_DECL 로 인식하지 못해 시그니처 정보를 잃는 C++ 선언 종류
MISSED_KINDS = (
    "CXX_METHOD",
    "CONSTRUCTOR",
    "DESTRUCTOR",
    "FUNCTION_TEMPLATE",
    "CLASS_TEMPLATE",
    "CLASS_DECL",
    "STRUCT_DECL",
    "NAMESPACE",
    "CONVERSION_FUNCTION",
    "USING_DECLARATION",
    "TYPE_ALIAS_DECL",
)


def classify(message: str) -> str:
    for name, pattern in DIAGNOSTIC_RULES:
        if pattern.search(message):
            return name
    return "other"


def iter_sources(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in SOURCE_SUFFIXES:
            yield path


def is_test_source(path: Path) -> bool:
    return bool(TEST_NAME_RE.search(path.stem))


def collect_tu(path: Path, args):
    """진단 원문과 해당 파일 자체의 선언 종류를 모은다.

    `analyze_with_clang()` 은 진단을 통째로 버리고 예외만 잡아 폴백하므로,
    실패 원인을 남기려면 여기서 따로 파싱해야 한다.
    """
    if not HAVE_CLANG:
        return None
    try:
        index = cindex.Index.create()
        tu = index.parse(str(path), args=list(args))
    except Exception as exc:
        return {
            "parse_exception": f"{type(exc).__name__}: {exc}",
            "diagnostics": [],
            "own_kind_counts": {},
        }

    diagnostics = []
    for diag in tu.diagnostics:
        if diag.severity < cindex.Diagnostic.Error:
            continue
        location = ""
        try:
            if diag.location.file:
                location = f"{diag.location.file}:{diag.location.line}"
        except Exception:
            location = ""
        diagnostics.append({
            "severity": "fatal" if diag.severity >= cindex.Diagnostic.Fatal else "error",
            "message": diag.spelling,
            "location": location,
            "category": classify(diag.spelling),
        })

    target = os.path.normcase(os.path.abspath(str(path)))
    own_kinds = Counter()
    for cursor in tu.cursor.walk_preorder():
        try:
            if not cursor.location.file:
                continue
            if os.path.normcase(os.path.abspath(cursor.location.file.name)) != target:
                continue
        except Exception:
            continue
        own_kinds[cursor.kind.name] += 1

    return {
        "parse_exception": None,
        "diagnostics": diagnostics,
        "own_kind_counts": dict(own_kinds),
    }


def api_candidates(analysis: dict) -> int:
    """logosfuzz.pipeline.ext_to_api_metadata 와 동일한 규칙으로 살아남는 API 수."""
    source_file = analysis.get("file", "")
    count = 0
    for node in analysis.get("nodes", []):
        if node.get("kind") != "FUNCTION_DECL":
            continue
        location = node.get("location") or ""
        if not location or source_file not in location:
            continue
        if node.get("spelling") == "main":
            continue
        if not node.get("params"):
            continue
        if node.get("is_static"):
            continue
        count += 1
    return count


def survey_file(path: Path, source_root: Path, cxx_args) -> dict:
    rel = path.relative_to(source_root).as_posix()

    # 1) 파이프라인이 실제로 호출하는 경로 그대로
    analysis = analyze_file(str(path))
    fallback = bool(analysis.get("clang_fallback"))
    kinds = Counter(n["kind"] for n in analysis.get("nodes", []))

    own_nodes = [
        n for n in analysis.get("nodes", [])
        if (n.get("location") or "").startswith(str(path))
    ]
    own_kinds = Counter(n["kind"] for n in own_nodes)

    # 2) 기본 인자(-std=c11) 로 파싱했을 때의 진단
    default_tu = collect_tu(path, ["-std=c11"])
    # 3) C++ 로 올바르게 지시했을 때의 진단 (비교군)
    cxx_tu = collect_tu(path, cxx_args)

    def summarize(tu_info):
        if tu_info is None:
            return None
        counter = Counter(d["category"] for d in tu_info["diagnostics"])
        examples = {}
        for diag in tu_info["diagnostics"]:
            examples.setdefault(diag["category"], diag["message"])
        if tu_info["parse_exception"]:
            # TU 자체가 안 열린 경우. analyze_with_clang 은 이걸 예외로만 받아
            # 정규식 폴백으로 내려가므로, 진단 0건을 "성공"으로 세면 안 된다.
            counter["translation_unit_load_error"] += 1
            examples.setdefault("translation_unit_load_error", tu_info["parse_exception"])
        return {
            "parse_exception": tu_info["parse_exception"],
            "failed": bool(tu_info["parse_exception"]) or bool(tu_info["diagnostics"]),
            "error_count": len(tu_info["diagnostics"]),
            "by_category": dict(counter),
            "category_examples": examples,
            "first_errors": tu_info["diagnostics"][:5],
        }

    # C++ 로 제대로 파싱했을 때 이 파일에 실제로 존재하는 선언들.
    # 현행 분석기가 FUNCTION_DECL 만 보기 때문에 이 중 대부분이 버려진다.
    cxx_own_kinds = Counter((cxx_tu or {}).get("own_kind_counts", {}))

    return {
        "path": rel,
        "is_test_source": is_test_source(path),
        "suffix": path.suffix,
        "clang_fallback": fallback,
        "node_count": len(analysis.get("nodes", [])),
        "kind_counts": dict(kinds),
        "own_file_kind_counts": dict(own_kinds),
        "cxx_own_kind_counts": dict(cxx_own_kinds),
        "missed_cxx_decls": {k: cxx_own_kinds[k] for k in MISSED_KINDS if cxx_own_kinds.get(k)},
        "cxx_function_decls": cxx_own_kinds.get("FUNCTION_DECL", 0),
        "api_candidates": api_candidates(analysis),
        "default_c11": summarize(default_tu),
        "cxx17": summarize(cxx_tu),
    }


def aggregate(files: list) -> dict:
    prod = [f for f in files if not f["is_test_source"]]

    def sum_categories(key):
        counter = Counter()
        for f in files:
            diag = f.get(key)
            if diag:
                counter.update(diag["by_category"])
        return dict(counter.most_common())

    def category_detail(key):
        """분류별로 진단 건수 / 영향받은 파일 수 / 대표 메시지를 뽑는다."""
        detail = {}
        for f in files:
            diag = f.get(key)
            if not diag:
                continue
            for category, count in diag["by_category"].items():
                slot = detail.setdefault(
                    category,
                    {"diagnostics": 0, "files": 0, "example_message": "", "example_file": ""},
                )
                slot["diagnostics"] += count
                slot["files"] += 1
                if not slot["example_message"]:
                    slot["example_message"] = diag["category_examples"].get(category, "")
                    slot["example_file"] = f["path"]
        return dict(sorted(detail.items(), key=lambda kv: -kv[1]["diagnostics"]))

    failing_default = [f for f in files if (f["default_c11"] or {}).get("failed")]
    failing_cxx = [f for f in files if (f["cxx17"] or {}).get("failed")]

    missed = Counter()
    for f in files:
        missed.update(f["missed_cxx_decls"])

    return {
        "file_count": len(files),
        "production_file_count": len(prod),
        "test_file_count": len(files) - len(prod),
        "files_with_errors_default_c11": len(failing_default),
        "files_with_errors_cxx17": len(failing_cxx),
        "files_clean_default_c11": len(files) - len(failing_default),
        "error_categories_default_c11": sum_categories("default_c11"),
        "error_categories_cxx17": sum_categories("cxx17"),
        "category_detail_default_c11": category_detail("default_c11"),
        "category_detail_cxx17": category_detail("cxx17"),
        "clang_fallback_files": sum(1 for f in files if f["clang_fallback"]),
        "total_api_candidates": sum(f["api_candidates"] for f in files),
        "production_api_candidates": sum(f["api_candidates"] for f in prod),
        "cxx_function_decls": sum(f["cxx_function_decls"] for f in files),
        "missed_cxx_declarations": dict(missed.most_common()),
    }


MARKDOWN_TEMPLATE = """# EXT-01-01 — `//score/json` C++ 파싱 실패 케이스 목록

1주차 A(추출·KB) 산출물. 현행 `logosfuzz/extract/ast_analyzer.py` 를 **한 줄도 고치지 않고**
`//score/json`(eclipse-score/baselibs) 전체에 적용한 결과다.

재현:

```
python -m scripts.score_json_ast_survey \\
    --source-root {source_root} \\
    --output report/score-json-ast-survey.json \\
    --markdown docs/EXT-01-01-SCORE-JSON-CPP-FAILURES.md
```

## 0. 한 줄 결론

**대상 소스 {file_count}개 전부({files_with_errors_default_c11}/{file_count}) 실패했고,
하네스 생성에 넘길 API 후보는 {total_api_candidates}개다.** 같은 파일을 C++ 로 제대로
지시해 파싱하면 파일 자체에만 `FUNCTION_DECL` {cxx_function_decls}개 + `CXX_METHOD`
{cxx_method_count}개가 존재한다. 즉 소스가 없는 게 아니라 분석기가 못 읽는다.

- 대상 소스: **{file_count}** 개 (프로덕션 {production_file_count}, 테스트 {test_file_count})
- 기본 인자(`-std=c11`)에서 TU 로드 자체가 실패해 **정규식 폴백으로 내려간 파일: {clang_fallback_files}개**
- `ext_to_api_metadata` 까지 살아남는 **API 후보: {total_api_candidates}개**
  (프로덕션 소스 기준 {production_api_candidates}개)

## 1. 실패 케이스 카탈로그 — 현행 경로(`-std=c11`)

| # | 분류 | 진단 건수 | 영향 파일 | 대표 메시지 |
| --- | --- | --- | --- | --- |
{catalog_rows}

### 1-1. 분류별 뜻과 원인

| 분류 | 무엇이 깨지는가 | 근본 원인 |
| --- | --- | --- |
| `translation_unit_load_error` | `.cpp` 를 `-std=c11` 로 열면 libclang 이 TU 를 아예 못 만든다. `analyze_with_clang()` 은 이 예외를 잡아 정규식 폴백으로 내려가고, 폴백은 `nodes` 스키마를 만들지 않는다 → 해당 파일의 API 는 무조건 0개 | `analyze_with_clang()` 의 하드코딩된 `clang_args = ["-std=c11"]` |
| `cxx_keyword_under_c_std` | `namespace` / `class` / `template` / `constexpr` 가 타입 이름으로 오인된다 | 같음 (C 표준으로 C++ 를 파싱) |
| `host_stl_rejects_c_mode` | `.h` 는 libclang 이 C 로 간주해 파싱을 시작하지만, `<string>` 같은 C++ STL 헤더가 `STL1003: Unexpected compiler` 로 스스로 거부한다 | 같음 |
| `cxx_template_syntax` | 템플릿 인자 목록·`>` 파싱 실패로 그 뒤 선언이 통째로 유실 | 같음 |
| `missing_include` | `score/result/result.h`, `score/assert.hpp`, `nlohmann/json.hpp`, `gtest/gtest.h` 를 못 찾는다 | include 경로를 **아무도 공급하지 않는다**. Bazel 만이 정답을 안다 |
| `unknown_type` | `score::Result`, `score::cpp::*` 등 해석 실패 | `missing_include` 의 연쇄 |
| `cascade_from_unresolved_dep` | 기반 클래스가 안 풀려 `expected class name`, `only virtual member functions can be marked 'override'` 등이 연쇄 발생 | 같음 |

## 2. 추출 단계 실패 — 파싱돼도 버려지는 C++ 선언

`analyze_with_clang()` 은 `FUNCTION_DECL` 에만 `return_type`/`params`/`is_static`
을 채운다. 아래 종류는 노드로 남아도 시그니처가 비어 `logosfuzz.pipeline.ext_to_api_metadata`
의 "파라미터 없는 함수 제외" 규칙에서 전부 탈락한다.

즉 **파싱을 고쳐도 추출기를 안 고치면 여전히 0개**다.

| CursorKind | `//score/json` 내 선언 수 | 현행 처리 |
| --- | --- | --- |
{missed_rows}

## 3. 실패 파일 목록 (앞 10개 = 오류 폭발형, 뒤 10개 = TU 로드 실패형)

| 파일 | 폴백 | c11 오류 | c++17 오류 | 주요 원인 | API 후보 |
| --- | --- | --- | --- | --- | --- |
{file_rows}

전체 {file_count}개 파일의 파일별 진단은 `report/score-json-ast-survey.json` 에 있다.

## 4. 측정의 한계

- **측정 호스트는 Windows(MSVC STL)다.** 그래서 `host_stl_rejects_c_mode` 처럼
  호스트 STL 이 만든 분류가 섞여 있다. 리눅스에서는 이 건들이 `cxx_keyword_under_c_std`
  쪽으로 옮겨갈 뿐, **TU 로드 실패 {tu_error_count}건과 API 후보 0개라는 결론은 바뀌지 않는다**
  (`-std=c11` + `.cpp` 조합은 호스트와 무관하게 libclang 이 거부한다).
- **비교군(`-x c++ -std=c++17`)은 참고용이다.** Windows 호스트 STL 로 파싱했고
  `gtest`/`nlohmann`/`score_cpp` 외부 의존은 해결되지 않은 상태다. 그래서 비교군에도
  `missing_include`/`cascade_from_unresolved_dep` 가 남는다. 결론(현행 경로 전량 실패)은
  이 한계와 무관하다.
- include 경로는 사람이 손으로 추정했다(`-I<baselibs>`, `-I<baselibs>/score/language/futurecpp/include`).
  **이 추정을 없애는 것이 2주차 `extract/bazel_query.py` 의 목적**이다.
- 테스트 소스 판별은 S-CORE 관례(`ut_*`, `ct_*`, `*_test`)에 따른 이름 기반이다.

## 5. 2주차로 넘기는 요구사항

1. `analyze_with_clang()` 의 언어 판정 — 확장자·`--std` 를 인자로 받고 `.cpp/.cc/.h`
   를 C++ 로 지시한다. (`translation_unit_load_error` {tu_error_count}건 제거)
2. include 경로 수급 — `bazel query` 로 타깃의 `deps`·헤더 경로를 받아 `-I` 로 넘긴다.
   LLM 에게 추측시키지 않는다. (`missing_include` {missing_include_count}건 제거)
3. 추출 대상 확장 — `CXX_METHOD`/`CONSTRUCTOR`/`FUNCTION_TEMPLATE` 를 `FUNCTION_DECL`
   과 같은 수준으로 처리하고, 네임스페이스 한정 이름(`score::json::JsonParser::FromBuffer`)
   을 보존한다. (`logosfuzz/knowledge/kb_eval.py` 도 `FUNCTION_DECL` 만 세므로 같이 고쳐야 한다)
4. `logosfuzz/knowledge/knowledge_base.py` 스키마에 Bazel 타깃·deps 필드를 추가한다.
"""


MISSED_KIND_NOTE = {
    "CXX_METHOD": "노드만 남고 시그니처 없음 → API 후보 탈락",
    "CONSTRUCTOR": "노드만 남고 시그니처 없음 → API 후보 탈락",
    "DESTRUCTOR": "노드만 남고 시그니처 없음 → API 후보 탈락",
    "FUNCTION_TEMPLATE": "인스턴스화 대상 미결정 → 하네스 생성 불가",
    "CLASS_TEMPLATE": "타입 정보 미보존",
    "CLASS_DECL": "타입 정보 미보존 (객체 생성 시퀀스 표현 불가)",
    "STRUCT_DECL": "타입 정보 미보존",
    "NAMESPACE": "한정 이름(`score::json::...`) 유실 → extern 선언 생성 불가",
    "CONVERSION_FUNCTION": "무시됨",
    "USING_DECLARATION": "무시됨",
    "TYPE_ALIAS_DECL": "무시됨 (`score::Result` 별칭 추적 불가)",
}


def _escape_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def render_markdown(summary: dict, files: list, source_root: str) -> str:
    detail = summary["category_detail_default_c11"]
    catalog_rows = "\n".join(
        "| {i} | `{cat}` | {diags} | {nfiles} | `{msg}` |".format(
            i=i,
            cat=cat,
            diags=info["diagnostics"],
            nfiles=info["files"],
            msg=_escape_cell(info["example_message"])[:88] or "-",
        )
        for i, (cat, info) in enumerate(detail.items(), start=1)
    ) or "| - | (없음) | 0 | 0 | - |"

    missed_rows = "\n".join(
        f"| `{k}` | {v} | {MISSED_KIND_NOTE.get(k, '무시됨')} |"
        for k, v in summary["missed_cxx_declarations"].items()
    ) or "| (없음) | 0 | - |"

    # 폴백(TU 로드 실패)과 "파싱은 시작됐지만 오류 폭발" 두 유형을 각각 보여준다.
    # 전자만 나열하면 오류 건수가 전부 0 으로 찍혀 오해를 부른다.
    by_errors = sorted(
        (f for f in files if not f["clang_fallback"]),
        key=lambda f: -((f["default_c11"] or {}).get("error_count", 0)),
    )[:10]
    fallbacks = [f for f in files if f["clang_fallback"]][:10]

    def file_row(f):
        c11 = (f["default_c11"] or {})
        return "| `{path}` | {fb} | {c11} | {cxx} | `{cause}` | {api} |".format(
            path=f["path"],
            fb="예" if f["clang_fallback"] else "아니오",
            c11="TU 로드 실패" if c11.get("parse_exception") else c11.get("error_count", "-"),
            cxx=(f["cxx17"] or {}).get("error_count", "-"),
            cause=next(iter(c11.get("by_category", {})), "-"),
            api=f["api_candidates"],
        )

    file_rows = "\n".join(file_row(f) for f in by_errors + fallbacks) \
        or "| (없음) | - | - | - | - | - |"

    return MARKDOWN_TEMPLATE.format(
        source_root=source_root,
        catalog_rows=catalog_rows,
        missed_rows=missed_rows,
        file_rows=file_rows,
        cxx_method_count=summary["missed_cxx_declarations"].get("CXX_METHOD", 0),
        tu_error_count=detail.get("translation_unit_load_error", {}).get("diagnostics", 0),
        missing_include_count=detail.get("missing_include", {}).get("diagnostics", 0),
        **summary,
    )


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source-root", default="third_party/score-baselibs/score/json")
    parser.add_argument("--repo-root", default="third_party/score-baselibs",
                        help="C++ 비교군 파싱에 쓸 -I 루트")
    parser.add_argument("--include", "-I", action="append", default=[],
                        help="비교군 파싱에 추가할 include 경로 (repo-root 기준 상대경로 허용)")
    parser.add_argument("--output", "-o", help="상세 결과 JSON 경로")
    parser.add_argument("--markdown", "-m", help="요약 마크다운 경로")
    parser.add_argument("--limit", type=int, help="처음 N개 파일만 (디버그용)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    source_root = Path(args.source_root).resolve()
    repo_root = Path(args.repo_root).resolve()
    if not source_root.is_dir():
        raise SystemExit(f"source root not found: {source_root}")

    # 비교군: bazel 없이 사람이 손으로 추정한 include 경로. 외부 의존
    # (gtest / nlohmann / score_cpp)은 여기서 해결되지 않는다 — 이게 2주차
    # `bazel query` 수급이 필요한 이유 그 자체다.
    extra_includes = args.include or [
        "score/language/futurecpp/include",
    ]
    cxx_args = ["-x", "c++", "-std=c++17", f"-I{repo_root}"]
    for inc in extra_includes:
        candidate = Path(inc)
        if not candidate.is_absolute():
            candidate = repo_root / inc
        cxx_args.append(f"-I{candidate}")

    sources = list(iter_sources(source_root))
    if args.limit:
        sources = sources[: args.limit]

    files = []
    for path in sources:
        files.append(survey_file(path, source_root, cxx_args))
        print(f"  parsed {path.relative_to(source_root).as_posix()}", file=sys.stderr)

    summary = aggregate(files)
    payload = {
        "source_root": source_root.as_posix(),
        "analyzer": "logosfuzz/extract/ast_analyzer.py (unmodified)",
        "have_clang": HAVE_CLANG,
        "summary": summary,
        "files": files,
    }

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"wrote {out}")

    if args.markdown:
        md = Path(args.markdown)
        md.parent.mkdir(parents=True, exist_ok=True)
        # 재현 명령에는 저장소 기준 상대 경로를 적는다. 측정할 때 절대 경로를
        # 넘겼더라도 문서에 로컬 홈 디렉터리가 박히면 남이 그대로 못 쓴다.
        display_root = args.source_root.replace("\\", "/")
        default_root = parse_args([]).source_root
        if display_root.endswith(default_root):
            display_root = default_root
        md.write_text(
            render_markdown(summary, files, display_root), encoding="utf-8"
        )
        print(f"wrote {md}")

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return payload


if __name__ == "__main__":
    main()
