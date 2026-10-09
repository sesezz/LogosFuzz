"""Simple AST analyzer for C/C++ files.

Usage:
  python -m logosfuzz.extract.ast_analyzer path/to/file.c --output out.json
  python -m logosfuzz.extract.ast_analyzer --profile targets/libsndfile.json --output out.json

``--profile`` 이 비-Bazel(cmake/prebuilt) 대상이면 compile_commands.json 의
-I/-isystem/-D/-std 를 clang 인자로 쓰고(:mod:`logosfuzz.extract.compile_db`),
Bazel 대상이면 기존처럼 ``bazel query`` 그래프를 쓴다. 프로필이 없으면 기존 동작 그대로.

This script will use clang Python bindings if available; otherwise falls back to a
lightweight regex-based extractor (includes, simple function names).
"""
import os
import sys
import json
import re
import argparse
import logging
from collections import Counter

logger = logging.getLogger(__name__)

CXX_SUFFIXES = {".cc", ".cp", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx"}
C_HEADER_SUFFIXES = {".h"}
ANALYZABLE_SUFFIXES = CXX_SUFFIXES | C_HEADER_SUFFIXES | {".c"}

try:
    from clang import cindex
    HAVE_CLANG = True
except Exception:
    HAVE_CLANG = False

_libclang_resolved = False


def _resolve_libclang():
    """기본 탐색이 실패할 때만 pip ``libclang`` 패키지에 동봉된 라이브러리를 등록한다.

    Windows에서는 동봉된 ``clang/native/libclang.dll``을 cindex가 자동으로
    찾지 못해, 원인 없이 정규식 폴백에 빠진다(=다운스트림 API 0개).
    기본 탐색이 되는 환경(주로 Linux)의 동작까지 바꾸지 않기 위해
    먼저 그대로 시도해보고, 실패한 경우에만 동봉 라이브러리를 지정한다.
    """
    global _libclang_resolved
    if _libclang_resolved or cindex.Config.loaded:
        return
    _libclang_resolved = True

    try:
        cindex.Index.create()
        return  # 기본 탐색 성공 - 건드리지 않는다
    except Exception:
        pass

    try:
        import clang.native
        native_dir = os.path.dirname(clang.native.__file__)
        for lib_name in ("libclang.dll", "libclang.so", "libclang.dylib"):
            candidate = os.path.join(native_dir, lib_name)
            if os.path.exists(candidate):
                cindex.Config.set_library_file(candidate)
                return
    except Exception:
        pass


def clang_args_for_path(path, clang_args=None, language=None):
    """Return language-correct clang arguments for a source/header path.

    S-CORE headers are C++ headers even when they use the conventional ``.h``
    suffix.  An explicit ``-x`` or ``-std`` supplied by the caller always wins;
    otherwise we add a safe project default.

    ``language`` 는 프로필의 ``language``(``"c"``/``"cpp"``)다. ``"c"`` 이면 ``.h`` 를
    C 헤더로 파싱한다(libsndfile 같은 C 라이브러리). ``None`` 이면 기존 동작.
    """
    args = list(clang_args or [])
    suffix = os.path.splitext(str(path))[1].lower()
    if language == "c":
        is_cxx = suffix in CXX_SUFFIXES
    else:
        is_cxx = suffix in CXX_SUFFIXES or suffix in C_HEADER_SUFFIXES

    has_language = any(
        arg == "-x" or str(arg).startswith("-x") for arg in args
    )
    has_standard = any(str(arg).startswith("-std=") for arg in args)
    defaults = []
    if not has_language:
        defaults.extend(["-x", "c++" if is_cxx else "c"])
    if not has_standard:
        defaults.append("-std=c++17" if is_cxx else "-std=c11")
    return defaults + args


def qualified_name(cursor):
    """Build a namespace/class-qualified spelling for a clang cursor."""
    parts = []
    current = cursor
    scope_kinds = {
        "NAMESPACE", "CLASS_DECL", "CLASS_TEMPLATE", "STRUCT_DECL",
        "UNION_DECL", "ENUM_DECL", "FUNCTION_DECL", "FUNCTION_TEMPLATE",
        "CXX_METHOD", "CONSTRUCTOR", "DESTRUCTOR", "CONVERSION_FUNCTION",
    }
    if getattr(getattr(cursor, "kind", None), "name", "") not in scope_kinds:
        return ""
    while current is not None:
        kind = getattr(getattr(current, "kind", None), "name", "")
        spelling = getattr(current, "spelling", "") or ""
        if spelling and kind in scope_kinds:
            parts.append(spelling)
        current = getattr(current, "semantic_parent", None)
        if getattr(getattr(current, "kind", None), "name", "") == "TRANSLATION_UNIT":
            break
    return "::".join(reversed(parts))


def _is_callable_cursor(node):
    return node.kind.name in {
        "FUNCTION_DECL", "CXX_METHOD", "CONSTRUCTOR", "FUNCTION_TEMPLATE",
    }


def analyze_with_clang(path, clang_args=None, language=None):
    _resolve_libclang()

    clang_args = clang_args_for_path(path, clang_args, language=language)

    # clang 내장 resource dir(stddef.h 등)은 호출자가 clang_args를 넘겼든
    # 아니든 항상 붙여야 한다. 이게 빠지면 libclang이 size_t 같은 표준
    # typedef를 resolve하지 못하고 `int`로 잘못 보고한다.
    #   실제: dlt_message_header(..., size_t textlength, ...)
    #   오인: dlt_message_header(..., int    textlength, ...)
    # 그 시그니처로 하네스가 extern 선언을 만들면 헤더와 conflicting types로
    # 컴파일이 깨진다(dlt-daemon에서 10건 중 8건이 이 원인이었다).
    if not any(str(a).startswith("-resource-dir") for a in clang_args):
        import subprocess, shutil
        clang_bin = shutil.which("clang") or "clang"
        try:
            resource_dir = subprocess.check_output(
                [clang_bin, "-print-resource-dir"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
            if resource_dir:
                inc = f"-I{resource_dir}/include"
                if inc not in clang_args:
                    clang_args = list(clang_args) + [inc]
        except Exception:
            pass

    try:
        index = cindex.Index.create()
        tu = index.parse(path, args=clang_args)
    except Exception as e:
        logger.warning(
            "libclang을 사용할 수 없어 정규식 폴백으로 전환합니다 (%s: %s). "
            "이 폴백은 'nodes'/'FUNCTION_DECL' 스키마를 만들지 않으므로 "
            "다운스트림(ext_to_api_metadata)이 API를 0개로 인식할 수 있습니다. "
            "`pip install libclang`으로 해결 가능합니다.",
            type(e).__name__, e,
        )
        result = analyze_simple(path)
        result["clang_fallback"] = True
        return result

    nodes = []
    try:
        source_text = open(path, 'r', encoding='utf-8', errors='ignore').read()
    except OSError:
        source_text = ""

    def is_definition(node):
        try:
            defined = bool(node.is_definition())
        except Exception:
            defined = False
        if defined or node.kind.name != "FUNCTION_TEMPLATE":
            return defined
        if any(child.kind.name == "COMPOUND_STMT" for child in node.get_children()):
            return True
        try:
            if any(token.spelling == "{" for token in node.get_tokens()):
                return True
        except Exception:
            pass
        if source_text:
            try:
                head = source_text[:node.extent.end.offset].rstrip()
                tail = source_text[node.extent.end.offset:].lstrip()
                return head.endswith("{") or tail.startswith("{")
            except Exception:
                pass
        return False

    def walk(node):
        loc = None
        try:
            loc = f"{node.location.file}:{node.location.line}" if node.location.file else None
        except Exception:
            loc = None
        entry = {'kind': node.kind.name, 'spelling': node.spelling or '', 'location': loc}

        qname = qualified_name(node)
        if qname:
            entry['qualified_name'] = qname

        if node.kind.name in {"NAMESPACE", "CLASS_DECL", "CLASS_TEMPLATE", "STRUCT_DECL"}:
            entry['scope_kind'] = node.kind.name

        if _is_callable_cursor(node):
            try:
                entry['return_type'] = (
                    None if node.kind.name == "CONSTRUCTOR"
                    else node.result_type.spelling
                )
            except Exception:
                entry['return_type'] = None
            try:
                entry['params'] = [
                    {'name': a.spelling or '', 'type': a.type.spelling}
                    for a in node.get_arguments()
                ]
            except Exception:
                entry['params'] = []
            # 가변인자(`...`)는 get_arguments()에 나오지 않는다. 표시하지 않으면
            # 하네스가 `f(char *a, char *b)`로 extern 선언을 만들어 헤더의
            # `f(char *a, char *b, ...)`와 conflicting types가 된다
            # (dlt-daemon의 dlt_execute_command에서 실제 발생).
            try:
                entry['is_variadic'] = bool(node.type.is_function_variadic())
            except Exception:
                entry['is_variadic'] = False
            try:
                entry['is_static'] = (node.storage_class == cindex.StorageClass.STATIC)
            except Exception:
                entry['is_static'] = False
            entry['is_definition'] = is_definition(node)
            entry['callable_kind'] = node.kind.name
            entry['is_method'] = node.kind.name in {"CXX_METHOD", "CONSTRUCTOR"}
            entry['is_template'] = node.kind.name == "FUNCTION_TEMPLATE"
            entry['template_parameters'] = [
                child.spelling or ""
                for child in node.get_children()
                if child.kind.name in {
                    "TEMPLATE_TYPE_PARAMETER",
                    "TEMPLATE_NON_TYPE_PARAMETER",
                    "TEMPLATE_TEMPLATE_PARAMETER",
                }
            ]
            parent = getattr(node, "semantic_parent", None)
            if parent is not None and parent.kind.name in {
                "CLASS_DECL", "CLASS_TEMPLATE", "STRUCT_DECL",
            }:
                entry['class_name'] = qualified_name(parent)
                entry['is_method'] = True

        nodes.append(entry)
        for c in node.get_children():
            walk(c)

    walk(tu.cursor)
    counts = dict(Counter(n['kind'] for n in nodes))
    diagnostics = [
        {
            'severity': int(diagnostic.severity),
            'spelling': diagnostic.spelling,
            'location': str(diagnostic.location),
        }
        for diagnostic in tu.diagnostics
    ]
    return {
        'file': path,
        'clang_args': list(clang_args),
        'counts': counts,
        'nodes': nodes,
        'diagnostics': diagnostics,
    }


def analyze_simple(path):
    text = open(path, 'r', encoding='utf-8', errors='ignore').read()
    includes = re.findall(r'^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]', text, re.M)
    # Very naive function capture: matches 'return_type name(...) {' at line start
    funcs = re.findall(r'^[\w\s\*\&]+?\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{]*\)\s*\{', text, re.M)
    counts = {'includes': len(includes), 'functions': len(funcs)}
    return {'file': path, 'includes': includes, 'functions': list(dict.fromkeys(funcs)), 'counts': counts}


def analyze_file(path, clang_args=None, language=None):
    if HAVE_CLANG:
        return analyze_with_clang(path, clang_args=clang_args, language=language)
    else:
        return analyze_simple(path)


def _analysis_files(paths):
    files = []
    for path in paths or []:
        if os.path.isdir(path):
            for root, _, names in os.walk(path):
                files.extend(
                    os.path.join(root, name)
                    for name in names
                    if os.path.splitext(name)[1].lower() in ANALYZABLE_SUFFIXES
                )
        elif os.path.splitext(path)[1].lower() in ANALYZABLE_SUFFIXES:
            files.append(path)
    return sorted(dict.fromkeys(files))


class ProfileCompileContext:
    """비-Bazel 프로필의 파일별 clang 인자 공급자.

    compile_commands.json 에 항목이 있는 소스는 그 파일의 플래그를 쓰고,
    항목이 없는 파일(주로 헤더)은 전체 합집합을 쓰되 ``-std`` 는 빼서 파일
    언어 기본값을 따르게 한다(C 프로젝트의 -std=gnu99 가 .hpp 에 붙지 않도록).
    프로필의 ``build.include_dirs`` 는 항상 뒤에 붙인다. compile_commands.json 이
    아직 없으면(configure 전) 경고만 남기고 include_dirs 만으로 진행한다.
    """

    def __init__(self, profile):
        from logosfuzz.extract.compile_db import (
            CompileDbError, CompileFlags, flags_for_profile,
        )

        self.profile = profile
        try:
            self.by_file = flags_for_profile(profile)
        except CompileDbError as exc:
            logger.warning("compile_commands.json 없이 include_dirs 만 사용합니다: %s", exc)
            self.by_file = {}
        merged = CompileFlags()
        for flags in self.by_file.values():
            merged.merge(flags)
        merged.std = ""
        self.merged = merged
        self.include_args = [f"-I{profile.abs(d)}" for d in profile.build.include_dirs]

    def files(self):
        """프로필만 주어졌을 때의 분석 후보: compile_db 소스 + include_dirs."""
        candidates = [path for path in self.by_file if os.path.exists(path)]
        candidates.extend(
            str(self.profile.abs(d)) for d in self.profile.build.include_dirs
            if os.path.isdir(self.profile.abs(d))
        )
        return candidates

    def clang_args(self, path):
        flags = self.by_file.get(os.path.normpath(os.path.abspath(path)), self.merged)
        args = flags.clang_args()
        args.extend(a for a in self.include_args if a not in args)
        return args


def analyze_paths(paths, clang_args=None, bazel_graph=None, profile=None):
    """Analyze paths, applying Bazel compile context when it is available.

    ``profile`` 이 비-Bazel 대상이면 compile_db 플래그를 파일별로 덧붙인다.
    Bazel 프로필은 ``bazel_graph`` 경로를 그대로 쓰므로 언어 정보만 반영된다.
    """
    language = profile.language if profile is not None else None
    profile_ctx = None
    if profile is not None and not profile.is_bazel:
        profile_ctx = ProfileCompileContext(profile)

    candidates = list(paths or [])
    if bazel_graph is not None:
        candidates.extend(
            path
            for target in bazel_graph.targets.values()
            for path in target.sources + target.headers
            if os.path.exists(path)
        )
    if profile_ctx is not None and not candidates:
        candidates = profile_ctx.files()

    results = []
    for path in _analysis_files(candidates):
        context = bazel_graph.compile_context(path) if bazel_graph is not None else {}
        combined_args = list(clang_args or [])
        combined_args.extend(
            flag for flag in context.get("compile_flags", [])
            if flag not in combined_args
        )
        if profile_ctx is not None:
            combined_args.extend(
                flag for flag in profile_ctx.clang_args(path)
                if flag not in combined_args
            )
        if language is None:
            result = analyze_file(path, clang_args=combined_args)
        else:
            result = analyze_file(path, clang_args=combined_args, language=language)
        if context:
            result["build_system"] = context["build_system"]
            result["build_target"] = context["build_target"]
            result["build_deps"] = context["build_deps"]
        results.append(result)
    return results


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('paths', nargs='*', help='Files or directories to analyze')
    p.add_argument('--output', '-o', help='Output JSON file (defaults to stdout)')
    p.add_argument('--clang-arg', action='append', default=[],
                   help='Additional clang argument (repeatable)')
    p.add_argument('--bazel-workspace')
    p.add_argument('--bazel-target', action='append', default=[])
    p.add_argument('--bazel', help='bazel/bazelisk executable')
    p.add_argument('--profile', help='targets/*.json 대상 프로필')
    args = p.parse_args(argv)

    profile = None
    if args.profile:
        from logosfuzz.common.target_profile import load_profile
        profile = load_profile(args.profile)

    bazel_graph = None
    if profile is not None and profile.is_bazel and not (args.bazel_workspace or args.bazel_target):
        # 자동차(Bazel) 프로필은 기존 bazel query 경로로 보낸다.
        args.bazel_workspace = str(profile.abs(profile.build.bazel.workspace))
        args.bazel_target = [profile.build.bazel.target]
    if args.bazel_workspace or args.bazel_target:
        if not (args.bazel_workspace and args.bazel_target):
            p.error('--bazel-workspace and --bazel-target must be used together')
        from logosfuzz.extract.bazel_query import query_bazel
        bazel_graph = query_bazel(
            args.bazel_workspace, args.bazel_target, bazel=args.bazel
        )
    if not args.paths and bazel_graph is None and profile is None:
        p.error('provide paths, a Bazel workspace/target, or --profile')

    results = analyze_paths(
        args.paths,
        clang_args=args.clang_arg,
        bazel_graph=bazel_graph,
        profile=profile,
    )

    out = json.dumps(results, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as fh:
            fh.write(out)
        print(f'Wrote {args.output}')
    else:
        print(out)


if __name__ == '__main__':
    main()
