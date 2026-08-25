"""Simple AST analyzer for C/C++ files.

Usage:
  python -m src.ast_analyzer path/to/file.c --output out.json

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


def analyze_with_clang(path, clang_args=None):
    _resolve_libclang()

    if clang_args is None:
        # 시스템 include 경로를 명시하지 않으면 libclang이 size_t 같은
        # 표준 typedef를 resolve하지 못하고 int로 잘못 파싱한다.
        # clang 내장 resource dir을 찾아서 자동으로 추가한다.
        import subprocess, shutil
        clang_args = ["-std=c11"]
        clang_bin = shutil.which("clang") or "clang"
        try:
            resource_dir = subprocess.check_output(
                [clang_bin, "-print-resource-dir"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
            if resource_dir:
                clang_args += [f"-I{resource_dir}/include"]
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

    def walk(node):
        loc = None
        try:
            loc = f"{node.location.file}:{node.location.line}" if node.location.file else None
        except Exception:
            loc = None
        entry = {'kind': node.kind.name, 'spelling': node.spelling or '', 'location': loc}

        if node.kind == cindex.CursorKind.FUNCTION_DECL:
            try:
                entry['return_type'] = node.result_type.spelling
            except Exception:
                entry['return_type'] = None
            try:
                entry['params'] = [
                    {'name': a.spelling or '', 'type': a.type.spelling}
                    for a in node.get_arguments()
                ]
            except Exception:
                entry['params'] = []
            try:
                entry['is_static'] = (node.storage_class == cindex.StorageClass.STATIC)
            except Exception:
                entry['is_static'] = False
            try:
                entry['is_definition'] = node.is_definition()
            except Exception:
                entry['is_definition'] = False

        nodes.append(entry)
        for c in node.get_children():
            walk(c)

    walk(tu.cursor)
    counts = dict(Counter(n['kind'] for n in nodes))
    return {'file': path, 'counts': counts, 'nodes': nodes}


def analyze_simple(path):
    text = open(path, 'r', encoding='utf-8', errors='ignore').read()
    includes = re.findall(r'^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]', text, re.M)
    # Very naive function capture: matches 'return_type name(...) {' at line start
    funcs = re.findall(r'^[\w\s\*\&]+?\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{]*\)\s*\{', text, re.M)
    counts = {'includes': len(includes), 'functions': len(funcs)}
    return {'file': path, 'includes': includes, 'functions': list(dict.fromkeys(funcs)), 'counts': counts}


def analyze_file(path, clang_args=None):
    if HAVE_CLANG:
        return analyze_with_clang(path, clang_args=clang_args)
    else:
        return analyze_simple(path)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('paths', nargs='+', help='Files or directories to analyze')
    p.add_argument('--output', '-o', help='Output JSON file (defaults to stdout)')
    args = p.parse_args(argv)

    results = []
    for pth in args.paths:
        if os.path.isdir(pth):
            for root, _, files in os.walk(pth):
                for f in files:
                    if f.endswith(('.c', '.cpp', '.cc', '.h', '.hpp')):
                        results.append(analyze_file(os.path.join(root, f)))
        else:
            results.append(analyze_file(pth))

    out = json.dumps(results, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as fh:
            fh.write(out)
        print(f'Wrote {args.output}')
    else:
        print(out)


if __name__ == '__main__':
    main()
