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
from collections import Counter

try:
    from clang import cindex
    HAVE_CLANG = True
except Exception:
    HAVE_CLANG = False


def analyze_with_clang(path):
    index = cindex.Index.create()
    try:
        tu = index.parse(path, args=['-std=c11'])
    except Exception as e:
        return {'file': path, 'error': f'libclang parse error: {e}'}

    nodes = []

    def walk(node):
        loc = None
        try:
            loc = f"{node.location.file}:{node.location.line}" if node.location.file else None
        except Exception:
            loc = None
        nodes.append({'kind': node.kind.name, 'spelling': node.spelling or '', 'location': loc})
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


def analyze_file(path):
    if HAVE_CLANG:
        return analyze_with_clang(path)
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
