"""Bazel query adapter for build-unit and dependency metadata.

The S-CORE repositories use Bazel's strict dependency and visibility model, so
guessing include paths from the directory tree is not reliable.  This module
runs ``bazel query --output=xml`` and turns the result into a small, stable
schema that the knowledge base and BUILD-file generator can share.

Example::

    python -m logosfuzz.extract.bazel_query \
        --workspace third_party/score-baselibs \
        --target //score/json:json \
        --output build/score-json-graph.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence


_CPP_RULE_RE = re.compile(r"^(?:cc_|.*_cc_).*")
_SOURCE_SUFFIXES = {
    ".c", ".cc", ".cp", ".cpp", ".cxx", ".c++", ".s", ".S", ".asm",
}
_HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc", ".ipp", ".tpp"}
_LABEL_RE = re.compile(r"^(?:@@?[^/]+)?//[^\s]*$")


class BazelQueryError(RuntimeError):
    """Raised when Bazel cannot provide a usable dependency graph."""


@dataclass
class BazelTarget:
    """One Bazel rule represented as a build unit."""

    target: str
    rule_kind: str
    deps: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    headers: List[str] = field(default_factory=list)
    include_dirs: List[str] = field(default_factory=list)
    compile_flags: List[str] = field(default_factory=list)
    build_file: str = ""
    build_system: str = "bazel"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BazelGraph:
    """Dependency graph plus file-to-owner lookups used by the KB."""

    workspace: str
    roots: List[str]
    targets: Dict[str, BazelTarget] = field(default_factory=dict)
    build_system: str = "bazel"

    def to_dict(self) -> dict:
        return {
            "build_system": self.build_system,
            "workspace": self.workspace,
            "roots": list(self.roots),
            "targets": {
                label: target.to_dict()
                for label, target in sorted(self.targets.items())
            },
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "BazelGraph":
        raw_targets = payload.get("targets", {})
        targets = {
            str(label): BazelTarget(**dict(value))
            for label, value in dict(raw_targets).items()
        }
        return cls(
            workspace=str(payload.get("workspace", "")),
            roots=[str(value) for value in payload.get("roots", [])],
            targets=targets,
            build_system=str(payload.get("build_system", "bazel")),
        )

    def target_for_file(self, path: str) -> Optional[BazelTarget]:
        """Return the most specific rule that directly owns ``path``."""
        wanted = _normal_path(path)
        owners = [
            target for target in self.targets.values()
            if wanted in {_normal_path(p) for p in target.sources + target.headers}
        ]
        if not owners:
            return None
        # Prefer a root requested by the caller, then the rule with fewer direct
        # dependencies.  This keeps ownership deterministic when a file is shared.
        root_rank = {label: index for index, label in enumerate(self.roots)}
        return sorted(
            owners,
            key=lambda target: (
                root_rank.get(target.target, len(root_rank)),
                len(target.deps),
                target.target,
            ),
        )[0]

    def transitive_deps(self, target: str) -> List[str]:
        """Return known transitive dependencies in deterministic DFS order."""
        seen: set[str] = set()
        ordered: List[str] = []

        def visit(label: str) -> None:
            unit = self.targets.get(label)
            if unit is None:
                return
            for dep in unit.deps:
                if dep in seen:
                    continue
                seen.add(dep)
                ordered.append(dep)
                visit(dep)

        visit(target)
        return ordered

    def deps_for(self, target: str, include_self: bool = True,
                 transitive: bool = False) -> List[str]:
        """Return BUILD-rule deps for GEN's ``BazelQueryDepsProvider``.

        A generated fuzz rule must depend on the target under test itself.  Its
        direct deps are included as well because S-CORE's strict include checks
        require directly included public-header targets to be declared.
        """
        unit = self.targets.get(target)
        if unit is None:
            normalized = normalize_label(target)
            unit = next(
                (
                    candidate for label, candidate in self.targets.items()
                    if normalize_label(label) == normalized
                ),
                None,
            )
        deps = (
            self.transitive_deps(unit.target) if transitive and unit is not None
            else list(unit.deps) if unit is not None
            else []
        )
        return _unique(([target] if include_self else []) + deps)

    def compile_context(self, path: str) -> dict:
        """Return Bazel ownership, deps, include dirs and flags for one file."""
        owner = self.target_for_file(path)
        if owner is None:
            return {}

        closure = [owner]
        closure.extend(
            self.targets[label]
            for label in self.transitive_deps(owner.target)
            if label in self.targets
        )
        include_dirs = _unique(
            directory for unit in closure for directory in unit.include_dirs
        )
        flags = _unique(flag for unit in closure for flag in unit.compile_flags)
        for directory in include_dirs:
            include_flag = f"-I{directory}"
            if include_flag not in flags:
                flags.append(include_flag)
        return {
            "build_system": self.build_system,
            "build_target": owner.target,
            "build_rule_kind": owner.rule_kind,
            "build_deps": list(owner.deps),
            "include_dirs": include_dirs,
            "compile_flags": flags,
            "directory": self.workspace,
        }

    def build_units(self) -> List[dict]:
        return [
            target.to_dict()
            for _, target in sorted(self.targets.items())
        ]


def _normal_path(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _unique(values: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(value for value in values if value))


def _package_of(label: str) -> str:
    local = label.split("//", 1)[-1]
    package = local.split(":", 1)[0]
    return package.strip("/")


def normalize_label(label: str) -> str:
    """Expand a shorthand package label (``//a/b`` -> ``//a/b:b``)."""
    value = label.strip()
    if not _LABEL_RE.match(value) or ":" in value.split("//", 1)[-1]:
        return value
    prefix, package = value.split("//", 1)
    target = package.rsplit("/", 1)[-1] if package else ""
    return f"{prefix}//{package}:{target}"


def label_to_path(label: str, workspace: str, package: str = "") -> Optional[str]:
    """Map a workspace file label to an absolute path.

    External-repository and generated labels deliberately return ``None``: a
    source checkout does not have a stable local path for them.
    """
    if not label or label.startswith("@"):
        return None
    if label.startswith(":"):
        relative = f"{package}/{label[1:]}" if package else label[1:]
    elif label.startswith("//"):
        body = label[2:]
        if ":" in body:
            pkg, name = body.split(":", 1)
            relative = f"{pkg}/{name}" if pkg else name
        else:
            relative = body
    else:
        return None
    return str((Path(workspace) / Path(relative)).resolve())


def _attribute_values(rule: ET.Element, name: str) -> List[str]:
    """Read scalar/list/select values from a Bazel XML rule attribute."""
    values: List[str] = []
    for element in rule.iter():
        if element is rule or element.get("name") != name:
            continue
        if element.get("value"):
            values.append(str(element.get("value")))
        for child in element.iter():
            if child is element:
                continue
            value = child.get("value")
            if value:
                values.append(str(value))
    return _unique(values)


def _paths_from_labels(labels: Iterable[str], workspace: str,
                       package: str, suffixes: set[str]) -> List[str]:
    paths: List[str] = []
    for label in labels:
        path = label_to_path(label, workspace, package=package)
        if path and Path(path).suffix in suffixes:
            paths.append(path)
    return _unique(paths)


def parse_query_xml(xml_text: str, workspace: str,
                    roots: Optional[Sequence[str]] = None) -> BazelGraph:
    """Parse ``bazel query --output=xml`` into :class:`BazelGraph`."""
    workspace_path = str(Path(workspace).resolve())
    try:
        query = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise BazelQueryError(f"invalid Bazel query XML: {exc}") from exc

    targets: Dict[str, BazelTarget] = {}
    for rule in query.findall(".//rule"):
        label = rule.get("name", "")
        rule_kind = rule.get("class", "")
        if not label or not rule_kind or not _CPP_RULE_RE.match(rule_kind):
            continue
        package = _package_of(label)
        source_labels = _attribute_values(rule, "srcs")
        header_labels = (
            _attribute_values(rule, "hdrs")
            + _attribute_values(rule, "textual_hdrs")
        )
        deps = [
            value for value in _attribute_values(rule, "deps")
            if _LABEL_RE.match(value)
        ]

        package_dir = str((Path(workspace_path) / package).resolve())
        include_dirs = [workspace_path, package_dir]
        for value in _attribute_values(rule, "includes"):
            include_path = Path(value)
            if not include_path.is_absolute():
                include_path = Path(package_dir) / include_path
            include_dirs.append(str(include_path.resolve()))

        compile_flags = list(_attribute_values(rule, "copts"))
        compile_flags.extend(
            f"-D{value}" for value in _attribute_values(rule, "defines")
        )
        compile_flags.extend(
            f"-D{value}" for value in _attribute_values(rule, "local_defines")
        )

        location = re.sub(r":\d+(?::\d+)?$", "", rule.get("location", ""))
        targets[label] = BazelTarget(
            target=label,
            rule_kind=rule_kind,
            deps=_unique(deps),
            sources=_paths_from_labels(
                source_labels, workspace_path, package, _SOURCE_SUFFIXES
            ),
            headers=_paths_from_labels(
                header_labels, workspace_path, package, _HEADER_SUFFIXES
            ),
            include_dirs=_unique(include_dirs),
            compile_flags=_unique(compile_flags),
            build_file=location,
        )

    if not targets:
        raise BazelQueryError("Bazel query returned no C/C++ build rules")
    return BazelGraph(
        workspace=workspace_path,
        roots=list(roots or []),
        targets=targets,
    )


def _bazel_binary(explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    return shutil.which("bazelisk") or shutil.which("bazel") or "bazel"


def _query_expression(targets: Sequence[str]) -> str:
    if not targets:
        raise ValueError("at least one Bazel target is required")
    invalid = [target for target in targets if not _LABEL_RE.match(target)]
    if invalid:
        raise ValueError(f"invalid Bazel target label: {invalid[0]}")
    return f"deps(set({' '.join(targets)}))"


def query_bazel(workspace: str, targets: Sequence[str], bazel: Optional[str] = None,
                runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                timeout: int = 120) -> BazelGraph:
    """Run Bazel once and return the complete C/C++ dependency graph."""
    workspace_path = str(Path(workspace).resolve())
    command = [
        _bazel_binary(bazel),
        "query",
        "--output=xml",
        "--noshow_progress",
        _query_expression(targets),
    ]
    try:
        completed = runner(
            command,
            cwd=workspace_path,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BazelQueryError(f"failed to execute {' '.join(command)}: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unknown error").strip()
        raise BazelQueryError(
            f"bazel query failed with exit code {completed.returncode}: {detail}"
        )
    return parse_query_xml(completed.stdout, workspace_path, roots=targets)


def deps_of(target_label: str, workspace: str = ".", bazel: Optional[str] = None,
            transitive: bool = False,
            runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> List[str]:
    """Compatibility callable for GEN's ``BazelQueryDepsProvider``.

    Use ``functools.partial(deps_of, workspace=...)`` when the Bazel workspace
    is not the current directory.
    """
    graph = query_bazel(workspace, [target_label], bazel=bazel, runner=runner)
    return graph.deps_for(target_label, transitive=transitive)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Export Bazel C/C++ dependency graph")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--target", action="append", dest="targets", required=True)
    parser.add_argument("--bazel", help="bazel/bazelisk executable")
    parser.add_argument("--output", "-o")
    return parser.parse_args(argv)


def main(argv=None) -> None:
    args = parse_args(argv)
    graph = query_bazel(args.workspace, args.targets, bazel=args.bazel)
    output = json.dumps(graph.to_dict(), ensure_ascii=False, indent=2)
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(output, encoding="utf-8")
        print(f"Wrote {target}")
    else:
        print(output)


if __name__ == "__main__":
    main()
