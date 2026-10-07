"""
GEN-03-01 : 하네스 산출물을 ``.cc`` + BUILD 룰 **쌍**으로 만든다 (3주차, B 송서원)
=================================================================================

2주차까지 GEN-03-01 의 산출물은 "하네스 소스 텍스트" 하나였다. S-CORE 처럼
Bazel 이 빌드를 소유하는 대상에서는 소스만으로는 아무것도 못 한다 — 그 소스를
어떤 deps 로, 어느 패키지에서, 어떤 룰로 빌드할지가 함께 있어야 퍼저 바이너리가
나온다. 그래서 산출물 단위를 ``HarnessPair`` 로 바꾼다.

    HarnessPair = <group>_fuzz.cc  +  BUILD.bazel(cc_fuzz_test 1개)

배치 규칙
---------
Logic Group 하나당 패키지 하나. 빌드 단위(대상 라벨)의 ``fuzz/`` 아래 그룹
이름으로 하위 패키지를 판다.

    대상 //score/json:json, 그룹 lg_json_parser
      -> score/json/fuzz/lg_json_parser/lg_json_parser_fuzz.cc
      -> score/json/fuzz/lg_json_parser/BUILD.bazel
           cc_fuzz_test(name = "lg_json_parser_fuzz_test", ...)

- 대상의 **하위** 패키지여야 ``__subpackages__`` 가시성 헤더를 직접 의존할 수
  있다(1주차 실측, ``bazel/build_file.fuzz_package_for`` 주석 참고). 하위의
  하위도 ``__subpackages__`` 에 포함된다.
- 그룹마다 패키지를 나누면 BUILD 파일 하나에 룰 하나라서, 2주차 어댑터·자가치유
  (``BazelAdapter.emit_build_definition`` 이 BUILD 를 통째로 쓴다)를 그대로 쓴다.
  한 패키지에 여러 그룹을 몰면 그룹 B 를 쓰는 순간 그룹 A 의 룰이 지워진다.

흐름
----
    KB ─ logic_groups(빌드 단위 경계, A 3주차) ─ SCH-02-02/03 스케줄
       └ llm_harness_generator(C++/FuzzedDataProvider 프롬프트)
            └ pair_drivers() ─ HarnessPair 목록
                 └ write_pairs(out_root)  -> <package>/{*.cc,BUILD.bazel} + harness_pairs.json
                 └ ctr_06_01_controller 의 BUILD 단계가 manifest 를 읽어 빌드·자가치유

사용
----
    # LLM 없이 1주차 참조 하네스로 쌍 1개를 만들어 본다
    python -m logosfuzz.generate.gen_03_01_harness_generator --demo --out out/pairs

    # KB 에서 그룹을 뽑아 LLM 으로 생성 (OPENAI_API_KEY 필요)
    python -m logosfuzz.generate.gen_03_01_harness_generator \\
        --kb build/score-kb.json --workspace ~/baselibs --out out/pairs --top 3
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from logosfuzz.generate.bazel.build_file import (
    FuzzTargetSpec,
    fuzz_package_for,
    parse_label,
    render_build_file,
)
from logosfuzz.generate.bazel.deps_provider import (
    DepsProvider,
    StaticDepsProvider,
    VERIFIED_SCORE_JSON_DEPS,
)
from logosfuzz.generate.llm_harness_generator import (
    LANG_CPP,
    REFERENCE_HARNESS_PATH,
    ApiContext,
    FuzzDriver,
    generate_harness,
    normalize_cpp_harness,
)

MANIFEST_NAME = "harness_pairs.json"
MANIFEST_SCHEMA_VERSION = "1.0"
BUILD_FILE_NAME = "BUILD.bazel"

# KB 컨텍스트를 프롬프트에 넣을 때 그룹당 API 상한. 32개(logic_groups 상한)를
# 다 넣으면 프롬프트가 max_tokens 보다 커진다.
MAX_CONTEXT_APIS = 8
# 프롬프트에 넣는 선언 발췌: API 하나당 / 그룹 전체 상한(문자 수).
MAX_EXCERPT_CHARS = 900
MAX_HEADER_CONTENT_CHARS = 6000


# ---------------------------------------------------------------------
# 1. 산출물 모델
# ---------------------------------------------------------------------

def group_slug(name: str) -> str:
    """그룹 이름을 Bazel 패키지·타깃 이름으로 쓸 수 있게 만든다.

    Bazel 타깃 이름은 대부분의 문자를 허용하지만 패키지 경로와 C++ 파일 이름을
    겸하므로 ``[a-z0-9_]`` 로 좁힌다. 숫자로 시작하면 앞에 ``g_`` 를 붙인다.
    """
    slug = re.sub(r"[^a-z0-9_]+", "_", name.strip().lower()).strip("_")
    if not slug:
        slug = "group"
    if slug[0].isdigit():
        slug = f"g_{slug}"
    return slug


@dataclass
class HarnessPair:
    """하네스 소스 1개 + 그것을 빌드하는 cc_fuzz_test 룰 1개."""

    group_name: str
    target_label: str          # 퍼징 대상 빌드 단위 (예: //score/json:json)
    spec: FuzzTargetSpec
    source: str
    language: str = LANG_CPP
    prompt_used: str = ""

    @property
    def source_filename(self) -> str:
        return self.spec.srcs[0]

    @property
    def source_relpath(self) -> str:
        """워크스페이스(또는 out_root) 기준 하네스 경로."""
        return f"{self.spec.package}/{self.source_filename}"

    @property
    def build_relpath(self) -> str:
        return f"{self.spec.package}/{BUILD_FILE_NAME}"

    @property
    def build_file(self) -> str:
        return render_build_file(self.spec)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group": self.group_name,
            "build_target": self.target_label,
            "build_system": "bazel",
            "language": self.language,
            "package": self.spec.package,
            "name": self.spec.name,
            "fuzz_target": self.spec.label,
            "bin_target": self.spec.bin_label,
            "source": self.source_relpath,
            "build_file": self.build_relpath,
            "srcs": list(self.spec.srcs),
            "deps": list(self.spec.deps),
            "tags": list(self.spec.tags),
            "notes": list(self.spec.notes),
        }


def make_pair_spec(
    group_name: str,
    target_label: str,
    deps_provider: Optional[DepsProvider] = None,
    *,
    package: str = "",
) -> FuzzTargetSpec:
    """그룹 하나에 대한 cc_fuzz_test 명세."""
    parse_label(target_label)  # 형식 오류를 여기서 바로 드러낸다
    provider = deps_provider or StaticDepsProvider()
    slug = group_slug(group_name)
    return FuzzTargetSpec(
        name=f"{slug}_fuzz_test",
        package=package or f"{fuzz_package_for(target_label)}/{slug}",
        srcs=(f"{slug}_fuzz.cc",),
        deps=tuple(provider.deps_for(target_label)),
        notes=(
            f"LogosFuzz GEN-03-01 자동 생성 - Logic Group {group_name}",
            f"빌드 단위: {target_label}",
            "",
            "tags = [\"manual\"] : //... 전체 빌드에 딸려 들어가면",
            "--config=bl-x86_64-linux(GCC) 회귀 빌드가 libFuzzer 링크에서 깨진다.",
        ),
    )


def pair_driver(
    driver: FuzzDriver,
    target_label: str = "",
    deps_provider: Optional[DepsProvider] = None,
) -> HarnessPair:
    """LLM 이 만든 FuzzDriver 하나를 .cc + BUILD 쌍으로 만든다."""
    label = target_label or getattr(driver, "build_target", "")
    if not label:
        raise ValueError(
            f"그룹 {driver.group_name!r} 의 빌드 단위를 모른다 — "
            "group_targets 에 넣거나 default_target 을 지정하라"
        )
    spec = make_pair_spec(driver.group_name, label, deps_provider)
    return HarnessPair(
        group_name=driver.group_name,
        target_label=label,
        spec=spec,
        source=normalize_cpp_harness(driver.code),
        language=LANG_CPP,
        prompt_used=driver.prompt_used,
    )


def pair_drivers(
    drivers: Sequence[FuzzDriver],
    group_targets: Optional[Mapping[str, str]] = None,
    deps_provider: Optional[DepsProvider] = None,
    *,
    default_target: str = "",
) -> Tuple[List[HarnessPair], List[str]]:
    """여러 FuzzDriver 를 쌍으로 만든다. (쌍 목록, 건너뛴 그룹 이름) 반환.

    빌드 단위를 알 수 없는 그룹은 예외 대신 건너뛴다. 한 그룹 때문에 나머지
    그룹의 BUILD 생성까지 멈추면 안 된다.
    """
    targets = dict(group_targets or {})
    pairs: List[HarnessPair] = []
    skipped: List[str] = []
    for driver in drivers:
        label = targets.get(driver.group_name) or driver.build_target or default_target
        if not label:
            skipped.append(driver.group_name)
            continue
        pairs.append(pair_driver(driver, label, deps_provider))
    return pairs, skipped


# ---------------------------------------------------------------------
# 2. 파일 쓰기 / 읽기 (manifest)
# ---------------------------------------------------------------------

def write_pairs(
    pairs: Sequence[HarnessPair],
    out_root: Path | str,
    *,
    manifest_name: str = MANIFEST_NAME,
) -> Path:
    """쌍을 ``<out_root>/<package>/`` 에 쓰고 manifest 경로를 돌려준다.

    ``out_root`` 를 Bazel 워크스페이스 루트로 주면 바로 빌드 가능한 상태가 되고,
    스테이징 폴더로 주면 사람이 먼저 검토할 수 있다. 어느 쪽이든 컨트롤러의
    BUILD 단계는 manifest 만 읽는다.
    """
    root = Path(out_root).expanduser().resolve()
    seen: Dict[str, str] = {}
    for pair in pairs:
        other = seen.get(pair.spec.package)
        if other is not None:
            raise ValueError(
                f"패키지 충돌: {pair.spec.package} 를 그룹 {other!r} 와 "
                f"{pair.group_name!r} 가 같이 쓰려 한다 (그룹 이름 slug 가 같다)"
            )
        seen[pair.spec.package] = pair.group_name

    for pair in pairs:
        pkg_dir = root / pair.spec.package
        pkg_dir.mkdir(parents=True, exist_ok=True)
        (pkg_dir / pair.source_filename).write_text(pair.source, encoding="utf-8")
        (pkg_dir / BUILD_FILE_NAME).write_text(pair.build_file, encoding="utf-8")

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "root": str(root),
        "pairs": [pair.to_dict() for pair in pairs],
    }
    manifest_path = root / manifest_name
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest_path


def load_pairs(manifest_path: Path | str) -> List[HarnessPair]:
    """``write_pairs`` 가 쓴 manifest 를 다시 HarnessPair 로 읽는다.

    소스는 manifest 가 있는 폴더 기준 상대 경로에서 읽는다(폴더째 옮겨도 된다).
    """
    path = Path(manifest_path).expanduser().resolve()
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError(
            f"지원하지 않는 manifest schema_version: {data.get('schema_version')!r}"
        )
    base = path.parent
    pairs: List[HarnessPair] = []
    for item in data.get("pairs") or []:
        spec = FuzzTargetSpec(
            name=item["name"],
            package=item["package"],
            srcs=tuple(item["srcs"]),
            deps=tuple(item.get("deps") or ()),
            tags=tuple(item.get("tags") or ("manual",)),
            notes=tuple(item.get("notes") or ()),
        )
        source = (base / item["source"]).read_text(encoding="utf-8")
        pairs.append(HarnessPair(
            group_name=item["group"],
            target_label=item["build_target"],
            spec=spec,
            source=source,
            language=item.get("language", LANG_CPP),
        ))
    return pairs


# ---------------------------------------------------------------------
# 3. KB -> 프롬프트 입력 (A 파트 3주차 빌드 단위 메타 사용)
# ---------------------------------------------------------------------

def include_path_for(header: str, workspace_root: Path | str | None) -> str:
    """헤더를 Bazel include 루트 기준 경로로 바꾼다.

    S-CORE 는 ``#include "score/json/json_parser.h"`` 처럼 워크스페이스 루트
    기준으로 include 한다. KB 에는 절대 경로가 들어 있으므로 루트를 떼 낸다.
    ``//pkg:file.h`` 라벨도 받아 준다. 루트 밖이면 원래 문자열을 그대로 둔다.

    A 의 ``as_include_path`` 는 역슬래시만 슬래시로 바꿀 뿐 워크스페이스 상대화는
    하지 않는다(절대 경로가 그대로 남는다). 그래서 대체하지 않고 그 정규화만 흡수했다.
    """
    # Windows 에서 수집한 KB 경로의 역슬래시는 C/C++ #include 에서 이스케이프로
    # 읽힌다 — A 의 kb_adapters.as_include_path 와 같은 정규화를 먼저 한다.
    value = (header or "").strip().replace("\\", "/")
    if not value:
        return ""
    if value.startswith("//") or value.startswith("@"):
        local = value.split("//", 1)[1]
        pkg, _, name = local.partition(":")
        return f"{pkg}/{name}" if name else pkg
    if workspace_root:
        try:
            return Path(value).resolve().relative_to(
                Path(workspace_root).expanduser().resolve()
            ).as_posix()
        except ValueError:
            pass
    return value


def kb_context_db(kb: Any) -> Dict[int, ApiContext]:
    """KB 문서를 GEN 의 ApiContext 로 바꾼다 (VECTOR_DB_MOCK 대체)."""
    db: Dict[int, ApiContext] = {}
    for document in kb.documents:
        constraints = [
            str(c.get("description") or "")
            for c in document.get("constraints") or []
            if c.get("kind") != "error_contract"
        ]
        call_order = [document.get("function", "")]
        call_order.extend(document.get("calls_internal") or [])
        db[int(document["api_id"])] = ApiContext(
            api_id=int(document["api_id"]),
            func_signature=str(document.get("signature") or document.get("function")),
            call_order=[c for c in call_order if c],
            constraints=[c for c in constraints if c][:12],
            source_type=str(document.get("build_target") or "TARGET"),
        )
    return db


def error_contracts_of(document: Mapping[str, Any]) -> List[str]:
    """A 파트 constraint_extractor 가 뽑은 score::Result 에러계약 설명."""
    out = []
    for constraint in document.get("constraints") or []:
        if constraint.get("kind") != "error_contract":
            continue
        text = str(constraint.get("description") or "")
        evidence = str(constraint.get("expression") or "")
        if evidence:
            text = f"{text} (evidence: {evidence})"
        out.append(f"{document.get('function', '?')}: {text}")
    return out


def is_test_header(path: str) -> bool:
    """테스트·mock 보조 헤더인가 (퍼징 하네스가 include 하면 안 되는 헤더).

    KB 의 API->헤더 매핑은 그 이름을 선언·언급한 헤더를 고르기 때문에, 테스트 스위트
    헤더(``parsers_test_suite.h``)가 실제 공개 헤더 대신 잡히는 일이 있다. 그걸 include
    하면 빌드 단위 밖 헤더라 deps·visibility 에러로 이어진다.
    """
    parts = path.replace("\\", "/").lower().split("/")
    name = parts[-1]
    if any(token in name for token in ("_test", "test_suite", "mock")):
        return True
    return any(part in ("test", "tests", "testing", "mock", "mocks") for part in parts[:-1])


def _header_file_for_document(document: Mapping[str, Any]) -> str:
    """API 의 공개 헤더 **파일 경로**(절대 경로일 수 있다). 없으면 "".

    1. KB 가 기록한 헤더가 테스트·mock 용이 아니면 그대로 쓴다.
    2. 아니면(비었거나 테스트 헤더) API 정의 파일과 이름이 같은 헤더를 같은 폴더에서
       찾는다 (``vajson_parser.cpp`` -> ``vajson_parser.h``).
    """
    header = str(document.get("header") or "").replace("\\", "/")
    if header and not is_test_header(header):
        return header
    source = str(document.get("file") or "").replace("\\", "/")
    if source:
        stem = str(Path(source).with_suffix(""))
        for suffix in (".h", ".hpp", ".hh"):
            candidate = stem + suffix
            if Path(candidate).is_file() and not is_test_header(candidate):
                return candidate
    return ""


def header_for_document(document: Mapping[str, Any],
                        workspace_root: Path | str | None = None) -> str:
    """API 를 쓰려면 include 해야 할 **공개 헤더**(워크스페이스 상대 경로). 없으면 ""."""
    header = _header_file_for_document(document)
    return include_path_for(header, workspace_root) if header else ""


_CLASS_DECL_RE = re.compile(
    r"^(?P<indent>\s*)(?:template\s*<.*>\s*)?(?P<kind>class|struct)\s+(?P<name>\w+)")
_ACCESS_RE = re.compile(r"^\s*(?:public|private|protected)\s*:")
_COMMENT_PREFIXES = ("//", "*", "/*")


# namespace 선언(이름 있는 것만) / 여는 중괄호 / 닫는 중괄호 를 한 줄에서 순서대로 읽는다.
_SCOPE_TOKEN_RE = re.compile(
    r"\bnamespace\s+(?P<name>[\w:]+)(?P<alias>\s*=)?|(?P<open>\{)|(?P<close>\})")


def _enclosing_namespaces(lines: Sequence[str], upto: int) -> list[str]:
    """``lines[:upto]`` 를 훑어 ``upto`` 줄을 감싼 namespace 이름들을 바깥부터 돌려준다.

    중괄호 깊이만 센다(``//`` 주석은 자른다). 한계: 클래스 안의 중첩 클래스는 바깥 클래스
    이름이 빠진다(namespace 만 본다). ``namespace a { namespace b {`` 처럼 한 줄에
    여럿이거나 ``namespace a`` 다음 줄에 ``{`` 가 오는 스타일 모두 읽는다. 이름 없는
    namespace, ``extern "C" {``, namespace alias(``namespace fs = ...``)는 이름에 넣지 않는다.
    """
    stack: list[str | None] = []
    pending: str | None = None
    for raw in lines[:upto]:
        text = raw.split("//", 1)[0]
        for token in _SCOPE_TOKEN_RE.finditer(text):
            if token.group("name"):
                # alias(`namespace fs = ...`)와 `using namespace std;` 는 범위를 열지 않는다.
                if token.group("alias") or text[:token.start()].rstrip().endswith("using"):
                    continue
                pending = token.group("name")
            elif token.group("open"):
                stack.append(pending)
                pending = None
            elif stack:
                stack.pop()
    return [name for name in stack if name]


def _locate_declaration(document: Mapping[str, Any], header_file: str) -> dict[str, Any] | None:
    """헤더에서 API 선언을 찾아 소속 클래스·접근 지정자까지 해석한다. 못 찾으면 None."""
    name = str(document.get("function") or "")
    if not name or not header_file:
        return None
    try:
        lines = Path(header_file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    call = re.compile(rf"\b{re.escape(name)}\s*\(")
    index = next((i for i, text in enumerate(lines)
                  if call.search(text) and not text.lstrip().startswith(_COMMENT_PREFIXES)), None)
    if index is None:
        return None

    start = index - 1 if index > 0 and lines[index - 1].lstrip().startswith("template") else index
    end = index
    while end < min(len(lines) - 1, index + 5) and ";" not in lines[end] and "{" not in lines[end]:
        end += 1

    indent = len(lines[index]) - len(lines[index].lstrip())
    class_line = class_name = class_kind = access_line = None
    class_index = -1
    for i in range(index - 1, -1, -1):
        text = lines[i]
        if access_line is None and _ACCESS_RE.match(text):
            access_line = text.rstrip()
        match = _CLASS_DECL_RE.match(text)
        # 전방 선언(`class Foo;`)이나 같은 들여쓰기의 클래스는 소속 클래스가 아니다.
        if match and not text.rstrip().endswith(";") and len(match.group("indent")) < indent:
            class_line, class_name, class_kind = text.rstrip(), match.group("name"), match.group("kind")
            class_index = i
            break

    access = ""
    if class_name:
        if access_line:
            access = access_line.strip().rstrip(":").strip()
        else:                               # 지정자가 없으면 class 는 private, struct 는 public
            access = "private" if class_kind == "class" else "public"
    declaration = [text.rstrip() for text in lines[start:end + 1]]
    qualified_class = ""
    if class_name:
        qualified_class = "::".join([*_enclosing_namespaces(lines, class_index), class_name])
    return {
        "line": index + 1,
        "declaration": declaration,
        "is_static": bool(re.search(r"\bstatic\b", " ".join(declaration))),
        "qualified_class": qualified_class,
        "class_line": class_line,
        "class_name": class_name,
        "access_line": access_line if class_line else None,
        "access": access,
    }


def declaration_access(document: Mapping[str, Any], header_file: str) -> str:
    """멤버 함수의 접근 지정자(``public``/``private``/``protected``). 자유 함수·모르면 ""."""
    found = _locate_declaration(document, header_file)
    return found["access"] if found else ""


def header_declaration_excerpt(
    document: Mapping[str, Any],
    header_file: str,
    workspace_root: Path | str | None = None,
    *,
    max_chars: int = MAX_EXCERPT_CHARS,
) -> str:
    """공개 헤더에서 API **선언**을 찾아 소속 클래스·접근 지정자와 함께 발췌한다.

    KB 는 정의 위치(``.cpp``)와 시그니처만 알고 "어느 클래스의 **static** 멤버인지",
    "public 인지", 생성자가 열려 있는지는 모른다. LLM 이 이걸 추정하면 private 생성자를
    가진 클래스를 인스턴스로 만들려 한다(실제 사례: ``VajsonParser::FromBuffer`` 는
    public static 인데 ``JsonData`` 를 만들어 ``VajsonParser parser{json_data}`` 를 썼다).
    선언 줄과 그것을 감싼 ``class`` 줄, 가장 가까운 ``public:``/``private:`` 를 보여 준다.
    못 찾으면 빈 문자열.
    """
    found = _locate_declaration(document, header_file)
    if found is None:
        return ""
    parts = [found["class_line"]] if found["class_line"] else []
    if found["class_line"] and found["access_line"]:
        parts.append(found["access_line"])
    parts.extend(found["declaration"])
    if found["is_static"] and found["access"] == "public" and found["qualified_class"]:
        # LLM 이 참조 하네스의 `Foo parser{}; parser.Call()` 패턴을 베끼지 않게 호출 모양을 못 박는다.
        parts.append(
            f"// Usage: {found['qualified_class']}::{document.get('function')}(...) — "
            f"static member: call it directly, NEVER create a {found['class_name']} instance")
    body = "\n".join(parts)
    if len(body) > max_chars:
        body = body[:max_chars].rstrip() + "\n// ... (truncated)"
    where = f" (member of {found['class_name']})" if found["class_name"] else ""
    return f"// {include_path_for(header_file, workspace_root)}:{found['line']}{where}\n{body}"


# 단어 경계를 본다: file_path / filePath / path / dirname 은 잡고, profile·pathology 는 놓친다.
_FILE_PARAM_RE = re.compile(r"(?:^|_)(?:file|path|dir)")
_FILE_FUNCTION_RE = re.compile(r"File|_file(?:_|$)")      # FromFile, ReadFile, from_file


def _is_file_param(name: str) -> bool:
    lowered = name.lower()
    return bool(_FILE_PARAM_RE.search(lowered)) or lowered.endswith(("path", "filename"))


def unfuzzable_reason(document: Mapping[str, Any]) -> str:
    """하네스가 호출하면 안 되는 API 면 그 이유, 아니면 "".

    - private/protected 멤버: 밖에서 호출할 수 없다(``GetData``).
    - 파일 경로를 받는 API: 퍼저 입력으로 임의 경로를 열게 되고, 규칙 9(파일 접근 금지)에
      어긋난다. 같은 일을 하는 buffer 변형(``FromBuffer``)을 퍼징하면 된다.
    프롬프트 규칙으로 "빼라"고 하면 LLM 이 API 목록을 따라 그대로 호출하므로 목록에서 뺀다.
    """
    access = declaration_access(document, _header_file_for_document(document))
    if access in ("private", "protected"):
        return f"{access} 멤버"
    params = document.get("params") or []
    if _FILE_FUNCTION_RE.search(str(document.get("function") or "")) or any(
            _is_file_param(str(p.get("name") or "")) for p in params if isinstance(p, Mapping)):
        return "파일 경로를 받는 API"
    return ""


def fuzzable_api_ids(kb: Any, group: Any) -> tuple[list[int], list[tuple[str, str]]]:
    """그룹의 API 중 하네스가 호출할 것만 고른다. (남긴 api_id, [(함수, 제외 이유)]).

    같은 (함수, 시그니처)의 중복 정의(선언+정의, 오버로드된 같은 시그니처)는 첫 번째만 남긴다.
    """
    kept: list[int] = []
    excluded: list[tuple[str, str]] = []
    seen: set = set()
    for api_id in group.api_ids:
        document = kb.api(api_id)
        if not document:
            continue
        key = (document.get("function"), document.get("signature"))
        if key in seen:
            continue
        seen.add(key)
        reason = unfuzzable_reason(document)
        if reason:
            item = (str(document.get("function")), reason)
            if item not in excluded:            # 시그니처만 다른 같은 이름은 한 번만 알린다
                excluded.append(item)
        else:
            kept.append(api_id)
    return kept, excluded


def restrict_to_fuzzable(kb: Any, groups: Sequence[Any]) -> List[Any]:
    """각 그룹의 API 목록을 ``fuzzable_api_ids`` 로 줄인다. 남은 API 가 없는 그룹은 뺀다."""
    out: List[Any] = []
    for group in groups:
        kept, excluded = fuzzable_api_ids(kb, group)
        for function, reason in excluded:
            print(f"  [GEN] {group.group_id}: {function} 제외 ({reason})")
        if not kept:
            print(f"  [GEN] {group.group_id}: 하네스가 호출할 API 가 없어 건너뜀")
            continue
        out.append(replace(group, api_ids=kept))
    return out


def declaration_excerpt(
    document: Mapping[str, Any],
    workspace_root: Path | str | None = None,
    *,
    before: int = 2,
    after: int = 10,
    max_chars: int = MAX_EXCERPT_CHARS,
) -> str:
    """KB 가 기록한 선언 위치(파일·줄)의 **실제 소스**를 발췌한다.

    LLM 은 시그니처와 문서 주석만 보면 반환 타입·소유권·호출 규약을 추정하게 된다.
    (실제로 ``JsonParser::StringArray(const Fn&) -> JsonParser&`` 를 ``Result`` 로 착각해
    ``.has_value()`` 를 호출한 하네스가 나왔다.) 선언 줄 앞뒤 몇 줄을 그대로 보여 주면
    ``template <...>`` 헤더와 반환 타입이 같이 보인다. 읽을 수 없으면 빈 문자열.
    """
    path = str(document.get("file") or "").replace("\\", "/")
    try:
        line = int(document.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    if not path or line <= 0:
        return ""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    body = "\n".join(lines[max(0, line - 1 - before): min(len(lines), line + after)])
    if not body.strip():                      # 줄 번호가 파일 끝을 넘어선 오래된 KB
        return ""
    if len(body) > max_chars:
        body = body[:max_chars].rstrip() + "\n// ... (truncated)"
    return f"// {include_path_for(path, workspace_root)}:{line}\n{body}"


def filter_groups(groups: Sequence[Any], patterns: Sequence[str] = ()) -> List[Any]:
    """정규식(``re.search``) 중 하나라도 그룹 이름이나 빌드 단위에 맞는 그룹만 남긴다.

    패턴이 없으면 그대로 돌려준다. ``--top`` 은 이 필터 **뒤에** 적용된다.
    """
    if not patterns:
        return list(groups)
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error as exc:
            raise ValueError(f"잘못된 --only 패턴 {pattern!r}: {exc}") from exc

    def matches(group: Any) -> bool:
        haystack = [str(group.group_id), *map(str, getattr(group, "build_units", None) or [])]
        return any(rx.search(text) for rx in compiled for text in haystack)

    return [g for g in groups if matches(g)]


def list_groups(kb: Any, only: Sequence[str] = ()) -> List[Dict[str, Any]]:
    """Logic Group 목록(LLM 호출 없음). ``--only`` 패턴을 고를 때 본다."""
    from logosfuzz.schedule.logic_groups import build_groups

    rows = []
    for group in filter_groups(build_groups(kb), only):
        documents = [kb.api(aid) for aid in list(group.api_ids)]
        names = [d["function"] for d in documents if d]
        rows.append({
            "group": group.group_id,
            "build_units": list(getattr(group, "build_units", None) or []),
            "apis": len(names),
            "sample_apis": names[:4],
        })
    return rows


def clean_context_block(block: str, include: str = "") -> str:
    """KB 컨텍스트 블록(``harness_context``)에서 프롬프트에 해로운 줄을 정리한다.

    - ``include:`` : KB 가 기록한 헤더는 테스트 보조 헤더일 수 있다(``parsers_test_suite.h``).
      해결해 둔 공개 헤더(``include``)로 바꾸고, 없으면 줄을 뺀다.
    - ``compile flags:`` : ``-I`` 수십 개. 빌드는 Bazel 이 하므로 LLM 에게는 잡음일 뿐이다.
    """
    out: list[str] = []
    for line in block.splitlines():
        if line.startswith("compile flags:"):
            continue
        if line.startswith("include: "):
            if include:
                out.append(f'include: #include "{include}"')
            continue
        out.append(line)
    return "\n".join(out)


def prune_call_order(context_db: Mapping[int, ApiContext], kb: Any, groups: Sequence[Any]) -> None:
    """각 API 의 호출 순서에서 **같은 그룹에 남은 API** 만 남긴다 (중복 제거, 순서 유지).

    KB 의 ``calls_internal`` 은 구현 내부 호출(``HandleEvent``, private ``GetData`` …)까지
    담는다. 그대로 보여 주면 LLM 이 제외한 API 를 호출 순서에 따라 부르게 된다.
    """
    for group in groups:
        names = {str(kb.api(i)["function"]) for i in group.api_ids if kb.api(i)}
        for api_id in group.api_ids:
            ctx = context_db.get(api_id)
            if ctx is not None:
                ctx.call_order = list(dict.fromkeys(n for n in ctx.call_order if n in names))


def try_plan(kb: Any, api_id: int, target_label: str, group_id: str) -> Any:
    """A 의 ``kb_bridge.plan_harness`` 로 API 계획을 만든다. 못 만들면 None.

    kb_bridge 는 dev 병합 전에는 없으므로 지연 import 한다. static/테스트 API,
    빌드 단위 미연결 API 는 ``KnowledgeBridgeError`` 가 나는데, 그룹 전체를 멈출
    이유가 아니라서 그 API 만 건너뛴다(기존 KB 직접 조회 경로가 대신 채운다).
    """
    try:
        from logosfuzz.generate.kb_bridge import KnowledgeBridgeError, plan_harness
    except ImportError:
        return None
    try:
        return plan_harness(kb, api_id, target_label=target_label, logic_group=group_id)
    except KnowledgeBridgeError:
        return None


def group_meta_from_kb(
    kb: Any,
    groups: Sequence[Any],
    *,
    workspace_root: Path | str | None = None,
    deps_provider: Optional[DepsProvider] = None,
    default_target: str = "",
    plans_out: Optional[Dict[str, List[Any]]] = None,
) -> Tuple[Dict[str, str], Dict[str, Dict[str, Any]]]:
    """그룹별 (빌드 단위, 프롬프트 부가 정보) 를 만든다.

    ``groups`` 는 ``logic_groups.GroupInfo``(3주차부터 ``build_units`` 보유) 목록.
    빌드 단위가 여러 개로 잡힌 그룹은 없어야 정상이지만(경계가 빌드 단위라서),
    레거시 KB 대비로 첫 번째를 쓰고 비어 있으면 ``default_target`` 을 쓴다.

    A 의 ``plan_harness`` 가 있으면(dev 병합 후) 그 결과를 재사용한다.

    - ``prompt_context`` : 계획 값을 **쓰지 않는다**. 함수 이름으로 조회해서 같은 이름의
      다른 API 가 잡힌다(``harness_context`` 를 api_id 로 직접 부른다).
    - ``error_contracts``: 계획 값은 설명만 있다. ``error_contracts_of`` 는 함수 이름과
      evidence 식까지 붙여 주는 상위 집합이라 **그쪽을 유지**한다.
    - ``includes``       : 계획의 ``include`` 는 역슬래시만 고친다(절대 경로 유지).
      워크스페이스 상대화가 필요해서 ``include_path_for`` 를 유지한다.

    ``plans_out`` 을 주면 ``{group_id: [HarnessBuildPlan, ...]}`` 를 채워 준다
    (BUILD 단계의 검증 artifact·소스 자가치유 힌트가 쓴다).
    """
    from logosfuzz.knowledge.kb_adapters import build_unit_metadata, harness_context

    provider = deps_provider or StaticDepsProvider()
    units = {u["build_target"]: u for u in build_unit_metadata(kb)}
    targets: Dict[str, str] = {}
    meta: Dict[str, Dict[str, Any]] = {}

    for group in groups:
        build_units = list(getattr(group, "build_units", None) or [])
        label = build_units[0] if build_units else default_target
        if not label:
            continue
        targets[group.group_id] = label

        documents = [kb.api(aid) for aid in list(group.api_ids)[:MAX_CONTEXT_APIS]]
        documents = [d for d in documents if d]
        plans = [try_plan(kb, d["api_id"], label, group.group_id) for d in documents]
        if plans_out is not None:
            plans_out[group.group_id] = [p for p in plans if p is not None]

        headers: List[str] = []
        for document in documents:
            header = header_for_document(document, workspace_root)
            if header:
                headers.append(header)
        if not headers and label in units:
            headers = [include_path_for(h, workspace_root) for h in units[label]["headers"]
                       if not is_test_header(h)]

        contracts: List[str] = []
        for document in documents:
            contracts.extend(error_contracts_of(document))

        excerpts = []
        for document in documents:
            # 공개 헤더의 클래스 선언을 우선, 못 찾으면 정의 위치(.cpp) 발췌로 대신한다.
            excerpt = (header_declaration_excerpt(
                           document, _header_file_for_document(document), workspace_root)
                       or declaration_excerpt(document, workspace_root))
            if excerpt:
                excerpts.append(excerpt)
        excerpts = list(dict.fromkeys(excerpts))

        meta[group.group_id] = {
            "build_target": label,
            "build_deps": list(provider.deps_for(label)),
            "includes": list(dict.fromkeys(h for h in headers if h)),
            # api_id 로 조회한다. 함수 이름으로 조회하면(``plan.prompt_context`` 도 그렇다)
            # 같은 이름의 다른 API(다른 빌드 단위의 FromBuffer)가 잡힌다.
            "context_blocks": [
                clean_context_block(harness_context(kb, document["api_id"]),
                                    header_for_document(document, workspace_root))
                for document in documents
            ],
            "error_contracts": contracts,
        }
        if excerpts:
            # generate_harness 가 그룹별 header_content 를 프롬프트의 "참고용 소스"로 싣는다.
            meta[group.group_id]["header_content"] = \
                "\n\n".join(excerpts)[:MAX_HEADER_CONTENT_CHARS]
    return targets, meta


# ---------------------------------------------------------------------
# 4. 생성 진입점
# ---------------------------------------------------------------------

def generate_pairs(
    schedule: Sequence[Any],
    logic_groups: Mapping[str, List[int]],
    group_targets: Mapping[str, str],
    *,
    deps_provider: Optional[DepsProvider] = None,
    context_db: Optional[Mapping[int, ApiContext]] = None,
    group_meta: Optional[Mapping[str, Mapping[str, Any]]] = None,
    default_target: str = "",
    llm: Optional[Callable[[str], str]] = None,
) -> Tuple[List[HarnessPair], List[str]]:
    """스케줄 순서대로 C++ 하네스를 생성하고 BUILD 쌍으로 묶는다."""
    provider = deps_provider or StaticDepsProvider()
    meta: Dict[str, Dict[str, Any]] = {k: dict(v) for k, v in (group_meta or {}).items()}
    for group, label in group_targets.items():
        entry = meta.setdefault(group, {})
        entry.setdefault("build_target", label)
        entry.setdefault("build_deps", list(provider.deps_for(label)))

    drivers = generate_harness(
        list(schedule), dict(logic_groups),
        language=LANG_CPP,
        context_db=context_db,
        group_meta=meta,
        llm=llm,
    )
    return pair_drivers(drivers, group_targets, provider, default_target=default_target)


def select_top_groups(groups: Sequence[Any], ranking: Sequence[Tuple[str, float]],
                      top_n: int) -> Tuple[List[Any], List[Tuple[str, float]]]:
    """랭킹 상위 ``top_n`` 개 그룹만 남긴다. ``top_n <= 0`` 이면 전부.

    ``ranking`` 은 ``rank_logic_groups`` 출력(점수 내림차순). 반환하는 그룹 목록은 입력
    순서를 유지하고, 랭킹은 상위 N개만 돌려준다(퍼징 예산 배분이 이 N개에만 적용된다).
    """
    if top_n <= 0:
        return list(groups), list(ranking)
    kept_ranking = list(ranking)[:top_n]
    keep = {name for name, _ in kept_ranking}
    return [g for g in groups if g.group_id in keep], kept_ranking


def generate_pairs_from_kb(
    kb: Any,
    *,
    workspace_root: Path | str | None = None,
    deps_provider: Optional[DepsProvider] = None,
    budget_sec: int = 3600,
    top_n: int = 0,
    default_target: str = "",
    llm: Optional[Callable[[str], str]] = None,
    plans_out: Optional[Dict[str, List[Any]]] = None,
    only: Sequence[str] = (),
    meta_out: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[List[HarnessPair], List[str]]:
    """KB -> Logic Group(빌드 단위 경계) -> 스케줄 -> C++ 하네스 쌍.

    ``only`` 는 그룹 이름·빌드 단위에 대한 정규식 목록(``filter_groups``). 주면 맞는
    그룹만 대상이 되고 ``top_n`` 은 그 안에서 **시너지 랭킹 상위 N개**를 고른다.
    ``meta_out`` 을 주면 그룹별 프롬프트 부가 정보(``header_content`` 등)를 채워 준다
    (BUILD 단계의 소스 자가치유가 같은 API 선언을 힌트로 쓴다).

    ``deps_provider`` 를 안 주면 KB 기반 공급자를 기본으로 쓴다(``make_deps_provider``).
    ``plans_out`` 은 ``group_meta_from_kb`` 로 그대로 넘어간다.
    """
    from logosfuzz.knowledge.kb_adapters import to_synergy_inputs
    from logosfuzz.schedule.logic_groups import build_groups, to_group_map

    if deps_provider is None:
        deps_provider = make_deps_provider("auto", Path(workspace_root) if workspace_root else None, kb=kb)
    from logosfuzz.schedule.sch_02_02_synergy_scheduler import (
        compute_pairwise_synergy, rank_logic_groups,
    )
    from logosfuzz.schedule.sch_02_03_resource_allocator import allocate_resources

    groups = filter_groups(build_groups(kb), only)
    if only and not groups:
        print(f"[WARN] --only {list(only)} 와 맞는 그룹이 없다 (--list-groups 로 확인)")
        return [], []
    groups = restrict_to_fuzzable(kb, groups)
    if not groups:
        return [], []
    context_db = kb_context_db(kb)
    prune_call_order(context_db, kb, groups)
    group_map = to_group_map(groups)

    apis, constraints = to_synergy_inputs(kb)
    ranking = rank_logic_groups(group_map, compute_pairwise_synergy(apis, constraints))
    # 랭킹(시너지 점수 내림차순) **뒤에** 상위 N개를 고른다. 예전에는 랭킹 전에 목록 앞에서
    # N개를 잘라서 우선순위와 무관한 그룹(목록 맨 앞의 내부 구현 그룹)이 뽑혔다.
    groups, ranking = select_top_groups(groups, ranking, top_n)
    schedule = allocate_resources(ranking, [], budget_sec=budget_sec)

    targets, meta = group_meta_from_kb(
        kb, groups,
        workspace_root=workspace_root,
        deps_provider=deps_provider,
        default_target=default_target,
        plans_out=plans_out,
    )
    if meta_out is not None:
        meta_out.update(meta)
    return generate_pairs(
        schedule, group_map, targets,
        deps_provider=deps_provider,
        context_db=context_db,
        group_meta=meta,
        default_target=default_target,
        llm=llm,
    )


def demo_pair(
    target_label: str = "@score_baselibs//score/json",
    group_name: str = "lg_json_parser",
) -> HarnessPair:
    """LLM 없이 1주차 참조 하네스로 쌍 1개를 만든다(설치 확인·데모용)."""
    source = REFERENCE_HARNESS_PATH.read_text(encoding="utf-8")
    driver = FuzzDriver(group_name=group_name, code=source, language=LANG_CPP,
                        build_target=target_label)
    return pair_driver(driver, target_label, StaticDepsProvider(VERIFIED_SCORE_JSON_DEPS))


# ---------------------------------------------------------------------
# 5. CLI
# ---------------------------------------------------------------------

def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GEN-03-01: C++ 하네스 + BUILD.bazel 쌍 생성",
    )
    parser.add_argument("--out", type=Path, default=None,
                        help="쌍을 쓸 루트(스테이징 폴더 또는 Bazel 워크스페이스). --list-groups 외에는 필수")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true",
                      help="LLM 없이 1주차 참조 하네스로 쌍 1개 생성")
    mode.add_argument("--kb", type=Path, help="KB JSON (knowledge_base.py 산출물)")
    parser.add_argument("--workspace", type=Path, default=None,
                        help="Bazel 워크스페이스 루트 (헤더 include 경로 계산, --deps query)")
    parser.add_argument("--target", default="",
                        help="빌드 단위가 없는 그룹에 쓸 기본 대상 라벨")
    parser.add_argument("--deps", choices=("auto", "kb", "static", "query"), default="auto",
                        help="auto: KB 가 있으면 kb, 없으면 static / kb: KB 의 Bazel 의존성 / "
                             "static: 1주차 검증 deps + 자기 자신 / query: bazel query")
    parser.add_argument("--top", type=int, default=0, help="시너지 랭킹 상위 N개 그룹만 (--only 로 거른 뒤 적용)")
    parser.add_argument("--only", action="append", default=[], metavar="REGEX",
                        help="그룹 이름·빌드 단위가 이 정규식에 맞는 그룹만(반복 가능). "
                             "예: --only '//score/json:json$'. --top 은 그 안에서 적용")
    parser.add_argument("--list-groups", action="store_true",
                        help="Logic Group 목록만 출력하고 끝낸다(LLM 호출 없음, --kb 필요)")
    parser.add_argument("--budget", type=int, default=3600, help="SCH 퍼징 예산(초)")
    args = parser.parse_args(argv)
    if args.list_groups and not args.kb:
        parser.error("--list-groups 는 --kb 와 함께 쓴다")
    if not args.list_groups and args.out is None:
        parser.error("--out 이 필요하다 (--list-groups 제외)")
    return args


def make_deps_provider(
    kind: str = "auto",
    workspace: Optional[Path] = None,
    kb: Any = None,
) -> DepsProvider:
    """CLI/컨트롤러 공용 deps 공급자 팩토리.

    - ``kb``     : A 의 ``kb_bridge.KnowledgeBaseDepsProvider(kb)``. repo 접두사까지 처리한다.
    - ``auto``   : KB 가 있고 kb_bridge 를 쓸 수 있으면 ``kb``, 아니면 ``static``.
    - ``static`` : 1주차 검증 deps 표 (표에 없으면 대상 자신만).
    - ``query``  : A 파트 ``extract/bazel_query.deps_of``. deps_of 는 대상의 **의존**만
      돌려주므로 대상 자신을 맨 앞에 붙인다(구현 링크가 대상에 있다).
    """
    if kind == "auto":
        kind = "kb" if kb is not None and _kb_bridge_available() else "static"
    if kind == "kb":
        if kb is None:
            raise ValueError("--deps kb 는 KB 가 필요하다 (--kb)")
        try:
            from logosfuzz.generate.kb_bridge import KnowledgeBaseDepsProvider
        except ImportError as exc:
            raise ValueError(
                "--deps kb 는 logosfuzz.generate.kb_bridge(A, origin/dev) 가 필요하다 "
                f"— dev 를 병합하거나 --deps static 을 써라 ({exc})"
            ) from exc
        return KnowledgeBaseDepsProvider(kb)
    if kind == "static":
        return StaticDepsProvider(VERIFIED_SCORE_JSON_DEPS)
    if kind != "query":
        raise ValueError(f"알 수 없는 deps 공급자: {kind!r}")
    if workspace is None:
        raise ValueError("--deps query 는 --workspace 가 필요하다")

    from logosfuzz.extract.bazel_query import deps_of, normalize_label
    from logosfuzz.generate.bazel.deps_provider import BazelQueryDepsProvider

    ws = str(Path(workspace).expanduser().resolve())

    def query(label: str) -> List[str]:
        own = normalize_label(label)
        return list(dict.fromkeys([own, *deps_of(own, workspace=ws)]))

    return BazelQueryDepsProvider(query)


def _kb_bridge_available() -> bool:
    try:
        import logosfuzz.generate.kb_bridge  # noqa: F401
    except ImportError:
        return False
    return True


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    if args.demo:
        pairs, skipped = [demo_pair(args.target or "@score_baselibs//score/json")], []
    else:
        from logosfuzz.knowledge.knowledge_base import KnowledgeBase

        kb = KnowledgeBase.load(str(args.kb))
        if args.list_groups:
            rows = list_groups(kb, args.only)
            print(f"[GEN-03-01] Logic Group {len(rows)}개 "
                  "(--top 은 시너지 랭킹 순이라 이 목록 순서와 다르다. 특정 그룹은 --only)")
            for row in rows:
                print(f"  {row['group']}  apis={row['apis']}  "
                      f"units={','.join(row['build_units']) or '-'}  "
                      f"e.g. {', '.join(row['sample_apis'])}")
            return 0
        provider = make_deps_provider(args.deps, args.workspace, kb=kb)
        pairs, skipped = generate_pairs_from_kb(
            kb,
            workspace_root=args.workspace,
            deps_provider=provider,
            budget_sec=args.budget,
            top_n=args.top,
            default_target=args.target,
            only=args.only,
        )

    manifest = write_pairs(pairs, args.out)
    print(f"\n[GEN-03-01] 쌍 {len(pairs)}개 생성 -> {manifest}")
    for pair in pairs:
        print(f"  {pair.group_name}: {pair.source_relpath} + {pair.build_relpath}"
              f"  ({pair.spec.bin_label})")
    if skipped:
        print(f"  [WARN] 빌드 단위를 몰라 건너뛴 그룹 {len(skipped)}개: {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
