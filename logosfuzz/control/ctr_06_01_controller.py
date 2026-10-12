"""
CTR-06-01 : Compatibility Checklist + Auto-run Pipeline + Regression Test

Responsibilities
----------------
1. CompatibilityChecker : Pre-run checklist (Python version, tools, env vars, paths)
2. AutoPipeline         : Run EXT -> SCH -> GEN -> EXE -> ANA in sequence
3. BuildStage           : (3주차) GEN 산출물(.cc + BUILD 쌍)을 Bazel 로 빌드하고
                          BUILD 룰 수준 자가치유까지 돌려 퍼저 바이너리를 만든다
4. RegressionTester     : Compare current run results against baseline to detect regression

BUILD 단계를 어디에 끼웠나
--------------------------
    EXT -> SCH -> GEN(.cc + BUILD 쌍) -> [BUILD] -> EXE -> ANA

GEN 과 EXE 사이다. EXE 는 빌드 시스템을 모르고 **바이너리 경로**만 받는다
(1주차 팀 결정 ④). 그 경로를 만들어 넘기는 게 이 단계의 유일한 책임이고,
결과는 ``build_summary.json`` 으로 남겨 EXE·리포트(reporting/summary.py)가
빌드 단위 키로 조인한다.

Usage
-----
# 기존 C 파이프라인 (dlt/can-utils)
python -m logosfuzz.control.ctr_06_01_controller --source test_target.c --output harness_output.c
python -m logosfuzz.control.ctr_06_01_controller --regression --baseline baseline.json

# Bazel: GEN-03-01 이 쓴 manifest 를 빌드
python -m logosfuzz.control.ctr_06_01_controller --mode bazel \
    --workspace ~/baselibs --pairs out/pairs/harness_pairs.json

# Bazel: 하네스 1개 + 대상 라벨로 바로 빌드
python -m logosfuzz.control.ctr_06_01_controller --mode bazel --workspace ~/baselibs \
    --harness my_fuzz.cc --build-target @score_baselibs//score/json --group lg_json

# Bazel: KB 에서 LLM 생성 -> BUILD -> 빌드 까지 한 번에
python -m logosfuzz.control.ctr_06_01_controller --mode bazel --workspace ~/baselibs \
    --kb build/score-kb.json --top 3

# Bazel: 소스(.cc) 컴파일 에러까지 자가치유(LLM) + EXE/검증 게이트용 산출물 저장
python -m logosfuzz.control.ctr_06_01_controller --mode bazel --workspace ~/baselibs \
    --kb build/score-kb.json --top 3 --heal-rounds 2 \
    --groups-out out/groups.json --artifacts-out out/artifacts.json
"""

from __future__ import annotations
import os
import re
import sys
import json
import shutil
import argparse
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()  # cwd부터 상위로 .env 자동 탐색 (팀원 환경마다 경로가 다르므로 하드코딩 금지)


# ---------------------------------------------------------------------
# 1. Compatibility Checker
# ---------------------------------------------------------------------

@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str


class CompatibilityChecker:
    """
    Pre-run checklist.
    Verifies environment before starting the pipeline.
    """

    def __init__(self):
        self.results: list[CheckResult] = []

    def _check(self, name: str, condition: bool, ok_msg: str, fail_msg: str):
        self.results.append(CheckResult(name, condition, ok_msg if condition else fail_msg))

    def run_all(self, *, require_bazel: bool = False,
                require_openai: bool = True,
                workspace: str | Path | None = None,
                bazel: str = "bazel") -> bool:
        """Run all checks. Returns True if all pass.

        require_bazel  : BUILD 단계를 돌릴 때만 켠다. bazel(또는 bazelisk)과
                         워크스페이스 MODULE.bazel 을 확인한다.
        require_openai : LLM 생성 없이 이미 만든 쌍만 빌드할 때는 끈다.
        """
        self.results.clear()

        # Python version
        major, minor = sys.version_info[:2]
        self._check(
            "Python version",
            major == 3 and minor >= 9,
            f"Python {major}.{minor} OK",
            f"Python {major}.{minor} - requires 3.9+"
        )

        # Required tools
        # bear 는 제외했다 — 빌드를 Bazel 이 소유하므로 컴파일 명령을 가로챌 일이 없다.
        for tool in ["clang", "clang++"]:
            found = shutil.which(tool) is not None
            self._check(f"Tool: {tool}", found, f"{tool} found", f"{tool} not found in PATH")

        # Bazel (BUILD 단계)
        if require_bazel:
            found = shutil.which(bazel) or shutil.which("bazelisk")
            self._check(f"Tool: {bazel}", bool(found),
                        f"{found} found", f"{bazel}/bazelisk not found in PATH")
            if workspace is not None:
                ws = Path(workspace).expanduser()
                has_module = (ws / "MODULE.bazel").is_file()
                self._check("Bazel workspace", has_module,
                            f"{ws} OK", f"{ws}/MODULE.bazel not found")
                bazelrc = ws / ".bazelrc"
                has_fuzz = bazelrc.is_file() and "build:fuzz" in bazelrc.read_text(
                    encoding="utf-8", errors="replace")
                self._check("build:fuzz config", has_fuzz,
                            "overlay applied (.bazelrc has build:fuzz)",
                            "build:fuzz missing - run "
                            "python -m logosfuzz.generate.bazel.apply_overlay "
                            f"--baselibs-root {ws}")

        # OpenAI API key
        if require_openai:
            api_key = os.environ.get("OPENAI_API_KEY", "")
            self._check(
                "OPENAI_API_KEY",
                bool(api_key),
                "OPENAI_API_KEY set",
                "OPENAI_API_KEY not set"
            )

        # Required Python packages
        packages = ["dotenv", "clang"] + (["openai"] if require_openai else [])
        for pkg in packages:
            try:
                __import__(pkg)
                self._check(f"Package: {pkg}", True, f"{pkg} installed", "")
            except ImportError:
                self._check(f"Package: {pkg}", False, "", f"{pkg} not installed - run pip install {pkg}")

        # Print results
        print("\n=== CTR-06-01 Compatibility Checklist ===")
        all_passed = True
        for r in self.results:
            status = "✅" if r.passed else "❌"
            print(f"  {status} {r.name}: {r.message}")
            if not r.passed:
                all_passed = False

        print(f"\n  Result: {'ALL PASSED' if all_passed else 'SOME CHECKS FAILED'}\n")
        return all_passed


# ---------------------------------------------------------------------
# 2. Auto Pipeline
# ---------------------------------------------------------------------

@dataclass
class PipelineResult:
    """Result of a single pipeline run."""
    run_id: str
    source: str
    output: str
    started_at: str
    finished_at: str = ""
    success: bool = False
    harness_count: int = 0
    error: str = ""


class AutoPipeline:
    """
    Runs the full EXT -> SCH -> GEN pipeline automatically.
    Wraps pipeline.py as a subprocess for isolation.
    """

    def __init__(self, pipeline_script: str | None = None):
        # None 이면 패키지 모듈(logosfuzz.pipeline)로 실행한다. 예전 기본값
        # "pipeline.py" 는 저장소 루트에서 실행하면 파일이 없어 바로 실패했다.
        self.pipeline_script = pipeline_script

    def _command(self) -> list[str]:
        if self.pipeline_script:
            return [sys.executable, self.pipeline_script]
        return [sys.executable, "-m", "logosfuzz.pipeline"]

    def run(self, source: str, output: str, budget: int = 3600) -> PipelineResult:
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        result = PipelineResult(
            run_id=run_id,
            source=source,
            output=output,
            started_at=datetime.now().isoformat(),
        )

        print(f"\n[PIPELINE] Starting run {run_id}...")
        print(f"  Source : {source}")
        print(f"  Output : {output}")
        print(f"  Budget : {budget}s")

        try:
            proc = subprocess.run(
                [*self._command(),
                 "--source", source,
                 "--output", output,
                 "--budget", str(budget)],
                capture_output=True, text=True, timeout=budget + 60
            )

            result.finished_at = datetime.now().isoformat()

            if proc.returncode == 0:
                result.success = True
                # Count generated harness groups.
                # pipeline.py 는 그룹마다 <stem>_<group>.c 로 따로 쓴다.
                out_path = Path(output)
                per_group = list(out_path.resolve().parent.glob(f"{out_path.stem}_*.c"))
                if per_group:
                    result.harness_count = len(per_group)
                elif out_path.exists():
                    content = out_path.read_text(encoding="utf-8")
                    result.harness_count = content.count("// ===")
                print(f"  [DONE] Pipeline completed. {result.harness_count} harness(es) generated.")
            else:
                result.success = False
                result.error = proc.stderr
                print(f"  [FAIL] Pipeline failed:\n{proc.stderr}")

        except subprocess.TimeoutExpired:
            result.success = False
            result.error = "Pipeline timed out"
            print(f"  [TIMEOUT] Pipeline exceeded budget {budget}s")

        except Exception as e:
            result.success = False
            result.error = str(e)
            print(f"  [ERROR] {e}")

        return result


# ---------------------------------------------------------------------
# 3. Build Stage (3주차) — GEN 산출물(.cc + BUILD 쌍) -> 퍼저 바이너리
# ---------------------------------------------------------------------

BUILD_SUMMARY_SCHEMA_VERSION = "1.0"

# 빌드 단위 1개의 최종 상태
BUILD_STATUS_BUILT = "built"          # 1라운드에 성공
BUILD_STATUS_REPAIRED = "repaired"    # BUILD 자가치유 후 성공
BUILD_STATUS_FAILED = "failed"
BUILD_STATUS_EMITTED = "emitted"      # --emit-only: 파일만 쓰고 빌드 안 함


@dataclass
class BuildStageResult:
    """BUILD 단계 전체 결과. ``build_summary.json`` 으로 저장된다."""

    workspace: str
    config: str
    started_at: str
    finished_at: str = ""
    units: list[dict] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    regression: list[dict] = field(default_factory=list)

    def _count(self, status: str) -> int:
        return sum(1 for u in self.units if u.get("status") == status)

    @property
    def total(self) -> int:
        return len(self.units)

    @property
    def built(self) -> int:
        """바이너리가 나온 단위 수 (1라운드 성공 + 자가치유 성공)."""
        return self._count(BUILD_STATUS_BUILT) + self._count(BUILD_STATUS_REPAIRED)

    @property
    def failed(self) -> int:
        return self._count(BUILD_STATUS_FAILED)

    @property
    def healed(self) -> int:
        """하네스 소스(.cc) 자가치유로 복구된 단위 수."""
        return sum(1 for u in self.units if (u.get("heal") or {}).get("ok"))

    @property
    def ok(self) -> bool:
        return self.failed == 0 and all(r.get("ok") for r in self.regression)

    def binaries(self) -> dict[str, str]:
        """{group: 바이너리 경로} — EXE 가 직접 실행할 목록."""
        return {u["group"]: u["binary"] for u in self.units if u.get("binary")}

    def groups(self, corpus_root: str | Path | None = None) -> list[dict]:
        """EXE(``logosfuzz fuzz --groups``) 입력 — ``cli.discover_groups`` 형식.

        ``name`` 은 Logic Group 이름이다. 4주차 리포트(reporting/summary.py)가 이
        이름으로 build_summary 와 조인하므로 다른 이름을 쓰면 안 된다.
        ``corpus`` 는 ``<corpus_root>/<group>`` 폴더가 실제로 있을 때만 넣는다.
        """
        root = Path(corpus_root).expanduser().resolve() if corpus_root else None
        out: list[dict] = []
        for unit in self.units:
            if not unit.get("binary"):
                continue
            # 심볼릭 링크를 **풀어서** 실제 파일 경로를 넘긴다. bazel-out 의 `_bin` 은 execroot 의
            # `..._raw_` 로 가는 링크인데, EXE(docker_runner)는 호스트 경로를 resolve() 한 폴더를
            # 마운트하면서 컨테이너 안 실행 경로에는 harness_path.name 을 그대로 쓴다. 링크 경로를
            # 주면 마운트된 폴더에 `_bin` 이 없어 컨테이너에서 실행이 실패한다.
            # (build_summary·artifact 는 `_bin` 경로를 유지한다. 리포트 조인은 그룹 이름 기준이다.)
            entry = {"name": unit["group"],
                     "harness": str(Path(unit["binary"]).expanduser().resolve())}
            if root is not None and (root / unit["group"]).is_dir():
                entry["corpus"] = str(root / unit["group"])
            out.append(entry)
        return out

    def to_dict(self) -> dict:
        return {
            "schema_version": BUILD_SUMMARY_SCHEMA_VERSION,
            "build_system": "bazel",
            "workspace": self.workspace,
            "config": self.config,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "total_units": self.total,
            "built_units": self.built,
            "repaired_units": self._count(BUILD_STATUS_REPAIRED),
            "healed_units": self.healed,
            "failed_units": self.failed,
            "emitted_units": self._count(BUILD_STATUS_EMITTED),
            "skipped_groups": list(self.skipped),
            "regression": list(self.regression),
            "units": list(self.units),
        }


# BUILD 파일을 고쳐야 풀리는 처방(D 의 FixAction 값). 소스 자가치유 대상이 아니다.
_BUILD_FILE_ACTIONS = frozenset({
    "add_load", "fix_build_syntax", "define_target", "expand_visibility",
    "add_deps", "fix_dep_label", "add_srcs_file",
})
_NOT_AUTO_FIXABLE_ACTIONS = frozenset({"break_cycle", "escalate"})

# D 분류기가 없을 때의 폴백 판별(dev 병합 전).
_BUILD_CAUSE_RE = re.compile(
    r"no such (?:target|package)|is not visible from|"
    r"fatal error: '[^']+' file not found|dependency cycle", re.IGNORECASE)
_SOURCE_ERROR_RE = re.compile(
    r"\.(?:cc|cpp|cxx|hpp|hh|h):\d+:\d+: (?:fatal )?error:|undefined reference|"
    r"ld(?:\.lld)?: error")


def _d_classify(log: str, bin_label: str):
    """D 의 ``bazel_errors.classify``. 없거나 실패하면 None."""
    try:
        from logosfuzz.generate.bazel_errors import classify
    except ImportError:
        return None
    try:
        return classify(log, requested_target=bin_label)
    except Exception:
        return None


def is_source_error(log: str, bin_label: str, classify=None) -> bool:
    """빌드 실패 원인이 하네스 **소스(.cc)** 에러인가.

    BUILD 파일(deps·load·visibility)을 고쳐야 풀리는 실패는 소스를 아무리 다시
    써도 같은 에러가 반복되므로 자가치유(LLM) 대상이 아니다. 판별은

    1. D 분류기가 있으면 그 처방으로: BUILD 수정/사람 판단 -> False, 심볼 해결 -> True
    2. 분류 못 했거나 D 가 없으면 로그로: BUILD 원인 문구가 있으면 False,
       소스 컴파일 에러·링크 에러 문구가 있으면 True
    """
    report = (classify or _d_classify)(log or "", bin_label)
    primary = getattr(report, "primary", None)
    if primary is not None:
        action = str(getattr(getattr(primary, "action", ""), "value",
                             getattr(primary, "action", "")))
        if action in _BUILD_FILE_ACTIONS or action in _NOT_AUTO_FIXABLE_ACTIONS:
            return False
        if action == "resolve_symbol":
            return True
    if _BUILD_CAUSE_RE.search(log or ""):
        return False
    return bool(_SOURCE_ERROR_RE.search(log or ""))


def _heal_details(heal) -> dict:
    """SelfHealLoop 결과에서 원인 파악에 필요한 것만 뽑는다(없는 속성은 건너뛴다).

    자가치유가 ``exhausted`` 로 끝났다는 사실만으로는 왜 실패했는지 알 수 없다.
    마지막 라운드의 에러 요약과 라운드별 분류·LLM 메모를 build_summary.json 에 남긴다.
    """
    details: dict = {}
    last = getattr(heal, "last_compile", None)
    digest = getattr(last, "error_digest", None)
    if callable(digest):
        try:
            details["error_digest"] = digest()
        except Exception:
            pass
    rounds = []
    for item in getattr(heal, "rounds", None) or []:
        rounds.append({
            "index": getattr(item, "index", None),
            "ok": bool(getattr(item, "ok", False)),
            "diagnosis": getattr(item, "diagnosis", "") or "",
            "note": getattr(item, "llm_note", "") or "",
        })
    if rounds:
        details["rounds"] = rounds
    return details


class HealUnavailable(RuntimeError):
    """소스 자가치유에 필요한 모듈(D, dev 병합 후)이 없을 때."""


class BuildStage:
    """GEN-03-01 의 HarnessPair 들을 빌드한다.

    빌드·자가치유 자체는 2주차 ``BuildFileGenerator`` 가 한다. 이 클래스는
    파이프라인 단계로서 (1) 쌍을 순서대로 넘기고 (2) 결과를 빌드 단위 키로
    정리하고 (3) 회귀 게이트를 선택적으로 돌리는 것만 맡는다.

    adapter 를 주입할 수 있어서 테스트는 bazel 없이 가짜 어댑터로 돈다.

    소스 자가치유(``heal_rounds > 0``): BUILD deps 수리로도 못 고친 실패의 원인이
    하네스 소스 에러면 D 의 ``SelfHealLoop(BazelCompiler)`` 로 넘긴다. 이 경로는
    LLM 이 필요하고 D 모듈(origin/dev)이 있어야 하며, 없으면 건너뛰고 기록만 남긴다.
    ``heal_loop_factory(pair, spec) -> loop`` 로 루프를 주입할 수 있다(테스트용).
    """

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        config: str = "fuzz",
        bazel: str = "bazel",
        max_rounds: int = 3,
        deps_provider=None,
        adapter=None,
        timeout_s: float | None = None,
        emit_only: bool = False,
        stream=None,
        heal_rounds: int = 0,
        llm=None,
        plans: dict | None = None,
        group_meta: dict | None = None,
        heal_loop_factory=None,
        classify_errors=None,
    ) -> None:
        from logosfuzz.generate.bazel.adapter import BazelAdapter

        self.workspace_root = Path(workspace_root).expanduser().resolve()
        self.config = config
        self.bazel = bazel
        self.timeout_s = timeout_s
        self.max_rounds = max_rounds
        self.deps_provider = deps_provider
        self.emit_only = emit_only
        self.heal_rounds = max(0, heal_rounds)
        self.llm = llm
        self.plans = plans or {}
        self.group_meta = group_meta or {}
        self.heal_loop_factory = heal_loop_factory
        self.classify_errors = classify_errors
        self.stream = stream or sys.stdout
        self.adapter = adapter or BazelAdapter(
            self.workspace_root, config=config, bazel=bazel, timeout_s=timeout_s,
        )

    def _log(self, msg: str) -> None:
        self.stream.write(msg + "\n")
        self.stream.flush()

    def _find_binary(self, spec):
        """최종 바이너리 경로 — cquery 기반 ``BazelAdapter.binary_path`` 로 다시 구한다.

        D 의 ``BazelCompiler.artifact_path()`` 는 ``bazel-bin`` 심볼릭 링크를 추측하고
        ``@repo//`` 라벨을 못 다룬다. 링크는 직전 빌드 설정을 가리켜서 쉽게 어긋난다.
        """
        finder = (getattr(self.adapter, "binary_path", None)
                  or getattr(self.adapter, "_binary_path", None))
        return finder(spec) if callable(finder) else None

    def _make_heal_loop(self, pair, spec):
        if self.heal_loop_factory is not None:
            return self.heal_loop_factory(pair, spec)
        try:
            from logosfuzz.generate.bazel_compiler import BazelCompiler
            from logosfuzz.generate.selfheal import SelfHealLoop
        except ImportError as exc:
            raise HealUnavailable(
                f"소스 자가치유에 D 모듈이 필요하다 (origin/dev 병합 필요): {exc}") from exc
        llm = self.llm
        if llm is None:
            from logosfuzz.generate.llm import OpenAILLMClient
            llm = OpenAILLMClient()
        compiler = BazelCompiler(
            self.workspace_root,
            target=spec.bin_label,
            source_path=pair.source_relpath,
            config=self.config,
            timeout_sec=self.timeout_s or 900.0,
            executable=self.bazel,
        )
        loop = SelfHealLoop(compiler, llm, max_round=self.heal_rounds)
        plans = self.plans.get(pair.group_name) or []
        if plans:
            plans[0].configure_self_heal(loop)  # A 의 KB 힌트 주입
        # 생성 때 프롬프트에 넣은 실제 헤더 선언(소속 클래스·static·public)을 수리 프롬프트에도
        # 준다. 로그만 보면 "JsonData 가 없다" 같은 증상만 보이고 API 모양은 알 수 없다.
        declarations = (self.group_meta.get(pair.group_name) or {}).get("header_content")
        if declarations:
            knowledge = dict(getattr(loop, "knowledge", None) or {})
            knowledge.setdefault("api_declarations", "\n" + declarations)
            loop.knowledge = knowledge
        return loop

    def _heal_source(self, pair, report) -> dict | None:
        """BUILD 수리 후에도 실패했고 원인이 소스 에러면 SelfHealLoop 로 넘긴다.

        None 이면 자가치유 대상이 아니다(BUILD 원인 등). 반환 dict 는 unit["heal"].
        """
        spec = report.spec
        log = report.rounds[-1].build.log if report.rounds else ""
        if not is_source_error(log, spec.bin_label, self.classify_errors):
            return None
        try:
            loop = self._make_heal_loop(pair, spec)
        except HealUnavailable as exc:
            self._log(f"      [HEAL] skipped: {exc}")
            return {"attempted": False, "ok": False, "outcome": "unavailable",
                    "rounds_used": 0, "reason": str(exc)}

        from logosfuzz.generate.models import HarnessDraft

        # 생성기는 마지막 수리 spec 을 쓰지 않고 끝날 수 있다 — 자가치유가 컴파일할
        # BUILD 를 마지막 spec 으로 맞춰 둔다.
        self.adapter.emit_build_definition(spec, pair.source)
        apis = [p.api_name for p in self.plans.get(pair.group_name) or []]
        draft = HarnessDraft(
            logic_group=pair.group_name, source=pair.source, target_apis=apis,
            language=pair.language, context={"bazel_target": spec.bin_label},
        )
        self._log(f"      [HEAL] source error -> SelfHealLoop(max_round={self.heal_rounds})")
        heal = loop.run(draft)
        outcome = getattr(heal, "outcome", "")
        info = {
            "attempted": True,
            "ok": bool(getattr(heal, "success", False)),
            "outcome": str(getattr(outcome, "value", outcome)),
            "rounds_used": int(getattr(heal, "rounds_used", 0) or 0),
            "reason": "",
            "binary": None,
            **_heal_details(heal),
        }
        self._log(f"      [HEAL] {info['outcome']} (LLM rounds={info['rounds_used']})")
        if not info["ok"]:
            info["reason"] = str(getattr(heal, "hitl_decision", "") or info["outcome"])
            for line in (info.get("error_digest") or "").splitlines()[:5]:
                self._log(f"        {line}")
            return info
        binary = self._find_binary(spec)
        if binary is None:
            info.update(ok=False, reason="빌드는 통과했지만 바이너리 경로를 찾지 못했다")
            return info
        info["binary"] = str(binary)
        pair.source = getattr(heal, "final_source", None) or pair.source
        return info

    @staticmethod
    def _status(report) -> str:
        if report.repaired:
            return BUILD_STATUS_REPAIRED
        if report.ok:
            return BUILD_STATUS_BUILT
        return BUILD_STATUS_FAILED

    def run(self, pairs, *, skipped: list[str] | None = None,
            regression: bool = False) -> BuildStageResult:
        from logosfuzz.generate.bazel.repair import BuildFileRepairer, default_classifier
        from logosfuzz.generate.build_file_generator import BuildFileGenerator

        result = BuildStageResult(
            workspace=str(self.workspace_root),
            config=self.config,
            started_at=datetime.now().isoformat(),
            skipped=list(skipped or []),
        )
        generator = BuildFileGenerator(
            adapter=self.adapter,
            deps_provider=self.deps_provider,
            # D 분류기 우선, 못 분류하면 내장 분류기 (dev 병합 전에는 내장만)
            repairer=BuildFileRepairer(classifier=default_classifier()),
            max_rounds=self.max_rounds,
        )

        self._log(f"\n[BUILD] {len(pairs)} pair(s) -> {self.workspace_root} "
                  f"(--config={self.config}{', emit-only' if self.emit_only else ''})")
        for i, pair in enumerate(pairs, 1):
            base = {
                "group": pair.group_name,
                "build_target": pair.target_label,
                "build_system": "bazel",
                "fuzz_target": pair.spec.label,
                "bin_target": pair.spec.bin_label,
                "source": pair.source_relpath,
                "build_file": pair.build_relpath,
            }
            if self.emit_only:
                self.adapter.emit_build_definition(pair.spec, pair.source)
                result.units.append({
                    **base, "status": BUILD_STATUS_EMITTED, "ok": None,
                    "repaired": False, "rounds_used": 0, "binary": None,
                    "deps": list(pair.spec.deps), "rounds": [],
                })
                self._log(f"  [{i}/{len(pairs)}] {pair.group_name}: emitted {pair.build_relpath}")
                continue

            report = generator.generate(pair.target_label, pair.source, spec=pair.spec)
            unit = {**report.to_dict(), **base, "status": self._status(report),
                    "deps": list(report.spec.deps)}
            # to_dict 의 "target" 은 build_target 과 같은 값이라 중복 키를 없앤다.
            unit.pop("target", None)
            if not report.ok and self.heal_rounds > 0:
                heal = self._heal_source(pair, report)
                if heal is not None:
                    unit["heal"] = heal
                    if heal["ok"]:
                        unit.update(status=BUILD_STATUS_REPAIRED, ok=True, repaired=True,
                                    binary=heal["binary"])
            result.units.append(unit)
            self._log(f"  [{i}/{len(pairs)}] {pair.group_name}: {unit['status']}"
                      f" (rounds={report.rounds_used})")
            for line in report.summary().splitlines()[1:]:
                self._log(f"      {line}")

        if regression and not self.emit_only:
            regress = getattr(self.adapter, "regression_build", None)
            if callable(regress):
                for target in dict.fromkeys(p.target_label for p in pairs):
                    r = regress(target)
                    result.regression.append({
                        "build_target": target, "ok": r.ok,
                        "duration_s": round(r.duration_s, 2),
                        "error_excerpt": "" if r.ok else r.short_log,
                    })
                    self._log(f"  [REGRESSION] {target}: {'OK' if r.ok else 'FAIL'}")

        result.finished_at = datetime.now().isoformat()
        self._log(f"[BUILD] built {result.built}/{result.total}"
                  f" (repaired {result._count(BUILD_STATUS_REPAIRED)},"
                  f" source-healed {result.healed}, failed {result.failed})")
        return result

    @staticmethod
    def write(result: BuildStageResult, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(result.to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return destination


    @staticmethod
    def build_artifacts(result: BuildStageResult, plans: dict | None = None, *,
                        gen_model: str = "", corpus_root: str | Path | None = None) -> list:
        """빌드 성공 그룹마다 D 검증 게이트 입력(``contracts.HarnessArtifact``)을 만든다.

        kb_bridge.build_harness_from_kb 가 만드는 것과 같은 형태다:
        harness_path=바이너리, source_path=워크스페이스의 하네스 .cc,
        api_signatures=A 의 계획(plan)에서. 계획이 없으면(--pairs/--harness) 빈 목록.
        """
        from logosfuzz.generate.contracts import HarnessArtifact

        workspace = Path(result.workspace)
        root = Path(corpus_root).expanduser().resolve() if corpus_root else None
        artifacts = []
        for unit in result.units:
            if not unit.get("binary"):
                continue
            group = unit["group"]
            corpus = root / group if root is not None and (root / group).is_dir() else None
            artifacts.append(HarnessArtifact(
                group_id=group,
                harness_path=Path(unit["binary"]),
                source_path=workspace / unit["source"] if unit.get("source") else None,
                corpus_dir=corpus,
                api_signatures=[p.api_signature() for p in (plans or {}).get(group) or []],
                gen_model=gen_model,
            ))
        return artifacts

    @staticmethod
    def write_artifacts(artifacts, path: str | Path) -> Path:
        def _path(value):
            return str(value) if value is not None else None

        data = {
            "schema_version": BUILD_SUMMARY_SCHEMA_VERSION,
            "artifacts": [{
                "group_id": a.group_id,
                "harness_path": _path(a.harness_path),
                "source_path": _path(a.source_path),
                "corpus_dir": _path(a.corpus_dir),
                "api_signatures": [
                    {"name": g.name, "param_types": list(g.param_types),
                     "return_type": g.return_type, "source": g.source}
                    for g in a.api_signatures
                ],
                "gen_model": a.gen_model,
            } for a in artifacts],
        }
        return BuildStage._write_json(path, data)

    @staticmethod
    def write_groups(result: BuildStageResult, path: str | Path,
                     corpus_root: str | Path | None = None) -> Path:
        return BuildStage._write_json(path, result.groups(corpus_root))

    @staticmethod
    def _write_json(path: str | Path, data) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
        return destination


@dataclass
class PairSource:
    """``collect_pairs_ctx`` 결과: 쌍 + 같은 입력에서 만든 deps 공급자·KB 계획."""

    pairs: list
    skipped: list[str] = field(default_factory=list)
    deps_provider: object = None
    plans: dict = field(default_factory=dict)   # {group: [HarnessBuildPlan]} (dev 병합 후)
    group_meta: dict = field(default_factory=dict)   # {group: 프롬프트 부가 정보(header_content 등)}


def save_generation_artifacts(pairs, directory: str | Path) -> list[Path]:
    """LLM 이 받은 프롬프트와 **첫 초안**을 저장한다 (``<group>.prompt.txt``, ``<group>.draft.cc``).

    자가치유가 소스를 고쳐 쓰면 디스크의 하네스는 마지막 수정본이 되어 첫 초안이 사라지고,
    프롬프트는 어디에도 남지 않는다. 생성이 왜 그렇게 나왔는지 보려면 둘 다 필요하다.
    프롬프트가 없는 쌍(``--pairs`` manifest 로 읽은 것)은 생성 기록이 없으므로 건너뛴다.
    """
    written: list[Path] = []
    target = Path(directory)
    for pair in pairs:
        if not getattr(pair, "prompt_used", ""):
            continue
        target.mkdir(parents=True, exist_ok=True)
        for suffix, text in ((".prompt.txt", pair.prompt_used), (".draft.cc", pair.source)):
            path = target / f"{pair.group_name}{suffix}"
            path.write_text(text, encoding="utf-8")
            written.append(path)
    return written


def collect_pairs(args) -> tuple[list, list[str]]:
    """CLI 인자에서 빌드할 HarnessPair 목록을 모은다 (기존 호환용)."""
    source = collect_pairs_ctx(args)
    return source.pairs, source.skipped


def collect_pairs_ctx(args) -> PairSource:
    """CLI 인자에서 빌드할 HarnessPair 목록과 그 부속 정보를 모은다.

    우선순위: --pairs(manifest) > --harness(단일) > --kb(LLM 생성).
    """
    from logosfuzz.generate import gen_03_01_harness_generator as gen

    workspace = Path(args.workspace).expanduser() if args.workspace else None

    def provider_for(kb=None):
        try:
            return gen.make_deps_provider(args.deps, workspace, kb=kb)
        except ValueError as exc:
            raise SystemExit(f"[ERROR] {exc}") from exc

    if args.pairs:
        return PairSource(gen.load_pairs(args.pairs), [], provider_for())

    if args.harness:
        if not args.build_target:
            raise SystemExit("--harness 는 --build-target 과 함께 써야 한다")
        from logosfuzz.generate.llm_harness_generator import FuzzDriver, LANG_CPP

        code = Path(args.harness).read_text(encoding="utf-8")
        group = args.group or Path(args.harness).stem
        driver = FuzzDriver(group_name=group, code=code, language=LANG_CPP,
                            build_target=args.build_target)
        provider = provider_for()
        return PairSource([gen.pair_driver(driver, args.build_target, provider)], [], provider)

    if args.kb:
        from logosfuzz.knowledge.knowledge_base import KnowledgeBase

        only = list(getattr(args, "only", None) or [])
        try:
            gen.filter_groups([], only)            # 잘못된 정규식은 LLM 호출 전에 알린다
        except ValueError as exc:
            raise SystemExit(f"[ERROR] {exc}") from exc
        kb = KnowledgeBase.load(str(args.kb))
        provider = provider_for(kb)
        plans: dict = {}
        group_meta: dict = {}
        pairs, skipped = gen.generate_pairs_from_kb(
            kb,
            workspace_root=workspace,
            deps_provider=provider,
            budget_sec=args.budget,
            top_n=args.top,
            default_target=args.build_target or "",
            plans_out=plans,
            only=only,
            meta_out=group_meta,
        )
        if args.stage_dir:
            manifest = gen.write_pairs(pairs, args.stage_dir)
            print(f"[GEN-03-01] 쌍 {len(pairs)}개 스테이징 -> {manifest}")
        return PairSource(pairs, skipped, provider, plans, group_meta)

    raise SystemExit("--mode bazel 에는 --pairs / --harness / --kb 중 하나가 필요하다")


# ---------------------------------------------------------------------
# 4. Regression Tester
# ---------------------------------------------------------------------

@dataclass
class RegressionResult:
    passed: bool
    baseline_count: int
    current_count: int
    message: str


class RegressionTester:
    """
    Compares current pipeline output against a saved baseline.
    Detects regression in harness count or structure.
    """

    def save_baseline(self, pipeline_result: PipelineResult, baseline_path: str):
        """Save current run as baseline."""
        baseline = {
            "run_id": pipeline_result.run_id,
            "source": pipeline_result.source,
            "harness_count": pipeline_result.harness_count,
            "success": pipeline_result.success,
            "saved_at": datetime.now().isoformat(),
        }
        Path(baseline_path).write_text(json.dumps(baseline, indent=2), encoding="utf-8")
        print(f"\n[BASELINE] Saved to {baseline_path}")

    def compare(self, current: PipelineResult, baseline_path: str) -> RegressionResult:
        """Compare current result against baseline."""
        if not Path(baseline_path).exists():
            return RegressionResult(
                passed=False,
                baseline_count=0,
                current_count=current.harness_count,
                message=f"Baseline not found: {baseline_path}"
            )

        baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        baseline_count = baseline.get("harness_count", 0)
        current_count = current.harness_count

        passed = current_count >= baseline_count

        print(f"\n=== Regression Test ===")
        print(f"  Baseline harness count : {baseline_count}")
        print(f"  Current  harness count : {current_count}")
        print(f"  Result : {'PASS ✅' if passed else 'REGRESSION DETECTED ❌'}")

        return RegressionResult(
            passed=passed,
            baseline_count=baseline_count,
            current_count=current_count,
            message="OK" if passed else f"Regression: harness count dropped {baseline_count} -> {current_count}"
        )

    # --- BUILD 단계용 (3주차) --------------------------------------------
    # 비교 기준은 "바이너리가 나온 빌드 단위 수" 다. 그룹 이름은 LLM·스케줄
    # 결과에 따라 바뀔 수 있어서 이름별 비교는 하지 않는다. 대신 이전에
    # 성공했는데 이번에 실패한 빌드 단위(build_target)는 메시지에 적는다.

    def save_build_baseline(self, build_result: BuildStageResult, baseline_path: str):
        built_targets = sorted({
            u["build_target"] for u in build_result.units
            if u.get("status") in (BUILD_STATUS_BUILT, BUILD_STATUS_REPAIRED)
        })
        baseline = {
            "mode": "bazel",
            "total_units": build_result.total,
            "built_units": build_result.built,
            "built_targets": built_targets,
            "saved_at": datetime.now().isoformat(),
        }
        Path(baseline_path).write_text(json.dumps(baseline, indent=2), encoding="utf-8")
        print(f"\n[BASELINE] Saved to {baseline_path}")

    def compare_build(self, current: BuildStageResult, baseline_path: str) -> RegressionResult:
        if not Path(baseline_path).exists():
            return RegressionResult(False, 0, current.built,
                                    f"Baseline not found: {baseline_path}")
        baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        baseline_count = int(baseline.get("built_units", 0))
        current_targets = {
            u["build_target"] for u in current.units
            if u.get("status") in (BUILD_STATUS_BUILT, BUILD_STATUS_REPAIRED)
        }
        lost = sorted(set(baseline.get("built_targets") or []) - current_targets)
        passed = current.built >= baseline_count and not lost

        print("\n=== Regression Test (BUILD) ===")
        print(f"  Baseline built units : {baseline_count}")
        print(f"  Current  built units : {current.built}")
        if lost:
            print(f"  Lost build targets   : {lost}")
        print(f"  Result : {'PASS ✅' if passed else 'REGRESSION DETECTED ❌'}")

        if passed:
            message = "OK"
        elif lost:
            message = f"Regression: build targets no longer build: {lost}"
        else:
            message = f"Regression: built units dropped {baseline_count} -> {current.built}"
        return RegressionResult(passed, baseline_count, current.built, message)




# ---------------------------------------------------------------------
# 5. Main
# ---------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CTR-06-01 Controller")
    parser.add_argument("--mode", choices=("pipeline", "bazel"), default="pipeline",
                        help="pipeline: 기존 C 파이프라인 / bazel: .cc+BUILD 쌍 빌드 단계")
    parser.add_argument("--source", default="test_target.c", help="Target C/C++ source file")
    parser.add_argument("--output", default="harness_output.c", help="Output harness file")
    parser.add_argument("--budget", type=int, default=3600, help="Fuzzing budget (seconds)")
    parser.add_argument("--baseline", default="baseline.json", help="Baseline JSON path")
    parser.add_argument("--save-baseline", action="store_true", help="Save current run as baseline")
    parser.add_argument("--regression", action="store_true", help="Run regression test")
    parser.add_argument("--skip-check", action="store_true", help="Skip compatibility check")

    bz = parser.add_argument_group("bazel mode (3주차 BUILD 단계)")
    bz.add_argument("--workspace", help="Bazel 워크스페이스 루트 (예: ~/baselibs)")
    bz.add_argument("--pairs", help="GEN-03-01 manifest (harness_pairs.json)")
    bz.add_argument("--harness", help="단일 하네스 .cc 경로")
    bz.add_argument("--build-target", default="",
                    help="--harness 의 대상 라벨 / --kb 에서 빌드 단위가 없는 그룹의 기본 라벨")
    bz.add_argument("--group", default="", help="--harness 의 그룹 이름 (기본: 파일 stem)")
    bz.add_argument("--kb", help="KB JSON — LLM 으로 쌍을 생성한 뒤 빌드")
    bz.add_argument("--top", type=int, default=0, help="--kb: 시너지 랭킹 상위 N개 그룹만 (--only 로 거른 뒤 적용)")
    bz.add_argument("--only", action="append", default=[], metavar="REGEX",
                    help="--kb: 그룹 이름·빌드 단위가 이 정규식에 맞는 그룹만(반복 가능). "
                         "예: --only '//score/json:json$'. --top 은 그 안에서 적용. "
                         "목록은 gen_03_01_harness_generator --kb ... --list-groups")
    bz.add_argument("--stage-dir", default="",
                    help="--kb: 생성한 쌍을 이 폴더에도 manifest 와 함께 남긴다")
    bz.add_argument("--deps", choices=("auto", "kb", "static", "query"), default="auto",
                    help="deps 공급자. auto: --kb 가 있으면 KB(kb_bridge), 없으면 static / "
                         "kb: KB 의 Bazel 의존성 / static: 1주차 검증 deps / query: bazel query")
    bz.add_argument("--config", default="fuzz", help="bazel --config (기본 fuzz)")
    bz.add_argument("--bazel", default="bazel", help="bazel 실행 파일 (bazelisk 등)")
    bz.add_argument("--max-build-rounds", type=int, default=3,
                    help="BUILD 룰 자가치유 최대 라운드")
    bz.add_argument("--build-timeout", type=float, default=None,
                    help="bazel 호출 1회 타임아웃(초)")
    bz.add_argument("--emit-only", action="store_true",
                    help="워크스페이스에 .cc/BUILD 만 쓰고 빌드하지 않는다")
    bz.add_argument("--regression-build", action="store_true",
                    help="빌드 후 --config=bl-x86_64-linux 로 대상 회귀 빌드")
    bz.add_argument("--build-summary", default="out/build_summary.json",
                    help="BUILD 단계 결과 JSON 경로")
    bz.add_argument("--heal-rounds", type=int, default=0,
                    help="BUILD 수리로 못 고친 하네스 소스(.cc) 컴파일 에러의 자가치유 최대 "
                         "라운드 (0=끔, 기본). LLM(OPENAI_API_KEY)과 origin/dev 병합이 필요하다")
    bz.add_argument("--groups-out", default="",
                    help="EXE(logosfuzz fuzz --groups) 입력 JSON 저장 경로")
    bz.add_argument("--artifacts-out", default="",
                    help="D 검증 게이트용 HarnessArtifact 목록 JSON 저장 경로")
    bz.add_argument("--corpus-dir", default="",
                    help="그룹별 시드 코퍼스 루트(<dir>/<group>). groups/artifacts 에 반영")
    bz.add_argument("--prompts-dir", default="",
                    help="LLM 프롬프트·첫 초안 저장 폴더 (기본: --build-summary 옆의 prompts/)")
    bz.add_argument("--no-save-prompts", action="store_true",
                    help="프롬프트·첫 초안을 저장하지 않는다")
    bz.add_argument("--gen-model", default="",
                    help="artifact 의 gen_model 값 (ANA 추적용)")
    return parser


def run_bazel_mode(args) -> int:
    if not args.workspace:
        print("[ERROR] --mode bazel 에는 --workspace 가 필요하다", file=sys.stderr)
        return 2

    if not args.skip_check:
        checker = CompatibilityChecker()
        passed = checker.run_all(
            require_bazel=not args.emit_only,
            require_openai=bool(args.kb) or args.heal_rounds > 0,
            workspace=args.workspace,
            bazel=args.bazel,
        )
        if not passed:
            print("[WARN] Some checks failed. Continuing anyway...\n")

    source = collect_pairs_ctx(args)
    pairs, skipped = source.pairs, source.skipped
    if skipped:
        print(f"[WARN] 빌드 단위를 몰라 건너뛴 그룹: {skipped}")
    if not pairs:
        print("[ERROR] 빌드할 쌍이 없다", file=sys.stderr)
        return 1
    if not args.no_save_prompts:
        prompts_dir = Path(args.prompts_dir) if args.prompts_dir \
            else Path(args.build_summary).parent / "prompts"
        saved = save_generation_artifacts(pairs, prompts_dir)
        if saved:
            print(f"[GEN] 프롬프트·첫 초안 저장 -> {prompts_dir} ({len(saved)}개)")

    workspace = Path(args.workspace).expanduser()
    stage = BuildStage(
        workspace,
        config=args.config,
        bazel=args.bazel,
        max_rounds=args.max_build_rounds,
        deps_provider=source.deps_provider,
        timeout_s=args.build_timeout,
        emit_only=args.emit_only,
        heal_rounds=args.heal_rounds,
        plans=source.plans,
        group_meta=source.group_meta,
    )
    result = stage.run(pairs, skipped=skipped, regression=args.regression_build)
    path = BuildStage.write(result, args.build_summary)
    print(f"  -> {path}")
    for group, binary in result.binaries().items():
        print(f"  [BIN] {group}: {binary}")

    corpus_root = args.corpus_dir or None
    if args.groups_out:
        print(f"  -> {BuildStage.write_groups(result, args.groups_out, corpus_root)}"
              f"  (EXE: logosfuzz fuzz --groups)")
    if args.artifacts_out:
        artifacts = BuildStage.build_artifacts(
            result, source.plans, gen_model=args.gen_model, corpus_root=corpus_root)
        print(f"  -> {BuildStage.write_artifacts(artifacts, args.artifacts_out)}"
              f"  ({len(artifacts)} artifact)")

    tester = RegressionTester()
    if args.save_baseline:
        tester.save_build_baseline(result, args.baseline)
    elif args.regression:
        if not tester.compare_build(result, args.baseline).passed:
            return 1

    print("\n=== CTR-06-01 Complete ===")
    return 0 if result.ok else 1


def run_pipeline_mode(args) -> int:
    # Step 1: Compatibility check
    if not args.skip_check:
        checker = CompatibilityChecker()
        passed = checker.run_all()
        if not passed:
            print("[WARN] Some checks failed. Continuing anyway...\n")

    # Step 2: Run pipeline
    pipeline = AutoPipeline()
    result = pipeline.run(args.source, args.output, args.budget)

    # Step 3: Save baseline or run regression test
    tester = RegressionTester()
    if args.save_baseline:
        tester.save_baseline(result, args.baseline)
    elif args.regression:
        reg = tester.compare(result, args.baseline)
        if not reg.passed:
            return 1

    print("\n=== CTR-06-01 Complete ===")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.mode == "bazel":
        return run_bazel_mode(args)
    return run_pipeline_mode(args)


if __name__ == "__main__":
    sys.exit(main())
