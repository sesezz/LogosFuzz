"""``logosfuzz run``: 범용(비-Bazel) 대상 한 줄 E2E

프로필 하나로 EXT 부터 ANA 까지 자동 실행::

    logosfuzz run --profile targets/libsndfile.json --budget 600 -o out/libsndfile

단계와 산출물(``-o`` 아래)::

    BUILD   adapter_for(profile).prepare()   대상 라이브러리 계측 빌드 (캐시)
    EXT     KnowledgeBase.build(profile=)    kb.json
    SCH     build_groups → 시너지 랭킹 → allocate_resources(budget)
    GEN     generate_harness (LLM)           gen/<group>.prompt.txt, gen/<group>.draft.c
    HEAL    heal_loop_for(profile) 로 링크까지 빌드·자가치유·스텁   build/harness, build/bin
    SMOKE   validation.run_smoke_test dry-run (즉시 크래시·저커버리지면 사유 넣어 재생성)
                                                          smoke/<group>/, logs/<group>/smoke.*.log
    COVBIN  같은 하네스를 커버리지 계측으로 다시 빌드              build/bin-cov
    EXE     FuzzSession (SCH 배분 시간, 시드 → corpus/<group>)   fuzz_summary.json, crashes/
    COV     collect_corpus_coverage (최종 코퍼스 재생)          coverage/<group>.summary.json
    ANA     analyze --profile (중복 제거 + 판별)               analysis.json
    요약                                                     run_summary.json, validation-summary.json

``run_summary.json`` 의 ``stages[*].automatic`` 은 모두 ``true`` (사람 개입 단계 없음)
수동 개입 내역은 docs/VERIFY-GENERIC-libsndfile.md 에 별도 기록

Bazel 프로필 미지원 (자동차 대상은 ``ctr_06_01_controller --mode bazel`` 경로 사용)
"""

from __future__ import annotations

import json
import math
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

#: 그룹별 최소 퍼징 시간(초) (SCH 0초 배정 그룹도 최소한 실행)
MIN_GROUP_SEC = 30

DEFAULT_MODEL = "gpt-4o-mini"

#: 스모크 테스트 기본값 (dry-run 실행 횟수, 시간 상한(초), 최소 edge 커버리지, 재생성 횟수)
SMOKE_RUNS = 200
SMOKE_TIMEOUT_SEC = 30
SMOKE_MIN_EDGES = 30
SMOKE_RETRIES = 2
#: 계측 edge 총수 대비 최소 비율. 대상이 작아 총수가 적으면 SMOKE_MIN_EDGES 대신 이 비율 적용
SMOKE_MIN_RATIO = 0.3

_COUNTERS_RE = re.compile(r"\((\d+) inline 8-bit counters\)")

#: 재생성 프롬프트에 넣을 dry-run 로그 최대 길이(자)
_SMOKE_LOG_CHARS = 4000

_SMOKE_RULES = """\
- 퍼징 입력 바이트로 포인터·함수 포인터·핸들 값을 채우지 않기 (memcpy 로 구조체 포인터 채우기 금지)
- 상태 핸들은 대상 라이브러리의 생성 API(open/create 계열)로 열고, 열기 실패 시 바로 return 0
- 파일 형식 라이브러리는 퍼징 입력을 메모리 버퍼로 감싼 가상 I/O(길이·seek·read·tell 콜백)로 열기
- 콜백 구조체는 모든 필드를 실제 함수로 채우기 (0 으로 비워 두지 않기)
- 퍼징 입력(data, size)이 대상 API 의 실제 처리 경로까지 전달되게 하기"""


@dataclass
class RunOptions:
    profile: Path
    budget: int
    output: Path
    max_round: int = 3
    use_docker: bool = True
    top: int = 0
    model: str = DEFAULT_MODEL
    image: Optional[str] = None
    no_build: bool = False
    coverage: bool = True
    # 스모크 테스트 (GEN-03-04 dry-run)
    smoke: bool = True
    smoke_runs: int = SMOKE_RUNS
    smoke_timeout: int = SMOKE_TIMEOUT_SEC
    smoke_min_edges: int = SMOKE_MIN_EDGES
    smoke_retries: int = SMOKE_RETRIES
    # libFuzzer 실행 옵션 (0/None 이면 FuzzConfig 기본값)
    input_timeout_ms: Optional[int] = None
    rss_limit_mb: Optional[int] = None
    malloc_limit_mb: Optional[int] = None
    max_len: int = 0
    dict_dir: Optional[Path] = None
    # fork 모드 병렬 작업 수 (0 이면 단일 프로세스)
    fork_jobs: int = 0


@dataclass
class Stage:
    name: str
    ok: bool = False
    duration_s: float = 0.0
    detail: Dict[str, Any] = field(default_factory=dict)
    automatic: bool = True

    def to_dict(self) -> dict:
        return {"stage": self.name, "ok": self.ok, "automatic": self.automatic,
                "duration_s": round(self.duration_s, 2), **self.detail}


class StageFailed(RuntimeError):
    """단계 실패로 후속 단계 실행 불가"""


# --------------------------------------------------------------------------- #
# 시간 배분
# --------------------------------------------------------------------------- #
def split_budget(schedule: Sequence[Any], budget: int, *, floor: int = MIN_GROUP_SEC) -> Dict[str, int]:
    """SCH 배분(``allocated_sec``) 기반 그룹별 최소 ``floor`` 초 보장

    합계는 ``budget`` 이하 (바닥값 합이 예산 초과 시 균등 분배)
    """
    names = [r.group_name for r in schedule]
    if not names or budget <= 0:
        return {}
    floor = min(floor, budget // len(names))
    rest = budget - floor * len(names)
    weights = {r.group_name: max(0, int(getattr(r, "allocated_sec", 0) or 0)) for r in schedule}
    total = sum(weights.values())
    out: Dict[str, int] = {}
    for name in names:
        share = (rest * weights[name] // total) if total else rest // len(names)
        out[name] = floor + share
    # 정수 나눗셈 나머지는 첫 그룹(최우선)에 배정
    out[names[0]] += budget - sum(out.values())
    return out


def smoke_threshold(log: str, min_edges: int) -> int:
    """dry-run 통과 최소 edge 수

    libFuzzer 가 출력한 계측 edge 총수(``N inline 8-bit counters``)의
    ``SMOKE_MIN_RATIO`` 와 ``min_edges`` 중 작은 값. 총수를 모르면 ``min_edges``
    (작은 예제 대상이 고정 임계치에 걸려 불필요하게 재생성되는 문제 방지)
    """
    totals = [int(n) for n in _COUNTERS_RE.findall(log or "")]
    if not totals or min_edges <= 0:
        return min_edges
    return max(1, min(min_edges, math.ceil(sum(totals) * SMOKE_MIN_RATIO)))


def _smoke_test_config(opts: "RunOptions"):
    """RunOptions → validation.SmokeTestConfig"""
    from logosfuzz.generate.validation import SmokeTestConfig

    return SmokeTestConfig(runs=opts.smoke_runs, timeout_sec=float(opts.smoke_timeout))


# --------------------------------------------------------------------------- #
# 실행기
# --------------------------------------------------------------------------- #
class GenericRun:
    """프로필 대상 E2E 실행기 (LLM, 빌드 어댑터, 퍼징 세션, 커버리지 도구 주입 가능)"""

    def __init__(
        self,
        opts: RunOptions,
        *,
        llm=None,
        adapter_factory: Optional[Callable[..., Any]] = None,
        session_factory: Optional[Callable[[Any], Any]] = None,
        coverage_runner=None,
        smoke_executor=None,
        stream=None,
    ) -> None:
        self.opts = opts
        self.out = Path(opts.output)
        self.stream = stream or sys.stdout
        self._llm = llm
        self._adapter_factory = adapter_factory
        self._session_factory = session_factory
        self._coverage_runner = coverage_runner
        self._smoke_executor = smoke_executor
        self._heal_loop = None
        self._prompts: Dict[str, str] = {}
        self.stages: List[Stage] = []
        self.profile = None
        self.kb = None
        self.groups: List[Dict[str, Any]] = []

    # ---- 공통 --------------------------------------------------------------
    def _log(self, msg: str) -> None:
        self.stream.write(msg + "\n")
        self.stream.flush()

    def _stage(self, name: str):
        run = self

        class _Ctx:
            def __enter__(self_inner):
                self_inner.stage = Stage(name)
                self_inner.started = time.monotonic()
                run._log(f"\n[{name}] 시작")
                return self_inner.stage

            def __exit__(self_inner, exc_type, exc, tb):
                stage = self_inner.stage
                stage.duration_s = time.monotonic() - self_inner.started
                if exc_type is None:
                    stage.ok = True
                elif "error" not in stage.detail:
                    stage.detail["error"] = str(exc)
                run.stages.append(stage)
                run._log(f"[{name}] {'완료' if stage.ok else '실패'} ({stage.duration_s:.1f}s)")
                return False

        return _Ctx()

    @property
    def llm(self):
        if self._llm is None:
            from logosfuzz.generate.llm import OpenAILLMClient

            self._llm = OpenAILLMClient(model=self.opts.model)
        return self._llm

    def make_adapter(self, profile, *, coverage: bool = False):
        if self._adapter_factory is not None:
            return self._adapter_factory(profile, coverage=coverage)
        from logosfuzz.generate.build import adapter_for

        return adapter_for(profile, work_dir=self.out / "build", coverage=coverage)

    # ---- 단계 --------------------------------------------------------------
    def load_profile(self):
        from logosfuzz.common.target_profile import load_profile

        self.profile = load_profile(self.opts.profile)
        return self.profile

    def stage_prepare(self) -> None:
        with self._stage("BUILD") as st:
            result = self.make_adapter(self.profile).prepare()
            st.detail.update(build_system=self.profile.build.system,
                             cached=str(result.log).startswith("(캐시)"))
            if not result.ok:
                st.detail["error"] = result.short_log
                raise StageFailed(f"대상 라이브러리 빌드 실패:\n{result.short_log}")

    def stage_ext(self) -> None:
        from logosfuzz.knowledge.knowledge_base import KnowledgeBase

        with self._stage("EXT") as st:
            self.kb = KnowledgeBase.build(profile=self.profile)
            path = self.kb.save(str(self.out / "kb.json"))
            meta = self.kb.profile or {}
            st.detail.update(kb=str(path), apis=len(self.kb.documents),
                             apis_missing=list(meta.get("apis_missing", [])))
            if not self.kb.documents:
                raise StageFailed("KB 에 퍼징할 API 가 없다 (profile.apis / 소스 경로 확인)")

    def stage_sch(self):
        from logosfuzz.generate.gen_03_01_harness_generator import (
            restrict_to_fuzzable, select_top_groups,
        )
        from logosfuzz.knowledge.kb_adapters import to_synergy_inputs
        from logosfuzz.schedule.logic_groups import build_groups, to_group_map
        from logosfuzz.schedule.sch_02_02_synergy_scheduler import (
            compute_pairwise_synergy, rank_logic_groups,
        )
        from logosfuzz.schedule.sch_02_03_resource_allocator import allocate_resources

        with self._stage("SCH") as st:
            groups = restrict_to_fuzzable(self.kb, build_groups(self.kb, domain=self.profile.domain))
            if not groups:
                raise StageFailed("퍼징 가능한 Logic Group 이 없다")
            group_map = to_group_map(groups)
            apis, constraints = to_synergy_inputs(self.kb)
            ranking = rank_logic_groups(group_map, compute_pairwise_synergy(apis, constraints))
            groups, ranking = select_top_groups(groups, ranking, self.opts.top)
            group_map = to_group_map(groups)
            schedule = allocate_resources(ranking, [], budget_sec=self.opts.budget)
            timeouts = split_budget(schedule, self.opts.budget)
            st.detail.update(groups=[
                {"group": r.group_name, "apis": [self.kb.api(a)["function"] for a in group_map[r.group_name]
                                                 if self.kb.api(a)],
                 "score": r.final_score, "allocated_sec": r.allocated_sec,
                 "fuzz_sec": timeouts.get(r.group_name, 0)}
                for r in schedule
            ])
            return groups, group_map, schedule, timeouts

    def stage_gen(self, groups, group_map, schedule):
        from logosfuzz.generate.gen_03_01_harness_generator import (
            StaticDepsProvider, group_meta_from_kb, kb_context_db, prune_call_order,
        )
        from logosfuzz.generate.llm_harness_generator import LANG_C, LANG_CPP, generate_harness

        language = LANG_CPP if self.profile.language == "cpp" else LANG_C
        with self._stage("GEN") as st:
            _, meta = group_meta_from_kb(self.kb, groups, deps_provider=StaticDepsProvider(),
                                         default_target=self.profile.name)
            context_db = kb_context_db(self.kb)
            prune_call_order(context_db, self.kb, groups)
            headers = sorted({Path(h).name for m in meta.values() for h in m.get("includes", [])})
            llm = self.llm
            drivers = generate_harness(
                list(schedule), dict(group_map),
                header_filenames=headers,
                language=language,
                context_db=context_db,
                group_meta=meta,
                llm=lambda prompt: llm.complete(prompt),
                domain=self.profile.domain,
            )
            gen_dir = self.out / "gen"
            gen_dir.mkdir(parents=True, exist_ok=True)
            suffix = ".cc" if language == LANG_CPP else ".c"
            for d in drivers:
                (gen_dir / f"{d.group_name}.prompt.txt").write_text(d.prompt_used, encoding="utf-8")
                (gen_dir / f"{d.group_name}.draft{suffix}").write_text(d.code, encoding="utf-8")
            st.detail.update(language=language, headers=headers, generated=len(drivers),
                             prompts=str(gen_dir))
            if not drivers:
                raise StageFailed("LLM 이 하네스를 하나도 만들지 못했다")
            return drivers

    def stage_heal(self, drivers, group_map):
        from logosfuzz.generate.adapter_compiler import heal_loop_for
        from logosfuzz.generate.gen_03_01_harness_generator import group_slug
        from logosfuzz.generate.hygiene import sanitize_harness
        from logosfuzz.generate.llm import RepairPromptBuilder
        from logosfuzz.generate.models import HarnessDraft

        with self._stage("HEAL") as st:
            loop = heal_loop_for(
                self.profile, self.llm, max_round=self.opts.max_round, kb=self.kb,
                adapter_factory=lambda p: self.make_adapter(p),
                work_dir=self.out / "build",
                prompt_builder=RepairPromptBuilder(domain=self.profile.domain),
                sanitize=sanitize_harness,
            )
            built = []
            for d in drivers:
                names = [self.kb.api(a)["function"] for a in group_map.get(d.group_name, [])
                         if self.kb.api(a)]
                draft = HarnessDraft(logic_group=group_slug(d.group_name), source=d.code,
                                     project=self.profile.name, target_apis=names,
                                     language=d.language)
                self._prompts[draft.logic_group] = d.prompt_used
                self._log(f"  ▶ {d.group_name} (최대 {self.opts.max_round} 라운드)")
                report = loop.run(draft)
                compiled = report.last_compile
                entry = {
                    "group": d.group_name,
                    "slug": draft.logic_group,
                    "apis": names,
                    "outcome": report.outcome.value,
                    "llm_rounds": report.rounds_used,
                    "compiles": len(report.rounds),
                    "stubbed_symbols": report.stubbed_symbols,
                    "binary": compiled.artifact_path if report.success and compiled else None,
                    "source": None,
                }
                if report.success:
                    entry["source"] = str(loop.compiler.adapter.emit_build_definition(
                        loop.compiler.spec_for(draft), report.final_source))
                    built.append((entry, draft, report.final_source))
                self.groups.append(entry)
                self._log(f"    -> {entry['outcome']} (LLM 수정 {entry['llm_rounds']}회"
                          f"{', 스텁 ' + ', '.join(entry['stubbed_symbols']) if entry['stubbed_symbols'] else ''})")
            st.detail.update(total=len(drivers), built=len(built),
                             llm_repaired=sum(1 for e, _, _ in built if e["llm_rounds"] > 0),
                             stubbed=sorted({s for e in self.groups for s in e["stubbed_symbols"]}))
            if not built:
                raise StageFailed("빌드에 성공한 하네스가 없다 (gen/ 의 초안과 run_summary 의 outcome 확인)")
            self._heal_loop = loop
            return built, loop.compiler

    def fuzz_config(self, n_groups: int):
        """SMOKE·EXE 공통 FuzzConfig (격리 이미지, libFuzzer 옵션)"""
        from logosfuzz.cli import default_exec_dockerfile, default_exec_image
        from logosfuzz.config import CoverageMode, Engine, FuzzConfig

        system = self.profile.build.system
        extra: Dict[str, Any] = {}
        if self.opts.input_timeout_ms:
            extra["per_input_timeout_ms"] = self.opts.input_timeout_ms
        if self.opts.rss_limit_mb is not None:
            extra["rss_limit_mb"] = self.opts.rss_limit_mb
        if self.opts.malloc_limit_mb is not None:
            extra["malloc_limit_mb"] = self.opts.malloc_limit_mb
        return FuzzConfig(
            engine=Engine.LIBFUZZER,
            timeout_sec=max(1, self.opts.budget // max(1, n_groups)),
            use_docker=self.opts.use_docker,
            harness_dir=self.out / "build" / "bin",
            output_dir=self.out,
            image=self.opts.image or default_exec_image(system),
            dockerfile=default_exec_dockerfile(system),
            coverage=CoverageMode.NONE,   # 커버리지는 종료 후 최종 코퍼스 재생으로 측정
            max_len=max(0, self.opts.max_len),
            fork_jobs=max(0, self.opts.fork_jobs),
            dict_dir=Path(self.opts.dict_dir) if self.opts.dict_dir else self.out / "dict",
            **extra,
        )

    def _smoke_once(self, runner, entry, seeds):
        """하네스 1개 dry-run. validation.run_smoke_test 판정 + check_coverage"""
        from logosfuzz.config import LogicGroup
        from logosfuzz.execute.seeds import seed_group_corpora
        from logosfuzz.generate.contracts import HarnessArtifact
        from logosfuzz.generate.validation import RunResult, check_coverage, run_smoke_test

        [group] = seed_group_corpora(
            [LogicGroup(name=entry["slug"], harness_path=Path(entry["binary"]))],
            seeds, self.out / "smoke" / "corpus")

        def via_isolation(_argv, timeout):  # 본 퍼징과 같은 격리(Docker/호스트)로 실행
            proc = runner.run_smoke(group, self.opts.smoke_runs, int(timeout))
            return RunResult(exit_code=proc.exit_code, timed_out=proc.timed_out,
                             log=(proc.stdout or "") + "\n" + (proc.stderr or ""))

        smoke = run_smoke_test(
            HarnessArtifact(group_id=entry["slug"], harness_path=Path(entry["binary"])),
            _smoke_test_config(self.opts), runner=via_isolation)
        if not smoke.passed:
            return smoke, smoke.reason, smoke.log
        cov = check_coverage(smoke.coverage_edges, smoke_threshold(smoke.log, self.opts.smoke_min_edges))
        return smoke, ("" if cov.passed else cov.reason), smoke.log

    def _regenerate(self, entry, draft, source, reason, log):
        """dry-run 실패 사유를 넣어 LLM 재생성 → HEAL 재빌드. 성공 시 (draft, source)"""
        from logosfuzz.generate.llm import extract_code, truncate_middle
        from logosfuzz.generate.models import HarnessDraft

        prompt = (
            f"{self._prompts.get(entry['slug'], '')}\n\n"
            "# 이전 하네스 dry-run 실패 → 다시 작성\n"
            f"아래 하네스는 컴파일은 됐지만 짧은 dry-run 에서 실패했다.\n사유: {reason}\n\n"
            f"## 이전 하네스\n```c\n{source}\n```\n\n"
            f"## dry-run 로그 (일부)\n```\n{truncate_middle(log, _SMOKE_LOG_CHARS)}\n```\n\n"
            f"## 지켜야 할 규칙\n{_SMOKE_RULES}\n\n"
            "수정한 전체 하네스 소스 파일 하나만 코드 블록으로 출력하라."
        )
        code = extract_code(self.llm.complete(prompt))
        new_draft = HarnessDraft(logic_group=draft.logic_group, source=code,
                                 project=draft.project, target_apis=list(draft.target_apis),
                                 language=draft.language)
        report = self._heal_loop.run(new_draft)
        compiled = report.last_compile
        if not (report.success and compiled):
            return None
        entry["binary"] = compiled.artifact_path
        entry["source"] = str(self._heal_loop.compiler.adapter.emit_build_definition(
            self._heal_loop.compiler.spec_for(new_draft), report.final_source))
        return new_draft, report.final_source

    def stage_smoke(self, built):
        """GEN-03-04 dry-run 게이트. 통과한 하네스만 EXE 로 전달

        걸러내는 두 경우: 시작 직후 크래시(타임아웃 포함), 크래시는 없지만
        edge 커버리지가 ``smoke_min_edges`` 미만(대상 라이브러리 미도달).
        실패 시 사유·로그를 넣어 최대 ``smoke_retries`` 회 재생성
        모두 실패하면 크래시 없는 저커버리지 하네스만 남겨 EXE 진행(전부 크래시면 중단)
        """
        from logosfuzz.execute.docker_runner import DockerIsolationRunner
        from logosfuzz.execute.errors import ExecuteError
        from logosfuzz.execute.seeds import profile_seed_paths

        with self._stage("SMOKE") as st:
            runner = DockerIsolationRunner(self.fuzz_config(len(built)),
                                           executor=self._smoke_executor)
            if self.opts.use_docker and not self.opts.no_build and self._smoke_executor is None:
                try:
                    runner.ensure_image()
                except ExecuteError as exc:
                    raise StageFailed(f"격리 이미지 준비 실패: {exc}") from exc
            seeds = profile_seed_paths(self.profile)
            passed, low_cov = [], []
            for entry, draft, source in built:
                attempts = []
                while True:
                    smoke, reason, log = self._smoke_once(runner, entry, seeds)
                    attempts.append({"passed": not reason, "reason": reason,
                                     "crashed": smoke.crashed, "timed_out": smoke.timed_out,
                                     "coverage_edges": smoke.coverage_edges})
                    self._log(f"  {entry['slug']}: dry-run "
                              f"{'통과' if not reason else '실패 - ' + reason} "
                              f"(cov {smoke.coverage_edges})")
                    if not reason or len(attempts) > self.opts.smoke_retries:
                        break
                    self._log(f"    -> 실패 사유를 넣어 재생성 ({len(attempts)}/{self.opts.smoke_retries})")
                    regenerated = self._regenerate(entry, draft, source, reason, log)
                    if regenerated is None:
                        attempts[-1]["regenerate"] = "rebuild-failed"
                        break
                    draft, source = regenerated
                last = attempts[-1]
                entry["smoke"] = {"passed": last["passed"], "regenerated": len(attempts) - 1,
                                  "attempts": attempts}
                if last["passed"]:
                    passed.append((entry, draft, source))
                elif not (last["crashed"] or last["timed_out"]):
                    low_cov.append((entry, draft, source))
            kept = passed
            if not kept and low_cov:
                self._log("  [WARN] dry-run 통과 하네스가 없다 - 크래시 없는 저커버리지 하네스로 계속한다")
                kept = low_cov
            for entry, _, _ in built:
                entry["smoke"]["used"] = any(entry is e for e, _, _ in kept)
            st.detail.update(total=len(built), passed=len(passed),
                             immediate_crash=sum(1 for e, _, _ in built
                                                 if e["smoke"]["attempts"][0]["crashed"]),
                             low_coverage=sum(1 for e, _, _ in built
                                              if not e["smoke"]["attempts"][0]["passed"]
                                              and not e["smoke"]["attempts"][0]["crashed"]),
                             regenerated=sum(e["smoke"]["regenerated"] for e, _, _ in built),
                             used=len(kept), min_edges=self.opts.smoke_min_edges)
            if not kept:
                raise StageFailed("모든 하네스가 dry-run 에서 즉시 크래시했다 (logs/<group>/smoke.stderr.log)")
            return kept

    def stage_coverage_build(self, built, compiler) -> None:
        with self._stage("COVBIN") as st:
            adapter = self.make_adapter(compiler.effective_profile, coverage=True)
            prepared = adapter.prepare()
            if not prepared.ok:
                st.detail["error"] = prepared.short_log
                raise StageFailed(f"커버리지 계측 라이브러리 빌드 실패:\n{prepared.short_log}")
            ok = 0
            for entry, draft, source in built:
                spec = compiler.spec_for(draft)
                adapter.emit_build_definition(spec, source)
                result = adapter.build(spec)
                entry["coverage_binary"] = str(result.binary) if result.ok else None
                ok += bool(result.ok)
            st.detail.update(built=ok, total=len(built))

    def stage_exe(self, built, timeouts):
        from logosfuzz.config import LogicGroup
        from logosfuzz.execute.fuzz_session import FuzzSession
        from logosfuzz.execute.seeds import profile_seed_paths, seed_group_corpora

        with self._stage("EXE") as st:
            config = self.fuzz_config(len(built))
            groups = [LogicGroup(name=e["slug"], harness_path=Path(e["binary"])) for e, _, _ in built]
            seeds = profile_seed_paths(self.profile)
            groups = seed_group_corpora(groups, seeds, self.out / "corpus")
            slug_timeouts = {e["slug"]: timeouts.get(e["group"], config.timeout_sec)
                             for e, _, _ in built}
            session = (self._session_factory or FuzzSession)(config)
            summary = session.run(groups, ensure_image=not self.opts.no_build, timeouts=slug_timeouts)
            data = summary.to_dict()
            by_slug = {g["group"]: g for g in data["groups"]}
            for entry, _, _ in built:
                g = by_slug.get(entry["slug"], {})
                entry.update(fuzz_sec=slug_timeouts[entry["slug"]], execs=g.get("execs", 0),
                             crashes=len(g.get("crashes", [])),
                             failed_to_start=g.get("failed_to_start", False),
                             corpus=str(self.out / "corpus" / entry["slug"]))
            st.detail.update(docker=self.opts.use_docker, seeds=[str(s) for s in seeds],
                             total_crashes=data["total_crashes"],
                             failed_groups=data["failed_groups"],
                             summary=str(self.out / "fuzz_summary.json"))
            if data["failed_groups"] and len(data["failed_groups"]) == len(groups):
                raise StageFailed("모든 하네스가 한 번도 실행되지 못했다 (logs/<group>/run.stderr.log)")
            return data

    def stage_cov(self, built) -> None:
        from logosfuzz.execute.coverage import collect_corpus_coverage, write_coverage

        with self._stage("COV") as st:
            measured = 0
            for entry, _, _ in built:
                binary = entry.get("coverage_binary")
                if not binary:
                    entry["coverage"] = None
                    continue
                cov = collect_corpus_coverage(
                    binary, [Path(entry["corpus"])], self.out / "coverage",
                    group=entry["slug"], runner=self._coverage_runner)
                entry["coverage"] = None if cov is None else {
                    "lines": cov.lines.to_dict(), "functions": cov.functions.to_dict(),
                    "regions": cov.regions.to_dict(), "branches": cov.branches.to_dict(),
                }
                if cov is not None:
                    write_coverage(self.out / "coverage" / f"{entry['slug']}.summary.json", cov)
                    measured += 1
                    self._log(f"  {entry['slug']}: lines {cov.lines.covered}/{cov.lines.count} "
                              f"({cov.lines.percent}%), branches {cov.branches.covered}/"
                              f"{cov.branches.count} ({cov.branches.percent}%)")
            st.detail.update(measured=measured, total=len(built))

    def stage_ana(self) -> Optional[dict]:
        from logosfuzz.analyze import cli as ana_cli

        with self._stage("ANA") as st:
            out = self.out / "analysis.json"
            argv = [
                "analyze", str(self.out / "fuzz_summary.json"),
                "--profile", str(self.opts.profile),
                "--kb", str(self.out / "kb.json"),
                "--source-root", str(self.profile.root),
                "--harness-dir", str(self.out / "build" / "harness"),
                "--review-store", str(self.out / "hitl" / "reviews.json"),
                "--project", self.profile.name,
                "-o", str(out),
            ]
            rc = ana_cli.main(argv)
            if rc != 0:
                raise StageFailed(f"analyze 종료 코드 {rc}")
            analysis = json.loads(out.read_text(encoding="utf-8"))
            st.detail.update(output=str(out), **analysis.get("summary", {}))
            return analysis

    # ---- 전체 --------------------------------------------------------------
    def run(self) -> int:
        started = datetime.now().isoformat()
        try:
            self.load_profile()
        except Exception as exc:  # ProfileError 등
            self._log(f"[프로필 오류] {exc}")
            return 2
        if self.profile.is_bazel:
            self._log("[오류] logosfuzz run 은 비-Bazel(cmake/prebuilt) 프로필용이다. 자동차(Bazel) "
                      "대상은 python -m logosfuzz.control.ctr_06_01_controller --mode bazel 을 쓴다.")
            return 2
        self.out.mkdir(parents=True, exist_ok=True)
        self._log(f"=== LogosFuzz run | {self.profile.name} ({self.profile.domain}, "
                  f"{self.profile.build.system}) budget={self.opts.budget}s "
                  f"max-round={self.opts.max_round} docker={self.opts.use_docker} -> {self.out} ===")

        rc = 0
        fuzz_summary = analysis = None
        try:
            self.stage_prepare()
            self.stage_ext()
            groups, group_map, schedule, timeouts = self.stage_sch()
            drivers = self.stage_gen(groups, group_map, schedule)
            built, compiler = self.stage_heal(drivers, group_map)
            if self.opts.smoke:
                built = self.stage_smoke(built)
            if self.opts.coverage:
                try:
                    self.stage_coverage_build(built, compiler)
                except StageFailed as exc:
                    self._log(f"  [WARN] {exc} - 커버리지 없이 계속한다")
            fuzz_summary = self.stage_exe(built, timeouts)
            if self.opts.coverage:
                self.stage_cov(built)
            analysis = self.stage_ana()
        except StageFailed as exc:
            self._log(f"\n[중단] {exc}")
            rc = 1
        except Exception as exc:  # 예상 못 한 실패(LLM 연결 오류 등)에도 요약 기록
            self._log(f"\n[중단] {type(exc).__name__}: {exc}")
            rc = 1

        self.write_summary(started, fuzz_summary, analysis, rc)
        return rc

    def write_summary(self, started: str, fuzz_summary, analysis, rc: int) -> None:
        payload = {
            "command": "logosfuzz run",
            "profile": str(self.opts.profile),
            "target": self.profile.name,
            "version": self.profile.version,
            "domain": self.profile.domain,
            "build_system": self.profile.build.system,
            "budget_sec": self.opts.budget,
            "max_round": self.opts.max_round,
            "docker": self.opts.use_docker,
            "started_at": started,
            "finished_at": datetime.now().isoformat(),
            "ok": rc == 0,
            "stages": [s.to_dict() for s in self.stages],
            "groups": self.groups,
            "totals": {
                "groups": len(self.groups),
                "harness_built": sum(1 for g in self.groups if g.get("binary")),
                "llm_repaired": sum(1 for g in self.groups if g.get("binary") and g["llm_rounds"]),
                "smoke_passed": sum(1 for g in self.groups if (g.get("smoke") or {}).get("passed")),
                "smoke_immediate_crash": sum(
                    1 for g in self.groups
                    if g.get("smoke") and g["smoke"]["attempts"][0]["crashed"]),
                "crashes": (fuzz_summary or {}).get("total_crashes", 0),
                **({k: analysis["summary"][k] for k in ("true_positive", "false_positive",
                                                         "needs_review")
                    if k in analysis.get("summary", {})} if analysis else {}),
            },
        }
        path = self.out / "run_summary.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        self._log(f"\n=== run {'완료' if rc == 0 else '중단'}: 하네스 "
                  f"{payload['totals']['harness_built']}/{payload['totals']['groups']}개 빌드, "
                  f"크래시 {payload['totals']['crashes']}건 -> {path} ===")
        if fuzz_summary is not None:
            self._write_validation_summary(fuzz_summary, analysis)

    def _write_validation_summary(self, fuzz_summary, analysis) -> None:
        from logosfuzz.reporting.summary import (
            ValidationSummaryError, build_validation_summary, profile_metadata,
            write_validation_summary,
        )
        try:
            result = build_validation_summary(fuzz_summary, analysis,
                                              metadata=profile_metadata(self.profile))
            write_validation_summary(self.out / "validation-summary.json", result)
        except (OSError, ValidationSummaryError) as exc:
            self._log(f"  [WARN] validation-summary.json 을 못 썼다: {exc}")


def add_run_parser(sub) -> None:
    r = sub.add_parser(
        "run",
        help="범용(비-Bazel) 대상 한 줄 E2E: EXT → SCH → GEN(자가치유) → EXE → 커버리지 → ANA",
    )
    r.add_argument("--profile", required=True, type=Path, help="대상 프로필 targets/*.json")
    r.add_argument("--budget", required=True, type=int,
                   help="전체 퍼징 시간(초). SCH 가 그룹별로 나눈다(그룹당 최소 30초)")
    r.add_argument("--max-round", type=int, default=3,
                   help="자가치유 LLM 수정 최대 라운드 (기본 3, 0 이면 초안만 빌드)")
    r.add_argument("--docker", dest="docker", action="store_true", default=True,
                   help="Docker 격리 퍼징(기본값)")
    r.add_argument("--no-docker", dest="docker", action="store_false",
                   help="호스트에서 직접 퍼징(격리 없음)")
    r.add_argument("--output", "-o", type=Path, default=None,
                   help="출력 디렉터리 (기본 out/<profile.name>)")
    r.add_argument("--top", type=int, default=0,
                   help="시너지 랭킹 상위 N개 그룹만 (기본 0 = 전부)")
    r.add_argument("--model", default=DEFAULT_MODEL, help=f"LLM 모델 (기본 {DEFAULT_MODEL})")
    r.add_argument("--image", default=None, help="격리 이미지 태그 (기본: 빌드 시스템으로 선택)")
    r.add_argument("--no-build", action="store_true", help="격리 이미지 자동 빌드 생략")
    r.add_argument("--no-coverage", dest="coverage", action="store_false", default=True,
                   help="커버리지 빌드·재생 생략")
    r.add_argument("--no-smoke", dest="smoke", action="store_false", default=True,
                   help="HEAL 뒤 dry-run 스모크 테스트·재생성 생략")
    r.add_argument("--smoke-retries", type=int, default=SMOKE_RETRIES,
                   help=f"dry-run 실패 시 재생성 최대 횟수 (기본 {SMOKE_RETRIES})")
    r.add_argument("--smoke-min-edges", type=int, default=SMOKE_MIN_EDGES,
                   help=f"dry-run 통과 최소 edge 커버리지 (기본 {SMOKE_MIN_EDGES})")
    r.add_argument("--smoke-runs", type=int, default=SMOKE_RUNS,
                   help=f"dry-run 실행 횟수 -runs (기본 {SMOKE_RUNS})")
    r.add_argument("--input-timeout-ms", type=int, default=None,
                   help="입력 1건 실행 제한(ms, libFuzzer -timeout). 기본 EXE-04-03 값")
    r.add_argument("--rss-limit-mb", type=int, default=None,
                   help="libFuzzer -rss_limit_mb (기본 2048, 0 이면 생략)")
    r.add_argument("--malloc-limit-mb", type=int, default=None,
                   help="libFuzzer -malloc_limit_mb (기본 2048, 0 이면 생략)")
    r.add_argument("--max-len", type=int, default=0,
                   help="libFuzzer -max_len (기본 0 = libFuzzer 자동)")
    r.add_argument("--dict-dir", type=Path, default=None,
                   help="<그룹>.dict 탐색 디렉터리 (기본 <출력>/dict). 있으면 -dict= 자동 추가")
    r.add_argument("--fork", dest="fork_jobs", type=int, default=0,
                   help="libFuzzer -fork=N -ignore_crashes=1 병렬 퍼징 (기본 0 = 단일 프로세스). "
                        "Docker --cpus 는 N 이상으로 상향")


def options_from_args(args) -> RunOptions:
    output = args.output
    if output is None:
        try:
            from logosfuzz.common.target_profile import load_profile
            output = Path("out") / load_profile(args.profile).name
        except Exception:
            output = Path("out") / Path(args.profile).stem
    return RunOptions(profile=args.profile, budget=args.budget, output=output,
                      max_round=args.max_round, use_docker=args.docker, top=args.top,
                      model=args.model, image=args.image, no_build=args.no_build,
                      coverage=args.coverage, smoke=args.smoke,
                      smoke_retries=max(0, args.smoke_retries),
                      smoke_min_edges=max(0, args.smoke_min_edges),
                      smoke_runs=max(1, args.smoke_runs),
                      input_timeout_ms=args.input_timeout_ms,
                      rss_limit_mb=args.rss_limit_mb, malloc_limit_mb=args.malloc_limit_mb,
                      max_len=max(0, args.max_len), dict_dir=args.dict_dir,
                      fork_jobs=max(0, getattr(args, "fork_jobs", 0)))


def main_run(args) -> int:
    if args.budget <= 0:
        print("[오류] --budget 은 1 이상이어야 한다", file=sys.stderr)
        return 2
    if args.max_round < 0:
        print("[오류] --max-round 는 0 이상이어야 한다", file=sys.stderr)
        return 2
    return GenericRun(options_from_args(args)).run()
