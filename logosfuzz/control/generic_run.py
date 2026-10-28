"""``logosfuzz run``: 범용(비-Bazel) 대상 한 줄 E2E

프로필 하나로 EXT 부터 ANA 까지 자동 실행::

    logosfuzz run --profile targets/libsndfile.json --budget 600 -o out/libsndfile

단계와 산출물(``-o`` 아래)::

    BUILD   adapter_for(profile).prepare()   대상 라이브러리 계측 빌드 (캐시)
    EXT     KnowledgeBase.build(profile=)    kb.json
    SCH     build_groups → 시너지 랭킹 → allocate_resources(budget)
    GEN     generate_harness (LLM)           gen/<group>.prompt.txt, gen/<group>.draft.c
    HEAL    heal_loop_for(profile) 로 링크까지 빌드·자가치유·스텁   build/harness, build/bin
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
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

#: 그룹별 최소 퍼징 시간(초) (SCH 0초 배정 그룹도 최소한 실행)
MIN_GROUP_SEC = 30

DEFAULT_MODEL = "gpt-4o-mini"


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
    smoke_rounds: int = 2     # 시드 스모크에서 하네스 결함이 나오면 LLM 으로 고치는 최대 횟수 (0 이면 생략)


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
        stream=None,
    ) -> None:
        self.opts = opts
        self.out = Path(opts.output)
        self.stream = stream or sys.stdout
        self._llm = llm
        self._adapter_factory = adapter_factory
        self._session_factory = session_factory
        self._coverage_runner = coverage_runner
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
            return built, loop.compiler

    def stage_smoke(self, built, compiler):
        """퍼징 전 시드 스모크: 유효한 시드로 하네스를 한 번씩 돌려 하네스 결함을 고친다 (generate/smoke.py)."""
        from logosfuzz.execute.seeds import profile_seed_paths
        from logosfuzz.generate.hygiene import sanitize_harness
        from logosfuzz.generate.smoke import smoke_repair

        seeds = profile_seed_paths(self.profile)
        with self._stage("SMOKE") as st:
            if self.opts.smoke_rounds <= 0 or not seeds:
                st.detail["skipped"] = "smoke_rounds=0" if self.opts.smoke_rounds <= 0 else "시드 없음"
                return built
            adapter = self.make_adapter(compiler.effective_profile)
            updated, statuses = [], {}
            for entry, draft, source in built:
                spec = compiler.spec_for(draft)

                def rebuild(new_source, spec=spec):
                    adapter.emit_build_definition(spec, new_source)
                    result = adapter.build(spec)
                    return Path(result.binary) if result.ok and result.binary else None

                outcome = smoke_repair(
                    Path(entry["binary"]), source, seeds=seeds, profile=self.profile, kb=self.kb,
                    complete=lambda prompt, system: self.llm.complete(prompt, system=system),
                    rebuild=rebuild, rounds=self.opts.smoke_rounds,
                    sanitize=lambda text, draft=draft: sanitize_harness(text, draft),
                    log=self._log,
                )
                entry["smoke"] = outcome.status
                entry["smoke_rounds"] = outcome.rounds
                if outcome.source != source or outcome.rounds:
                    # 마지막으로 채택한 소스를 디스크에도 남긴다(실패한 수정본이 파일에 남지 않게)
                    entry["source"] = str(adapter.emit_build_definition(spec, outcome.source))
                    entry["binary"] = str(outcome.binary)
                statuses[entry["slug"]] = outcome.status
                self._log(f"  ▶ {entry['group']}: 시드 스모크 {outcome.status}"
                          f"{' (LLM 수정 ' + str(outcome.rounds) + '회)' if outcome.rounds else ''}"
                          f"{' - ' + outcome.detail if outcome.detail else ''}")
                updated.append((entry, draft, outcome.source))
            st.detail.update(seeds=len(seeds), groups=statuses)
            return updated

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
        from logosfuzz.cli import default_exec_dockerfile, default_exec_image
        from logosfuzz.config import CoverageMode, Engine, FuzzConfig, LogicGroup
        from logosfuzz.execute.fuzz_session import FuzzSession
        from logosfuzz.execute.seeds import profile_seed_paths, seed_group_corpora

        with self._stage("EXE") as st:
            system = self.profile.build.system
            config = FuzzConfig(
                engine=Engine.LIBFUZZER,
                timeout_sec=max(1, self.opts.budget // max(1, len(built))),
                use_docker=self.opts.use_docker,
                harness_dir=self.out / "build" / "bin",
                output_dir=self.out,
                image=self.opts.image or default_exec_image(system),
                dockerfile=default_exec_dockerfile(system),
                coverage=CoverageMode.NONE,   # 커버리지는 종료 후 최종 코퍼스 재생으로 측정
                # 범용 대상: UB 경고 한 번에 세션이 끝나지 않게 하고(실측: 11초 만에 종료),
                # 메모리 오류로 크래시가 나도 남은 시간 동안 같은 그룹을 다시 퍼징한다
                ubsan_options="print_stacktrace=1:halt_on_error=0",
                resume_after_crash=True,
            )
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
            built = self.stage_smoke(built, compiler)
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
    r.add_argument("--smoke-rounds", type=int, default=2,
                   help="시드 스모크에서 하네스 결함이 나오면 LLM 으로 고치는 최대 횟수 (기본 2, 0 이면 생략)")


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
                      coverage=args.coverage, smoke_rounds=getattr(args, "smoke_rounds", 2))


def main_run(args) -> int:
    if args.budget <= 0:
        print("[오류] --budget 은 1 이상이어야 한다", file=sys.stderr)
        return 2
    if args.max_round < 0:
        print("[오류] --max-round 는 0 이상이어야 한다", file=sys.stderr)
        return 2
    return GenericRun(options_from_args(args)).run()
