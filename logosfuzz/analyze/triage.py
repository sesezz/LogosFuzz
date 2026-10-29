"""ANA-05-01: LLM 기반 정탐/오탐(True/False Positive) 자동 판별

입력: ANA-05-04(Crash Deduplication)의 :class:`CrashCluster` 목록
출력: 클러스터별 :class:`TriageResult` (``to_triage_dict()`` 는 ANA-05-02 입력 계약과 일치)

대표 1건 판정 결과를 클러스터 전체에 적용해 LLM 호출 최소화

판별기
--------------
- :class:`RuleBasedTriager` (기본): 결함 분류 규칙과 콜스택 위치·재현성 신호 기반 결정적 휴리스틱
  (결함 분류 어휘는 :mod:`logosfuzz.analyze.categories` 단일 정의)
- :class:`LLMTriager`: 추론 특화 LLM 연동 (모델 부재 시 규칙 기반 폴백)

판정에 사용한 신호는 HITL 검토용으로 ``signals`` 에 기록
"""

from __future__ import annotations

from logosfuzz.analyze import contracts as _contracts
from logosfuzz.analyze.categories import (
    CONCURRENCY_BUGS,
    MEMORY_BUGS,
    NULL_DEREF_BUGS,
    SANITIZER_MEMORY_BUGS,
)
from logosfuzz.analyze.models import CrashCluster, TriageResult, Verdict
from logosfuzz.analyze.signature import application_frames, has_application_frame

RULE_MODEL_NAME = "logosfuzz-rule-triage/v1"

# 판정 임계값 (정탐 점수 기준)
_TP_THRESHOLD = 0.65
_FP_THRESHOLD = 0.35


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


# 프로필 없이 부르면(기존 자동차 모드 호출부) 지금까지와 같게 score::Result 계약과
# 자동차 문구 사용. 프로필이 있으면 profile.error_contract / profile.domain 기준
_LEGACY_CONTRACT = "score_result"
_LEGACY_DOMAIN = "automotive"


def _domain(profile) -> str:
    if profile is None:
        return _LEGACY_DOMAIN
    return getattr(profile, "domain", "") or "generic"


def _resolve_contract(rep, contract=None, profile=None, kb=None):
    """(플러그인, 근거). 근거가 주어지면 그 타입의 플러그인 사용"""
    if contract is not None:
        plugin = _contracts.contract_for_evidence(contract)
        if plugin is not None:
            return plugin, contract
    if profile is None:
        plugin = _contracts.get_contract(_LEGACY_CONTRACT)
    else:
        plugin = _contracts.contract_for_profile(profile)
    return plugin, plugin.analyze(rep, kb=kb, profile=profile)


def _mocking_rationale(profile) -> str:
    """mocking-fail-fp 근거문. 자동차 표현(CAN/UDS)은 automotive 에서만 사용"""
    if _domain(profile) == "automotive":
        return (
            "하네스의 가상 네트워크(CAN/UDS) 모킹 미구현으로 발생한 가짜 크래시다. "
            "대상 라이브러리 결함이 아니라 하네스 환경 문제이므로 오탐으로 판정한다. "
            "원인 모킹 코드를 보완하면 사라진다(GEN-03-03 피드백 대상)."
        )
    return (
        "하네스의 외부 장치·주변장치(HAL) 모킹 미구현으로 발생한 가짜 크래시다. "
        "대상 라이브러리 결함이 아니라 하네스 환경 문제이므로 오탐으로 판정한다. "
        "원인 모킹 코드를 보완하면 사라진다(GEN-03-03 피드백 대상)."
    )


def rule_triage(cluster: CrashCluster, context=None, contract=None,
                profile=None) -> TriageResult:
    """결정적 휴리스틱 기반 단일 클러스터 판별

    Args:
        cluster: 판별 대상
        context: :class:`~logosfuzz.analyze.reachability.ReachabilityContext`
            (선택). 정적으로 증명 가능한 도달 가능성 신호만 점수에 반영
            (불변식 추론은 ``reachability.render_for_prompt()`` 로 LLM 판별기에 위임)
        contract: 에러계약 근거(선택). ``analyze.contracts`` 플러그인이 만든 객체
            (``ErrorContractEvidence``/``CReturnCodeEvidence``/...). 없으면 대표 레코드의
            원문 로그만으로 계산 — 스택에서 읽히는 계약 위반은 KB 없이도 증명되기
            때문. KB 의 선언된 계약까지 보려면 ``ContractProvider`` 로 만든 근거 전달
        profile: :class:`~logosfuzz.common.target_profile.TargetProfile` (선택)
            있으면 ``profile.error_contract`` 로 계약 플러그인을, ``profile.domain`` 으로
            근거문 표현 선택. 없으면 기존 동작(``score_result``, 자동차 표현)
    """
    rep = cluster.representative
    plugin, contract = _resolve_contract(rep, contract, profile)
    cat = cluster.bug_type
    signals: list[str] = []

    # (0) mocking 실패 = 외부 장치 모킹 실패로 인한 가짜 크래시 → 오탐(설계서 명시)
    if cat == "mocking-fail-fp":
        return TriageResult(
            verdict=Verdict.FALSE_POSITIVE,
            confidence=0.9,
            rationale=_mocking_rationale(profile),
            triage_model=RULE_MODEL_NAME,
            cluster_id=cluster.cluster_id,
            signals=["mocking-fail-fp"],
        )

    # (1) 결함 유형 사전확률
    if cat in MEMORY_BUGS:
        score = 0.70
        signals.append("memory-corruption")
    elif cat in NULL_DEREF_BUGS:
        # 대상 코드 프레임이면 정탐 임계치를 넘지만, 에러계약이 하네스 위반을
        # 증명하면 오탐으로 내려간다 (NULL 반환 미확인이 흔한 가짜 크래시)
        score = 0.50
        signals.append("null-dereference")
    elif cat in CONCURRENCY_BUGS:
        score = 0.50
        signals.append("concurrency-needs-context")
    elif cat == "watchdog-timeout":
        score = 0.35
        signals.append("realtime-timeout")  # 타임아웃 임계치 튜닝(EXE-04-03) 대상 가능성
    else:  # unknown 등
        score = 0.30
        signals.append("unclassified-category")

    # (2) 크래시 위치: 대상 라이브러리 코드 또는 하네스
    if has_application_frame(rep):
        score += 0.20
        signals.append("target-code-frame")
    else:
        score -= 0.35
        signals.append("harness-only-frame")  # 하네스/드라이버 문제 가능성

    # (3) 재현성: 같은 시그니처의 입력 수
    if cluster.count >= 3:
        score += 0.10
        signals.append("highly-reproducible")
    elif cluster.count >= 2:
        score += 0.05
        signals.append("reproduced")

    # (4) sanitizer 신뢰도: ASAN 메모리 오류는 오탐이 드묾
    # 단, 프레임이 하네스에만 있으면 대상 라이브러리 검증이 아니므로 보너스 미부여
    if (rep.sanitizer.upper() == "ASAN" and cat in SANITIZER_MEMORY_BUGS
            and has_application_frame(rep)):
        score += 0.05
        signals.append("asan-high-fidelity")

    # (5) 도달 가능성: 실제 제품 코드의 호출 여부
    if context is not None:
        from logosfuzz.analyze.reachability import derive_signals

        delta, reach_signals = derive_signals(context)
        score += delta
        signals.extend(reach_signals)

    # (6) 에러계약: API 가 알린 오류(score::Result 오류 대안, NULL/오류 반환 코드)를
    # 누가 무시했는가 / 거부 통로가 있는 API 가 거부 대신 메모리를 깨뜨렸는가
    delta, contract_signals = plugin.derive_signals(contract, cat)
    score += delta
    signals.extend(contract_signals)

    score = _clamp(score)

    # 근거문 위치는 런타임(abort/raise 등)을 건너뛴 첫 프레임
    top = (application_frames(rep) or rep.traceback)[:1]
    loc = f"{top[0].file}:{top[0].line}" if top else "위치 미상"
    if score >= _TP_THRESHOLD:
        verdict = Verdict.TRUE_POSITIVE
        # 자동 판정은 1.0 미만으로 제한 (최종 확정은 HITL)
        confidence = _clamp(score, hi=0.95)
        rationale = (
            f"{rep.sanitizer}가 {cat.replace('-', ' ')}를 탐지했고 대상 코드({loc})에서 "
            f"발생했으며 {cluster.count}개 입력에서 동일 시그니처로 관측되어 정탐 가능성이 높다."
        )
    elif score <= _FP_THRESHOLD:
        verdict = Verdict.FALSE_POSITIVE
        confidence = _clamp(1.0 - score, hi=0.95)
        rationale = (
            f"{cat.replace('-', ' ')} 이벤트가 대상 라이브러리 코드가 아닌 하네스/실행 환경 "
            f"요인({loc})에서 비롯된 정황이 강해 오탐으로 판정한다."
        )
    else:
        verdict = Verdict.NEEDS_REVIEW
        confidence = _clamp(1.0 - abs(score - 0.5) * 2.0, 0.3, 0.9)
        rationale = (
            f"{cat.replace('-', ' ')}({loc})는 정탐/오탐 신호가 혼재해 자동 판정이 모호하다. "
            f"사람 검토(HITL)로 확정이 필요하다."
        )

    # 도달 가능성 근거는 HITL 검토 우선 정보이므로 근거문에 기록
    if "harness-only-caller" in signals:
        rationale += (
            " 이 함수는 헤더에 선언돼 있지 않고 대상 트리에서 하네스/테스트 코드만 "
            "호출한다 — 제품 경로가 아니라 하네스가 만들어낸 상황일 가능성이 크다."
        )
    elif "unreferenced-internal-function" in signals:
        rationale += (
            " 이 함수는 헤더에도 선언돼 있지 않고 대상 트리 어디에서도 호출되지 않는다"
            "(사실상 죽은 코드) — 외부 입력이 닿는 경로를 확인할 수 없다."
        )
    elif "public-api-no-in-tree-caller" in signals:
        rationale += (
            " 이 함수는 공개 헤더에 선언된 API 이나 대상 트리 안에는 호출부가 없다 — "
            "의도된 호출자가 라이브러리를 링크하는 외부 애플리케이션이라는 뜻이므로, "
            "도달 불가로 해석하면 안 된다."
        )
    # 에러계약 근거는 위 도달 가능성 근거와 독립이라 함께 기록
    rationale += plugin.render_rationale(contract)

    return TriageResult(
        verdict=verdict,
        confidence=confidence,
        rationale=rationale,
        triage_model=RULE_MODEL_NAME,
        cluster_id=cluster.cluster_id,
        signals=signals,
    )


class RuleBasedTriager:
    """결정적 규칙 기반 판별기 (기본)

    Args:
        context_provider: ``cluster -> ReachabilityContext`` 콜러블 (선택)
            ``reachability.SourceReachabilityProvider(대상_소스_루트)`` 지정 시
            호출부 증거를 점수에 반영 (없으면 기존 동작)
        contract_provider: ``cluster -> 에러계약 근거`` 콜러블(선택)
            ``contracts.ContractProvider.for_profile(profile, kb)`` 나
            ``error_contract.KnowledgeBaseContractProvider(kb)`` 를 넣으면 KB 에
            선언된 에러계약까지 근거로 사용. 없으면 원문 로그만 확인
        profile: TargetProfile (선택). 계약 플러그인·근거문 표현 선택
    """

    model_name = RULE_MODEL_NAME

    def __init__(self, context_provider=None, contract_provider=None, profile=None) -> None:
        self.context_provider = context_provider
        self.contract_provider = contract_provider
        self.profile = profile

    def triage(self, cluster: CrashCluster) -> TriageResult:
        return rule_triage(
            cluster,
            context=_safe_context(self.context_provider, cluster),
            contract=_safe_context(self.contract_provider, cluster),
            profile=self.profile,
        )


def _safe_context(provider, cluster):
    """컨텍스트 수집 실패가 판별을 막지 않도록 감싸는 래퍼"""
    if provider is None:
        return None
    try:
        return provider(cluster)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# LLM 연동 판별기
# --------------------------------------------------------------------------- #

_TRIAGE_SYSTEM = (
    "너는 C/C++ 퍼징 크래시를 분석해 정탐(true_positive)과 "
    "오탐(false_positive)을 판별하는 보안 분석가다.\n"
    "핵심 판단 기준은 '메모리 오류가 났는가'가 아니라 "
    "'그 오류를 유발한 인자·상태가 공개 API 경로로 도달 가능한가'다. "
    "sanitizer가 오류를 잡았다는 사실만으로 정탐이라고 결론짓지 마라 — "
    "퍼저가 라이브러리의 불변식을 우회해 직접 만들어낸 상태라면 오탐이다.\n"
    "판단이 모호하면 needs_review로 답한다. 반드시 JSON 하나만 출력한다."
)

# 도달 가능성 판정을 명시적으로 요구하는 질문 (1단계 검증 공통 오판 원인 보완)
_REACHABILITY_QUESTION = """\
판별 절차 — 아래 순서로 따져라.
  1. 크래시가 난 지점에서 무엇을 읽거나 쓰다 경계를 벗어났는가?
  2. 그 경계를 정하는 값(길이·인덱스·크기 필드)은 누가 넣은 값인가?
  3. 하네스가 공개 API 계약을 어겼는가? (NULL 금지 인자에 NULL, 초기화 API
     건너뛰기, 내부 구조체 필드 직접 조작 등)
  4. **결정적 질문 — 3번이 "어겼다"라도 여기서 끝내지 마라.**
     계약을 지킨 호출만으로 2번의 값이 만들어질 수 있는가?
     위 증거의 "이 상태에 값을 기록하는 API" 본문을 읽고, 그 API 를 문서대로
     호출했을 때 크래시를 유발한 값(길이·인덱스·크기)이 저장될 수 있는지 보라.
     - 만들어질 수 있다 -> **true_positive**
       (하네스가 계약을 어겼더라도 함수 자체의 로직 결함이다. 기록 API 가
        길이를 캡핑하지 않는데 소비 API 가 그 길이를 그대로 믿는 식의
        비대칭이 대표적이다.)
     - 계약 위반이 **있어야만** 재현된다(기록 API 가 그 값을 막는다)
       -> **false_positive**
     - 기록 API 소스가 없거나 판단이 안 선다 -> needs_review (추측 금지)

  주의 — 흔한 오판: "in-tree 호출부가 0곳"은 오탐 근거가 **아니다**.
  공개 헤더에 선언된 API 는 의도된 호출자가 이 소스 트리 밖(라이브러리를
  링크하는 서드파티 애플리케이션)이다. 호출부가 없다는 건 도달 불가가 아니라
  in-tree 공격 표면이 없다는 뜻일 뿐이다. 헤더에 선언돼 있으면 공개 API 로
  취급하고, 3번 질문(계약 위반이 필요한가)으로 판단하라."""


def build_triage_prompt(cluster: CrashCluster, context=None, contract=None,
                        profile=None) -> str:
    """클러스터 대표 결함의 LLM 판별용 프롬프트 직렬화

    Args:
        cluster: 판별 대상
        context: :class:`~logosfuzz.analyze.reachability.ReachabilityContext`
            (선택). 호출부·링키지·결함 라인 소스를 증거로 함께 탑재
            (없으면 콜스택만으로 판단해 "ASAN 검출 = 정탐" 편향)
    """
    rep = cluster.representative
    frames = "\n".join(f"  #{i} {f.file}:{f.line}" for i, f in enumerate(rep.traceback))
    raw = "\n".join(rep.raw_log[:20])

    evidence = ""
    if context is not None:
        from logosfuzz.analyze.reachability import render_for_prompt

        evidence = render_for_prompt(context) + "\n\n"

    plugin, contract = _resolve_contract(rep, contract, profile)
    contract_block = plugin.render_for_prompt(contract)
    if contract_block:
        evidence += contract_block + "\n\n"

    return (
        f"[결함 유형] {cluster.bug_type}\n"
        f"[Sanitizer] {rep.sanitizer}\n"
        f"[원인] {rep.error_reason}\n"
        f"[재현 입력 수] {cluster.count}\n"
        f"[콜스택]\n{frames}\n"
        f"[원문 로그]\n{raw}\n\n"
        f"{evidence}"
        "위 크래시가 대상 라이브러리의 실제 취약점(true_positive)인지, "
        "하네스/모킹/환경 요인에 의한 가짜 크래시(false_positive)인지 판별하라.\n\n"
        f"{_REACHABILITY_QUESTION}\n\n"
        '출력 형식(JSON): {"verdict": "true_positive|false_positive|needs_review", '
        '"confidence": 0.0~1.0, "rationale": "근거 한두 문장(어느 호출부를 근거로 '
        '삼았는지 명시)"}'
    )


def parse_llm_verdict(text: str) -> dict | None:
    """LLM 응답 텍스트의 판정 JSON 추출 (실패 시 None)"""
    import json
    import re

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if "verdict" not in data:
        return None
    try:
        Verdict(str(data["verdict"]))
    except ValueError:
        return None
    return data


class LLMTriager:
    """추론형 LLM 기반 판별기 (모델 부재·파싱 실패 시 규칙 기반 폴백)

    Args:
        client: ``complete(prompt, system=...) -> str`` 제공 LLM 클라이언트
        model_name: 판정 결과에 기록할 모델 식별자
        fallback: 폴백 판별기 (기본 RuleBasedTriager)
    """

    def __init__(self, client, model_name: str = "deepseek-r1", fallback=None,
                 context_provider=None, contract_provider=None, profile=None) -> None:
        self.client = client
        self.model_name = model_name
        self.context_provider = context_provider
        self.contract_provider = contract_provider
        self.profile = profile
        self.fallback = fallback or RuleBasedTriager(
            context_provider=context_provider, contract_provider=contract_provider,
            profile=profile,
        )

    def triage(self, cluster: CrashCluster) -> TriageResult:
        context = _safe_context(self.context_provider, cluster)
        contract = _safe_context(self.contract_provider, cluster)
        try:
            raw = self.client.complete(
                build_triage_prompt(cluster, context=context, contract=contract,
                                    profile=self.profile),
                system=_TRIAGE_SYSTEM,
            )
        except Exception:
            return self._fallback(cluster, "llm-call-failed")
        parsed = parse_llm_verdict(raw)
        if parsed is None:
            return self._fallback(cluster, "llm-parse-failed")
        signals = ["llm-judgment"]
        if context is not None and context.resolved:
            signals.append("reachability-context")
        _, contract = _resolve_contract(cluster.representative, contract, self.profile)
        if contract.found:
            signals.append("error-contract-context")
        return TriageResult(
            verdict=Verdict(str(parsed["verdict"])),
            confidence=_clamp(float(parsed.get("confidence", 0.5))),
            rationale=str(parsed.get("rationale", "")).strip() or "(근거 미제공)",
            triage_model=self.model_name,
            cluster_id=cluster.cluster_id,
            signals=signals,
        )

    def _fallback(self, cluster: CrashCluster, reason: str) -> TriageResult:
        result = self.fallback.triage(cluster)
        result.signals = [*result.signals, reason]
        return result


def triage_clusters(clusters: list[CrashCluster], triager=None) -> list[TriageResult]:
    """클러스터 목록 판별 (기본: 규칙 기반)"""
    triager = triager or RuleBasedTriager()
    return [triager.triage(c) for c in clusters]


def summarize(results: list[TriageResult]) -> dict:
    """판정 결과 개수 요약"""
    summary = {v.value: 0 for v in Verdict}
    for r in results:
        summary[r.verdict.value] += 1
    return summary
