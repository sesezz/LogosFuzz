"""ANA-05-01: LLM 기반 정탐/오탐(True/False Positive) 자동 판별.

입력: ANA-05-04(Crash Deduplication)가 만든 :class:`CrashCluster` 목록
      (설계서: "5주 Dedup 결과 입력받아 진행").
출력: 클러스터별 :class:`TriageResult`. 각 결과의 ``to_triage_dict()``는
      ANA-05-02 ``build_cve_report(triage_result=...)`` 입력 계약과 일치한다.

왜 중복 제거 결과를 입력으로 받나
--------------------------------
정/오탐 판별은 비싸다(LLM 추론 호출). Dedup으로 버그 1개당 대표 1건만 남겨,
같은 버그를 수백 번 다시 판별하지 않는다. 대표에 대한 판정을 그 묶음 전체에
적용한다.

두 가지 판별기
--------------
- :class:`RuleBasedTriager` (기본): 표준 라이브러리만 쓰는 결정적 휴리스틱.
  설계서의 결함 분류 규칙(특히 ``mocking-fail-fp`` = 가짜 크래시)과 콜스택
  위치·재현성 신호를 결합한다. 의존성/네트워크 없이 항상 같은 결과를 낸다.
- :class:`LLMTriager`: 설계서가 명시한 "추론 특화 LLM"(예: DeepSeek-R1) 연동
  자리. ``logosfuzz.generate.llm.LLMClient`` 인터페이스를 재사용하며, 실제
  모델이 없으면 규칙 기반으로 안전하게 폴백한다.

설계 근거(설계서에 판정 규약이 명시되지 않아 합리적 기본값 + 근거 기록)
---------------------------------------------------------------------
설계서는 "LLM이 실행 로그와 Sanitizer 결과를 분석해 정/오탐 분류"라고만 하고
구체적 규칙·점수·임계값을 정의하지 않는다. 그래서 아래 신호를 근거로
투명한 점수화를 구현하고, 각 판정에 사용한 신호를 ``signals``로 남겨
설명가능성(HITL 검토)을 확보한다.
"""

from __future__ import annotations

from logosfuzz.analyze.models import CrashCluster, TriageResult, Verdict
from logosfuzz.analyze.signature import has_application_frame

# 전통적 메모리 커럽션 계열: sanitizer 탐지 신뢰도가 높아 정탐 사전확률이 크다.
_MEMORY_BUGS = {
    "use-after-free",
    "double-free",
    "heap-buffer-overflow",
    "buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "bad-alloc",
    "null-pointer-dereference",
}
# 동시성 계열: 실재하지만 문맥(락 순서/공유자원) 확인이 필요.
_CONCURRENCY_BUGS = {"race-condition", "data-race", "deadlock"}

RULE_MODEL_NAME = "logosfuzz-rule-triage/v1"

# 판정 임계값(정탐 점수 기준). 근거는 모듈 docstring 참조.
_TP_THRESHOLD = 0.65
_FP_THRESHOLD = 0.35


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def rule_triage(cluster: CrashCluster, context=None) -> TriageResult:
    """결정적 휴리스틱으로 하나의 클러스터를 판별한다.

    Args:
        cluster: 판별 대상.
        context: :class:`~logosfuzz.analyze.reachability.ReachabilityContext`
            (선택). 주어지면 정적으로 증명 가능한 도달 가능성 신호를 점수에
            반영한다. 불변식 추론이 필요한 사안은 여기서 판정하지 않는다 —
            그건 ``reachability.render_for_prompt()`` 로 LLM 판별기에 넘긴다.
    """
    rep = cluster.representative
    cat = cluster.bug_type
    signals: list[str] = []

    # (0) mocking 실패 = 가상 네트워크 모킹 실패로 인한 가짜 크래시 → 오탐(설계서 명시)
    if cat == "mocking-fail-fp":
        return TriageResult(
            verdict=Verdict.FALSE_POSITIVE,
            confidence=0.9,
            rationale=(
                "하네스의 가상 네트워크(CAN/UDS) 모킹 미구현으로 발생한 가짜 크래시다. "
                "대상 라이브러리 결함이 아니라 하네스 환경 문제이므로 오탐으로 판정한다. "
                "원인 모킹 코드를 보완하면 사라진다(GEN-03-03 피드백 대상)."
            ),
            triage_model=RULE_MODEL_NAME,
            cluster_id=cluster.cluster_id,
            signals=["mocking-fail-fp"],
        )

    # (1) 결함 유형 사전확률
    if cat in _MEMORY_BUGS:
        score = 0.70
        signals.append("memory-corruption")
    elif cat in _CONCURRENCY_BUGS:
        score = 0.50
        signals.append("concurrency-needs-context")
    elif cat == "watchdog-timeout":
        score = 0.35
        signals.append("realtime-timeout")  # 타임아웃 임계치 튜닝(EXE-04-03) 사안일 수 있음
    else:  # unknown 등
        score = 0.30
        signals.append("unclassified-category")

    # (2) 크래시 위치: 대상 라이브러리 코드인가, 하네스뿐인가
    if has_application_frame(rep):
        score += 0.20
        signals.append("target-code-frame")
    else:
        score -= 0.35
        signals.append("harness-only-frame")  # 대상 코드가 아닌 하네스/드라이버 문제일 가능성

    # (3) 재현성: 같은 시그니처로 여러 입력이 모였는가
    if cluster.count >= 3:
        score += 0.10
        signals.append("highly-reproducible")
    elif cluster.count >= 2:
        score += 0.05
        signals.append("reproduced")

    # (4) sanitizer 신뢰도: ASAN 메모리 오류는 오탐이 드물다
    if rep.sanitizer.upper() == "ASAN" and cat in _MEMORY_BUGS:
        score += 0.05
        signals.append("asan-high-fidelity")

    # (5) 도달 가능성: 이 함수를 실제 제품 코드가 부르는가
    if context is not None:
        from logosfuzz.analyze.reachability import derive_signals

        delta, reach_signals = derive_signals(context)
        score += delta
        signals.extend(reach_signals)

    score = _clamp(score)

    loc = f"{rep.traceback[0].file}:{rep.traceback[0].line}" if rep.traceback else "위치 미상"
    if score >= _TP_THRESHOLD:
        verdict = Verdict.TRUE_POSITIVE
        # 자동 판정은 절대 확신(1.0)을 피한다: 최종 확정은 HITL(사람)이 한다.
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

    # 도달 가능성 근거는 HITL 검토자가 가장 먼저 봐야 할 정보이므로 근거문에 남긴다.
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

    return TriageResult(
        verdict=verdict,
        confidence=confidence,
        rationale=rationale,
        triage_model=RULE_MODEL_NAME,
        cluster_id=cluster.cluster_id,
        signals=signals,
    )


class RuleBasedTriager:
    """결정적 규칙 기반 판별기(기본).

    Args:
        context_provider: ``cluster -> ReachabilityContext`` 콜러블(선택).
            ``reachability.SourceReachabilityProvider(대상_소스_루트)`` 를 넣으면
            호출부 증거를 점수에 반영한다. 없으면 기존 동작 그대로다.
    """

    model_name = RULE_MODEL_NAME

    def __init__(self, context_provider=None) -> None:
        self.context_provider = context_provider

    def triage(self, cluster: CrashCluster) -> TriageResult:
        return rule_triage(cluster, context=_safe_context(self.context_provider, cluster))


def _safe_context(provider, cluster):
    """컨텍스트 수집 실패가 판별 자체를 막지 않게 감싼다."""
    if provider is None:
        return None
    try:
        return provider(cluster)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# LLM 연동 판별기 (설계서의 추론형 LLM 자리)
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

# 도달 가능성 판정을 실제로 시키는 질문. 1단계 검증에서 두 판별기가 똑같이
# 틀린 이유가 "이 질문을 받은 적이 없어서"였다.
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


def build_triage_prompt(cluster: CrashCluster, context=None) -> str:
    """클러스터 대표 결함을 LLM 판별용 프롬프트로 직렬화한다.

    Args:
        cluster: 판별 대상.
        context: :class:`~logosfuzz.analyze.reachability.ReachabilityContext`
            (선택). 주어지면 호출부·링키지·결함 라인 소스를 증거로 함께 싣는다.
            이게 없으면 모델이 볼 수 있는 건 콜스택뿐이라 "ASAN 이 잡았으니
            정탐"이라는 결론밖에 못 낸다.
    """
    rep = cluster.representative
    frames = "\n".join(f"  #{i} {f.file}:{f.line}" for i, f in enumerate(rep.traceback))
    raw = "\n".join(rep.raw_log[:20])

    evidence = ""
    if context is not None:
        from logosfuzz.analyze.reachability import render_for_prompt

        evidence = render_for_prompt(context) + "\n\n"

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
    """LLM 응답 텍스트에서 판정 JSON을 추출한다. 실패 시 None."""
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
    """추론형 LLM(예: DeepSeek-R1) 기반 판별기.

    실제 모델 호출은 주입된 ``LLMClient``(``logosfuzz.generate.llm``)가 담당한다.
    모델이 없거나 응답 파싱에 실패하면 규칙 기반으로 폴백해 파이프라인을
    멈추지 않는다.

    Args:
        client: ``complete(prompt, system=...) -> str`` 를 제공하는 LLM 클라이언트.
        model_name: 판정 결과에 기록할 모델 식별자.
        fallback: 폴백 판별기(기본 RuleBasedTriager).
    """

    def __init__(self, client, model_name: str = "deepseek-r1", fallback=None,
                 context_provider=None) -> None:
        self.client = client
        self.model_name = model_name
        self.context_provider = context_provider
        self.fallback = fallback or RuleBasedTriager(context_provider=context_provider)

    def triage(self, cluster: CrashCluster) -> TriageResult:
        context = _safe_context(self.context_provider, cluster)
        try:
            raw = self.client.complete(
                build_triage_prompt(cluster, context=context), system=_TRIAGE_SYSTEM
            )
        except Exception:
            return self._fallback(cluster, "llm-call-failed")
        parsed = parse_llm_verdict(raw)
        if parsed is None:
            return self._fallback(cluster, "llm-parse-failed")
        signals = ["llm-judgment"]
        if context is not None and context.resolved:
            signals.append("reachability-context")
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
    """클러스터 목록을 판별한다(기본: 규칙 기반)."""
    triager = triager or RuleBasedTriager()
    return [triager.triage(c) for c in clusters]


def summarize(results: list[TriageResult]) -> dict:
    """판정 결과 개수 요약."""
    summary = {v.value: 0 for v in Verdict}
    for r in results:
        summary[r.verdict.value] += 1
    return summary
