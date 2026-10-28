"""domain 별 동작 분리 테스트 (GENERIC-B 2일차). automotive 는 기존과 같고, 그 외에는 자동차 용어를 쓰지 않는다."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from logosfuzz.analyze.regenerate import DRAFT_SYSTEM_PROMPT, draft_system_prompt
from logosfuzz.generate.llm import RepairPromptBuilder, domain_subject
from logosfuzz.generate.llm_harness_generator import ApiContext, build_cpp_prompt, build_prompt
from logosfuzz.reporting.summary import profile_metadata
from logosfuzz.schedule.logic_groups import extract_realtime_signals

TEXTS = ["UDS P2 서버 응답 시간은 50ms 이내여야 한다.", "워치독은 100ms 주기로 리셋해야 한다."]
CTX = ApiContext(api_id=1, func_signature="int sf_close(SNDFILE *f)", call_order=["sf_close"],
                 constraints=[], source_type="INTERNAL")


def test_realtime_signals_only_for_automotive():
    assert {s.kind for s in extract_realtime_signals(TEXTS)} == {"uds_p2", "watchdog"}       # 기본 = 기존 동작
    assert len(extract_realtime_signals(TEXTS, domain="automotive")) == 2
    assert extract_realtime_signals(TEXTS, domain="generic") == []
    assert extract_realtime_signals(TEXTS, domain="embedded") == []


def test_repair_system_prompt_follows_domain():
    default = RepairPromptBuilder()
    assert default.system_prompt() == RepairPromptBuilder.SYSTEM            # 기존 문구 그대로
    assert "automotive" in default.system_prompt()

    generic = RepairPromptBuilder(domain="generic").system_prompt()
    assert "automotive" not in generic
    assert "C/C++ libraries and embedded firmware" in generic
    assert "LLVMFuzzerTestOneInput" in generic                                # 나머지 지시는 유지


def test_draft_system_prompt_follows_domain():
    assert draft_system_prompt() == DRAFT_SYSTEM_PROMPT and "automotive" in DRAFT_SYSTEM_PROMPT
    generic = draft_system_prompt("generic")
    assert "automotive" not in generic and "C/C++ libraries and embedded firmware" in generic
    assert "LLVMFuzzerTestOneInput" in generic


def test_domain_subject():
    assert domain_subject("automotive") == "automotive open-source libraries"
    assert domain_subject("generic") == domain_subject("embedded")


def test_cpp_prompt_names_score_result_only_for_automotive():
    kwargs = dict(error_contracts=["returns an error code"])
    automotive = build_cpp_prompt("g", [CTX], **kwargs)
    generic = build_cpp_prompt("g", [CTX], domain="generic", **kwargs)

    assert "score::Result" in automotive
    assert "score::Result" not in generic
    assert "REFERENCE HARNESS" in automotive and "REFERENCE HARNESS" not in generic   # S-CORE 참조는 automotive 만
    assert "ERROR CONTRACTS (Result" in generic and "Result<T> / expected" in generic
    assert build_prompt("g", [CTX], language="cpp", **kwargs) == automotive    # 기본값 = 기존 프롬프트


def test_profile_metadata_carries_target_and_domain():
    profile = SimpleNamespace(name="libsndfile", domain="generic")
    assert profile_metadata(profile, commit="72f6af1", environment=None) == {
        "project": "libsndfile", "target": "libsndfile", "domain": "generic", "commit": "72f6af1",
    }


def test_c_prompt_generic_adds_handle_and_callback_rules():
    """실측 결함 방지: 핸들을 열지 않고 NULL 로 부르는 하네스, 콜백 구조체를 입력으로 채우는 하네스."""
    automotive = build_prompt("g", [CTX], language="c")
    generic = build_prompt("g", [CTX], language="c", domain="generic")

    assert build_prompt("g", [CTX], language="c", domain="automotive") == automotive   # 기본값 = 기존 프롬프트
    assert "NEVER pass a NULL or uninitialised handle" not in automotive
    assert "Do NOT invent or call any function not explicitly listed above." in automotive

    assert "NEVER pass a NULL or uninitialised handle" in generic
    assert "function pointers or callbacks" in generic
    assert "EXACTLY as declared in the included headers" in generic          # 헤더의 구조체를 재정의하지 않음
    assert "never read, seek or tell outside [0, size]" in generic           # 콜백의 범위 검사
    assert "choose it from the input" in generic                              # 명령 코드를 고정값으로 두지 않음
    assert "NEVER pass the fuzzer input (or a pointer into it) as a `char *` string" in generic   # NUL 없는 문자열 전달 금지
    assert "NEVER pass the fuzzer input" not in automotive
    assert "mkstemps(template, suffix_length)" in generic                       # 접미사가 있는 임시 파일 템플릿
    assert "Do NOT invent or call any function not explicitly listed above." not in generic
    assert "needed to create, open, initialise or release" in generic        # 열기·닫기 함수 허용
    assert "STRICT RULES:" in generic and generic.index("STRICT RULES:") < generic.index("13. NEVER")


def test_c_prompt_embedded_uses_the_same_generic_rules():
    assert build_prompt("g", [CTX], language="c", domain="embedded") == \
        build_prompt("g", [CTX], language="c", domain="generic")
