"""
GEN-03 하네스 생성 - LLM 클라이언트 & 리페어 프롬프트
=====================================================

자가 치유 루프(GEN-03-02)가 컴파일 에러를 LLM에 되먹여 소스를 수정할 때 사용한다.

- LLMClient       : 인터페이스(complete)
- OpenAILLMClient : GPT-4o-mini 등 OpenAI 호환 모델 연동 (openai>=1.0 클라이언트 사용)
- ScriptedLLMClient / FnLLMClient : 테스트/데모용
- RepairPromptBuilder : 컴파일 로그 기반 수정 프롬프트 생성
- extract_code    : LLM 응답에서 코드 블록만 추출
"""
from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from typing import Callable, Dict, List, Optional

from .models import CompileResult, HarnessDraft


# --------------------------------------------------------------------------- #
# LLM 클라이언트
# --------------------------------------------------------------------------- #
class LLMClient(ABC):
    """텍스트 프롬프트를 받아 완성 텍스트를 반환하는 최소 인터페이스."""

    @abstractmethod
    def complete(self, prompt: str, *, system: str = "") -> str:
        raise NotImplementedError


class OpenAILLMClient(LLMClient):
    """
    GPT-4o-mini 등 OpenAI 호환 모델 연동.

    api_key를 명시하지 않으면 OPENAI_API_KEY 환경변수(.env 로드는 호출자 책임)를 사용한다.
    openai 패키지(>=1.0, `from openai import OpenAI` 스타일)가 필요하다.
    """

    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.2,
                 api_key: Optional[str] = None, base_url: Optional[str] = None,
                 max_retries: int = 2) -> None:
        self.model = model
        self.temperature = temperature
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = base_url
        self.max_retries = max_retries
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError as e:  # pragma: no cover
                raise RuntimeError(
                    "openai 패키지가 설치되어 있지 않습니다. `pip install openai`로 설치하세요."
                ) from e
            if not self.api_key:
                raise RuntimeError(
                    "OPENAI_API_KEY가 설정되어 있지 않습니다. 환경변수로 설정하거나 "
                    "OpenAILLMClient(api_key=...)로 직접 전달하세요."
                )
            kwargs = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = OpenAI(**kwargs)
        return self._client

    def complete(self, prompt: str, *, system: str = "") -> str:
        client = self._get_client()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            messages=messages,
        )
        return resp.choices[0].message.content or ""


class FnLLMClient(LLMClient):
    """콜백 함수를 LLM처럼 사용(테스트/커스텀 로직 주입용)."""

    def __init__(self, fn: Callable[[str, str], str]) -> None:
        self._fn = fn

    def complete(self, prompt: str, *, system: str = "") -> str:
        return self._fn(prompt, system)


class ScriptedLLMClient(LLMClient):
    """미리 정해진 응답을 순서대로 반환(데모/테스트용)."""

    def __init__(self, responses: List[str]) -> None:
        self._responses = list(responses)
        self._i = 0
        self.calls: List[str] = []

    def complete(self, prompt: str, *, system: str = "") -> str:
        self.calls.append(prompt)
        if self._i >= len(self._responses):
            # 응답이 소진되면 마지막 응답을 반복(수렴 실패 흉내)
            return self._responses[-1] if self._responses else ""
        r = self._responses[self._i]
        self._i += 1
        return r


# --------------------------------------------------------------------------- #
# 코드 추출
# --------------------------------------------------------------------------- #
_FENCE_RE = re.compile(r"```(?:[a-zA-Z0-9+#]*)\n(?P<code>.*?)```", re.DOTALL)


def extract_code(llm_response: str) -> str:
    """
    LLM 응답에서 코드만 추출한다.
    ```로 감싼 블록이 있으면 첫 블록을, 없으면 응답 전체를 코드로 간주.
    """
    m = _FENCE_RE.search(llm_response or "")
    if m:
        return m.group("code").strip("\n")
    return (llm_response or "").strip()


def extract_note(llm_response: str) -> str:
    """코드 블록 앞의 설명 텍스트(있으면)를 한 줄로 요약."""
    m = _FENCE_RE.search(llm_response or "")
    if not m:
        return ""
    head = llm_response[: m.start()].strip().replace("\n", " ")
    return head[:200]


# --------------------------------------------------------------------------- #
# 리페어 프롬프트
# --------------------------------------------------------------------------- #
class RepairPromptBuilder:
    """컴파일 에러를 고치기 위한 수정 프롬프트를 만든다."""

    SYSTEM = (
        "You are a C/C++ fuzzing-harness repair assistant for the LogosFuzz project. "
        "You fix compilation errors in libFuzzer/AFL++ harnesses for automotive open-source "
        "libraries. Return ONLY the full corrected source file inside a single ```c code block. "
        "Do not add explanations outside the code block. Preserve the LLVMFuzzerTestOneInput "
        "entry point and the intended target API calls."
    )

    def __init__(self, max_log_chars: int = 2000) -> None:
        self.max_log_chars = max_log_chars

    def system_prompt(self) -> str:
        return self.SYSTEM

    def build(
        self,
        draft: HarnessDraft,
        source: str,
        compile_result: CompileResult,
        round_idx: int,
        knowledge: Optional[Dict[str, str]] = None,
    ) -> str:
        digest = compile_result.error_digest()[: self.max_log_chars]
        apis = ", ".join(draft.target_apis) if draft.target_apis else "(미지정)"
        kb = ""
        if knowledge:
            kb = "\n# 지식베이스 힌트\n" + "\n".join(f"- {k}: {v}" for k, v in knowledge.items())
        return f"""\
# 작업: 컴파일 에러 수정 (라운드 {round_idx})
프로젝트: {draft.project or '-'}
로직 그룹: {draft.logic_group}
타깃 API: {apis}
{kb}

# 현재 하네스 소스
```c
{source}
```

# 컴파일러 에러
```
{digest}
```

# 지시
위 에러를 모두 해결한 '전체' 수정 소스를 하나의 ```c 코드 블록으로만 출력하라.
누락된 헤더/선언을 추가하고, 시그니처 불일치를 맞추되, 타깃 API 호출 의도는 유지하라."""
