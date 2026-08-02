"""
GEN (Generate) 계층 - LLM 기반 퍼징 하네스 자동 생성.

- GEN-03-01 실시간 컨텍스트 주입 기반 하네스 초안 생성 (TODO: draft.py)
- GEN-03-02 컴파일 에러 자가 치유 루프 ★ (selfheal.py)
- GEN-03-03 자동차 환경 가상화(Mocking) 코드 삽입 (TODO: mocking.py)

공개 API
--------
    from logosfuzz.generate import SelfHealLoop, HarnessDraft
    from logosfuzz.generate.compiler import SubprocessCompiler
    from logosfuzz.generate.llm import OpenAILLMClient

    loop = SelfHealLoop(compiler=SubprocessCompiler(), llm=OpenAILLMClient("gpt-4o-mini"),
                        max_round=3, hitl=hitl_manager)
    report = loop.run(draft)
"""
from .compiler import Compiler, FakeCompiler, SubprocessCompiler
from .llm import (
    FnLLMClient,
    LLMClient,
    OpenAILLMClient,
    RepairPromptBuilder,
    ScriptedLLMClient,
    extract_code,
)
from .models import (
    CompileResult,
    Diagnostic,
    GenerateReport,
    HarnessDraft,
    HealOutcome,
    HealRound,
    parse_diagnostics,
)
from .selfheal import SelfHealLoop, summarize

__all__ = [
    "SelfHealLoop",
    "summarize",
    "HarnessDraft",
    "GenerateReport",
    "HealOutcome",
    "HealRound",
    "CompileResult",
    "Diagnostic",
    "parse_diagnostics",
    "Compiler",
    "SubprocessCompiler",
    "FakeCompiler",
    "LLMClient",
    "OpenAILLMClient",
    "ScriptedLLMClient",
    "FnLLMClient",
    "RepairPromptBuilder",
    "extract_code",
]

__version__ = "0.1.0"  # GEN-03-02 골격
