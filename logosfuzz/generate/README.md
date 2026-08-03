# GEN-03-02 · 컴파일 에러 자가 치유 루프 ★

LLM이 생성한 퍼징 하네스가 컴파일에 실패하면, **컴파일 에러 로그를 LLM에 되먹여 소스를 수정하고 재컴파일**하는 과정을 `--max-round` 만큼 반복하는 제너레이트(GEN) 계층 골격입니다. 라운드를 모두 소진해도 고쳐지지 않으면 CTR-06-02 HITL의 `HARNESS_REVIEW`로 자동 에스컬레이션합니다.

설계서 GEN-03-00 대응: `logosfuzz generate --model <name> --max-round <n>` — "컴파일 오류 로그를 LLM에 재입력하여 자동 수정 후 재컴파일, 지정 횟수까지 반복. 실패 시 자기 자신(generate)으로 되돌아가는 재시도 루프."

## 구성

| 파일 | 역할 |
|---|---|
| `models.py` | `HarnessDraft`, `CompileResult`, `Diagnostic`(+로그 파서), `HealRound`, `GenerateReport`, `HealOutcome` |
| `compiler.py` | `Compiler` 인터페이스 + `SubprocessCompiler`(clang/gcc) + `FakeCompiler`(테스트) |
| `llm.py` | `LLMClient` 인터페이스 + `OpenAILLMClient`(GPT-4o-mini 자리) + `Scripted/FnLLMClient`, 코드 추출, `RepairPromptBuilder` |
| `selfheal.py` | **`SelfHealLoop`** — 핵심 재시도 루프 + `summarize` |
| `cli.py` | `logosfuzz generate` 명령 |
| `demo.py` | 3개 시나리오 시연 (`python -m logosfuzz.generate.demo`) |
| `tests/` | 단위 테스트 10종 |

## 루프 동작

```
HarnessDraft(초안)
      │
   [R0] 컴파일 ──ok──▶ SUCCESS
      │fail
      ▼
   에러 로그 → RepairPromptBuilder → LLM.complete() → 수정 소스
      │
   [R1..max] 재컴파일 ──ok──▶ SUCCESS
      │fail
      ├── 동일 에러 반복? ──yes──▶ STAGNATED (조기 중단)
      └── 라운드 소진? ─────────▶ EXHAUSTED
                                     │
                        (hitl 연결 시) HARNESS_REVIEW 큐로 에스컬레이션
```

정체(stagnation) 감지: 라운드 간 **에러 시그니처(line, message 집합)** 가 동일하거나 LLM이 소스를 전혀 바꾸지 못하면 무한 낭비를 막기 위해 조기 중단합니다(`stop_on_stagnation`).

## 사용법

```python
from logosfuzz.generate import SelfHealLoop, HarnessDraft
from logosfuzz.generate.compiler import SubprocessCompiler
from logosfuzz.generate.llm import OpenAILLMClient
from logosfuzz.control.hitl import HITLManager

loop = SelfHealLoop(
    compiler=SubprocessCompiler(cc="clang", include_dirs=["/path/inc"]),
    llm=OpenAILLMClient("gpt-4o-mini"),
    max_round=3,
    hitl=HITLManager.create(),   # 실패 시 사람 검토로 에스컬레이션(선택)
)
report = loop.run(draft)          # draft = GEN-03-01이 만든 초안
print(report.outcome, report.rounds_used)
```

CLI(흐름 시연):

```bash
python -m logosfuzz.generate.cli generate --demo --max-round 3 --project dlt-daemon
```

## 연결 지점(TODO)

- `OpenAILLMClient.complete()` 에 실제 openai 호출 연결(현재 골격)
- `SubprocessCompiler` 플래그를 대상 프로젝트 `compile_commands.json`(bear, EXT-01-03)과 연동
- 입력 초안 공급: GEN-03-01 초안 생성기 → `run_many([draft, ...])`
- `RepairPromptBuilder.knowledge` 에 RAG 지식베이스(EXT-01-02) 힌트 주입
- GEN-03-03 Mocking 삽입 단계와 파이프라인 연결
