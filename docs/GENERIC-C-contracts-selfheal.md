# GENERIC-C — 에러계약 플러그인 · 링커 오류 분류 · 스텁 자가치유 · 임베디드 샘플

담당: 민주 (판별·자가치유)
브랜치: `feature/GENERIC-C-contracts` → PR 대상 `feature/generic-embedded`

## 1. 무엇이 바뀌었나

| 영역 | 파일 | 내용 |
|---|---|---|
| 에러계약 플러그인 | `logosfuzz/analyze/contracts/` | `get_contract(name)` 레지스트리: `none` / `c_return_code` / `score_result` |
| score::Result 이동 | `analyze/contracts/score_result.py` | 기존 `error_contract.py` 본체를 그대로 옮겼다. `error_contract.py` 는 재수출만 한다(기존 import 그대로 동작) |
| C 반환 코드 계약 | `analyze/contracts/c_return_code.py` | 하네스가 NULL/오류 반환을 검사하지 않은 크래시 판정 |
| 판별기 | `analyze/triage.py`, `analyze/cli.py` | `profile=` / `--profile` 로 계약과 문구를 고른다. mocking-fail-fp 문구를 도메인별로 나눴다 |
| 링커 오류 분류 | `generate/errors.py`, `generate/bazel_errors.py` | `undefined symbol`, `multiple definition`, `cannot find -l` + clang/ld 원문용 분류기 `classify_toolchain_log` |
| 스텁 생성 | `generate/stubs.py` | 링커 로그 → 허용목록에 맞는 심볼만 `__attribute__((weak))` 스텁 C 파일 |
| 자가치유 연결 | `generate/adapter_compiler.py`, `generate/selfheal.py`, `generate/feedback_loop.py` | `adapter_for(profile)` 어댑터를 쓰는 컴파일 백엔드, 링크 실패 → 스텁 → 재빌드(LLM 호출 없음) |
| 임베디드 샘플 | `examples/embedded/`, `targets/embedded-sample.json` | HAL 을 부르는 프레임 파서(의도적 힙 OOB 1건) |

## 2. 에러계약 플러그인

```python
from logosfuzz.analyze.contracts import get_contract, ContractProvider
from logosfuzz.analyze.triage import RuleBasedTriager

contract = get_contract(profile.error_contract)        # "none" | "c_return_code" | "score_result"
evidence = contract.analyze(record, kb=kb, profile=profile)

triager = RuleBasedTriager(contract_provider=ContractProvider.for_profile(profile, kb),
                           profile=profile)
```

CLI:

```bash
python -m logosfuzz.analyze.cli analyze findings.jsonl --profile targets/embedded-sample.json
```

### 기본값과 기존 동작

- 프로필이 **있으면** `profile.error_contract` 플러그인을 쓴다. 값이 비어 있으면 `none`.
- 프로필이 **없으면**(지금의 자동차 모드 호출부: 컨트롤러, `analyze.cli` 를 `--profile` 없이 호출)
  지금까지처럼 `score_result` 와 자동차 문구를 쓴다. 자동차 골든 출력을 바꾸지 않으려고
  이렇게 했다. 범용 대상은 항상 `--profile` 을 넘기는 것을 전제로 한다.
- `targets/automotive.json` 은 `error_contract: score_result`, `domain: automotive` 라서 프로필을
  넘겨도 결과가 프로필 없는 경우와 같다(테스트 `test_score_result_only_with_automotive_profile`).
- `domain` 이 `automotive` 가 아니면 `score::Result` 신호·문구가 나오지 않는다.

### `c_return_code` 판정 규칙

셋 다 만족할 때만 `c-return-unchecked-by-harness` 신호(점수 −0.45)를 낸다.

1. 크래시 최상위 대상 프레임(런타임·sanitizer 프레임 제외)이 `profile.apis` 중 하나
2. 그 바로 위 호출자가 하네스(`LLVMFuzzerTestOneInput` 또는 하네스 파일)
3. NULL 근처 접근: ASan `SEGV on unknown address` 가 0 페이지(< 0x1000) 안이거나,
   ASan 의 zero page 힌트, 또는 UBSan `null pointer` 보고

하나라도 증명하지 못하면 신호를 내지 않는다. `profile.apis` 가 비어 있으면 1번을 증명할 수 없다.
스택이 없는 UBSan 한 줄 보고(`print_stacktrace=0`)도 호출자를 알 수 없어서 판단하지 않는다.
Docker 실행 이미지는 `UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1` 이라 스택이 남는다.

### 실측 fixture (`tests/fixtures/c_return_code_logs/`)

| 파일 | 내용 | 결과 |
|---|---|---|
| `harness_unchecked_null.txt` | `proto_create(data[0])` 의 NULL 을 확인하지 않고 `proto_parse` 호출. UBSan(스택 없음) + ASan SEGV `0x14` 두 건 | SEGV 건: **오탐**(0.95), UBSan 건: 신호 없음 → needs_review |
| `harness_unchecked_null_ubsan_stack.txt` | 같은 크래시 입력을 Docker 조건(UBSan 스택 출력·즉시 중단)으로 재현 | **오탐**(0.95) |
| `target_heap_overflow.txt` | 정상 하네스. `proto_parse` 가 길이 필드를 믿고 memcpy → 힙 OOB | **정탐**(0.95), 계약 신호 없음 |

하네스 결함 하네스 소스: `harness_unchecked.c`. 대상 결함 하네스: `examples/embedded/harness/fuzz_proto.c`.

## 3. 링커 오류 분류

CMake/prebuilt 어댑터 로그는 Bazel `ERROR:` 블록이 없는 clang/ld 원문이다. 기존
`bazel_errors.classify` 에 넣으면 진단을 못 찾아 성공으로 보이므로 `errors.classify_toolchain_log`
를 따로 둔다. 반환 타입은 같은 `BazelErrorReport` 라서 `selfheal`·`prompt_hint` 를 그대로 쓴다.

| 로그 | 종류 | 처방 |
|---|---|---|
| `undefined reference to 'X'` (GNU ld), `undefined symbol: X` (lld) | `undefined_symbol` | `resolve_symbol` (스텁 정책이 켜져 있으면 먼저 스텁) |
| `multiple definition of 'X'`, `duplicate symbol: X` | `multiple_definition` | `remove_duplicate_definition` (하네스 소스) |
| `cannot find -lX`, `unable to find library -lX` | `missing_library` | `escalate` (프로필 수정 필요) |
| `'h.h' file not found` | `missing_dep` | `retry_raw` (CMake 에는 deps 가 없다) |
| 그 밖의 clang `error:` | `unknown` | `retry_raw` |

`bazel_errors.classify_block` 도 Bazel 링크 블록 안의 `multiple definition` / `cannot find -l` 을
같은 종류로 분류한다. fixture: `tests/fixtures/linker_errors/` (clang 18.1.3, GNU ld 2.42, lld 18.1.3 실측).

## 4. 스텁 자가치유

```python
from logosfuzz.generate.adapter_compiler import heal_loop_for

loop = heal_loop_for(profile, llm, max_round=3, kb=kb)   # 컴파일 백엔드·분류기·스텁 정책 조립
report = loop.run(draft)
report.last_compile.artifact_path    # 어댑터의 BuildResult.binary (EXE 의 harness_path)
report.stubbed_symbols               # 자동 생성한 스텁 심볼
```

- `AdapterCompiler` 가 `adapter_for(profile)` 의 어댑터로 하네스를 **링크까지** 빌드한다.
  `adapter_for` 는 지연 import 라서 GENERIC-B 머지 전에도 import 는 된다(테스트는 가짜 어댑터 주입).
- 링크 실패 로그의 미정의 심볼 중 `embedded.stub_allowlist`(glob)에 맞는 것만
  `out/generic/<name>/stubs/<name>_stubs.c` 에 weak 로 만들고, 그 파일을 `build.link_flags` 뒤에 더한
  프로필 사본으로 다시 빌드한다(원래 프로필은 frozen 그대로).
- 시그니처: KB 에 문서가 있으면 그 반환형·파라미터(파일이 헤더면 `#include`), 없으면 `int X() { return 0; }`.
- 허용목록 밖 미정의 심볼만 남으면 `ESCALATED`(HITL `stop_reason` 에 심볼 이름). 다른 컴파일 에러와
  섞여 있으면 기존처럼 LLM 수정 라운드로 간다.
- `stub_undefined: false` 이거나 `apply_stubs` 가 없는 기존 컴파일러(`SubprocessCompiler`,
  `BazelCompiler`)는 동작이 바뀌지 않는다.
- Bazel 대상은 하네스 타깃이 필요해서 `compiler_for` 가 거부한다. 기존 `BazelCompiler` 경로를 쓴다.
- 검증 피드백 루프: `feedback_loop.selfheal_regenerate_fn(loop, draft_for)` 를 `validate_with_retry` 의
  `regenerate_fn` 으로 넣으면, 다시 빌드한 실행 파일 경로가 다음 라운드의 `harness_path` 가 된다.

## 5. 임베디드 샘플

```
examples/embedded/
  hal.h            HAL_UART_Transmit, HAL_GetTick 선언만(정의 없음)
  proto_parser.h/c 프레임 [A5][type][len][payload][checksum] 파서, 반환 코드 계약
  CMakeLists.txt   정적 라이브러리 libproto.a
  harness/fuzz_proto.c  수동 하네스(사람이 작성)
  seeds/valid_frame.bin 정상 프레임 1개
targets/embedded-sample.json  domain embedded, cmake, stub_undefined true, stub_allowlist ["HAL_*"],
                              strip_flags 기본값(-mcpu=* -mthumb -mfloat-abi=* -mfpu=* --specs=*),
                              error_contract c_return_code
```

의도적 결함: `proto_parse` 가 `len` 을 `ctx->capacity` 와 비교하지 않고 memcpy 한다(체크섬 검사는 복사 뒤).

## 6. 실측 (E2E)

환경: 클라우드 컨테이너 Ubuntu 24.04.5 LTS, clang 18.1.3, GNU ld 2.42, cmake 3.28.3, ninja 1.11.1.
**WSL Ubuntu-24.04 재검증은 아직 하지 않았다.** GENERIC-B(`origin/feature/GENERIC-B-build` `49c90c2`)를
임시 worktree 에 합쳐 실제 `CMakeAdapter` 로 돌렸고, 그 병합은 이 브랜치에 포함하지 않았다.
세은의 `logosfuzz run` 이 아직 없어서 `heal_loop_for`(adapter_for + selfheal) → 바이너리 직접 실행
(`--no-docker` 에 해당) → `analyze.cli --profile` 순서로 수동 연결했다.

| 단계 | 결과 | 자동/수동 |
|---|---|---|
| 하네스 | `examples/embedded/harness/fuzz_proto.c` | **수동**(사람 작성, 자동 생성 성공으로 세지 않음) |
| `CMakeAdapter.prepare()` + 1차 링크 | 실패: `undefined reference to 'HAL_GetTick'`, `'HAL_UART_Transmit'` | 자동 |
| 스텁 생성 → 재링크 | 성공. 스텁 2개, LLM 호출 0회, 빌드 2회, 자가치유 전체 1.43초(configure+라이브러리 빌드 포함) | 자동 |
| 퍼징(시드 코퍼스 사용, `-max_total_time=120`) | 0.14초 만에 `heap-buffer-overflow` (`proto_parser.c:64`) | 자동 |
| 퍼징(빈 코퍼스, `-seed=1/2/3`) | 0.16 / 0.15 / 0.16초, 실행 #5847 / #5122 / #6592 에서 같은 OOB | 자동 |
| ANA (`analyze --profile`) | 고유 1건, 정탐 conf 0.95 | 자동 |

## 7. 테스트

```bash
python -m pytest -q logosfuzz/analyze/tests/test_contracts.py tests/test_linker_errors.py \
    tests/test_stubs.py logosfuzz/generate/tests/test_selfheal_stubs.py
```

- `test_stubs.py::test_real_link_failure_then_stub_links` 는 clang + libFuzzer 런타임이 있으면 실제로
  링크 실패 → 스텁 → 링크 성공을 확인한다(없으면 skip).
- `test_selfheal_stubs.py::test_default_factory_uses_generic_build_adapter` 는 GENERIC-B 머지 전에는 skip.
- 전체: 이 브랜치 단독 `1089 passed, 5 skipped`, GENERIC-B 를 합친 상태 `1122 passed, 4 skipped`.
