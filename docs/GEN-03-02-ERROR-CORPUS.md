# GEN-03-02 자가치유 에러 코퍼스 (D 파트 1주차)

담당: D 김민주 (자가치유·판별)

퍼저고도화 v3 1주차 D 항목 두 가지의 결과물이다.

- `--config=asan_ubsan_lsan` 실행 후 UBSan 출력 원문 수집
- deps·visibility 고의 파손 → Bazel 에러 원문 수집

2주차에 만들 `generate/bazel_errors.py` 분류기와 `errors.py` 결과 타입이 이
코퍼스를 정답지로 삼는다. 추측으로 정규식을 짜지 않기 위해 **실제로 빌드를
깨뜨려서** 문장을 받아 왔다.

## 수집 환경과 재현

| 항목 | 값 |
| --- | --- |
| Bazel | 9.2.0 (`tests/fixtures/bazel_repro/.bazelversion` 고정) |
| clang | Ubuntu clang 18.1.3 (1ubuntu1) |
| OS | Ubuntu 24.04 (WSL2 / `docker/Dockerfile.selfheal` 동일 조합) |
| 재현 워크스페이스 | `tests/fixtures/bazel_repro/` |
| 수집기 | `scripts/collect_selfheal_corpus.sh` |

```bash
# WSL / 리눅스
bash scripts/collect_selfheal_corpus.sh --out-root .

# Docker (같은 결과)
docker build -f docker/Dockerfile.selfheal -t logosfuzz-selfheal .
docker run --rm -v "$PWD":/repo logosfuzz-selfheal
```

산출물:

- `tests/fixtures/bazel_errors/*.txt` — 파손 케이스 10종 + 정상 대조군
- `tests/fixtures/sanitizer_logs/*.txt` — UB/메모리 오류 11종 × 설정 2종
- 각 디렉터리의 `_META.json` — 버전·정규화 규칙

**정규화**: 에러 문장은 한 글자도 바꾸지 않았다. 머신마다 달라지는 값(절대경로,
PID, 주소, 소요 시간, Bazel config 해시, libFuzzer seed)만 `<WORKSPACE>`,
`<ADDR>` 같은 자리표시자로 치환했다. 규칙 전문은 `_META.json`에 있다.

> 대상(S-CORE baselibs) 전체를 받지 않고 같은 모양의 최소 워크스페이스
> (`//score/json`, private `//score/internal`, `//harness`)를 썼다. 분류기가
> 배워야 하는 건 대상 코드가 아니라 **Bazel 이 뱉는 문장**이고, 그 문장은
> 워크스페이스 크기와 무관하기 때문이다.

---

## 1. Bazel 에러 대응표

각 행의 "결정적 문구"가 분류기가 잡아야 할 신호다. **몇 번째 줄에 있는지**를
같이 적었다 — 아래 발견 A·B의 이유다.

| # | 케이스 | 결정적 문구 | 위치 | 원인 | 처방 |
| --- | --- | --- | --- | --- | --- |
| 1 | `no_such_target` | `no such target '//score/json:jsonn': target 'jsonn' not declared in package` | `ERROR:` 줄 | deps 에 적은 **타깃 이름이 틀림** | 이름 교정 (Bazel 이 `(did you mean json?)` 로 후보까지 준다) |
| 2 | `no_such_package` | `no such package 'score/jsonx': BUILD file not found` | `ERROR:` 줄 | deps 에 적은 **패키지 경로가 없음** | 경로 교정 / `bazel query` 로 실제 타깃 조회 |
| 3 | `not_visible` | `is not visible from` | **`ERROR:` 다음 줄** | 대상이 `visibility` 로 막혀 있음 | 대상 패키지 `visibility` 확장, 또는 공개된 우회 타깃 사용 |
| 4 | `missing_dep` | `fatal error: 'score/json/json.h' file not found` | clang 진단 줄 | include 는 하는데 **deps 누락** | 그 헤더를 제공하는 타깃을 deps 에 추가 |
| 5 | `undeclared_inclusion` | `fatal error: 'score/internal/helper.h' file not found` | clang 진단 줄 | deps 에 없는 패키지 헤더를 include | deps 추가 — 단 private 이면 3번으로 이어짐 |
| 6 | `dep_cycle` | `cycle in dependency graph:` | `ERROR:` 줄 | 순환 의존 | 구조 분리 (LLM 재시도로 못 고침 → HITL) |
| 7 | `missing_srcs_file` | `missing input file '//harness:json_fuzzer_extra.cc'` | `ERROR:` 줄 | `srcs` 가 없는 파일을 참조 | 파일 생성 또는 `srcs` 에서 제거 |
| 8 | `no_load_statement` | `This rule has been removed from Bazel. Please add a` + `load()` | `Error in fail:` 블록 | Bazel 9 는 네이티브 `cc_binary` 제거 | BUILD 맨 위에 `load("@rules_cc//cc:defs.bzl", ...)` 추가 |
| 9 | `bad_syntax` | `syntax error at 'newline': expected expression` | `ERROR:` 줄 | BUILD 구문 오류 | 구문 교정 |
| 10 | `link_undefined` | `ld.lld: error: undefined symbol: score::json::ParseStrict(...)` | 링커 줄 | 선언만 있고 정의가 없음 | 심볼을 제공하는 타깃을 deps 에 추가 / 호출 제거 |

---

## 발견 A — `no such target` 만으로 분류하면 틀린다

설계표는 `no such target → deps 추가`로 매핑했다. 그런데 **8번(`load()` 누락)과
9번(구문 오류)도 로그 끝에서 똑같은 문장을 낸다**:

```
ERROR: Skipping '//harness:json_fuzzer': no such target '//harness:json_fuzzer':
target 'json_fuzzer' not declared in package 'harness' defined by <WORKSPACE>/harness/BUILD.bazel
```

BUILD 파일이 파싱에 실패하면 그 안의 타깃이 아예 정의되지 않으므로, Bazel 입장에선
"요청한 타깃이 없다"가 맞다. 하지만 처방은 정반대다 — deps 를 아무리 고쳐도 안
고쳐지고, `load()` 한 줄이나 괄호 하나를 고쳐야 한다.

**분류기 규칙**: `no such target` 을 볼 때 괄호 안의 레이블이

- **하네스 자신의 타깃**(`//harness:json_fuzzer`)이면 → BUILD 작성 오류.
  앞쪽에서 `Error in fail:` / `syntax error` 를 먼저 찾아 그쪽으로 분류한다.
- **의존 대상**(`//score/json:jsonn`)이면 → 비로소 deps 문제.

LLM 이 만든 BUILD 파일에서 `load()` 누락은 아주 흔하다. 이 구분이 없으면 자가치유가
"deps 를 고쳐라"는 프롬프트를 반복해 던지다 정체(STAGNATED)로 끝난다.

## 발견 B — deps 누락은 `no such target` 이 아니라 clang 에러로 나온다

설계표의 `no such target → deps 추가` 는 실제 동작과 어긋난다. deps 를 **비워도**
Bazel 은 로딩·분석을 통과하고, 컴파일 단계에서 clang 이 헤더를 못 찾는다(4번):

```
harness/json_fuzzer.cc:7:10: fatal error: 'score/json/json.h' file not found
```

즉 "deps 추가" 처방으로 가는 입구는 `no such target` 이 아니라 **`fatal error:
'<헤더>' file not found`** 다. 그리고 이 문구에는 헤더 경로가 그대로 들어 있어,
`bazel query 'rdeps(..., <헤더>)'` 로 어느 타깃을 넣어야 하는지 바로 찾을 수 있다 —
A(황다연)의 2주차 `extract/bazel_query.py` 와 붙는 지점이다.

4번과 5번은 에러 모양이 **완전히 같다**. 둘 다 처방이 "그 헤더를 주는 타깃을 deps 에
추가"로 같으므로 분류기는 하나로 묶어도 된다. 다만 그 타깃이 private 이면 추가하는
순간 3번(visibility)으로 바뀌므로, 자가치유 루프는 **한 라운드 안에서 이 전이를
예상**해야 한다.

## 발견 C — visibility 판정 문구는 `ERROR:` 줄에 없다

```
ERROR: <WORKSPACE>/harness/BUILD.bazel:3:10: in cc_binary rule //harness:json_fuzzer: Visibility error:
target '//score/internal:helper' is not visible from
target '//harness:json_fuzzer'
Recommendation: modify the visibility declaration if you think the dependency is legitimate. ...
```

`ERROR:` 줄에는 `Visibility error:` 까지만 있고, **어떤 타깃이 안 보이는지는 다음
줄**에 있다. 게다가 `is not visible from` 뒤에서 줄이 한 번 더 끊긴다. 로그를 줄
단위로 훑으면서 `ERROR:` 로 시작하는 줄만 보는 분류기는 대상 타깃명을 못 얻는다.

**분류기 규칙**: 로그는 줄 배열이 아니라 **블록**으로 파싱한다. `ERROR:` 로 시작해
다음 `ERROR:`/`INFO:`/`WARNING:` 전까지를 한 진단으로 묶고, 그 블록 전체에
정규식을 건다.

---

## 2. Sanitizer 출력 수집 결과

`--config=asan_ubsan_lsan` 으로 빌드한 하네스를 UB 종류별 입력으로 1회씩 실행했다.
`_halt` 는 같은 설정에 `-fno-sanitize-recover=undefined` 만 추가한 것이다.

| 케이스 | UBSan `runtime error:` 문구 | 기본 exit | halt exit | SUMMARY 수 | 마지막 SUMMARY |
| --- | --- | --- | --- | --- | --- |
| signed_overflow | `signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'` | **0** | 1 | 1 | UBSan |
| shift_exponent | `shift exponent 33 is too large for 32-bit type 'int32_t' (aka 'int')` | **0** | 1 | 1 | UBSan |
| divide_by_zero | `division by zero` | **0** | 1 | 1 | UBSan |
| misaligned_load | `load of misaligned address <ADDR> for type 'const uint32_t' ..., which requires 4 byte alignment` | **0** | 1 | 1 | UBSan |
| float_cast_overflow | `1e+30 is outside the range of representable values of type 'int'` | **0** | 1 | 1 | UBSan |
| invalid_bool | `load of value 201, which is not a valid value for type 'bool'` | **0** | 1 | 1 | UBSan |
| null_deref | `member access within null pointer of type 'Header'` | 1 | 1 | **2** | **ASan** (SEGV) |
| array_bounds | `index 9 out of bounds for type 'int[8]'` | 1 | 1 | **2** | **ASan** (stack-buffer-overflow) |
| heap_overflow | — (ASan 전용) | 1 | 1 | 1 | ASan |
| memory_leak | — (LSan 전용) | **77** | 77 | 1 | ASan |
| clean | — | 0 | 0 | 0 | — |

## 발견 D — 기본 설정에서 UB 8종 중 6종이 크래시로 기록되지 않는다

위 표의 굵은 `0` 여섯 개가 핵심이다. UBSan 은 기본이 **복구 가능(recoverable)** 이라
진단을 찍고 **실행을 계속한다**. 프로세스가 정상 종료하므로:

- libFuzzer 가 크래시 아티팩트를 만들지 않는다
- 종료 코드가 0이라 `docker_runner` / `fuzz_session` 이 "정상 종료"로 집계한다
- ANA 단계에 크래시가 도착하지 않아 판별 대상 자체가 생기지 않는다

기본 설정 로그 꼬리에는 이런 줄까지 붙는다:

```
*** NOTE: fuzzing was not performed, you have only
***       executed the target code on a fixed set of inputs.
```

두 설정의 **진단 텍스트는 완전히 동일**하다(`ubsan_signed_overflow.txt` vs
`halt_ubsan_signed_overflow.txt` — 다른 건 exit code 와 libFuzzer 꼬리 줄뿐). 즉
로그만 보고는 이 UB 가 크래시로 기록될지 알 수 없다.

**제안 (C 파트와 합의 필요)**: `--config=asan_ubsan_lsan` 에
`--copt=-fno-sanitize-recover=undefined` 를 포함시킨다. 포함하지 않기로 한다면,
EXE 단계가 종료 코드와 별개로 stderr 의 `runtime error:` 를 스캔해 크래시로
승격시켜야 한다. 둘 중 하나는 반드시 해야 하고, 지금은 둘 다 없다.

## 발견 E — 한 로그에 진단이 둘일 수 있고, 마지막 SUMMARY 는 근본 원인이 아니다

`null_deref` 와 `array_bounds` 는 UBSan 이 먼저 잡고, 이어서 ASan 이 같은 사건을
다시 잡는다. 로그 안의 SUMMARY 가 2개고 **마지막 것은 ASan** 이다:

```
score/json/json.cc:55:41: runtime error: member access within null pointer of type 'Header'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior score/json/json.cc:55:41
==<PID>==ERROR: AddressSanitizer: SEGV on unknown address <ADDR> ...
SUMMARY: AddressSanitizer: SEGV /proc/self/cwd/score/json/json.cc:55:41 in score::json::Dispatch(...)
```

마지막 SUMMARY 만 읽는 파서는 이걸 "SEGV"로 분류한다 — 틀리진 않지만 **근본 원인
(널 역참조)을 버린다**. 중복 제거(ANA-05-04)에서도 같은 버그가 UBSan 시그니처와
ASan 시그니처로 갈라져 두 클러스터가 될 수 있다.

**파서 규칙**: 로그 안의 진단을 **전부** 수집하고, 시그니처는 **첫 번째**(시간순으로
가장 이른 = 근본 원인) 진단으로 잡는다.

## 발견 F — `SUMMARY:` 줄은 UB 종류를 구분하지 않는다

UBSan 의 SUMMARY 는 어느 검사에 걸렸든 항상 이 모양이다:

```
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior score/json/json.cc:38:11
```

`signed integer overflow` 인지 `division by zero` 인지가 **SUMMARY 에 없다**. 구체적
종류는 `runtime error:` 줄에만 있다. ASan(`SUMMARY: AddressSanitizer:
heap-buffer-overflow`)은 SUMMARY 에 종류가 들어가므로 습관대로 SUMMARY 를 파싱하면
UBSan 만 전부 `undefined-behavior` 한 덩어리로 뭉개진다.

## 발견 G — LSan 의 종료 코드는 77 이다

누수는 exit code **77**로 끝난다(1이 아니다). 그리고 ERROR 줄은 `LeakSanitizer` 인데
SUMMARY 줄은 `AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).` 라 도구 이름이
엇갈린다. `exit_code == 1` 이나 시그널 기반으로 크래시를 판정하는 코드는 누수를
놓친다.

---

## 3. 다음 주차로 넘기는 것

**D 본인 (2주차)** — `generate/bazel_errors.py` 분류기와 `errors.py` 결과 타입은
위 대응표 10행 + 발견 A/B/C 규칙을 그대로 구현한다. 블록 단위 파싱, `no such
target` 의 레이블 주체 판별, `file not found` → deps 경로가 핵심이다.

**C 임세은 (3주차 `sanitizer.py` UBSan 파서 / 4주차 `signature.py`)** — 발견 E/F/G.
진단은 전부 수집하고 시그니처는 첫 진단으로, UBSan 종류는 `runtime error:` 줄에서,
누수 판정에 exit 77 포함. 표본은 `tests/fixtures/sanitizer_logs/` 에 있다.

**C 임세은 (1주차 `--config` 정의)** — 발견 D. `-fno-sanitize-recover=undefined`
포함 여부를 정해야 한다.

**B 송서원 (2주차 `build_file_generator.py`)** — 발견 A. 생성하는 BUILD 파일에
`load("@rules_cc//cc:defs.bzl", ...)` 가 **반드시** 들어가야 한다. Bazel 9 에는
네이티브 `cc_binary`/`cc_library` 가 없다.
