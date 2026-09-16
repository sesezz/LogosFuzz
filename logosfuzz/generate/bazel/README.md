# Bazel 빌드 어댑터 (S-CORE / baselibs)

퍼징 파이프라인의 **Bazel 어댑터**. `baselibs` 저장소에 퍼징 오버레이를 얹어
`cc_fuzz_test` 를 빌드 가능하게 만든다.

```
overlay/
  module_snippet.bazel              MODULE.bazel 에 append (rules_fuzzing)
  bazelrc_snippet                   .bazelrc 에 append (build:fuzz)
  score/json/fuzz/BUILD.bazel       수동 작성한 cc_fuzz_test 1개
  score/json/fuzz/json_parser_fuzz.cc   하네스 (3주차 LLM 참조 구현)
apply_overlay.py                    멱등 적용/제거 스크립트
```

## 사용

```bash
python -m logosfuzz.generate.bazel.apply_overlay --baselibs-root ~/baselibs --dry-run
python -m logosfuzz.generate.bazel.apply_overlay --baselibs-root ~/baselibs

cd ~/baselibs
bazel run --config=fuzz //score/json/fuzz:json_parser_fuzz_test_run -- -runs=2000000

# 회귀: 오버레이가 기존 GCC 빌드를 깨지 않았는지
bazel build --config=bl-x86_64-linux //score/json:json

# 되돌리기
python -m logosfuzz.generate.bazel.apply_overlay --baselibs-root ~/baselibs --revert
```

`--revert` 는 마커 블록과 복사한 파일만 지우고 baselibs 원본 줄은 건드리지
않는다. 재적용도 멱등이다.

---

## 팀 공유 결정사항 4건

C(실행)·D(자가치유) 파트가 2주차에 막히지 않으려면 아래를 전제로 작업해야 한다.

### ① `--config=fuzz` 와 `--config=bl-x86_64-linux` 는 상호 배타

병용하면 **GCC 가 이겨서 clang 이 밀려나고**, GCC 에는 `-fsanitize=fuzzer` 가
없어 링크에서 죽는다. baselibs 자신이 `tools/coverage/coverage.bazelrc` 에서
같은 경고를 하고 있다:

> "it registers the GCC toolchain after this file's flags,
>  the last `--extra_toolchains` wins resolution"

역할 분리:

| config | 역할 | 툴체인 |
|---|---|---|
| `bl-x86_64-linux` | **회귀 게이트** — 오버레이가 기존 빌드를 안 깼는지 | GCC 12.2.0 |
| `fuzz` | **퍼징 주경로** | clang 22 (`@llvm_toolchain`) |

`cc_fuzz_test` 에 `tags = ["manual"]` 을 붙인 것도 이 때문이다. 안 붙이면
`//...` 전체 빌드에 딸려 들어가 회귀 게이트가 깨진다.

### ② 퍼징에 `--config=asan_ubsan_lsan` 을 쓰면 안 된다

baselibs `.bazelrc` 에서 이 config 는 **`test:` 로만** 정의되어 있다
(91~103행). `build:`/`run:` 정의가 없어 `bazel run --config=asan_ubsan_lsan`
은 *"config value is not defined"* 로 실패한다.

그래서 오버레이는 `build:fuzz` 로 정의한다. `run`/`test` 가 `build` 를
상속하므로 세 명령 모두에서 쓸 수 있다.

### ③ 크래시 종료코드는 55 다

baselibs 의 `ASAN_OPTIONS` / `UBSAN_OPTIONS` 에 `exitcode=55`,
`halt_on_error=1` 이 박혀 있다. 크래시 감지는 **출력 파싱 + 종료코드**를 같이
봐야 한다.

2단계 검증에서 "ASan 리포트 없이 SIGSEGV 라 크래시가 조용히 사라진" 사고가
이미 한 번 있었다(`docs/VALIDATION-STEP2-4.md` §4.3).

### ④ EXE 계층은 `bazel run` 이 아니라 바이너리를 직접 실행한다

`cc_fuzz_test` 는 `<name>_bin` 이라는 **계측된 퍼저 바이너리**를 만든다.

```bash
bazel build --config=fuzz //score/json/fuzz:json_parser_fuzz_test_bin
# -> bazel-bin/score/json/fuzz/json_parser_fuzz_test_bin  (이걸 직접 실행)
```

`bazel run` 대신 이렇게 하는 이유:

1. **EXE 계층이 빌드 시스템과 무관해진다.** dlt-daemon(CMake) 바이너리든
   baselibs(Bazel) 바이너리든 `docker_runner` 에겐 그냥 실행 파일이다.
   범용성 목표상 이게 핵심이다.
2. ②의 config 제약을 아예 우회한다.
3. 이미 있는 `exe_04_05_corpus_manager.py` / `timeout_manager.py` 가 그대로
   쓰인다. `bazel run` 런처에 코퍼스 관리를 위임하면 그 코드들이 놀게 된다.

---

## 검증 상태

| 항목 | 상태 |
|---|---|
| `apply_overlay.py` dry-run / 적용 / 멱등 재적용 / revert | ✅ 픽스처로 검증 |
| `score::json::JsonParser::FromBuffer` 시그니처 | ✅ baselibs 원문 확인 |
| `score::Result` = `expected` (`has_value()`/`value()`) | ✅ 원문 확인 |
| `cc_fuzz_test` 생성 타깃 (`_bin`/`_run`/`_corpus`/`_dict`) | ✅ rules_fuzzing 0.8.0 원문 확인 |
| **`bazel build --config=fuzz` 실제 빌드** | ❌ **미검증** |
| **`bazel build --config=bl-x86_64-linux` 회귀** | ❌ **미검증** |
| `MODULE.bazel.lock` 재생성 | ❌ 미수행 |

작성 환경의 egress 정책이 `bcr.bazel.build` / `releases.bazel.build` 를
차단해 Bazel 을 실행하지 못했다. 아래는 **실행해 봐야 알 수 있는** 항목이다.

## 알려진 리스크 (첫 실행 시 여기부터 의심)

1. **rules_fuzzing 이 Python 툴체인 7종(3.8~3.14)을 등록**하고 3.14 를
   `is_default` 로 잡는다. baselibs 는 3.12 가 default 다. root 모듈이
   이기는 게 정상이지만 여기서 에러가 나면 1순위 의심 대상이다.
2. **`COMPILER_WARNING_FEATURES`**(`treat_warnings_as_errors`, `strict_warnings`,
   `additional_warnings`)가 모든 score 라이브러리에 걸려 있다. clang 으로
   클로저 전체를 재컴파일하면 gcc 에 없던 경고가 에러가 될 수 있다.
   `build:clang-tidy` 가 이미 `-Wno-error=deprecated-declarations` 예외를
   달고 있어 오버레이에도 같은 줄을 미리 넣어 뒀다. 부족하면 추가한다.
3. **`cc_engine_instrumentation` 은 전이(transition)** 라 `//score/json` 의
   의존 클로저 **전체**가 clang+sancov 로 재컴파일된다. 첫 빌드가 길다.
   bazel 캐시를 반드시 영속 볼륨에 둘 것.
4. **헤더 가시성** — `json_parser.h` 를 가진 `:parser_interface` 의
   visibility 가 `score/json:__subpackages__` 라, 오버레이 패키지를
   `score/json/fuzz` 에 두어 subpackage 가 되게 했다. 트리 밖(`//fuzz/json`)에
   두면 `layering_check` 가 켜진 툴체인에서 include 가 막힌다.

## 선행 검증

baselibs 에 손대기 전에 `examples/bazel_fuzz_probe/` 를 먼저 돌릴 것.
rules_fuzzing 배선만 독립적으로 확인하는 최소 모듈이고, 거기서 실패하면
baselibs 문제가 아니다.
