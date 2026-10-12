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
| **`bazel build --config=fuzz` 실제 빌드** | ✅ 7분 12초 / 159 actions |
| **`bazel build --config=bl-x86_64-linux` 회귀** | ✅ 성공 (오버레이 후에도 무손상) |
| 퍼저 실행 | ✅ 200만 회 / 521초 / 약 3,840 exec/s / 크래시 0건 |
| 계측 침투 깊이 | ✅ 자동 사전에 JSON 문법 학습 (true/false/UTF-8 BOM) |

WSL2 + clang 18 / Bazel 8.6.0 환경에서 전 항목 검증 완료.
1주차 게이트(빌드·실행·계측) 통과. 컨테이너 내 실행은 C 파트 Dockerfile 완료 후 재확인 필요.

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

---

## 3주차: 하네스 산출물 = `.cc` + BUILD 룰 쌍

`gen_03_01_harness_generator.py` 가 Logic Group 마다 빌드 단위의 하위 패키지에
하네스와 `cc_fuzz_test` 를 한 쌍으로 쓴다. 그룹마다 패키지를 나누는 이유는
`BazelAdapter.emit_build_definition` 이 BUILD 를 통째로 쓰기 때문이다(한 패키지에
여러 그룹을 몰면 뒤 그룹이 앞 그룹의 룰을 지운다).

```
대상 @score_baselibs//score/json, 그룹 lg_json_parser
  score/json/fuzz/lg_json_parser/lg_json_parser_fuzz.cc
  score/json/fuzz/lg_json_parser/BUILD.bazel   (cc_fuzz_test: lg_json_parser_fuzz_test)
```

```bash
# 1) 쌍 만들기 (LLM 없이 1주차 참조 하네스로)
python -m logosfuzz.generate.gen_03_01_harness_generator --demo --out out/pairs

# 2) BUILD 단계: 워크스페이스에 쓰고 빌드 + BUILD 자가치유 -> build_summary.json
python -m logosfuzz.control.ctr_06_01_controller --mode bazel \
    --workspace ~/baselibs --pairs out/pairs/harness_pairs.json \
    --build-summary out/build_summary.json --regression-build

# KB 에서 LLM(C++/FuzzedDataProvider 프롬프트) 생성까지 한 번에
python -m logosfuzz.control.ctr_06_01_controller --mode bazel \
    --workspace ~/baselibs --kb build/score-kb.json --top 3 --stage-dir out/pairs
```

### deps 공급자 (`--deps`)

| 값 | 동작 |
|---|---|
| `auto` (기본) | `--kb` 가 있고 `kb_bridge`(A, origin/dev)를 쓸 수 있으면 `kb`, 아니면 `static` |
| `kb` | A 의 `KnowledgeBaseDepsProvider(kb)` — KB 의 Bazel 소유권·직접 의존성, repo 접두사까지 처리 |
| `static` | 1주차 검증 deps 표. `//score/json:json` 처럼 repo 접두사만 다른 표기도 같은 대상으로 인식한다 |
| `query` | `bazel query` (A 의 `extract/bazel_query`) |

A 의 `plan_harness()` 결과는 소스 자가치유 힌트와 검증 artifact(`api_signatures`)에 쓴다.
프롬프트 컨텍스트(`plan.prompt_context`)는 **쓰지 않는다** — 함수 **이름**으로 KB 를 조회해서
같은 이름의 다른 API(다른 빌드 단위의 `FromBuffer`)가 잡힌다. `harness_context` 를 api_id 로
직접 불러 쓰고, 그 블록에서 (1) KB 가 기록한 헤더가 테스트 보조 헤더면 해결해 둔 공개 헤더로
바꾸고 (2) 잡음인 `compile flags:` 줄을 뺀다. `error_contracts`(함수 이름·evidence 포함)와
`includes`(워크스페이스 상대 경로)도 계획 값보다 정보가 많아 기존 계산을 유지한다.
각 API 의 호출 순서(`call_order`)에서는 같은 그룹에 남은 API 만 남긴다(구현 내부 호출·제외된
API 제거).

## 4주차 후속: 후속 파트로 넘기는 산출물과 소스 자가치유

BUILD 단계가 빌드에 성공한 그룹마다 아래를 만든다. 이름은 전부 **Logic Group 이름**이다
(4주차 리포트의 조인 키).

```bash
python -m logosfuzz.control.ctr_06_01_controller --mode bazel \
    --workspace ~/baselibs --kb build/score-kb.json --top 3 \
    --heal-rounds 2 \
    --groups-out out/groups.json \
    --artifacts-out out/artifacts.json --gen-model gpt-4o-mini \
    --corpus-dir out/corpus
```

- `--groups-out` : EXE 입력 `[{"name": 그룹, "harness": 바이너리 절대경로, "corpus": 선택}]`
  (`logosfuzz fuzz --groups out/groups.json`). `corpus` 는 `--corpus-dir/<그룹>` 이 있을 때만 들어간다.
- `--artifacts-out` : D 검증 게이트 입력 `contracts.HarnessArtifact` 목록
  (`group_id`, `harness_path`=바이너리, `source_path`, `corpus_dir`, `api_signatures`, `gen_model`).
  `api_signatures` 는 KB 계획이 있을 때만 채워진다(`--pairs`/`--harness` 는 빈 목록).
- `--heal-rounds N` : BUILD deps 수리로도 못 고친 실패의 원인이 **하네스 소스(.cc) 에러**일 때
  D 의 `SelfHealLoop(BazelCompiler)` 로 N 라운드까지 LLM 수리. 기본 0(끔).
  LLM(`OPENAI_API_KEY`)과 origin/dev 병합(`bazel_compiler`, `selfheal`)이 필요하며, 없으면
  건너뛰고 `build_summary.json` 의 `units[*].heal` 에 사유만 남긴다.
  BUILD 를 고쳐야 풀리는 원인(deps·visibility·load)이나 사람 판단이 필요한 원인은 보내지 않는다.
  성공하면 최종 바이너리 경로는 `BazelCompiler.artifact_path()`(심볼릭 링크 추측)가 아니라
  `BazelAdapter.binary_path()`(cquery)로 다시 구한다.

### 대상 그룹 고르기 (`--list-groups`, `--only`)

`--top N` 은 시너지 우선순위 상위 N개라서 **내부 구현 패키지**(예: `.../internal/.../vajson_impl`)가
뽑힐 수 있다. 내부 템플릿 API 는 LLM 이 쓰기 어렵고 공개 API 가 퍼징 가치가 더 크다. 목록을 보고 고른다.

```bash
# LLM 호출 없이 그룹 목록만 본다
python -m logosfuzz.generate.gen_03_01_harness_generator --kb build/score-kb.json --list-groups

# 빌드 단위가 //score/json:json 인 그룹만 (정규식, 그룹 이름·빌드 단위에 re.search)
python -m logosfuzz.control.ctr_06_01_controller --mode bazel --workspace ~/baselibs \
    --kb build/score-kb.json --only '//score/json:json$' --top 1 --heal-rounds 2
```

### LLM 프롬프트에 들어가는 실제 소스

KB 가 기록한 각 API 의 선언 위치(파일·줄)에서 앞 2줄~뒤 10줄을 그대로 발췌해 프롬프트의
"참고용 소스"로 넣는다(API 당 900자, 그룹 전체 6000자 상한). 시그니처와 문서 주석만 보면
반환 타입·복사 가능 여부를 LLM 이 추정하게 된다. 같은 이유로 STRICT RULES 5번은 "모든 결과에
`has_value()`" 가 아니라 **실제 반환 타입에 맞게** 소비하라고 지시한다(`Foo&` 는 `auto&` 로 받고
`has_value()` 호출 금지).

선언 발췌 끝에는 **호출 예시**가 붙는다. `public static` 멤버면
`// Usage: score::json::VajsonParser::FromBuffer(...) — static member: call it directly, NEVER create a VajsonParser instance`
(헤더의 `namespace` 를 읽어 만든다). 참조 하네스가 `Foo parser{}; parser.Call()` 인스턴스 패턴이라
LLM 이 static API 에도 그 패턴을 베끼는 일이 있어서 호출 모양을 못 박았다. 한계: 클래스 안의 중첩
클래스는 바깥 클래스 이름이 빠진다.

#### 하네스가 호출하지 않는 API 는 목록에서 뺀다

프롬프트는 "다음 API 를 퍼징하라"고 시키므로, 목록에 있는 API 는 규칙이 뭐라 하든 LLM 이
그대로 호출한다(실제로 `FromFile` 과 private `GetData` 가 호출돼 빌드가 깨졌다). 그래서
코드가 미리 뺀다(`fuzzable_api_ids`, 제외 내역은 `[GEN] <그룹>: <함수> 제외 (<이유>)` 로 출력).

- `private`/`protected` 멤버 — 공개 헤더의 클래스 선언에서 판별
- 파일 경로를 받는 API — 파라미터 이름(`file_path`, `path`, `dir…`)이나 함수 이름(`…File`).
  buffer 변형(`FromBuffer`)이 있으면 그쪽이 대상이 된다
- 같은 (함수, 시그니처)의 중복 정의 — 첫 번째만

남은 API 가 없는 그룹은 건너뛴다. 공개 헤더에서 선언을 못 찾으면(접근 지정자를 모르면) 제외하지 않는다.

#### 생성 기록 확인 (`out/prompts/`)

BUILD 단계는 LLM 이 받은 **프롬프트**(`<그룹>.prompt.txt`)와 **첫 초안**(`<그룹>.draft.cc`)을
`--build-summary` 옆의 `prompts/` 에 저장한다(`--prompts-dir` 로 변경, `--no-save-prompts` 로 끔).
소스 자가치유가 돌면 디스크의 하네스는 마지막 수정본이 되어 첫 초안이 사라지므로, 생성이 왜
그렇게 나왔는지는 이 파일로 본다. `--pairs` 로 읽은 쌍은 생성 기록이 없어 저장하지 않는다.

### BUILD deps 분류기

`BuildFileRepairer(classifier=default_classifier())` — D 의 `bazel_errors.classify` 결과를
`BuildFix` 로 바꿔 쓰고, D 가 없거나 분류하지 못하면 내장 분류기로 폴백한다.

| D 분류 | BuildFix |
|---|---|
| `MISSING_DEP` (`detail.header`) | `add_dep` |
| `NO_SUCH_TARGET` + suggestion / `FIX_DEP_LABEL` | `rename_dep` |
| `NOT_VISIBLE` / `EXPAND_VISIBILITY` | 안 보이는 대상이 **추측으로 넣은 의존**이면 `drop_dep`(제거). 대상 단위 자신(`deps[0]`)이거나 우리 deps 밖이면 수리 불가 |
| `ESCALATE` | 수리 불가(`repairable=False`) |
| 그 외 | 폴백(내장 분류기) |


## 4주차: 유닛테스트 vs 퍼징 커버리지 비교

`reporting/coverage_compare.py` 가 빌드 단위(Bazel 타깃)별로 두 커버리지를 나란히 놓는다.
두 입력만 만들면 된다. **아래 수집 절차는 아직 실제로 돌려 보지 않았다(미검증)** —
첫 실행에서 플래그·경로를 확인하고 고칠 것.

```bash
# 1) 유닛테스트 커버리지 (baselibs 의 coverage 설정이 lcov 를 만든다)
cd ~/baselibs
bazel coverage //score/json/...
cp bazel-out/_coverage/_coverage_report.dat ~/LogosFuzz-fuzz/out/unit.lcov

# 2) 퍼징 커버리지 — build:fuzz 에는 llvm-cov 계측 플래그가 없으므로 별도 출력 트리로 다시 빌드
FLAGS="--config=fuzz --platform_suffix=fuzzcov \
  --copt=-fprofile-instr-generate --copt=-fcoverage-mapping --linkopt=-fprofile-instr-generate"
TARGET=//score/json/fuzz/lg_json_parser:lg_json_parser_fuzz_test_bin
bazel build $FLAGS $TARGET
BIN=$(bazel cquery $FLAGS --output=files $TARGET | head -1)   # 상대 경로면 ~/baselibs/ 를 붙인다
LLVM_PROFILE_FILE=/tmp/fuzz.profraw "$BIN" -max_total_time=30
LLVM_COV_DIR=$(dirname "$(find ~/.cache/bazel -name llvm-cov -type f | head -1)")   # bazel 의 llvm 툴체인
"$LLVM_COV_DIR/llvm-profdata" merge -sparse /tmp/fuzz.profraw -o /tmp/fuzz.profdata
"$LLVM_COV_DIR/llvm-cov" export -format=lcov -instr-profile=/tmp/fuzz.profdata "$BIN" \
    > ~/LogosFuzz-fuzz/out/fuzz.lcov

# 3) 비교
cd ~/LogosFuzz-fuzz
python -m logosfuzz.reporting.coverage_compare \
    --unit-test out/unit.lcov --fuzz out/fuzz.lcov \
    --build out/build_summary.json --workspace ~/baselibs \
    -o out/coverage_compare.json --markdown out/coverage_compare.md
```

- `--fuzz` 에는 C 파트 `coverage.py` 가 남긴 llvm-cov export JSON / `<group>.summary.json` 도 넣을
  수 있다. 다만 JSON 에는 줄 상세가 없어서 **줄 단위 합집합·"퍼징만/유닛테스트만" 은 계산되지 않는다**
  (파일·지표 단위 비교만). 여러 그룹의 퍼징 결과는 `--fuzz a.lcov b.lcov` 로 합친다(줄 합집합).
- 테스트·퍼저 하네스·external 파일은 기본으로 뺀다(`--exclude`/`--no-default-exclude` 로 조정).
  유닛테스트 리포트에는 테스트 코드 자신이 100% 로 섞여 들어와 결과를 부풀린다.
- 한쪽에 없는 파일은 0% 로 본다. 함수·브랜치는 합집합을 알 수 없어 여러 입력을 합칠 때 최댓값(하한).
- 유닛테스트 쪽이 gcc(gcov) 기준으로 나오면 줄 번호·분모가 llvm-cov 와 조금 다를 수 있다.
  그 경우 줄 단위 겹침은 참고용으로만 쓴다.

`drop_dep` 배경: KB 공급자의 deps 는 `[대상 단위, *그 단위의 모든 build_deps]` 라서 대상이 내부에서만
쓰는 private 타깃(예: `nlohmann:json_builder`)이 섞인다. 하네스는 대상 단위만 있으면 링크되므로
그런 의존은 추측일 뿐이다. 안 보이는 것을 모두 한 번에 빼고 다시 빌드한다. 정말 필요했다면 다음
라운드에 "헤더 없음"(`add_dep`)으로 드러난다. 한 라운드에 여러 개가 걸려도 되도록 `--max-build-rounds`
(기본 3) 안에서 돌고, 못 빼는 경우는 이전처럼 사람이 본다.
