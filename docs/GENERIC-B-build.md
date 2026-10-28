# GENERIC-B 빌드 어댑터 사용법 (서원)

프로필의 `build.system` 에 따라 빌드 방식을 고른다. 자동 생성과 수동 빌드는 **따로 기록**한다.

| `build.system` | 어댑터 | 하는 일 |
|---|---|---|
| `bazel` | `BazelAdapter` (기존 그대로) | `cc_fuzz_test` 생성 + `bazel build` |
| `cmake` | `CMakeAdapter` | 라이브러리를 계측 빌드 → 하네스를 `clang` 으로 직접 링크 |
| `prebuilt` | `PrebuiltAdapter` | 이미 빌드된 라이브러리에 하네스만 링크 |

## 코드에서 쓰기

```python
from logosfuzz.common.target_profile import load_profile
from logosfuzz.generate.build import HarnessSpec, adapter_for

profile = load_profile("targets/libsndfile.json")
adapter = adapter_for(profile)                 # coverage=True 면 build-fuzz-cov 변형
adapter.prepare()                              # configure + 라이브러리 빌드 (캐시됨)
spec = HarnessSpec(name="sndfile_fuzz", srcs=("sndfile_fuzz.c",))
adapter.emit_build_definition(spec, harness_source)
result = adapter.build(spec)                   # result.binary -> LogicGroup.harness_path
```

- `prepare()` 는 `build()` 가 필요하면 알아서 부르므로 **EXT 전에 한 번 불러 두면** 시간이 겹친다.
- 라이브러리가 이미 있고 `CMakeCache.txt` 도 있으면 다시 만들지 않는다. 강제로 다시: `prepare(force=True)`.
- 실패 시 `result.log` 는 원문, `result.short_log` 는 오류 줄만 추려 준다 (자가치유 분류기 입력).

## 명령줄로 확인하기 (어댑터만)

```bash
python -m logosfuzz.generate.build --profile targets/libsndfile.json --prepare-only
python -m logosfuzz.generate.build --profile targets/libsndfile.json --harness my_fuzz.c
python -m logosfuzz.generate.build --profile targets/libsndfile.json --harness my_fuzz.c --coverage
```

성공하면 바이너리 경로를 출력한다. 이 경로가 EXE 로 넘어가는 계약이다.
**이 도구로 만든 바이너리는 "수동 하네스"** 이므로 자동 생성 성과에 넣지 않는다.

## 동작 규칙

- 컴파일러: `language: c` → `clang`, `cpp` → `clang++`.
- 계측: `-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined,fuzzer-no-link` (라이브러리), 링크는 `-fsanitize=address,undefined,fuzzer`.
- configure 인자는 `build.configure_args` 를 그대로 뒤에 붙인다. Ninja 가 있고 캐시가 없을 때만 `-G Ninja`.
- 커버리지: `<build_dir>-cov` 에 따로 빌드하고 `-fprofile-instr-generate -fcoverage-mapping` 을 추가한다.
- 출력 위치 기본값: `out/generic/<profile.name>/{harness,bin}/`.
- 하네스는 소스 파일 1개만 지원한다 (`srcs` 가 1개가 아니면 `ValueError`).

## Bazel 영향

`BuildResult` / `BuildAdapter` 를 `generate/build/base.py` 로 옮겼고 `bazel/adapter.py` 가 재수출한다.
기존 import 경로는 그대로 동작한다 (`tests/test_build_adapters.py::test_bazel_adapter_reexports_the_promoted_types`).

## 테스트

```bash
python -m pytest tests/test_build_adapters.py -q
python -m pytest -q
```

테스트는 `FakeRunner` 로 cmake/clang 없이 돈다. 실제 libsndfile 빌드는 WSL 에서 직접 확인하고, 측정값만 여기 기록한다.

| 확인 항목 | 결과 |
|---|---|
| `CMakeAdapter.prepare()` libsndfile 1.2.2 (WSL2, 첫 빌드) | OK, 62.9초 |
| `prepare()` 재실행 (캐시) | OK, 0.0초 |
| **수동 하네스** 빌드 (`sf_open_virtual` → `sf_readf_float` → `sf_close`) | OK, 1.0초 |
| 수동 하네스 `-runs=1000` | 크래시 없음, cov 368 / ft 370 / corp 2 |
| 전체 `pytest -q --ignore=examples` | 1076 passed, 1 skipped |

수동 하네스는 `out/manual/sndfile_manual_fuzz.c` 이고 자동 생성 결과가 아니다.
8개 API 중 `sf_open_virtual`, `sf_readf_float`, `sf_close` 3개만 호출한다.

## domain 별 동작 분리 (2일차)

`domain` 은 프로필 값(`generic` / `embedded` / `automotive`)이다. 자동차 전용 동작은 `automotive` 일 때만 켠다.
아래 함수들은 `domain` 인자를 받고, **기본값은 `automotive`** 다(프로필 없이 부르는 기존 호출부가 같은 결과를 받도록).
컨트롤러가 `profile.domain` 을 넘기면 된다.

| 위치 | `automotive` | 그 외 |
|---|---|---|
| `schedule/logic_groups.py` `extract_realtime_signals` / `attach_realtime_signals` / `build_groups` | 워치독·CAN 주기·UDS P2 신호 추출 | 신호 없음 |
| `generate/llm.py` `RepairPromptBuilder(domain=)` | "automotive open-source libraries" | "C/C++ libraries and embedded firmware" |
| `analyze/regenerate.py` `draft_system_prompt(domain)` | 위와 같음 | 위와 같음 |
| `generate/llm_harness_generator.py` `build_cpp_prompt(domain=)` | `score::Result` 이름 사용, S-CORE 참조 하네스 기본 포함 | `Result` 로 표기, 참조 하네스는 직접 줄 때만 |
| `generate/gen_03_01_harness_generator.py` `generate_pairs(_from_kb)` / `list_groups` | 위 값을 전달 | 위 값을 전달 |
| `reporting/summary.py` `profile_metadata(profile)` | 리포트 `metadata` 에 `project`/`target`/`domain` | 같음. 웹 리포트 제목에 `대상 (domain)` 표시 |

`common/models.py` 의 `SIGNAL_*` 상수는 그대로 두었다(자동차 전용 주석만 갱신).
`sch_02_02` / `sch_02_03` / `llm_harness_generator` 의 데모 데이터는 UDS·CAN 대신 일반 예시(`sf_open` 핸들 확인 후 `sf_read_*` 호출)로 바꿨다.

## C 하네스 프롬프트 보강 (E2E 실측 반영)

libsndfile E2E(`logosfuzz run`)에서 자동 생성된 C 하네스 2개에 결함이 있었음.

| 하네스 | 실측 | 원인 |
|---|---|---|
| `lg_sndfile` | cov 19, 9,562만 회 실행, 크래시 0 | `SNDFILE *sndfile = NULL` 로 두고 열지 않은 채 API 호출 |
| `lg_sf_info` | 입력 10회째 SEGV (`file_io.c:221`), cov 0 | 함수 포인터 구조체 `SF_VIRTUAL_IO` 를 입력 바이트로 채움 |

두 결과 모두 라이브러리 결함이 아니라 **하네스 결함**이며, 정탐으로 집계하지 않음(크래시는 `needs_review`, 사람이 `reject`).

`domain` 이 `automotive` 가 아닐 때만 C 프롬프트에 다음을 적용함(automotive 프롬프트는 변경 없음).

* 규칙 8 완화: 목록에 없어도 헤더에 선언된 열기·생성·초기화·해제 함수는 호출 허용
* 규칙 13~17 추가: NULL/미초기화 핸들 금지, 콜백 구조체를 입력으로 채우기 금지(메모리 버퍼 기반 콜백 사용), 메모리·콜백 기반 열기 우선, 구조체 0 초기화와 모든 경로에서 닫기, 입력을 데이터로 라이브러리에 전달

개선 여부는 재실행해 봐야 알 수 있음. 위 표의 수치는 **개선 전 기록**이며 개요서에 사용하지 않음.

### 2차 실측 (프롬프트 규칙 13~18 적용 후)

| 하네스 | 결과 | 판정 |
|---|---|---|
| `lg_sndfile` | `sf_open((const char *)data, ...)` 로 입력을 경로 문자열로 전달, `strlen` 이 버퍼 끝을 넘어 읽음 (`common.c:174`) | **하네스 결함.** 분류기가 `true_positive`(0.95)로 자동 승인했으나 오탐이며, 개요서의 정탐으로 쓰지 않음 |
| `lg_sf_info` | 빌드 실패 | 프롬프트에 `SF_VIRTUAL_IO` 구조체와 `sf_vio_*` 콜백 타입이 없어 필드·시그니처를 추측함 |

대응: 규칙 19 추가(입력을 NUL 종료 없는 `char *` 로 넘기지 않음). 구조체 정의 발췌는 별도 과제로 남김.

### 3차 보강 (2차 실측 반영)

| 문제 | 수정 |
|---|---|
| `lg_sf_info` 가 `SF_VIRTUAL_IO` 필드·콜백 시그니처를 추측해 빌드 실패 | `type_definitions_excerpt()` (`gen_03_01_harness_generator.py`): API 매개변수의 구조체·콜백 typedef·상수 열거형 정의를 헤더에서 발췌해 프롬프트에 포함. `.c` 소스 문서에만 적용 |
| `sf_get_string(sndfile, 0)` 처럼 정의되지 않은 상수 사용 | 같은 발췌에 `SF_STR_*`, `SFM_*` 등 짧은 열거형을 포함 |
| 입력을 NUL 없는 `char *` 로 넘긴 크래시가 `true_positive`(0.95) 로 자동 승인 | `c_return_code.py`: 스택(strlen 계열 → API → 하네스)과 하네스 소스 줄(`(const char *)data`)이 모두 맞을 때 하네스 결함으로 판정 (`c-string-unterminated-by-harness`, 오탐) |
| `applying zero offset to null pointer` 가 `null-dereference` 로 분류 | `sanitizer.py`: `null-pointer-arithmetic` 으로 분리 (실제 역참조 아님) |

### 4차 보강: UB 한 번에 세션이 끝나던 문제 (EXE)

실측: UBSan 경고 1건으로 그룹 퍼징이 5~11초 만에 끝남(`docker/Dockerfile.generic` 의 `UBSAN_OPTIONS=halt_on_error=1`). 커버리지·실행 횟수가 보고할 수 있는 수준에 못 미침.

| 설정 | 위치 | 효과 |
|---|---|---|
| `FuzzConfig.ubsan_options` | `config.py`, `docker_runner.py` | 비어 있지 않으면 `-e UBSAN_OPTIONS=` 로 이미지 기본값을 덮어씀. `generic_run` 은 `halt_on_error=0` 으로 설정 → UB 경고는 stderr 로 기록되고 퍼징은 계속됨(재현용 입력 파일은 만들어지지 않음) |
| `FuzzConfig.resume_after_crash` | `fuzz_session.py` | 크래시(예: ASan)가 나면 입력을 저장하고 같은 그룹을 남은 시간 동안 다시 실행. 코퍼스는 이어서 사용. `max_resumes`(5), `min_resume_sec`(10)로 제한. 시도별 로그는 `run.stderr.<N>.log` 로 보존 |

자동차 모드는 두 설정이 기본값(꺼짐/빈 값)이라 동작이 변하지 않음. `logosfuzz run`(generic)만 켬.

## 실측 기록: libsndfile 1.2.2 자동 실행 (시드 없음 vs 있음)

`logosfuzz run --profile targets/libsndfile.json --budget 600 --max-round 3 --model gpt-4o`
모든 단계 자동(`automatic: true`). 하네스는 LLM(gpt-4o)이 생성했고 수동 하네스가 아님. 단일 실행 1회씩이며 반복 측정이 아님.

| 항목 | run9 (시드 없음) | run10 (시드 9개) |
|---|---|---|
| EXE 소요 | 607.7초 | 610.1초 |
| `lg_sndfile` 라인 | 1155/25833 (4.47%) | 2324/25833 (9.00%) |
| `lg_sndfile` 분기 | 663/13140 (5.05%) | 1398/13140 (10.64%) |
| `lg_sndfile` 함수 | 64/996 (6.43%) | 92/996 (9.24%) |
| `lg_sf_info` 라인 | 874/25833 (3.38%) | 1224/25833 (4.74%) |
| `lg_sf_info` 분기 | 505/13140 (3.84%) | 682/13140 (5.19%) |
| `lg_sndfile` 실행 횟수 / exec/s | 7,808,215 / 13,674 | 372,930 / 653 |
| 크래시(ASan 등) | 0 | 0 |
| 결함 군집 (UBSan, 전부 `needs_review`) | 8 | 11 |

시드: `targets/seeds/libsndfile/` 9개(WAV 5, AIFF, AU, CAF, MAT4). `scripts/make_libsndfile_seeds.py` 가 표준 라이브러리만으로 생성하며 libsndfile 로 전부 열림을 확인함.

해석할 때 주의할 점
* 두 실행의 하네스 소스가 다름(LLM이 매번 새로 생성). 커버리지 차이가 시드만의 효과라고 단정할 수 없음.
* `lg_sndfile` 의 exec/s 가 약 20배 낮아짐(13,674 -> 653). 호스트에서 같은 `run10` 하네스로 측정한 결과:
  시드 9개는 5,000 exec/s 이상(1초 미만), 퍼징이 만든 최종 코퍼스(367개)는 465 exec/s.
  하네스·환경은 같고 입력만 달라서 하락은 **진화한 코퍼스 입력** 때문으로 판단함(Docker 실행 653 exec/s 와 비슷한 값).
  Docker 안(`logosfuzz-exec:generic`, `UBSAN_OPTIONS=halt_on_error=0`)에서 `run10` 하네스를 시드 9개로 5만 회 실행하면 7,142 exec/s 라서
  환경(Docker)이 원인은 아님. 어떤 입력이 느린지는 확인하지 않음.
* 두 실행 모두 `lg_sndfile` 하네스가 `sf_read_short(..., 0)`, `sf_readf_float(..., 0)` 처럼 **0개를 읽음**. 읽기 API 는 호출은 되지만
  샘플 디코딩 코드는 거의 실행되지 않으므로 "8개 API 포함"을 읽기 깊이로 해석하면 안 됨.
* 새로 나온 군집: `au.c:324/326/327` 정수 오버플로(AU 시드로 파서에 도달). 나머지는 `mat4.c`(5곳), `pcm.c:130`, `strings.c:176`(NULL 포인터 연산)로 이전 실행과 같음.
* 결함은 모두 UBSan 의 정의되지 않은 동작 경고이고 사람 검토 전에는 정탐이 아님. 메모리 오류(ASan)는 0건.

### 재현 사례: `au.c` 부호 있는 정수 오버플로 (UB, 취약점으로 확정하지 않음)

* 입력: 20바이트 AU 헤더 변형. Base64 `LnNuZFIA6QhhiYmJ5ImJYAAAJQA=` (`echo '<위 값>' | base64 -d > au_ub.bin`)
* 실행: `UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=1 <lg_sndfile 바이너리> au_ub.bin`
* 결과: `au.c:324:54`, `au.c:326:29`, `au.c:327:40` 에서 `signed integer overflow: 1375791368 + 1636403593 cannot be represented in type 'int'`.
  호출 경로 `sf_open -> psf_open_file -> au_open -> au_read_header`. 헤더의 `dataoffset` 과 `datasize` 두 값을 `int` 로 더하는 식임.
* 확인하지 않은 것: 합이 이후 메모리 할당·인덱스로 쓰여 실제 메모리 오류가 되는지(ASan 오류는 0건), 업스트림의 기존 이슈 여부.
* 같은 군집 계열: `mat4.c`(107, 318, 320, 322, 323), `pcm.c:130`, `strings.c:176` 은 재현 입력을 아직 정리하지 않음.

