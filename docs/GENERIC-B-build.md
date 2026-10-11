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
