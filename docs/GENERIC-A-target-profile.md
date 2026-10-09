# GENERIC-A: 대상 프로필과 compile_db

LogosFuzz 를 자동차/S-CORE(Bazel) 특화에서 C/C++ 임베디드 범용으로 넓히면서,
대상마다 흩어져 있던 빌드·API·에러계약 정보를 `targets/*.json` 한 파일에 모았다.
EXT/KB, GEN 빌드 어댑터, EXE, ANA 는 모두 `load_profile()` 결과만 읽는다.

| 모듈 | 역할 |
| --- | --- |
| `logosfuzz/common/target_profile.py` | 프로필 스키마, `load_profile()`, `ProfileError` |
| `logosfuzz/extract/compile_db.py` | CMake `compile_commands.json` → 파일별 `-I/-isystem/-D/-std` |
| `logosfuzz/extract/ast_analyzer.py` | `--profile`: compile_db 플래그로 libclang 파싱 |
| `logosfuzz/extract/constraint_extractor.py` | `score::Result` 계약은 `domain=automotive` 에서만 |

## 1. 프로필 작성법

### 필드

| 필드 | 필수 | 값 | 설명 |
| --- | --- | --- | --- |
| `name` | ✓ | 문자열 | 대상 이름. 리포트·KB 빌드 단위 이름으로 쓴다 |
| `version` |  | 문자열 | 릴리스나 커밋 (기록용) |
| `language` | ✓ | `c` / `cpp` | `c` 이면 `.h` 를 C 헤더로 파싱한다 |
| `domain` | ✓ | `generic` / `embedded` / `automotive` | `automotive` 일 때만 자동차 전용 기능(score::Result 계약 등)이 켜진다 |
| `build.system` | ✓ | `bazel` / `cmake` / `prebuilt` | 빌드 방식 |
| `build.source_root` | ✓ | 경로 | 대상 소스 루트 (아래 경로 규칙 참고) |
| `build.build_dir` |  | 경로 | CMake 빌드 디렉터리 |
| `build.configure_args` |  | 문자열 배열 | `cmake -S <root> -B <build_dir>` 뒤에 붙일 인자 |
| `build.libraries` |  | 경로 배열 | 하네스에 링크할 정적 라이브러리 |
| `build.include_dirs` |  | 경로 배열 | 공개 헤더 위치. 하네스 컴파일과 헤더 파싱에 쓴다 |
| `build.link_flags` |  | 문자열 배열 | 추가 링크 플래그 (`-lm` 등) |
| `build.compile_commands` |  | 경로 | `compile_commands.json` 위치. 비-Bazel 대상의 파싱 플래그 출처 |
| `build.bazel` | bazel 이면 ✓ | `{workspace, target}` 또는 `null` | `system=bazel` 일 때만 쓸 수 있다. `target` 은 `//` 나 `@` 로 시작하는 라벨이어야 한다 |
| `apis` |  | 문자열 배열 | 퍼징 대상 API. 비어 있으면 전체 |
| `error_contract` | ✓ | `none` / `c_return_code` / `score_result` | 오류 반환 규약. ANA 오류계약 플러그인이 고른다 |
| `embedded.strip_flags` |  | glob 배열 | 호스트 clang 에 넘기기 전에 지울 크로스컴파일 플래그 (`-mcpu=*`, `-mthumb`, `--specs=*` 등) |
| `embedded.stub_undefined` |  | bool | 링크할 때 미정의 심볼 스텁을 자동으로 만들지 정한다 |
| `embedded.stub_allowlist` |  | glob 배열 | 스텁을 만들어도 되는 심볼 (예: `HAL_*`) |
| `seeds` |  | 경로 배열 또는 문자열 | 시드 코퍼스 |

- 스키마는 엄격하다. 모르는 키(오타), enum 밖의 값, 타입 오류, `system=bazel` 인데
  `bazel` 블록이 없는 경우, `apis` 중복은 모두 `ProfileError` 가 된다.
- `_` 로 시작하는 키(`"_comment"` 등)는 메모로 보고 무시한다.
- 필드를 추가하려면 `target_profile.py` 와 `tests/test_target_profile.py` 를 함께 고친다.

### 경로 규칙

1. `build.source_root` 가 상대경로면 **현재 작업 디렉터리(저장소 루트)** 기준이다.
   다른 기준이 필요하면 `load_profile(path, base_dir=...)` 를 쓴다.
2. 나머지 `build.*` 경로(`build_dir`, `libraries`, `include_dirs`, `compile_commands`,
   `bazel.workspace`)와 `seeds` 는 **source_root 기준** 상대경로다.
3. 절대경로는 `profile.abs(path)` 로 얻는다. 이미 절대경로면 그대로 돌려준다.

```python
from logosfuzz.common.target_profile import load_profile, ProfileError

profile = load_profile("targets/libsndfile.json")
profile.abs(profile.build.compile_commands)
# -> <repo>/third_party/libsndfile/build-fuzz/compile_commands.json
profile.is_bazel, profile.is_automotive   # (False, False)
```

### 예시 1: CMake 범용 C 라이브러리 (`targets/libsndfile.json`)

```json
{
  "name": "libsndfile",
  "version": "1.2.2",
  "language": "c",
  "domain": "generic",
  "build": {
    "system": "cmake",
    "source_root": "third_party/libsndfile",
    "build_dir": "build-fuzz",
    "configure_args": ["-DBUILD_SHARED_LIBS=OFF", "-DBUILD_PROGRAMS=OFF",
                       "-DBUILD_EXAMPLES=OFF", "-DBUILD_TESTING=OFF",
                       "-DENABLE_EXTERNAL_LIBS=OFF", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
    "libraries": ["build-fuzz/libsndfile.a"],
    "include_dirs": ["include", "build-fuzz/include"],
    "link_flags": ["-lm"],
    "compile_commands": "build-fuzz/compile_commands.json",
    "bazel": null
  },
  "apis": ["sf_open", "sf_open_virtual", "sf_read_short", "sf_readf_float",
           "sf_seek", "sf_command", "sf_get_string", "sf_close"],
  "error_contract": "c_return_code",
  "embedded": {"strip_flags": [], "stub_undefined": false, "stub_allowlist": []},
  "seeds": []
}
```

```bash
git clone https://github.com/libsndfile/libsndfile third_party/libsndfile
git -C third_party/libsndfile checkout 72f6af15e8f85157bd622ed45b979025828b7001
cmake -S third_party/libsndfile -B third_party/libsndfile/build-fuzz \
  -DBUILD_SHARED_LIBS=OFF -DBUILD_PROGRAMS=OFF -DBUILD_EXAMPLES=OFF \
  -DBUILD_TESTING=OFF -DENABLE_EXTERNAL_LIBS=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

### 예시 2: 자동차 Bazel 대상 (`targets/automotive.json`)

```json
{
  "name": "score-json",
  "language": "cpp",
  "domain": "automotive",
  "build": {
    "system": "bazel",
    "source_root": "third_party/score-baselibs",
    "bazel": {"workspace": ".", "target": "//score/json:json"}
  },
  "apis": [],
  "error_contract": "score_result"
}
```

`bazel.workspace` 도 source_root 기준이므로 `"."` 은 `third_party/score-baselibs` 자체다.
baselibs 를 다른 곳(예: `~/baselibs`)에 두었다면 `source_root` 만 바꾸면 된다.

## 2. compile_db 사용법

`compile_db` 는 bear 폐기 결정(README)과 충돌하지 않는다. bear 처럼 컴파일러 호출을
가로채지 않고, CMake 가 `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` 으로 직접 만든 파일만 읽는다.
Bazel 대상은 계속 `bazel_query` 를 쓴다.

- `command` 문자열과 `arguments` 배열 형식을 모두 읽는다.
- `-I dir`·`-Idir`, `-isystem dir`·`-isystemdir`, `-D X`·`-DX`, `-std=` 를 뽑는다.
  `-std=` 가 여러 번 나오면 마지막 값을 쓴다.
- 상대 include 경로는 그 항목의 `directory` 를 기준으로 절대경로로 바꾼다.
  같은 파일이 여러 번 나오면 플래그를 합친다.
- `embedded.strip_flags` 의 glob 에 걸리는 토큰은 추출하기 전에 지운다.

```python
from logosfuzz.common.target_profile import load_profile
from logosfuzz.extract.compile_db import flags_for_profile, merged_flags_for_profile

profile = load_profile("targets/libsndfile.json")
per_file = flags_for_profile(profile)          # {절대경로: CompileFlags}
merged = merged_flags_for_profile(profile)     # 전체 합집합
merged.clang_args()   # ['-I...', '-isystem', '...', '-DHAVE_CONFIG_H', '-std=gnu99']
```

```bash
# 파일별 플래그 JSON
python -m logosfuzz.extract.compile_db --profile targets/libsndfile.json --output build/sndfile-flags.json
# 프로필 없이, 크로스컴파일 플래그를 지우고 합집합만 (glob 은 = 로 붙여 쓴다)
python -m logosfuzz.extract.compile_db --compile-db path/to/compile_commands.json \
  --strip-flag='-mcpu=*' --strip-flag='-mthumb' --merged
```

`compile_commands.json` 이 없거나 깨졌으면 `CompileDbError` 가 난다(CLI 는 종료 코드 1).

## 3. 추출 단계에서 프로필 쓰기

### ast_analyzer

```bash
python -m logosfuzz.extract.ast_analyzer --profile targets/libsndfile.json --output build/sndfile-ast.json
```

- 비-Bazel 프로필: compile_db 에 항목이 있는 소스는 그 파일의 플래그를 쓴다.
  항목이 없는 헤더는 전체 합집합을 쓰되 `-std` 는 빼고 파일 언어 기본값에 맡긴다.
  `build.include_dirs` 는 언제나 `-I` 로 붙인다.
- `paths` 를 주지 않으면 compile_db 의 소스 파일과 `include_dirs` 를 분석한다.
- configure 전이라 `compile_commands.json` 이 없으면 경고를 남기고 `include_dirs` 만 쓴다.
- Bazel 프로필은 `bazel.workspace`/`bazel.target` 으로 기존 `bazel query` 경로를 탄다.
- 프로필이 없으면 기존 동작과 같다.

### constraint_extractor

`score::Result` 계약(`MakeUnexpected`, `Unexpected{}`, `Result<T>{unexpect, e}`)과
그 분기를 오류 탈출로 보는 규칙은 S-CORE 관용구다. 그래서 다음 경우에만 켠다.

| 호출 | score::Result |
| --- | --- |
| `extract_from_text(text, profile=automotive)` | 켜짐 |
| `extract_from_text(text, profile=generic/embedded)` | 꺼짐 |
| `extract_from_text(text)` (프로필 없음) | 꺼짐 |
| `extract_from_text(text, score_result=True/False)` | 명시값이 우선 |
| `KnowledgeBase.build(..., bazel_graph=...)` | 켜짐 (기존 S-CORE KB 경로 유지) |

자동차 프로필의 출력은 이전과 바이트 단위로 같다. `third_party/score-baselibs/score`
전체와 `examples/`, 테스트 입력 문자열을 합친 1748개 입력으로 비교했다.

```bash
python -m logosfuzz.extract.constraint_extractor --profile targets/automotive.json \
  third_party/score-baselibs/score/json --output build/score-json-constraints.json
```
