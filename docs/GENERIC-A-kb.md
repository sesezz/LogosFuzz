# GENERIC-A: 프로필로 지식베이스(KB) 만들기

대상 프로필(`targets/*.json`, [GENERIC-A-target-profile.md](GENERIC-A-target-profile.md)) 하나로
KB 를 만들고, 그 KB 에서 하네스 계획(`plan_harness`)과 정확도 평가(`kb_eval`)까지 하는 방법이다.

| 모듈 | 바뀐 것 |
| --- | --- |
| `logosfuzz/knowledge/knowledge_base.py` | `build --profile`, 비-Bazel 빌드 단위 1개, `profile.apis` 필터, KB 에 `profile` 메타데이터 |
| `logosfuzz/generate/kb_bridge.py` | `plan_harness` 가 cmake/prebuilt 단위를 받고 `HarnessBuildPlan.build_system` 을 노출 |
| `logosfuzz/knowledge/kb_eval.py` | `run --profile`, 정답셋을 `profile.apis` 로 제한, nm 정답셋에도 compile_db 플래그 전달 |
| `targets/labels/libsndfile.json` | libsndfile 8개 API 정답 라벨 |
| `scripts/fetch_libsndfile.sh` | libsndfile 고정 커밋 받기·configure·빌드 |

## 1. 준비: libsndfile 소스

업스트림 소스는 저장소에 넣지 않는다(`.gitignore` 의 `third_party/`). score-baselibs 와 같은
원칙이다. 고정 커밋(1.2.2, `72f6af15`)으로 받아서 프로필의 `configure_args` 그대로 빌드한다.

```bash
bash scripts/fetch_libsndfile.sh --build   # 저장소 루트, WSL/리눅스
```

- `--configure` 는 cmake 까지만, 인자 없이 돌리면 clone 과 커밋 확인만 한다.
- ninja 가 있으면 `-G Ninja`, 없으면 cmake 기본 생성기를 쓴다. 산출물 경로는 같다.
- `compile_commands.json` 의 경로는 configure 한 환경 기준이다(WSL 이면 `/mnt/c/...`).
  **KB 빌드와 평가도 같은 환경(WSL)에서 돌린다.** Windows Python 에서 돌리면 파일별 플래그가
  매칭되지 않아 `include_dirs` 만 붙는다.

## 2. KB 빌드

```bash
python3 -m logosfuzz.knowledge.knowledge_base build --profile targets/libsndfile.json --output build/sndfile-kb.json
python3 -m logosfuzz.knowledge.knowledge_base stats --kb build/sndfile-kb.json
```

### `build.system` 에 따른 경로

| 프로필 | 동작 |
| --- | --- |
| `bazel` | 기존 경로 그대로. `bazel.workspace`·`bazel.target` 으로 `bazel query` 를 돌린다. `--bazel-*` 인자를 주면 그쪽이 우선이다 |
| `cmake` / `prebuilt` | compile_commands.json 으로 파일별 플래그를 채우고, 라이브러리 전체를 빌드 단위 1개로 기록한다 |

비-Bazel 경로의 세부 규칙:

- **대상 파일**: `--paths` 가 없으면 compile_db 의 소스와 `include_dirs`. compile_db 가 없으면
  `source_root` 전체를 본다. 어느 쪽이든 `tests/`, `examples/` 같은 테스트·예제 트리는 뺀다.
- **파일별 플래그**(`files[*].flags`, API 의 `compile_flags`): compile_db 에 항목이 있는 소스는 그 파일의
  `-I/-isystem/-D/-std`. 항목이 없는 헤더는 전체 합집합에서 `-std` 만 뺀 것. `include_dirs` 는 항상 `-I` 로 붙인다.
- **빌드 단위**(`build_units`, 1개):

  ```json
  {
    "build_system": "cmake",
    "build_target": "libsndfile",
    "build_rule_kind": "cmake_library",
    "build_deps": ["<절대경로>/build-fuzz/libsndfile.a"],
    "compile_flags": ["-I...", "..."],
    "include_dirs": ["<절대경로>/include"],
    "link_flags": ["-lm"],
    "sources": ["..."], "headers": ["..."], "visibility": [],
    "build_file": "<compile_commands.json 경로>"
  }
  ```

  모든 파일과 API 가 이 단위를 참조한다(`build_system`, `build_target`, `build_deps`).
- **`profile.apis`**: 있으면 그 API 의 정의만 KB 문서로 남긴다. 같은 이름의 정의가 여럿이면 외부
  하네스가 링크할 수 있는 non-static 정의를 고른다. 헤더는 계속 색인하므로 `header` 와 헤더 주석
  (`doc`)은 그대로 붙는다. 프로필에 적었는데 정의를 못 찾은 API 는 `profile.apis_missing` 에 남는다.
- **score::Result 계약**: 프로필의 `domain` 으로 정한다(`automotive` 일 때만).
- KB 파일에는 `profile` 키(`name`, `domain`, `build_system`, `apis`, `apis_missing`)가 추가된다.
  프로필 없이 만든 KB 는 이 키가 없고 기존 형식 그대로다. `stats` 에도 같은 내용이 나온다.

### libsndfile 실측 (WSL Ubuntu-24.04, Python 3.12.3)

`stats` 결과(발췌):

```json
{
  "apis": 8, "files": 94, "headers": 2, "constraints": 14,
  "apis_with_header": 8, "apis_with_compile_flags": 8, "apis_with_build_unit": 8,
  "build_units": 1, "build_units_by_system": {"cmake": 1},
  "constraint_coverage": 0.875,
  "profile": {"name": "libsndfile", "domain": "generic", "build_system": "cmake", "apis_missing": []}
}
```

| API | 정의 위치 | 헤더 | 제약조건 수 |
| --- | --- | --- | --- |
| `sf_open` | `src/sndfile.c:348` | `include/sndfile.h` | 3 |
| `sf_open_virtual` | `src/sndfile.c:472` | `include/sndfile.h` | 1 |
| `sf_close` | `src/sndfile.c:517` | `include/sndfile.h` | 0 |
| `sf_command` | `src/sndfile.c:995` | `include/sndfile.h` | 4 |
| `sf_seek` | `src/sndfile.c:1501` | `include/sndfile.h` | 1 |
| `sf_get_string` | `src/sndfile.c:1619` | `include/sndfile.h` | 1 |
| `sf_read_short` | `src/sndfile.c:1748` | `include/sndfile.h` | 2 |
| `sf_readf_float` | `src/sndfile.c:2019` | `include/sndfile.h` | 2 |

## 3. 하네스 계획: `plan_harness`

```python
from logosfuzz.knowledge.knowledge_base import KnowledgeBase
from logosfuzz.generate.kb_bridge import plan_harness

kb = KnowledgeBase.load("build/sndfile-kb.json")
plan = plan_harness(kb, "sf_open_virtual")
plan.build_system      # "cmake"
plan.target_label      # "libsndfile"  (프로필 이름)
plan.build_deps        # ("<root>/build-fuzz/libsndfile.a",)  링크할 라이브러리
plan.include           # "<root>/include/sndfile.h"
plan.compile_flags     # ("-I<root>/include", "-I<root>/build-fuzz/include", "-I<root>/src",
                       #  "-I<root>/build-fuzz/src", "-std=gnu99")
```

- `MissingBuildUnitError` 는 API 에 빌드 단위가 아예 없을 때만 난다(프로필 없이 `--paths` 로만 만든 KB 등).
- Bazel 단위는 이전과 같다(`target_label` 은 Bazel 라벨, `build_deps` 는 가시성 검사를 통과한 라벨).
  빌드 시스템 값이 없는 예전 KB 의 단위는 Bazel 로 본다.
- 비-Bazel 계획의 `repair_knowledge()` 는 `bazel_target`/`bazel_deps` 대신 `build_system`, `build_target`,
  `link_libraries` 를 준다. `to_draft()` 의 `context` 도 `build_system`·`build_target` 을 쓴다.
- `build_harness_from_kb()` 는 Bazel BUILD 생성기용이다. 비-Bazel 계획을 넘기면
  `KnowledgeBridgeError` 를 내고 `generate.build.adapter_for(profile)` 을 쓰라고 알려 준다.

## 4. 정확도 평가: `kb_eval --profile`

```bash
python3 -m logosfuzz.knowledge.kb_eval run --profile targets/libsndfile.json \
  --labels targets/labels/libsndfile.json --prefer labels --report
```

- `--profile` 을 주면 KB 를 프로필로 만들고, 정답셋을 `profile.apis` 로 좁힌다. 프로필 KB 는 대상 API 만
  담으므로, 좁히지 않으면 라이브러리 내부 함수가 전부 미탐으로 잡힌다.
- `--prefer auto` 는 clang → nm → 라벨 순으로 정답셋을 고른다. nm 경로는 이제 compile_db 플래그로
  컴파일한다(전에는 `-I` 가 없어 libsndfile 92개 중 70개가 컴파일에 실패했다).
- 라벨 형식은 `examples/uds/labels.json` 과 같다(`name`, `file`, `return_type`, `params`).

### libsndfile 8개 API 결과 (WSL, 2026-10-12)

| 지표 | 라벨 정답셋 | nm 정답셋 (auto) |
| --- | --- | --- |
| 정답셋 | 라벨 8개 | gcc+nm, 92개 파일 컴파일, apis 8개로 제한 |
| precision / recall / F1 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 |
| 정탐 · 오탐 · 미탐 | 8 · 0 · 0 | 8 · 0 · 0 |
| 인자 개수 일치율 | 1.000 | 비교 불가(nm 은 이름만) |
| 반환형 일치율 | 1.000 | 비교 불가 |
| API coverage | 1.000 | 1.000 |
| 제약조건 보유 · 헤더 해석 · 문서 보유 | 0.875 · 1.000 · 1.000 | 같음 |
| 호출그래프 편입 | 0.250 | 같음 |
| RAG recall@1 / recall@5 / MRR (자동 질의 5개) | 1.000 / 1.000 / 1.000 | 같음 |

- 라벨은 `third_party/libsndfile/src/sndfile.c` 의 정의를 사람이 옮겨 적은 것이다. 라벨만으로는 같은 소스를
  두 번 읽은 셈이라, 추출기와 독립인 nm 정답셋(컴파일러가 정의했다고 알려 주는 심볼)으로도 확인했다.
- WSL Python 에는 clang 바인딩이 없어서 auto 는 nm 으로 내려갔다.
- 제약조건이 없는 API 는 `sf_close` 하나다(0.875 = 7/8).
- 호출그래프 편입이 낮은 것은 KB 가 대상 API 8개만 담아서다. 대상 API 끼리의 호출만 남는다.
