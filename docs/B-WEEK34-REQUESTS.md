# B(송서원) 3·4주차 검증에서 나온 타 파트 요청

B 파트의 KB → BUILD → 빌드 → EXE 퍼징 → 빌드 단위 리포트 경로를 실제 baselibs 로 돌려 보며
발견한 문제 중 **B 파일에서는 고칠 수 없는 것**만 모았다. 각 항목의 근거는 실제로 확인한 출력이다.
B 쪽 우회는 이미 들어가 있어 지금 동작에는 지장이 없지만, 원인은 아래 파트에 남아 있다.

## 확인된 것 (참고)

| 단계 | 결과 |
|---|---|
| KB → LLM 하네스 → BUILD → 빌드 | 그룹 2개(`vajson_parser`, `nlohmann_parser`) 빌드 성공, BUILD 자가치유로 1건 복구 |
| EXE 퍼징(`--no-docker`) | 두 그룹 30초 퍼징 정상(14k~24k exec/s), 크래시 0건 |
| 10분 퍼징(`vajson_parser`) | 2,189,305회, 크래시 0건, cov 3095에서 포화 |
| 빌드 단위 리포트 | 두 단위가 `built`/`repaired` + `passed` 로 정상 조인 |
| 전체 테스트 | 최신 dev 병합 후 963 passed, 1 skipped |
| Docker 실행 | **실패** — 아래 C-1 |

## C 파트 (실행·계측)

### C-1. `docker/Dockerfile` 베이스 이미지를 24.04 로 올려 달라 (필수)
- 증상: `--docker` 로 돌리면 컨테이너가 바로 종료한다(exit 1, 0.5~1.3초, execs 0).
  ```
  libstdc++.so.6: version `GLIBCXX_3.4.32' not found
  libc.so.6:      version `GLIBC_2.38' not found
  ```
- 원인: Bazel 이 만든 퍼저 바이너리가 호스트(Ubuntu 24.04, glibc 2.39)의 libstdc++/glibc 를 동적 링크한다.
  이미지는 `ubuntu:22.04`(glibc 2.35) 라서 로더가 거부한다.
- 확인: 같은 바이너리를 `docker run -v <bin dir>:/harness:ro ubuntu:24.04 ... -max_total_time=5` 로 돌리면
  6초에 152,883회 정상 실행.
- 제안: `FROM ubuntu:24.04`. 상위 호환이라 호스트가 24.04 이하인 팀원도 문제없다.
  (근본 해결은 sysroot 를 고정한 hermetic 빌드이나 작업량이 크다. 정적 링크는 libstdc++ 만 풀고
  `GLIBC_2.38` 은 남아 효과가 없다.)

### C-2. 시작하지 못한 실행이 조용히 묻힌다
- 증상: 위 실패에서도 화면에는 `exec/s=0 cov=0 execs=0 ... 완료: 총 크래시 0건 → analyze 단계로 전달` 만 나온다.
  `fuzz_summary.json` 에는 `exit_code: 1, crashed: true` 로 기록되는데 크래시 산출물은 없다.
- 제안: `exit_code != 0` 이고 `execs == 0` 이면 stderr 마지막 줄과 함께 **실행 실패**로 알려 달라.
- B 쪽 대응: 리포트(`summary.py`)는 "증거 없음 + 처리량·커버리지·실행 횟수 0" 이면 `crashed` 가 아니라
  `failed` 로 분류하도록 바꿨다(스키마 문서 "시작 실패와 크래시의 구분").

### C-3. `fuzz_summary.json` 그룹에 총 실행 횟수(`execs`)를 기록해 달라
- 증상: 화면에는 `execs=743036` 이 나오는데 JSON 에는 `exec_per_sec`·`duration_sec`·`coverage` 만 있다.
- 제안: `fuzz_session.py` 그룹 dict 에 `"execs": g.stats.execs` 한 줄.
- B 쪽 대응: 없으면 `exec_per_sec × duration_sec` 로 추정해 `~` 를 붙여 표시한다(실측 대비 약 0.5%).
  `execs` 가 생기면 자동으로 실측값을 쓴다.

### C-4. llvm-cov 계측 빌드 설정 (4주차 커버리지 비교에 필요)
- `build:fuzz` 에는 `-fprofile-instr-generate -fcoverage-mapping` 이 없다. 유닛테스트 vs 퍼징 커버리지
  비교(`reporting/coverage_compare.py`)는 같은 단위(줄)의 퍼징 lcov 가 필요하다.
- libFuzzer 의 `cov:` 는 엣지 수라 유닛테스트의 줄 커버리지와 직접 비교할 수 없다.
- 수집 절차 초안은 `logosfuzz/generate/bazel/README.md` 의 "4주차: 유닛테스트 vs 퍼징 커버리지 비교" (미검증).

### C-5. (계약 확인) `groups.json` 의 `harness` 경로
- B 는 `bazel-out/.../*_bin`(심볼릭 링크)이 아니라 **링크를 푼 실제 파일 경로**(`.../*_raw_`)를 준다.
  `docker_runner` 가 호스트 경로를 `resolve()` 해서 마운트하면서 컨테이너 안 실행은 `harness_path.name`
  으로 하기 때문이다. 링크 경로를 주면 마운트된 폴더에 `_bin` 이 없어 실행이 실패한다.
  이 계약을 바꾸면 알려 달라.

## A 파트 (추출·KB)

### A-1. API → 헤더 매핑이 테스트 보조 헤더를 고른다
- 증상: `vajson_parser.cpp` 의 `FromFile`/`FromBuffer` 의 `header` 가 `score/json/internal/parser/parsers_test_suite.h`.
  실제 공개 헤더 `vajson/vajson_parser.h` 는 있다. LLM 이 테스트 헤더를 include 해 빌드가 깨졌다.
- 제안: `header_for` 후보에서 `_test`, `test_suite`, `mock` 이 들어간 파일과 `test/`, `testing/` 폴더를 제외하고,
  정의 파일과 같은 이름(`vajson_parser.cpp` → `vajson_parser.h`)의 헤더를 우선한다.
- B 쪽 대응: `gen_03_01_harness_generator.header_for_document` 가 같은 규칙으로 걸러 낸다.

### A-2. `harness_context` / `plan.prompt_context` 가 함수 이름으로 조회한다
- 증상: `kb_bridge.plan_harness()` 의 `prompt_context` 가 `harness_context(kb, str(document["function"]))` 라서
  같은 이름의 다른 API 가 잡힌다. `vajson_parser` 그룹의 `FromBuffer` 컨텍스트에 `nlohmann_parser.cpp` 의
  `FromBuffer`(api_id=63)가 들어왔다(빌드 단위, deps, include 모두 다른 API 것).
- 제안: `document["api_id"]` 로 조회 (`kb.api(int)` 가 이미 id 조회를 지원한다).
- B 쪽 대응: `prompt_context` 를 쓰지 않고 `harness_context(kb, api_id)` 를 직접 호출한다.

### A-3. `KnowledgeBaseDepsProvider` 가 private 타깃까지 deps 에 넣는다
- 증상: `deps_for(target)` 이 `[대상 단위, *그 단위의 모든 build_deps]` 를 돌려줘서 `nlohmann:json_builder` 같은
  내부 전용 타깃이 섞이고, fuzz 패키지에서 `is not visible from` 으로 분석 단계에서 막힌다.
- 제안: 퍼징 패키지에서 보이는 타깃만 돌려주거나(`bazel query 'visible(...)'`), 대상 단위 + 공개 인터페이스로 제한.
- B 쪽 대응: 안 보이는 의존을 `drop_dep` 로 제거하고 재빌드한다(`bazel/repair.py`).

### A-4. KB 구축이 `fuzz/` 폴더와 `*_test.cc` 까지 읽는다
- 증상: 그룹 목록에 우리가 만든 하네스(`lg_json_fuzz`, `lg_lg_json_parser_fuzz`: `LLVMFuzzerTestOneInput`)와
  `*_test` 그룹(빌드 단위 없음)이 섞인다.
- 제안: `iter_source_files` 에서 `*/fuzz/*`, `*_test.cc` 제외 옵션(또는 기본값).

## 팀 결정이 필요한 것

1. **"검증된 고유 크래시 목록"(4주차 완료 기준)** — 현재 크래시 0건이다. 빈 목록도 산출로 인정하는가,
   실제 크래시가 필요한가? 필요하다면 다른 진입점 추가, `*_test.cc` 시드 코퍼스, 1주차식 심은 결함 중 선택.
2. **크래시 분류 계약** — 시작 실패를 `crashed` 가 아니라 `failed` 로 구분하는 B 의 변경(C-2)에 동의하는가.
