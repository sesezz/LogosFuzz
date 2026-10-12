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
| Docker 실행(`ubuntu:22.04` 이미지) | **실패** — 아래 C-1 |
| Docker 실행(24.04 로컬 이미지) | 성공 — 두 그룹 10초 퍼징(17k~25k exec/s), 크래시 0건, 리포트 `passed` |

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
- 전체 경로 확인: `docker/Dockerfile` 사본(`FROM ubuntu:24.04`, `useradd` 줄만 아래처럼 수정)으로 로컬 이미지를
  빌드해 `logosfuzz fuzz --groups ...` (Docker 모드)를 돌리면 두 그룹이 정상 퍼징되고 리포트까지 이어진다.
- **주의(`FROM` 줄만 바꾸면 빌드가 깨진다)**: 24.04 베이스 이미지에는 UID 1000 의 `ubuntu` 사용자가 이미 있어
  `RUN useradd -m -u 1000 fuzzer ...` 가 `useradd: UID 1000 is not unique` 로 실패한다.
  `RUN (userdel -r ubuntu || true) && useradd -m -u 1000 fuzzer ...` 로 바꾸면 17단계 모두 통과한다.
- 제안(단기): `FROM ubuntu:24.04` + 위 `useradd` 수정. 컨테이너가 바이너리를 **빌드한 호스트보다 같거나 새로워야** 하므로,
  호스트가 24.04 이하인 팀원에게만 통한다. 호스트가 더 최신인 팀원은 같은 문제가 다시 난다.
- 제안(범용): 바이너리가 실행 환경과 무관하게 돌게 하려면 **빌드 쪽을 고정**해야 한다.
  1. 오래된 glibc 의 sysroot 를 Bazel LLVM 툴체인에 고정(오버레이 `MODULE.bazel`, B·C 협의) — 호스트 버전과
     무관하게 낮은 glibc 만 요구하는 바이너리가 나온다. 아직 시도하지 않았고 baselibs 가 그 libstdc++ 로
     빌드되는지 확인이 필요하다.
  2. 이미지 안에서 빌드하고 같은 이미지에서 실행(이미지에 bazelisk 가 이미 있다).
  (정적 링크는 libstdc++ 만 풀고 `GLIBC_2.38` 은 남으며, ASan 은 정적 glibc 와 함께 쓸 수 없어 해결책이 아니다.)

### C-2. 시작하지 못한 실행이 조용히 묻힌다
- 증상: 위 실패에서도 화면에는 `exec/s=0 cov=0 execs=0 ... 완료: 총 크래시 0건 → analyze 단계로 전달` 만 나온다.
  `fuzz_summary.json` 에는 `exit_code: 1, crashed: true` 로 기록되는데 크래시 산출물은 없다.
- 제안: `exit_code != 0` 이고 `execs == 0` 이면 stderr 마지막 줄과 함께 **실행 실패**로 알려 달라.
- B 쪽 대응: 리포트(`summary.py`)는 "증거 없음 + 처리량·커버리지·실행 횟수 0" 이면 `crashed` 가 아니라
  `failed` 로 분류하도록 바꿨다(스키마 문서 "시작 실패와 크래시의 구분").

### C-3. `fuzz_summary.json` 그룹에 총 실행 횟수(`execs`)를 기록해 달라
- 증상: 화면에는 `execs=743036` 이 나오는데 JSON 에는 `exec_per_sec`·`duration_sec`·`coverage` 만 있다.
- 제안: `fuzz_session.py` 그룹 dict 에 `"execs": g.stats.execs` 한 줄.
- B 쪽 대응: 없으면 `exec_per_sec × duration_sec` 로 추정해 `~` 를 붙여 표시한다(실측 대비 호스트 실행 약 0.5%, Docker 실행 약 4% — Docker 는 `duration_sec` 에 컨테이너 시작 시간이 들어간다).
  `execs` 가 생기면 자동으로 실측값을 쓴다.

### C-4. (확인 요청) 커버리지 비교 담당과 baselibs 기준 커밋
- 4주차 "유닛테스트 vs 퍼징 커버리지 비교실험"은 C 의 `scripts/compare_coverage.sh`(커밋 `d65c0dd`)가
  이미 구현·실측한 것으로 보인다. 이 항목이 C 담당이 맞는지 확인해 달라.
  B 가 만든 `reporting/coverage_compare.py` 는 기능이 겹치고 실데이터로 검증하지 못했다 — 제외해도 되는가?
- 스크립트는 baselibs `09be72c`(`--config=llvm_cov`, `tools/coverage/`) 기준이다. B 의 로컬 baselibs 는
  `ff0e4b6`(2026-06-03)이고 그 커밋은 없다. 이 환경에서 직접 시도한 `bazel coverage`와 수동 계측은
  막혔다(기본 config 에서 `-Werror=deprecated-declarations`, 이후 vajson 구현 `.cpp` 의 커버리지 매핑 누락).
  팀이 쓰는 baselibs 커밋을 알려 달라.

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

1. **"검증된 고유 크래시 목록"(4주차 완료 기준)** — 현재 크래시 0건이다(10분 퍼징 포함). 빈 목록도 산출로 인정하는가,
   실제 크래시가 필요한가? 필요하다면 다른 진입점 추가, `*_test.cc` 시드 코퍼스, 1주차식 심은 결함 중 선택.
2. **크래시 분류 계약** — 시작 실패를 `crashed` 가 아니라 `failed` 로 구분하는 B 의 변경(C-2)에 동의하는가
   (스키마 소유자 확인 필요).
3. **커버리지 비교 담당** — C 의 `scripts/compare_coverage.sh` 로 가는가? B 의 `coverage_compare.py` 는 제외?
4. **"최종 리포트 취합·발표자료"의 범위**(B 4주차 항목) — 코드인가 문서인가?
5. **baselibs 기준 커밋 통일**(C: `09be72c` / B 로컬: `ff0e4b6`) 과 **Docker 실행 환경 정책**
   (단기 24.04 이미지 / 범용 sysroot 고정 또는 이미지 안 빌드).
