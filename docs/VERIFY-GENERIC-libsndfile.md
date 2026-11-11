# 범용 대상 검증: libsndfile 1.2.2

LogosFuzz 를 C/C++ 임베디드 범용(자동차 프로필 포함)으로 넓힌 뒤, Bazel 이 아닌 대상
하나를 처음부터 끝까지 돌려 확인한 기록이다. **이 문서에는 실제로 돌려서 나온 값만 적는다.**
아직 돌리지 않은 측정은 빈칸이 아니라 "미실행"으로 적는다.

- 대상: libsndfile 1.2.2 (commit `72f6af15e8f85157bd622ed45b979025828b7001`), `targets/libsndfile.json`
- 명령: `logosfuzz run --profile targets/libsndfile.json --budget 600 --max-round 3 -o out/libsndfile`
- 한 번에 돌리는 스크립트: `scripts/e2e_generic_libsndfile.sh` (E2E + 커버리지 → 자동차 회귀 → 결과 Markdown)

## 1. 자동과 수동의 경계

`logosfuzz run` 안의 단계는 모두 자동이다. 사람이 고르거나 고치는 단계가 없다.
사람이 한 일은 전부 `run` 밖에 있고, 성과(자동 생성 성공률 등)에 넣지 않는다.

| 구분 | 무엇을 | 누가 | 비고 |
| --- | --- | --- | --- |
| 수동 (1회) | 프로필 `targets/libsndfile.json` 작성 | 사람 (GENERIC-A) | 빌드 인자·API 8개·에러계약. 대상마다 한 번 |
| 수동 (1회) | 고정 커밋·받는 스크립트 `scripts/fetch_libsndfile.sh` | 사람 (GENERIC-A) | |
| 수동 (환경) | 툴체인 설치, `OPENAI_API_KEY` 설정 | 사람 | README "범용 대상 빠른 시작" |
| 자동 | BUILD: 대상 라이브러리 계측 빌드 (ASan·UBSan·fuzzer-no-link) | `CMakeAdapter.prepare()` | 캐시됨 |
| 자동 | EXT: KB (API·제약조건·헤더·빌드 단위) | `KnowledgeBase.build(profile=)` | |
| 자동 | SCH: Logic Group, 시너지 랭킹, 시간 배분 | `build_groups` → `allocate_resources` | 그룹당 최소 30초 |
| 자동 | GEN: 하네스 생성 | LLM (`generate_harness`) | 프롬프트·첫 초안은 `gen/` |
| 자동 | HEAL: 링크까지 빌드, 실패 시 LLM 수정·미정의 심볼 스텁 | `heal_loop_for(profile)` | 라운드 수는 `run_summary.json` |
| 자동 | COVBIN: 같은 하네스를 커버리지 계측으로 재빌드 | `adapter_for(profile, coverage=True)` | `build-fuzz-cov`, `bin-cov/` |
| 자동 | EXE: 격리 퍼징 (시드 → `corpus/<group>/`) | `FuzzSession` | Docker 기본 |
| 자동 | COV: 최종 코퍼스 재생 → profdata → `llvm-cov export -summary-only` | `collect_corpus_coverage` | 하네스 소스 제외 |
| 자동 | ANA: 중복 제거·판별·승인 게이트 등록 | `analyze --profile` | |
| 수동 (사후) | 승인 게이트의 "검토대기" 크래시 판단 | 사람 (`logosfuzz review`) | 판단 전까지 검증된 크래시로 세지 않는다 |

## 2. EC2 실측 (r5.2xlarge, Ubuntu 24.04)

**미실행.** 아래 명령을 돌린 뒤 `out/libsndfile/e2e-report.md` 를 이 절에 그대로 붙인다.

```bash
export OPENAI_API_KEY=...
bash scripts/e2e_generic_libsndfile.sh          # BUDGET=600, Docker 격리
```

리포트에는 환경(인스턴스 타입·커밋·툴체인 버전), 단계별 성공 여부와 시간, 그룹별 자가치유
결과·LLM 수정 횟수·스텁·실행 수·크래시·라인/브랜치 커버리지, 자동차 회귀 결과가 들어간다.

## 3. 배관 확인 (클라우드 컨테이너, LLM 없이)

EC2 전에 `run` 의 단계 연결이 실제 도구로 도는지 확인했다. **이 측정은 하네스 자동 생성
성과가 아니다.** OpenAI 키가 없는 환경이라 GEN 단계의 LLM 자리에 사람이 쓴 하네스를 돌려주는
가짜를 넣었다(모든 그룹이 같은 하네스를 받는다). 그 외 단계(BUILD, EXT, SCH, HEAL, COVBIN,
EXE, COV, ANA)는 실제 cmake·clang·libFuzzer·llvm 도구로 돌았다.

환경: Ubuntu 24.04.5 LTS 컨테이너 4코어, clang 18.1.3, cmake 3.28.3, Python 3.13, `--no-docker`, 2026-10-14.

### libsndfile 1.2.2 (`--budget 60`)

넣은 하네스: `sf_open_virtual` → `sf_readf_float` → `sf_close` (메모리 가상 I/O, 사람 작성).

| 단계 | 결과 | 시간(초) | 비고 |
| --- | --- | --- | --- |
| BUILD | 성공 | 29.88 | 첫 빌드 (캐시 없음) |
| EXT | 성공 | 1.44 | API 8개, 누락 0 |
| SCH | 성공 | 0.01 | 그룹 2개 (아래) |
| GEN | 성공 | 0.01 | 가짜 LLM |
| HEAL | 성공 | 0.97 | 2/2 빌드, LLM 수정 0, 스텁 0 |
| COVBIN | 성공 | 30.34 | 커버리지 계측 라이브러리 첫 빌드 포함 |
| EXE | 성공 | 62.21 | 그룹당 30초 |
| COV | 성공 | 0.27 | 2/2 측정 |
| ANA | 성공 | 0.08 | 결함 7건 → 고유 6개, 모두 검토필요 |

| 그룹 | SCH 가 묶은 API | SCH 배분 → 실제(초) | 실행 수 | 크래시 | 라인 커버리지 | 브랜치 커버리지 |
| --- | --- | --- | --- | --- | --- | --- |
| lg_SNDFILE | sf_close, sf_command, sf_seek, sf_get_string, sf_read_short, sf_readf_float | 60 → 30 | 652,410 | 0 | 1091/25833 (4.22%) | 557/13140 (4.24%) |
| lg_SF_INFO | sf_open_virtual | 0 → 30 | 544,406 | 0 | 803/25833 (3.11%) | 407/13140 (3.10%) |

- 커버리지 분모(25,833줄)는 libsndfile 소스 전체다. 하네스 파일은 `-ignore-filename-regex` 로 빠졌다.
- ANA 가 받은 결함은 UBSan `integer-overflow` 보고다(퍼징을 멈추지 않는 종류라 크래시 수는 0).
  위치: `src/mat4.c:107, 318, 320, 322, 323(x2)`, `src/pcm.c:130`. 판별은 모두 "검토필요"이고
  정탐 여부는 확인하지 않았다.

### 임베디드 샘플 (`targets/embedded-sample.json`, `--budget 20`)

넣은 하네스: `examples/embedded/harness/fuzz_proto.c` (사람 작성).

| 항목 | 값 |
| --- | --- |
| HEAL | 2/2 빌드. 첫 링크에서 `HAL_GetTick`, `HAL_UART_Transmit` 미정의 → weak 스텁 자동 생성 → 재링크 성공 (LLM 수정 0) |
| EXE | 그룹당 10초. 두 그룹 모두 `proto_parse` 의 의도적 힙 OOB 를 찾음 (실행 6,998 / 7,878 회째) |
| COV | 라인 57/66 (86.36%), 브랜치 21/30 (70.0%) |
| ANA | 결함 2건 → 고유 1개, 검토필요 (아래 한계 1) |

같은 흐름이 `tests/test_cli_run.py::test_real_e2e_embedded_sample_no_docker` 로 매번 돈다.

## 4. 이번에 보인 한계

1. **ASan 크래시 위치가 `unknown`.** 실행 설정이 `ASAN_OPTIONS=symbolize=0` 이라(WSL 에서
   심볼라이저가 멈추던 문제의 회피책, `config.py`) ASan 스택에 파일:줄이 없다. 그래서 판별기가
   임베디드 샘플의 OOB 를 "검토필요"로 둔다. UBSan 보고는 자체적으로 위치를 찍어서 영향이 없다.
   크래시 입력을 퍼징 뒤에 심볼라이즈해서 다시 돌리는 단계가 필요하다(ANA 후속).
2. **생성자 없는 그룹.** SCH 가 libsndfile 을 `SNDFILE` 상태 타입으로 묶을 때 핸들을 만드는
   `sf_open`/`sf_open_virtual` 이 다른 그룹(`lg_SF_INFO`)으로 갔다. `lg_SNDFILE` 하네스를 LLM 이
   만들 때 핸들을 열 API 가 프롬프트에 없을 수 있다. 임베디드 샘플도 `proto_create` 가 따로 빠졌다.
   EC2 실측에서 이 그룹의 자가치유 결과를 보고 판단한다.
3. **SCH 가 0초를 준 그룹.** 점수 0 인 그룹에 0초를 배정해서, `run` 은 그룹당 최소 30초를 준다
   (합은 `--budget` 을 넘지 않는다).

## 5. 자동차 회귀

범용화 작업이 자동차(S-CORE, `--mode bazel`) 경로를 바꾸지 않았는지 골든과 비교한다.

```bash
python3 scripts/check_automotive_golden.py      # build_summary · BUILD.bazel 골든 비교
python3 -m pytest -q --ignore=examples           # tests/test_automotive_golden.py 포함
```

| 실행 | 결과 |
| --- | --- |
| 클라우드 컨테이너, 2026-10-14, 이 브랜치 | 골든 일치, `pytest` 1184 passed · 4 skipped |
| EC2 | 미실행 (스크립트가 같이 돈다) |
