# LogosFuzz

LLM 기반 C/C++ 임베디드 범용(자동차 프로필 포함) 퍼징 하네스 자동 생성 시스템.
대상 하나를 프로필(`targets/*.json`) 한 파일로 적으면 API 추출부터 하네스 생성,
빌드 자가치유, 격리 퍼징, 커버리지, 크래시 판별까지 한 줄로 돈다.

```
  targets/<대상>.json   ← 대상 하나 = 프로필 한 파일
          │
          ▼
  EXT-01  Bazel 그래프·C/C++ AST → API·제약조건 지식베이스(KB)
          │
          ▼
  SCH-02  Logic Group 묶기 · 그룹별 퍼징 자원 배분
          │
          ▼
  GEN-03  LLM 하네스 생성 → 빌드 실패 시 자가치유 루프(기본 최대 3라운드)
          │
          ▼
  EXE-04  Docker 격리 퍼징 → 코퍼스 · 커버리지 · 크래시 수집
          │
          ▼
  ANA-05  중복 제거 · 정오탐 판별 · CVE 리포트 → KB 역피드백(EXT-01 로)
          │
          ▼
  out/<대상>/  run_summary.json · analysis.json · validation-summary.json

  CTR-06 컨트롤러가 위 단계를 한 줄 실행으로 묶고 HITL 승인 게이트를 건다.
```

## 범용 대상 빠른 시작

리눅스(Ubuntu 24.04) 기준. CMake 로 빌드하는 C/C++ 라이브러리 예시로 libsndfile 1.2.2 를 쓴다.

```bash
# 0. 준비: clang/compiler-rt(libFuzzer·ASan), llvm(profdata/cov), cmake, ninja, docker
sudo apt-get install -y clang libclang-rt-18-dev llvm cmake ninja-build docker.io
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt -e .
export OPENAI_API_KEY=...                       # 하네스 생성·자가치유

# 1. 대상 소스 받기 (프로필의 source_root 로 받는다)
bash scripts/fetch_libsndfile.sh

# 2. 한 줄 E2E: EXT → SCH → GEN(LLM) → 자가치유 → 퍼징 → 커버리지 → ANA
logosfuzz run --profile targets/libsndfile.json --budget 600 -o out/libsndfile
#   --max-round 3   자가치유 LLM 수정 최대 라운드
#   --no-docker     Docker 없이 호스트에서 퍼징(격리 없음)
```

결과는 `out/libsndfile/` 에 모인다.

| 파일 | 내용 |
| --- | --- |
| `run_summary.json` | 단계별 성공 여부·시간, 그룹별 자가치유 결과·실행 수·크래시·커버리지 |
| `kb.json` | 추출한 API·제약조건 지식베이스 |
| `gen/` | LLM 프롬프트와 첫 초안 |
| `build/harness/`, `build/bin/`, `build/bin-cov/` | 최종 하네스, 퍼저 바이너리, 커버리지 바이너리 |
| `corpus/<group>/` | 시드에서 시작해 퍼징으로 자란 최종 코퍼스 |
| `crashes/`, `fuzz_summary.json` | 크래시 입력과 퍼징 요약 |
| `coverage/<group>.summary.json` | 최종 코퍼스 재생 커버리지(하네스 소스 제외) |
| `analysis.json`, `validation-summary.json` | 크래시 중복 제거·판별, 공유용 요약 |

다른 대상은 프로필만 새로 쓰면 된다. 필드 설명은
[docs/GENERIC-A-target-profile.md](docs/GENERIC-A-target-profile.md), 임베디드(HAL 스텁) 예시는
`targets/embedded-sample.json` 이다. 단계를 따로 돌리려면:

```bash
python -m logosfuzz.generate.build --profile targets/libsndfile.json --harness my_fuzz.c   # 수동 하네스 빌드
logosfuzz fuzz --profile targets/libsndfile.json --timeout 300                             # 시드·하네스 위치를 프로필에서
logosfuzz analyze out/fuzz_summary.json --profile targets/libsndfile.json -o out/analysis.json
```

자동차(S-CORE, Bazel) 대상은 기존 `ctr_06_01_controller --mode bazel` 경로를 그대로 쓴다.
범용화 전후로 그 경로가 바뀌지 않았는지는 `python3 scripts/check_automotive_golden.py`
(골든 비교, `pytest` 에도 포함)로 확인한다. 검증 절차와 실측은
[docs/VERIFY-GENERIC-libsndfile.md](docs/VERIFY-GENERIC-libsndfile.md) 에 있다.

## 저장소 구조

기능(파이프라인 단계) 기준으로 `logosfuzz/` 패키지 아래에 모아 두었다.

```
logosfuzz/
  extract/      EXT-01 : Bazel 그래프, C/C++ AST·제약조건 추출
  knowledge/    EXT-01-04 : 통합 지식베이스 + RAG 색인/검색, KB 어댑터·평가
  schedule/     SCH-02 : Logic Group 추출, 시너지 우선순위, 자원 할당
  generate/     GEN-03 : 하네스 생성, 빌드 에러 분류·자가치유, 하네스 검증
  execute/      EXE-04 : 격리 퍼징 실행, 커버리지·크래시 수집, 코퍼스 관리
  analyze/      ANA-05 : 크래시 트리아지·근본원인·KB 피드백
    cve_reporting/  ANA-05-02 : 크래시 -> CVE 리포트 생성
  reporting/    리포트 요약 및 정적 HTML 리포트(web/)
  control/      CTR-06 : 파이프라인 컨트롤러, HITL 게이트
  common/       공통 모델·로깅
  pipeline.py   EXT -> SCH -> GEN 연계 실행 스크립트
docs/           파트별 설계 문서
examples/       샘플 타깃 소스와 실행 예제
scripts/        검증 아티팩트 준비, 성능 평가 등 보조 스크립트
tests/          패키지 공통 테스트 (일부 테스트는 각 서브패키지 tests/ 에 위치)
docker/         퍼징 실행용 컨테이너 이미지
targets/        대상 프로필(JSON)
```

## 문서

| 문서 | 내용 |
| --- | --- |
| [docs/MODULE-NOTES.md](docs/MODULE-NOTES.md) | 모듈별 상세 노트 (KB·에러 분류기·자가치유·입력 소비 검증 등 사용법) |
| [docs/GENERIC-A-target-profile.md](docs/GENERIC-A-target-profile.md) | 대상 프로필 필드 설명 |
| [docs/VERIFY-GENERIC-libsndfile.md](docs/VERIFY-GENERIC-libsndfile.md) | 범용 대상 검증 절차와 실측 |
| [docs/VALIDATION-SUMMARY-SCHEMA.md](docs/VALIDATION-SUMMARY-SCHEMA.md) | 공유용 검증 요약 스키마 |
| [docs/security/secure-coding.md](docs/security/secure-coding.md) | 시큐어코딩 가이드 적용 현황과 정적 분석 결과 |
| [docs/security/supply-chain.md](docs/security/supply-chain.md) | 외부 구성요소 고정값과 무결성 검증 기록 |
| `docs/` 의 과제 코드 문서 | EXT-01 · SCH-02 · GEN-03 · EXE-04 · ANA-05 단계별 설계 |

## 커밋 메시지 규칙

- `feat`: 기능 추가
- `fix`: 버그 수정
- `docs`: 문서 업데이트
- `style`: 코드 스타일 변경
- `refactor`: 코드 리팩토링
- `test`: 테스트 추가
- `chore`: 기타 잡다한 변경

## Contributing Guide

1. `main` 브랜치는 배포용으로 직접 푸시 금지
2. `dev` 브랜치에 기능 브랜치(`feature/*`) 머지
3. 새 기능은 반드시 `feature` 브랜치에서 작업

## PR (Pull Request)

- `feature` 브랜치 → `dev` 브랜치로 PR 생성
- 최소 1명 이상 리뷰 후 머지
- `main` 브랜치는 `dev`에서만 머지
