# LogosFuzz

## 저장소 구조

기능(파이프라인 단계) 기준으로 `logosfuzz/` 패키지 아래에 모아 두었다.

```
logosfuzz/
  extract/      EXT-01 : 소스/컴파일 DB 파싱, AST·제약조건 추출
  knowledge/    EXT-01-04 : 통합 지식베이스 + RAG 색인/검색, KB 어댑터·평가
  schedule/     SCH-02 : Logic Group 추출, 시너지 우선순위, 자원 할당
  generate/     GEN-03 : 하네스 생성·컴파일 자가치유·검증, Mock 주입
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
```

## 빌드 정보 수급: bear → Bazel (EXT-01-03 폐기)

`bear` 기반 `compile_commands.json` 수급은 **제거했다**. 대상이 S-CORE 로 바뀌었고,
S-CORE 는 Bazel 로 빌드하며 strict deps·visibility 를 강제한다. 이 환경에서
`deps`·include 경로의 정답을 아는 것은 `bazel query` 뿐이며, `bear` 로 가로챈
컴파일 명령은 그 정보를 담지 못한다.

삭제한 것:

| 모듈 | 대체 |
| --- | --- |
| `logosfuzz/extract/bear_integration.py` | 없음 (Bazel 이 빌드를 소유) |
| `logosfuzz/extract/compile_commands.py` | 2주차 `extract/bazel_query.py` |
| `logosfuzz/extract/compile_db_analyzer.py` | 2주차 `extract/bazel_query.py` |
| `examples/run_bear_example.py` | 없음 |

`KnowledgeBase.build()` / `rag_constraints.build_kb()` / `kb_eval.evaluate()` /
`logic_groups` 의 `--compile-db` 옵션도 함께 없앴다. `FileInfo.flags` 와 문서의
`compile_flags` 필드는 **남겨 뒀다** — 2주차에 Bazel 타깃에서 받은 값으로 채우기
위해서다. 그때까지는 빈 리스트로 나간다.

### 예제 스크립트

- `examples/build_sample.sh`: 단순 빌드 샘플 생성
- `examples/parser_sample.c`: 제약조건 추출 예시 소스

## EXT-01-01 `//score/json` C++ 파싱 실패 케이스

현행 `logosfuzz/extract/ast_analyzer.py` 는 C 전용이다. `//score/json` 106개 파일에
그대로 돌린 결과와 실패 분류는
[docs/EXT-01-01-SCORE-JSON-CPP-FAILURES.md](docs/EXT-01-01-SCORE-JSON-CPP-FAILURES.md) 에 있다.
재현:

```bash
# 대상 소스 받기 (third_party/ 는 커밋하지 않는다)
git clone --depth 1 --filter=blob:none --sparse     https://github.com/eclipse-score/baselibs.git third_party/score-baselibs
git -C third_party/score-baselibs sparse-checkout set score

python -m scripts.score_json_ast_survey     --output report/score-json-ast-survey.json     --markdown docs/EXT-01-01-SCORE-JSON-CPP-FAILURES.md
```

## EXT-01-02 RAG 제약조건 추출

C/C++ 소스에서 함수별 API 제약조건(NULL 검사, 버퍼·길이 쌍, 범위 검사, 자원 해제 책임 등)을
추출하여 RAG 지식베이스로 색인합니다. 하네스 생성기(GEN-03-01)가 이 지식베이스에 질의해
프롬프트 컨텍스트를 얻습니다. 자세한 내용은 [docs/EXT-01-02.md](docs/EXT-01-02.md) 참고.

```bash
# 지식베이스 구축 (경로 기반)
python -m logosfuzz.knowledge.rag_constraints build --paths examples --output build/kb.json

# 검색 (한국어 질의 지원)
python -m logosfuzz.knowledge.rag_constraints query --kb build/kb.json "버퍼 길이 제약" --top-k 3

# 하네스 생성용 컨텍스트 블록
python -m logosfuzz.knowledge.rag_constraints context --kb build/kb.json --function parse_header

# 커버리지 통계 (6주차 API 추출 정확도 평가용)
python -m logosfuzz.knowledge.rag_constraints stats --kb build/kb.json
```

파이썬에서 직접 사용하려면:

```python
from logosfuzz.knowledge.rag_constraints import ConstraintKB

kb = ConstraintKB.load("build/kb.json")
print(kb.context_for("parse_header"))      # LLM 프롬프트에 넣을 텍스트 블록
print(kb.constraints_of("parse_header"))   # 구조화된 제약조건 목록
print(kb.search("메모리 해제 책임", top_k=5))
```

> 외부 의존성 없이 BM25 검색기로 동작합니다. `sentence-transformers`가 설치되어 있으면
> `--dense` 옵션으로 밀집 검색을 함께 사용할 수 있습니다.

## EXT-01-04 KB 통합 (B/D 지원)

EXT-01-01(AST) · EXT-01-02(제약조건)을 하나의 지식베이스로 합치고,
B/D 파트가 바로 쓸 수 있는 형태로 내보냅니다. 자세한 내용은
[docs/EXT-01-04.md](docs/EXT-01-04.md) 참고.

```bash
python -m logosfuzz.knowledge.knowledge_base build --paths examples/uds --output build/kb.json
python -m logosfuzz.knowledge.knowledge_base show  --kb build/kb.json --api uds_read_did
python -m logosfuzz.knowledge.knowledge_base stats --kb build/kb.json
```

**B 파트 (SCH-02-02/03)** — 목업 하드코딩을 한 줄로 대체합니다. B의 파일은 수정하지 않습니다.

```python
from logosfuzz.knowledge.knowledge_base import KnowledgeBase
from logosfuzz.knowledge.kb_adapters import to_synergy_inputs
from logosfuzz.schedule.sch_02_02_synergy_scheduler import compute_pairwise_synergy

kb = KnowledgeBase.load("build/kb.json")
apis, constraints = to_synergy_inputs(kb)       # ApiMetadata / Constraint 를 그대로 생성
results = compute_pairwise_synergy(apis, constraints)
```

**B 파트 (GEN-03-01)** — 하네스 프롬프트 컨텍스트 (시그니처 + 제약조건 + include + 플래그):

```python
from logosfuzz.knowledge.kb_adapters import harness_context
print(harness_context(kb, "uds_read_did"))
```

**D 파트 (GEN-03-02)** — 컴파일 에러 자가치유:

```python
from logosfuzz.knowledge.kb_adapters import suggest_fixes
suggest_fixes(kb, compiler_stderr)
# [{"error": "implicit_declaration", "action": "add_include",
#   "detail": '#include "uds.h"', "compile_flag": "-Iexamples/uds", ...}]
```

**D 파트 (ANA-05-01/02)** — 리포트 조인 키와 판별 근거:

```python
from logosfuzz.knowledge.kb_adapters import api_reference, constraints_for_triage
api_reference(kb, "uds_read_did")                                  # api_id/시그니처/헤더
constraints_for_triage(kb, "uds_read_did", min_confidence=0.7)     # 신뢰도 높은 제약조건
```

## GEN-03-02 자가치유 에러 코퍼스 (D 파트)

2주차 `generate/bazel_errors.py` 분류기를 추측으로 짜지 않기 위해, **실제로 빌드를
깨뜨려서** Bazel 에러와 sanitizer 출력 원문을 모아 뒀다. 대응표와 분석은
[docs/GEN-03-02-ERROR-CORPUS.md](docs/GEN-03-02-ERROR-CORPUS.md) 에 있다.

| 경로 | 내용 |
| --- | --- |
| `tests/fixtures/bazel_repro/` | 고의 파손용 최소 Bazel 워크스페이스 (+ `breaks/` 오버레이 10종) |
| `tests/fixtures/bazel_errors/` | deps·visibility·구문 오류 등 Bazel 에러 원문 |
| `tests/fixtures/sanitizer_logs/` | UBSan/ASan/LSan 출력 원문 (설정 2종 × 케이스 11종) |
| `scripts/collect_selfheal_corpus.sh` | 수집기 (리눅스 전용) |
| `docker/Dockerfile.selfheal` | 수집 환경 이미지 (bazelisk + clang 18 / Ubuntu 24.04) |

재수집(툴체인을 바꿨을 때만 필요하다 — 코퍼스는 커밋되어 있다):

```bash
bash scripts/collect_selfheal_corpus.sh --out-root .
```

```bash
docker build -f docker/Dockerfile.selfheal -t logosfuzz-selfheal . && docker run --rm -v "$PWD":/repo logosfuzz-selfheal
```

`tests/test_selfheal_corpus.py` 가 코퍼스와 문서 대응표의 일치를 지킨다. Bazel 없이
도는 순수 픽스처 테스트라 CI 에서 툴체인이 필요 없다.

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
