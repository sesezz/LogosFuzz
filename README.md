# LogosFuzz

## EXT-01-03 bear 빌드 통합

이 저장소는 `bear`를 사용해 컴파일 명령 데이터베이스를 생성하는 초기 통합을 제공합니다.

### Bear 설치

- Windows (PowerShell):
  ```powershell
  scoop install bear
  # 또는
  choco install bear
  ```
- WSL / Linux:
  ```bash
  sudo apt update
  sudo apt install bear build-essential clang
  ```

> Windows에서는 `bear`를 직접 설치하기보다 WSL 환경에서 사용하는 것이 더 안정적입니다.
>
> 이 저장소의 분석 도구는 `compile_commands.json`에 WSL 경로(`/mnt/c/...`)가 포함된 경우에도 Windows 경로로 변환하여 사용할 수 있습니다.

### 사용 방법

WSL에서 `bear`를 실행한 다음 Windows에서 분석을 수행하려면:

```bash
wsl bash -lc "cd /mnt/c/Users/Lenovo/Fuzz && python3 -m src.bear_integration --build 'gcc -c build/sample.c -o build/sample.o' --output build/compile_commands.json --cwd ."
python -m src.compile_db_analyzer --compile-db build/compile_commands.json --output build/compile_analysis.json
```

또는 Windows에서 `bear`가 직접 설치되어 있다면:

```bash
python -m src.bear_integration --build "gcc -c build/sample.c -o build/sample.o" --output build/compile_commands.json --cwd .
```

`run_bear_build(build_command, output_path=None, cwd=None)` 함수를 직접 호출하면, `bear` 실행 후 `compile_commands.json` 파일을 생성할 수 있습니다.

### 예시

```python
from src.bear_integration import run_bear_build

result = run_bear_build("gcc -c build/sample.c -o build/sample.o", output_path="build/compile_commands.json", cwd=".")
print(result["status"])
```

### compile_commands 로드

생성된 `compile_commands.json`을 읽으려면:

```python
from src.compile_commands import load_compile_commands

entries = load_compile_commands("build/compile_commands.json")
print(entries)
```

### compile_commands 기반 AST 분석

`compile_commands.json`에 기록된 컴파일 플래그를 활용하여 각 소스 파일을 분석하려면:

```bash
python -m src.compile_db_analyzer --compile-db build/compile_commands.json --output build/compile_analysis.json
```

또는 파이썬에서 직접:

```python
from src.compile_db_analyzer import analyze_compile_commands

results = analyze_compile_commands("build/compile_commands.json", output_path="build/compile_analysis.json")
print(results)
```

### 예제 스크립트

- `examples/build_sample.sh`: 단순 빌드 샘플 생성
- `examples/run_bear_example.py`: `bear`를 사용하여 `compile_commands.json` 생성
- `examples/parser_sample.c`: 제약조건 추출 예시 소스

> `bear` 실행 파일이 PATH에 없으면 `FileNotFoundError`가 발생합니다.

## EXT-01-02 RAG 제약조건 추출

C/C++ 소스에서 함수별 API 제약조건(NULL 검사, 버퍼·길이 쌍, 범위 검사, 자원 해제 책임 등)을
추출하여 RAG 지식베이스로 색인합니다. 하네스 생성기(GEN-03-01)가 이 지식베이스에 질의해
프롬프트 컨텍스트를 얻습니다. 자세한 내용은 [docs/EXT-01-02.md](docs/EXT-01-02.md) 참고.

```bash
# 지식베이스 구축 (경로 또는 compile_commands.json 기반)
python -m src.rag_constraints build --paths examples --output build/kb.json
python -m src.rag_constraints build --compile-db build/compile_commands.json --output build/kb.json

# 검색 (한국어 질의 지원)
python -m src.rag_constraints query --kb build/kb.json "버퍼 길이 제약" --top-k 3

# 하네스 생성용 컨텍스트 블록
python -m src.rag_constraints context --kb build/kb.json --function parse_header

# 커버리지 통계 (6주차 API 추출 정확도 평가용)
python -m src.rag_constraints stats --kb build/kb.json
```

파이썬에서 직접 사용하려면:

```python
from src.rag_constraints import ConstraintKB

kb = ConstraintKB.load("build/kb.json")
print(kb.context_for("parse_header"))      # LLM 프롬프트에 넣을 텍스트 블록
print(kb.constraints_of("parse_header"))   # 구조화된 제약조건 목록
print(kb.search("메모리 해제 책임", top_k=5))
```

> 외부 의존성 없이 BM25 검색기로 동작합니다. `sentence-transformers`가 설치되어 있으면
> `--dense` 옵션으로 밀집 검색을 함께 사용할 수 있습니다.

## EXT-01-04 KB 통합 (B/D 지원)

EXT-01-01(AST) · EXT-01-02(제약조건) · EXT-01-03(빌드 정보)을 하나의 지식베이스로 합치고,
B/D 파트가 바로 쓸 수 있는 형태로 내보냅니다. 자세한 내용은
[docs/EXT-01-04.md](docs/EXT-01-04.md) 참고.

```bash
python -m src.knowledge_base build --paths examples/uds --output build/kb.json
python -m src.knowledge_base show  --kb build/kb.json --api uds_read_did
python -m src.knowledge_base stats --kb build/kb.json
```

**B 파트 (SCH-02-02/03)** — 목업 하드코딩을 한 줄로 대체합니다. B의 파일은 수정하지 않습니다.

```python
from src.knowledge_base import KnowledgeBase
from src.kb_adapters import to_synergy_inputs
from sch_02_02_synergy_scheduler import compute_pairwise_synergy

kb = KnowledgeBase.load("build/kb.json")
apis, constraints = to_synergy_inputs(kb)       # ApiMetadata / Constraint 를 그대로 생성
results = compute_pairwise_synergy(apis, constraints)
```

**B 파트 (GEN-03-01)** — 하네스 프롬프트 컨텍스트 (시그니처 + 제약조건 + include + 플래그):

```python
from src.kb_adapters import harness_context
print(harness_context(kb, "uds_read_did"))
```

**D 파트 (GEN-03-02)** — 컴파일 에러 자가치유:

```python
from src.kb_adapters import suggest_fixes
suggest_fixes(kb, compiler_stderr)
# [{"error": "implicit_declaration", "action": "add_include",
#   "detail": '#include "uds.h"', "compile_flag": "-Iexamples/uds", ...}]
```

**D 파트 (ANA-05-01/02)** — 리포트 조인 키와 판별 근거:

```python
from src.kb_adapters import api_reference, constraints_for_triage
api_reference(kb, "uds_read_did")                                  # api_id/시그니처/헤더
constraints_for_triage(kb, "uds_read_did", min_confidence=0.7)     # 신뢰도 높은 제약조건
```

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
