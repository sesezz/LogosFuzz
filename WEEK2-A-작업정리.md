# 2주차 A(황다연) — Bazel 추출 자동화·C++ AST·빌드 단위 KB

**작업일** 2026-09-20
**기준 브랜치** `origin/dev` (`a03bd34`)
**작업 브랜치** `codex/dayeon-week2`

## 완료한 범위

### 1. `extract/bazel_query.py` 신규

- `bazel query --output=xml 'deps(set(...))'`를 한 번 실행해 C/C++ 타깃 그래프를 만든다.
- 타깃별 `deps`, `srcs`, `hdrs`, `includes`, `copts`, `defines`, `local_defines`를 보존한다.
- 파일 소유 타깃과 전이 deps를 찾아 libclang용 `-I`/`-D` 플래그를 만든다.
- B 파트의 `BazelQueryDepsProvider`에 바로 주입할 `deps_of()`와
  `BazelGraph.deps_for()`를 제공한다.
- 쉘 문자열을 만들지 않고 인자 배열로 Bazel을 실행하며, 실패 원문을
  `BazelQueryError`에 보존한다.

### 2. `ast_analyzer.py` C++ 확장

- `.c`는 C11, `.cc/.cpp/.h/.hpp`는 C++17로 자동 판정한다.
- `FUNCTION_DECL`뿐 아니라 `CXX_METHOD`, `CONSTRUCTOR`, `FUNCTION_TEMPLATE`의
  시그니처·파라미터·정의 여부를 수집한다.
- 네임스페이스/클래스 완전 한정 이름(예: `score::json::Parser::Parse`)과
  템플릿 파라미터를 보존한다.
- Bazel 그래프에서 받은 컴파일 플래그를 AST 분석에 실제로 전달한다.
- 진단 메시지와 적용된 `clang_args`를 결과 JSON에 남긴다.

### 3. KB 빌드 단위 스키마

- KB 버전을 2로 올리고 최상위 `build_units`를 추가했다.
- 파일/API 문서에 `build_system`, `build_target`, `build_rule_kind`, `build_deps`,
  `compile_flags`를 기록한다.
- 기존 버전 1 KB도 계속 읽을 수 있다.
- `kb_eval.py`도 C++ 메서드·생성자·함수 템플릿을 정답셋에 포함한다.

## B 파트 연결

```python
from functools import partial

from logosfuzz.extract.bazel_query import deps_of
from logosfuzz.generate.bazel.deps_provider import BazelQueryDepsProvider

provider = BazelQueryDepsProvider(
    partial(deps_of, workspace="third_party/score-baselibs")
)
```

`deps_for()` 결과는 `[대상 타깃, 직접 deps...]` 순서라 생성되는
`cc_fuzz_test(deps=...)`에 그대로 넣을 수 있다.

## 검증

```text
전체 회귀: 596 passed, 1 skipped
```

호스트에 Bazel 실행 파일은 없어 실제 `//score/json` 질의는 수행하지 못했다.
대신 Bazel XML 형식과 저장소의 `tests/fixtures/bazel_repro` 계약을 단위 테스트로
고정했다. 전체 2주차 게이트(자동 BUILD + 하네스 빌드 및 자가치유)는 B 파트 브랜치
`feat/score-bazel-overlay`가 `dev`에 병합된 뒤 컨테이너에서 함께 실행하면 된다.
