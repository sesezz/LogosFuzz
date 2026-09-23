# 3주차 A(황다연) — 빌드 단위 어댑터·Logic Group 경계·Result 계약

**작업일** 2026-09-23

**기준 브랜치** `origin/dev` (`89382c0`)

**작업 브랜치** `codex/dayeon-week3`

## 완료한 범위

### 1. `kb_adapters.py` 빌드 단위 메타데이터 노출

- `build_unit_metadata()`가 KB의 Bazel 규칙과 소속 API를 정규화해 반환한다.
- `build_unit_for_api()`로 API 이름/ID에서 소유 빌드 단위를 조회한다.
- `call_sequences_by_build_unit()`가 호출 순서를 빌드 타깃별로 제공한다.
- 스케줄러의 `dep_graph_ref`는 소스 파일 대신 Bazel 타깃을 가리킨다.
- 하네스 컨텍스트와 리포트 API 참조에 빌드 시스템, 타깃, 규칙 종류, deps를 넣는다.
- 빌드 정보가 없는 기존 KB는 소스 파일 기준으로 동일하게 동작한다.

### 2. `logic_groups.py`의 빌드 단위 경계 적용

- Bazel 타깃을 Logic Group의 최상위 경계로 사용한다.
- 같은 상태 타입을 공유하거나 호출 관계가 있어도 서로 다른 빌드 타깃은 병합하지 않는다.
- 상태 타입이 없는 API는 같은 빌드 단위 안에서 묶는다.
- `GroupInfo` 저장 형식과 통계에 `build_units`를 추가했다.
- 기존 버전 1 그룹 JSON은 `build_units`가 없어도 계속 읽을 수 있다.

### 3. `constraint_extractor.py`의 `score::Result` 에러 계약 추출

- `score::MakeUnexpected(error)`, `score::Unexpected{error}`,
  `score::Result<T>{score::unexpect, error}`를 `error_contract`로 추출한다.
- `child.error()`처럼 하위 오류를 전파하는 경우도 별도 계약으로 보존한다.
- `auto f() -> score::Result<T>` 후행 반환형과 일반 C++ 템플릿 반환형을 인식한다.
- `MakeUnexpected`가 있는 입력 거부 분기를 오류 경로로 판정해 인자 사전조건의 신뢰도를 높인다.

## 검증

```text
관련 모듈 회귀: 140 passed
전체 회귀:      653 passed, 1 skipped
```

실제 `score-baselibs`의 `result_example_cpp.cpp`, `json_writer.cpp`,
`sha256digest.cpp`를 표본으로 실행해 32개 함수에서 4개의 `error_contract`를
추출했다. 확인된 오류는 직접 오류 코드, 지역 오류 객체, `result.error()` 전파,
한정 C++ 멤버 함수 형태를 모두 포함한다.
