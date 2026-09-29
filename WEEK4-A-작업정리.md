# 황다연 고도화 4주차 작업 정리

## 목표

3주차에 완성한 통합 지식베이스의 API 메타데이터, Bazel 빌드 단위,
`score::Result` 오류 계약을 실제 하네스 생성 파이프라인이 소비하도록 연결했다.
이번 주차에는 새 추출기를 추가하지 않고 **EXT(KB)에서 GEN, BUILD,
VALIDATION까지 이어지는 입력 계약을 하나로 정리했다.**

## 구현 내용

### 1. KB 기반 하네스 빌드 계획

`logosfuzz/generate/kb_bridge.py`의 `plan_harness()`가 API 이름 또는 ID를 받아
다음 값을 한 번에 확정한다.

- 원본 함수 시그니처, 반환형, 파라미터 타입
- 선언 헤더와 컴파일 플래그
- API를 소유하는 Bazel 타깃과 직접 의존성
- 일반 제약조건과 `error_contract`
- C/C++ 언어 및 로직 그룹
- LLM 하네스 생성용 컨텍스트

정확히 일치하는 API만 허용하며, 외부 하네스에서 호출할 수 없는 `static` 함수와
테스트/예제 코드는 초기에 거절한다. Bazel 빌드 단위가 없는 API도 조용히 임의의
BUILD를 만들지 않고 명시적인 오류로 중단한다.

### 2. Bazel BUILD 의존성 연결

`KnowledgeBaseDepsProvider`는 3주차 KB의 build unit을 기존
`BuildFileGenerator`가 요구하는 deps 형식으로 변환한다.

- 대상 라이브러리 자체를 첫 번째 직접 의존성으로 포함
- KB에서 추출한 직접 deps 추가
- 중복 라벨 제거
- `@score_baselibs` 같은 외부 저장소 접두어를 모든 로컬 라벨에 일관되게 적용

이제 BUILD 생성기가 정적 하드코딩 목록 대신 실제 API 소유권 정보를 사용할 수
있다.

### 3. 자가치유 연결

`HarnessBuildPlan.repair_knowledge()`는 기존 `SelfHealLoop.knowledge` 입력 규격에
맞춰 다음 힌트를 제공한다.

- 대상 API 시그니처
- Bazel 타깃/deps
- include 및 컴파일 플래그
- 추출된 제약조건
- `score::Result` 등의 명시적 오류 계약

`configure_self_heal()`을 사용하면 팀원이 만든 자가치유 루프에 이 정보를 바로
주입할 수 있으며, 호출자가 직접 지정한 힌트는 유지한다. `to_draft()`에도 같은
정보가 context로 남아 이후 파이프라인에서 추적할 수 있다.

### 4. 검증 단계 산출물 연결

`build_harness_from_kb()`는 기존 `BuildFileGenerator`를 그대로 이용해 BUILD 생성과
빌드를 수행한다. 성공하면 GEN-03-04가 받는 `HarnessArtifact`를 만들고 다음 정보를
넘긴다.

- 퍼저 바이너리와 생성 소스 경로
- 로직 그룹
- 원본 API 시그니처
- 생성 모델명과 코퍼스 경로

KB에서 시작한 메타데이터는 빌드 성공 뒤 검증 단계까지 이어진다.

## 사용 예시

```python
from logosfuzz.generate import build_harness_from_kb, plan_harness

plan = plan_harness(
    kb,
    "parse_json",
    target_label="@score_baselibs//score/json:json",
)
draft = plan.to_draft(generated_source, project="score")
plan.configure_self_heal(self_heal_loop)

result = build_harness_from_kb(
    kb,
    "parse_json",
    healed_source,
    build_file_generator,
    target_label="@score_baselibs//score/json:json",
)
if result.ok:
    validation_pipeline.validate(result.artifact)
```

## 테스트 범위

`tests/test_kb_generate_bridge.py`에 다음 회귀 테스트를 추가했다.

- 외부 저장소 Bazel 라벨과 직접 deps 변환
- KB 메타데이터를 하네스 초안·자가치유·검증 계약으로 변환
- static 및 테스트 API 제외
- 존재하지 않는 API와 빌드 단위 누락 오류
- 빌드 성공 시 `HarnessArtifact` 생성

## 남은 통합 확인

실제 S-CORE 워크스페이스와 Bazel 툴체인이 준비된 환경에서는 생성된 하네스로
`@score_baselibs` 전체 빌드 및 GEN-03-04 dry-run을 수행해야 한다. 단위 테스트는
명령 실행 없이 데이터 계약과 연결 로직을 검증하도록 구성했다.
