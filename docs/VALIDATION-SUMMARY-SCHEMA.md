# Validation Summary JSON 계약

`logosfuzz summary`가 만드는 `validation-summary.json`은 실행기(EXE), 분석기(ANA), 정적 HTML 리포트가 함께 사용하는 공유 산출물이다.

## 생성 방법

```bash
python -m logosfuzz.cli summary \
  --run out/fuzz_summary.json \
  --analysis out/analyze.json \
  --project dlt-daemon \
  --environment ec2 \
  --output out/validation-summary.json
```

`--analysis`를 생략하면 분석 단계가 아직 실행되지 않은 결과로 기록된다. 이 경우 `analysis.status`가 `not_run`이 된다.

## ANA 도달 가능성 증거 연결

크래시의 콜스택만으로 정탐·오탐을 단정하지 않도록 대상 소스와 하네스 소스를
ANA에 함께 전달할 수 있다. `--source-root`를 지정하면 대상 함수 정의, 공개
헤더 선언, 프로덕션 호출부, 하네스 호출부가 판별 신호와 결과 JSON의
`reachability` 필드에 보존된다.

```bash
python -m logosfuzz.analyze.cli analyze \
  out/sanitizer \
  --source-root /work/dlt-daemon \
  --harness-dir /work/harnesses \
  --output out/analyze.json
```

`--source-root`를 생략하면 기존 규칙 기반 판별을 수행하며 `reachability`는
`null`이다. 소스 스캔에 실패해도 크래시 판별 자체는 중단하지 않고 실패 사유를
해당 필드에 기록한다.

## 최상위 구조

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-08-29T00:00:00+00:00",
  "metadata": {
    "project": "dlt-daemon",
    "environment": "ec2",
    "target": "dlt_message_read",
    "commit": "abc123"
  },
  "run": {
    "engine": "libfuzzer",
    "timeout_sec": 300,
    "total_groups": 1,
    "total_crashes": 0,
    "groups": []
  },
  "analysis": {
    "status": "completed",
    "triage_model": "logosfuzz-rule-triage/v1",
    "summary": {
      "true_positive": 0,
      "false_positive": 0,
      "needs_review": 0
    },
    "findings": []
  },
  "gen": {
    "status": "completed",
    "model": "gpt-4o",
    "total_groups": 2,
    "validated_groups": 2,
    "failed_groups": 0,
    "groups": []
  },
  "selection": {
    "status": "completed",
    "targets": []
  },
  "metrics": {
    "groups": 1,
    "passed_groups": 1,
    "failed_groups": 0,
    "timed_out_groups": 0,
    "crashed_groups": 0,
    "crashes": 0,
    "sanitizer_findings": 0,
    "true_positive": 0,
    "false_positive": 0,
    "needs_review": 0
  }
}
```

`gen`과 `selection`은 선택 입력이 없으면 각각 `not_run`과 빈 대상 목록으로
기록된다. `gen`은 GEN-03-04의 전체 라운드 로그를 복사하지 않고 그룹별 최종
상태·라운드 수·실패 단계·로그 경로만 보존한다. `selection.targets`에는 대상별
API 수, 로직 그룹 수, 제약 조건 커버리지를 기록해 EXT/SCH 선정 결과를 실행
결과와 함께 추적할 수 있다.

```bash
python -m logosfuzz.cli summary \
  --run out/fuzz_summary.json \
  --analysis out/analyze.json \
  --gen out/gen_validation_summary.json \
  --selection out/target_selection.json \
  --output out/validation-summary.json
```

## 그룹 상태

`run.groups[*].status`는 다음 네 값 중 하나다.

- `passed`: 정상 종료
- `failed`: 비정상 종료지만 크래시 산출물은 없음
- `timeout`: 지정된 실행 시간이 초과됨
- `crashed`: 크래시 산출물 또는 sanitizer 오류가 확인됨

그룹에는 `target`, `harness_name`, `exit_code`, `duration_sec`, `execs`, `exec_per_sec`, `coverage`, `crash_count`, `sanitizer_count`, `compile_error_count`, `crashes`, `sanitizer_findings`, `coverage_report`, `notes`가 포함된다. ANA의 각 finding에는 판별 결과와 함께 선택적인 `reachability` 증거가 포함된다.

## 호환성 규칙

- `schema_version`이 같은 동안 기존 필드의 의미를 바꾸지 않는다.
- 새 화면 기능은 선택 필드를 추가하는 방식으로 구현한다.
- 형식을 깨는 변경은 `schema_version`을 올리고 변환기를 함께 제공한다.
- HTML은 `run.groups`와 `metrics`만으로 기본 화면을 만들 수 있어야 한다.
