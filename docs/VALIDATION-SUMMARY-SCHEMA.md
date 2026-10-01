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

## 빌드 단위 집계 (4주차)

3주차부터 Logic Group 경계와 하네스 배치가 빌드 단위(Bazel 타깃) 기준이므로,
리포트도 빌드 단위를 키로 집계한다. CTR-06-01 BUILD 단계가 쓴
`build_summary.json`을 `--build`로 넘긴다.

```bash
python -m logosfuzz.cli summary \
  --run out/fuzz_summary.json \
  --build out/build_summary.json \
  --output out/validation-summary.json \
  --markdown out/build_units.md
```

- `run.groups[*]`에 선택 필드 `build_target`, `build_system`, `fuzz_target`, `binary`가 붙는다.
  그룹 이름·`cc_fuzz_test` 이름·`_bin` 바이너리 이름 중 무엇으로 기록돼도 조인된다.
  그룹 자체에 `build_target`이 있으면 그 값이 우선한다.
- 최상위 `build_units`: `status`(`completed`|`not_run`), `total_units`, `built_units`,
  `repaired_units`, `failed_units`, `crashed_units`, `units[]`.
- `units[*]`: `build_target`, `build_system`, `groups`, `fuzz_targets`, `binaries`,
  `build_status`(`failed` > `repaired` > `built` > `emitted` > `not_built`),
  `rounds_used`, `run_status`(`crashed` > `timeout` > `failed` > `passed` > `not_run`),
  `run_groups`, `crashes`, `sanitizer_findings`, `execs`, `duration_sec`, `coverage`(최댓값).
- `units[*].groups`는 **Logic Group 이름**으로 통일된다. EXE가 `cc_fuzz_test` 이름이나
  `_bin` 바이너리 이름으로 그룹을 기록해도 같은 빌드 결과로 합쳐져 중복 등장하지 않는다.
  처음부터 이름을 맞추려면 BUILD 단계의 `--groups-out`으로 만든 groups JSON(`name` =
  Logic Group 이름)을 `logosfuzz fuzz --groups`에 넘긴다.
- 소스(.cc) 자가치유(`--heal-rounds`)로 복구된 단위는 `build_status`가 `repaired`이다.
  `build_summary.json`의 `units[*].heal`(`attempted`, `ok`, `outcome`, `rounds_used`,
  `reason`)과 최상위 `healed_units`에 기록되며, 이 요약 JSON의 필드는 늘지 않는다.
- `execs`: 입력 `run` 그룹에 `execs` 가 있으면 그 값을 쓴다. EXE 의 `fuzz_summary.json` 은 총 실행
  횟수를 기록하지 않으므로(`exec_per_sec`·`duration_sec` 만 있다) 없을 때는
  `exec_per_sec × duration_sec` 로 **추정**하고 그룹과 빌드 단위에 `execs_estimated: true` 를
  붙인다. Markdown 표에서는 `~` 를 앞에 붙여 추정치임을 드러낸다. EXE 가 `execs` 를 기록하면
  자동으로 실측 값이 쓰인다.
- 빌드 정보가 없는 그룹은 `(unassigned)` 단위로 모이며 집계 수에서는 빠진다.
- 선택 필드 추가이므로 `schema_version`은 `1.0` 그대로이고 `metrics`는 바뀌지 않는다.

## 호환성 규칙

- `schema_version`이 같은 동안 기존 필드의 의미를 바꾸지 않는다.
- 새 화면 기능은 선택 필드를 추가하는 방식으로 구현한다.
- 형식을 깨는 변경은 `schema_version`을 올리고 변환기를 함께 제공한다.
- HTML은 `run.groups`와 `metrics`만으로 기본 화면을 만들 수 있어야 한다.
