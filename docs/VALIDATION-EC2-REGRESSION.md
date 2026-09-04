# 다연 담당 GEN·ANA·EC2 회귀 검증 기록

작성일: 2026-08-29

이 문서는 실행기 내부 구현이나 웹 화면 작업을 기록하는 문서가 아니다. GEN의
모델 선택, ANA 정탐·오탐 판별, 결과 JSON 연결과 EC2 회귀 결과만 정리한다.

## 이번 보강 내용

### GEN 기본 모델 고정

이전 검증에서 같은 컨텍스트를 사용했을 때 `gpt-4o-mini`는 컴파일 수정
라운드를 반복하다 실패했고, `gpt-4o`는 1라운드 안에 성공했다. 그래서
GEN의 기본값을 `gpt-4o`로 바꾸고, 비용이나 호환성 때문에 다른 모델이 필요한
경우에만 `LOGOSFUZZ_GEN_MODEL` 또는 `--model`로 명시적으로 덮어쓰도록 했다.

### ANA 도달 가능성 증거 연결

기존 ANA CLI는 콜스택만 보고 규칙 기반 판별을 수행했다. 이제 다음 명령으로
대상 소스와 하네스 소스를 함께 넘길 수 있다.

```bash
python -m logosfuzz.analyze.cli analyze out/fuzz_summary.json \
  --source-root /work/dlt-daemon \
  --harness-dir /work/harnesses \
  --output out/analyze.json
```

분석 결과의 각 `finding`에 대상 함수 정의, 공개 헤더 선언 여부, 프로덕션 및
하네스 호출부가 `reachability`로 보존된다. 소스 루트를 생략하면 기존 동작을
유지하고 `reachability: null`을 기록한다.

### 생성 하네스 프레임 오분류 수정

처음 생성된 SCORE 하네스의 ASAN 크래시는 `/work/gen/score_generated.cpp:64`에서
발생했다. 기존 프레임 분류가 `generated`와 `/gen/` 경로를 하네스로 인식하지
못해 대상 라이브러리 정탐으로 올렸다. 생성물 경로를 하네스 프레임으로 분류하고,
하네스 전용 프레임에는 ASAN 정탐 보너스를 적용하지 않도록 수정했다.

### GEN·ANA·EXT/SCH 결과 JSON 연결

실행 결과만 모아 둔 기존 보고서는 GEN 생성 시도와 대상 선정 수치를
HTML/보고서 입력에서 잃어버릴 수 있었다. `logosfuzz summary`에 `--gen`과
`--selection` 입력을 추가해 다음 정보를 같은 표준 JSON에 연결했다.

- `gen`: 모델, 생성·수선 시도 횟수, 생성된 소스·바이너리 경로
- `gen.gate_status`: 실제 GEN-03-04 `outcomes` 로그가 있으면 `completed`,
  생성 메타데이터만 있으면 `not_run`으로 기록해 품질 게이트 미실행을 숨기지 않음
- `selection.targets`: 대상별 API 수, 로직 그룹 수, 제약 조건 커버리지, KB 경로
- `selection.known_issues`: 커버리지 0 또는 과도하게 넓은 대상 그룹처럼 후속 조치가
  필요한 대상의 상태

최종 EC2 기록에서 표준 JSON을 재생성하는 명령은 다음과 같다.

```bash
python scripts/prepare_validation_artifacts.py \
  --legacy validation-summary-ec2-final.json
```

생성된 `validation-summary-ec2-generated-score-fixed.json`은 SCORE 생성
하네스 최종 실행의 크래시 0·Sanitizer 0·커버리지 216과, GEN 시도/수선 및
EXT/SCH 대상 수치를 함께 보존한다. 이후 EC2에서 실제 GEN-03-04 게이트를
100회 smoke로 실행해 DLT(coverage 2), SCORE(coverage 135) 모두 통과했고,
표준 JSON의 `gen.gate_status`도 `completed`로 갱신했다.

## 정량 결과

| 실행 | 상태 | 실행 속도(exec/s) | 커버리지 | 크래시 | Sanitizer | ANA |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| 기존 DLT 300초 | passed | 518,668 | 2 | 0 | 0 | 0건 |
| 기존 SCORE 300초 | passed | 116,788 | 181 | 0 | 0 | 0건 |
| 기존 GEN DLT 300초 | passed | 373,855 | 2 | 0 | 0 | 0건 |
| 기존 GEN SCORE 초기 | crashed | 0 | 163 | 1 | 1 | 재분석 결과 오탐 1건 |
| GEN SCORE 수정 후 300초 | passed | 32,025 | 216 | 0 | 0 | 0건 |
| DLT 고정 하네스 10초 | passed | 684,122 | 2 | 0 | 0 | 0건 |
| DLT 다중 하네스 3초 x2 | passed | 688,174 / 687,938 | 2 / 2 | 0 | 0 | 0건 |
| EC2 smoke 2초 | passed | 737,756 | 3 | 0 | 0 | 0건 |

초기 SCORE 생성 하네스 결과는 `validation-summary-ec2-score-harness-ana.json`에
보존했다. 표준 JSON의 핵심 수치는 `crashed_groups=1`, `crashes=1`,
`sanitizer_findings=1`, `true_positive=0`, `false_positive=1`이다. 이는
실제 대상 코드의 취약점으로 집계하지 않고 하네스 자체 오류로 분리한 결과다.

## 회귀 테스트

- 로컬 전체 테스트: **419 passed**
- EC2 전체 테스트: **456 passed**
- ANA 도달 가능성·SCORE 프레임 분류 집중 테스트: EC2 **27 passed**
- GEN 모델 기본값 및 환경변수 덮어쓰기 테스트: **2 passed**
- 표준 JSON의 GEN·대상 선정 연결 테스트: **10 passed** (요약 계약 테스트 전체)
- EC2 GEN-03-04 품질 게이트: **2/2 validated**, 각 100회 smoke, 실패 0

## 로컬·EC2 ANA 비교

동일한 EC2 sanitizer 입력(`validation-summary-ec2-score-harness-ana.json`)을
로컬에서도 다시 분석해 결과를 비교했다. 두 환경 모두 같은 클러스터
`CL-a8ec7c78157b`를 만들고 정탐 0·오탐 1·검토필요 0으로 일치했다. EC2 쪽은
대상 소스가 있어 `reachability` 근거까지 포함하고, 로컬 쪽은 그 소스가 없어
경로 기반 판별만 수행했다. 비교 원본은
`ana-score-local-ec2-compare.json`이다.

정탐·오탐·미탐 집계는 현재 입력에 실제 정답 라벨이 없어 정탐 0·오탐 1만
확정했고, 미탐·recall은 미측정으로 남겼다. 다음 단계에서 사람이 확정한
ground-truth 라벨을 추가하면 같은 JSON 계약에 recall/F1을 계산할 수 있다.

## 결과 파일

- `validation-summary-ec2-final.json`: 기존 2·4단계 최종 실행 결과
- `validation-summary-ec2-score-harness-ana.json`: 생성 SCORE 초기 크래시의 ANA 재분석 결과
- `ana-score-reachability-ec2.json`: 도달 가능성 근거가 포함된 원본 ANA 결과
- `validation-summary-ec2-generated-score-fixed.json`: GEN·ANA·대상 선정이 연결된 표준 결과
- `validation-target-selection-ec2.json`: EXT/SCH 대상 선정·제약 조건 원본
- `validation-gen-ec2.json`: 최종 EC2 GEN 생성 메타데이터
- `validation-gen-gate-ec2.json`: 실제 EC2 GEN-03-04 게이트 결과
- `validation-gen-gate-ec2-logs/`: 게이트 그룹별 상세 로그
- `ana-score-local-ec2-compare.json`: 동일 입력의 로컬·EC2 ANA 비교
- `docs/VALIDATION-SUMMARY-SCHEMA.md`: 공유 JSON 필드와 ANA 옵션 계약

## 남은 확인 사항

- 실제 대상 코드에서 발생한 크래시는 제품 소스 경로를 `--source-root`로 지정한
  뒤 `reachability` 근거를 함께 검토한다.
- 생성 하네스가 수정된 경우 GEN 결과와 ANA 결과 JSON을 같은 실행 ID로 묶어
  비교한다.
- 실제 GEN-03-04 품질 게이트 로그는 `validation-gen-gate-ec2.json`과
  `validation-gen-gate-ec2-logs/`에 보존했다. 두 생성 하네스 모두 smoke,
  coverage threshold, mock trace 단계를 통과했으며, 이 로그를
  `logosfuzz summary --gen`으로 묶어 `gen.gate_status=completed`인지 확인했다.
- Docker 실행 파이프라인과 HTML·CSS·JavaScript 리포트는 서원 담당으로 남겨
  두며, 이 문서의 다연 완료 항목에 포함하지 않는다.
