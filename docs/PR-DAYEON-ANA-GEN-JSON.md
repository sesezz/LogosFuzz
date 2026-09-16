# 다연 담당 PR - GEN·ANA·검증 결과 통합

## 변경 내용

- ANA CLI에 `--source-root`, `--harness-dir`를 연결해 대상 함수 정의·호출부·하네스 호출부를 `reachability` 근거로 보존
- 생성 하네스 프레임(`/gen/`, `*_generated.*`)을 대상 애플리케이션 프레임과 구분하고, 하네스 전용 ASAN을 자동 정탐으로 올리지 않도록 수정
- GEN 기본 모델을 `gpt-4o`로 고정하고 `LOGOSFUZZ_GEN_MODEL` 환경변수와 `--model`로 명시적 변경 지원
- 표준 `validation-summary.json`에 GEN 생성·수선·GEN-03-04 게이트 결과와 EXT/SCH 대상·제약 조건 결과를 선택 필드로 연결
- EC2 결과를 기준으로 표준 JSON·대상 선정 JSON·GEN 게이트 JSON을 생성하는 재현 스크립트 추가

## 검증 결과

- 로컬 전체 테스트: 419 passed
- EC2 전체 테스트: 456 passed
- EC2 GEN-03-04 게이트: DLT·SCORE 2/2 validated, 각 100회 smoke, 실패 0
- GEN SCORE 최종 실행: coverage 216, crash 0, sanitizer 0
- 동일 sanitizer 입력 ANA 비교: 로컬·EC2 모두 정탐 0·오탐 1·검토필요 0

## 산출물

- `validation-summary-ec2-generated-score-fixed.json`
- `validation-gen-gate-ec2.json`
- `validation-target-selection-ec2.json`
- `ana-score-local-ec2-compare.json`
- `docs/VALIDATION-EC2-REGRESSION.md`

## 제한 사항

현재 입력에는 사람이 확정한 ground-truth 라벨이 없어 미탐·recall·F1은 측정하지
않았다. can-utils 그룹 폭발과 socket/POSIX allowlist 문제는 반영했지만,
최종 EC2 수치에 없는 udslib 대상은 확인 전까지 완료로 단정하지 않는다.
