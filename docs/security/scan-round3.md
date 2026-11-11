# 3라운드 보안 스캔 기록 (2026-11-10)

코드 동결본을 대상으로 Bandit·pip-audit·Gitleaks 를 같은 기준으로 다시 돌린 기록이다.
적용 현황과 판단 근거는 [secure-coding.md](secure-coding.md), 외부 구성요소 고정값은
[supply-chain.md](supply-chain.md) 에 있다.

## 실행 환경

| 항목 | 값 |
| --- | --- |
| 대상 커밋 | `5741130` (dev, PR #114 머지) — 스캔은 그 위에 문서 커밋만 얹은 작업 브랜치에서 돌렸고 `logosfuzz/` 와 `requirements.txt` 는 동일하다 |
| Bandit | 1.8.6 (CI 와 같은 고정 버전) |
| pip-audit | 2.9.0 (CI 와 같은 고정 버전) |
| Gitleaks | 8.30.1 (`gitleaks_8.30.1_windows_x64.zip`, 릴리스 `checksums.txt` 로 sha256 확인) |
| 실행 방법 | `bash scripts/run_security_scans.sh` (CI 와 같은 명령) |
| 결과 원문 | `security-reports/*.json` (커밋하지 않는다. CI 는 아티팩트로 남긴다) |

## 결과 요약

| 도구 | 범위 | 차단 기준 | 결과 |
| --- | --- | --- | --- |
| Bandit | `logosfuzz` (`-x '*/tests/*'`) | severity·confidence medium 이상 | **medium 이상 0건**, low 35건 |
| pip-audit | `requirements.txt` | 알려진 취약점 1건 이상 | **0건** |
| Gitleaks | 커밋 이력 231개 + 작업 트리 | 비밀값 1건 이상 | **0건** (git 0, dir 0) |

세 검사 모두 차단 기준을 통과했다. **2라운드(29건) 대비 늘어난 차단 대상이 없어 따로
작성자에게 넘긴 건은 없다.** 다만 2라운드 29건의 구성(도구별·심각도별 내역)은 저장소에
남아 있지 않아 건별 대조는 못 했다. 저장소에 남아 있는 직전 기록은 보안 하드닝 당시의
"medium 이상 0건, low 41건"이고, 이번에는 low 35건이다.

## Bandit low 35건의 내용

전부 `subprocess` 사용 알림 두 종류다. 보안약점이 아니라 "확인했는지 묻는" 신호라
그대로 둔다. 판단 근거는 [secure-coding.md](secure-coding.md) 의 정적 분석 결과 항목과
같다 — 모두 argv 배열 호출이고 `shell=True` 는 한 곳도 없다.

| 규칙 | 내용 | 건수 |
| --- | --- | --- |
| `B404` | `import subprocess` | 18 |
| `B603` | `subprocess` 호출(부분 실행 경로) | 17 |

작성자별 분포(해당 줄의 `git blame` 기준). 늘어난 차단 대상이 없으므로 전달용이 아니라,
다음 라운드에서 증감을 보기 위한 기준값이다.

| 작성자 | 건수 |
| --- | --- |
| 30604R | 12 |
| natie17 | 9 |
| dayeon053 | 8 |
| sesezz | 6 |

파일별로는 `knowledge/kb_eval.py` 6건, `execute/docker_runner.py` 4건이 가장 많고,
나머지는 빌드·퍼징·분석 모듈에 1~2건씩 흩어져 있다.

## 이번에 같이 정리한 것

- `.gitleaks.toml` 추가. 기본 규칙은 그대로 쓰고, 커밋되지 않는 로컬 디렉터리
  (`.venv*`, `third_party/`, `out/`, `build/`, `security-reports/`, `node_modules/`)만
  경로 예외로 뒀다. 이 예외가 없으면 가상환경 안의 서드파티 시험 문자열이 200건씩
  잡혀 실제 신호를 덮는다. 커밋된 파일의 예외는 지금처럼 `.gitleaksignore` 의
  지문으로만 둔다.
- `.github/workflows/security-checks.yml` 에 Gitleaks job 추가. 바이너리는 버전과
  sha256 을 고정해 받는다(`8.30.1`). 이력 전체를 보도록 `fetch-depth: 0` 을 줬다.
- `scripts/run_security_scans.sh` 추가. CI 와 같은 명령·같은 고정 버전으로 세 검사를
  로컬에서 돌린다. 다음 라운드 기록은 이 스크립트 결과로 만든다.

## 다음 라운드에 할 일

- 2라운드 29건의 내역을 찾아 이 문서에 도구별로 붙이면 라운드 간 증감이 건별로 맞춰진다.
- [supply-chain.md](supply-chain.md) 의 남은 과제(lock+해시, SBOM, C/C++ 정적 분석)는
  그대로다.
