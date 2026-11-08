# 공급망 무결성 기록

「SW 공급망 보안 강화 로드맵」(2026.6)의 구성요소 추적관리, 무결성 검증 항목을 이 저장소
범위에 맞게 적용한 기록이다. 로드맵 정책 전체를 학생팀의 법적 의무로 보지는 않는다.
아래 값을 바꿀 때는 이 표와 Dockerfile 을 같은 커밋에서 바꾼다.

## 고정한 외부 구성요소

| 구성요소 | 위치 | 고정 값 | 검증 방식 |
| --- | --- | --- | --- |
| ubuntu:24.04 베이스 | `docker/Dockerfile`, `docker/Dockerfile.selfheal` | `sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac` (multi-arch index, 2026-10-26 조회) | `FROM ...@sha256:` (Docker 가 digest 불일치 시 거부) |
| Bazelisk v1.25.0 linux-amd64 | 위와 같음 | `fd8fdff418a1758887520fa42da7e6ae39aefc788cf5e7f7bb8db6934d279fc4` | `sha256sum -c` (불일치·빈 값이면 빌드 실패) |
| Bazelisk v1.25.0 linux-arm64 | `docker/Dockerfile` | `4c8d966e40ac2c4efcc7f1a5a5cceef2c0a2f16b957e791fa7a867cce31e8fcb` | 위와 같음 |
| CI 스캐너 | `.github/workflows/security-checks.yml` | bandit 1.8.6, pip-audit 2.9.0 | pip 버전 고정 |

갱신 절차:

1. 새 버전 바이너리를 받아 `sha256sum` 을 구한다.
2. 릴리스 페이지나 서명으로 그 값을 교차 확인한다.
3. Dockerfile ARG 와 이 표를 함께 바꾼다.
4. 이미지 빌드가 통과하는지 확인한다.

베이스 이미지는 `docker buildx imagetools inspect ubuntu:24.04` 로 새 digest 를 확인한다.

## 남은 과제

- Python 의존성 lock+해시(`pip-compile --generate-hashes`). `requirements.txt` 는 아직
  `libclang` 만 정확한 버전으로 고정되어 있다.
- SBOM 생성(예: `syft` 로 이미지와 Python 환경). 라이선스 목록.
- GitHub Action 을 전체 commit SHA 로 고정하고 보호 브랜치 승인을 켠다(저장소 설정).
- Bazelisk 가 내려받는 Bazel 본체와 외부 rule 의 해시 고정(`.bazelversion`, `MODULE.bazel.lock`).
