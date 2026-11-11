#!/usr/bin/env bash
# 로컬에서 CI(.github/workflows/security-checks.yml)와 같은 기준으로 보안 스캔 3종을
# 돌린다. 회의에서 쓰는 "N 라운드 재검사" 기록은 이 스크립트 결과로 만든다.
#
#   bandit    Python SAST. medium 이상 + confidence medium 이상이면 실패
#   pip-audit requirements.txt 의 알려진 취약점. 하나라도 있으면 실패
#   gitleaks  커밋 이력과 작업 트리의 비밀값. .gitleaksignore / .gitleaks.toml 적용
#
# 사용법:
#   bash scripts/run_security_scans.sh                # 세 종류 모두
#   bash scripts/run_security_scans.sh --no-gitleaks  # gitleaks 없이
#
# 결과 원문은 security-reports/ 에 JSON 으로 남는다(커밋하지 않는다).
# 버전은 CI 와 같은 값으로 고정한다. 올릴 때는 CI 와 docs/security/supply-chain.md
# 의 표를 같은 커밋에서 함께 바꾼다.
set -u

BANDIT_VERSION="1.8.6"
PIP_AUDIT_VERSION="2.9.0"
GITLEAKS_VERSION="8.30.1"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
OUT_DIR="security-reports"
mkdir -p "$OUT_DIR"

RUN_GITLEAKS=1
[ "${1:-}" = "--no-gitleaks" ] && RUN_GITLEAKS=0

fail=0
note() { printf '\n== %s\n' "$1"; }

note "bandit ${BANDIT_VERSION}"
if ! command -v bandit >/dev/null 2>&1; then
  echo "bandit 이 없다: pip install bandit==${BANDIT_VERSION}"
  fail=1
else
  bandit -r logosfuzz -x '*/tests/*' -f json -o "$OUT_DIR/bandit.json" -q || true
  bandit -r logosfuzz -x '*/tests/*' --severity-level medium --confidence-level medium || fail=1
fi

note "pip-audit ${PIP_AUDIT_VERSION}"
if ! command -v pip-audit >/dev/null 2>&1; then
  echo "pip-audit 가 없다: pip install pip-audit==${PIP_AUDIT_VERSION}"
  fail=1
else
  pip-audit -r requirements.txt --format json --output "$OUT_DIR/pip-audit.json" || true
  pip-audit -r requirements.txt || fail=1
fi

if [ "$RUN_GITLEAKS" = "1" ]; then
  note "gitleaks ${GITLEAKS_VERSION}"
  if ! command -v gitleaks >/dev/null 2>&1; then
    echo "gitleaks 가 없다: https://github.com/gitleaks/gitleaks/releases/tag/v${GITLEAKS_VERSION}"
    echo "(받은 파일은 같은 릴리스의 checksums.txt 로 sha256 을 맞춰 본 뒤 쓴다)"
    fail=1
  else
    gitleaks git . --config .gitleaks.toml --redact --report-format json \
      --report-path "$OUT_DIR/gitleaks-git.json" || fail=1
    gitleaks dir . --config .gitleaks.toml --redact --report-format json \
      --report-path "$OUT_DIR/gitleaks-dir.json" || fail=1
  fi
fi

note "결과 원문: $OUT_DIR/"
if [ "$fail" != "0" ]; then
  echo "기준을 넘는 결과가 있거나 도구가 없다."
  exit 1
fi
echo "세 검사 모두 기준 통과."
