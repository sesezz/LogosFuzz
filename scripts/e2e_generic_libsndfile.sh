#!/usr/bin/env bash
# GENERIC 마지막 단계: libsndfile 1.2.2 E2E + 커버리지 → 자동차 회귀 → 결과 Markdown
# =====================================================================================
#
# EC2(r5.2xlarge, Ubuntu 24.04) 기준, 저장소 루트에서 실행
#
#   export OPENAI_API_KEY=...            # 하네스 자동 생성·자가치유에 필요
#   bash scripts/e2e_generic_libsndfile.sh               # 기본 600초, Docker 격리
#   BUDGET=600 DOCKER=0 bash scripts/e2e_generic_libsndfile.sh   # 호스트 실행
#
# 수행 단계
#   1. 도구 확인 + 환경 기록 (out/libsndfile/env.txt)
#   2. libsndfile 고정 커밋 다운로드 (scripts/fetch_libsndfile.sh)
#   3. logosfuzz run --profile targets/libsndfile.json --budget $BUDGET --max-round 3
#      (BUILD → EXT → SCH → GEN(LLM) → 자가치유 → EXE → 커버리지 → ANA, 사람 개입 없음)
#   4. 자동차 회귀: scripts/check_automotive_golden.py (골든 비교) + pytest 전체
#   5. out/libsndfile/e2e-report.md 생성 (실측값만, docs/VERIFY-GENERIC-libsndfile.md 첨부용)
#
# 단계 실패 시 즉시 중단 및 0 이 아닌 코드로 종료
set -euo pipefail

BUDGET="${BUDGET:-600}"
MAX_ROUND="${MAX_ROUND:-3}"
DOCKER="${DOCKER:-1}"
OUT="${OUT:-out/libsndfile}"
PY="${PYTHON:-python3}"

[ -f targets/libsndfile.json ] || { echo "[ERROR] 저장소 루트에서 실행한다" >&2; exit 2; }
[ -n "${OPENAI_API_KEY:-}" ] || { echo "[ERROR] OPENAI_API_KEY 가 없다 (하네스 자동 생성에 필요)" >&2; exit 2; }

need=(git cmake clang llvm-profdata llvm-cov "$PY")
[ "$DOCKER" = "1" ] && need+=(docker)
for tool in "${need[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || { echo "[ERROR] $tool 이 없다" >&2; exit 2; }
done

mkdir -p "$OUT"
ENV_TXT="$OUT/env.txt"
{
  echo "date: $(date -Iseconds)"
  echo "commit: $(git rev-parse HEAD) ($(git rev-parse --abbrev-ref HEAD))"
  echo "os: $(. /etc/os-release && echo "$PRETTY_NAME") / $(uname -r)"
  # EC2 인스턴스 타입 (IMDSv2, EC2 가 아니면 빈 값)
  TOKEN="$(curl -s -m 2 -X PUT http://169.254.169.254/latest/api/token \
            -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null || true)"
  ITYPE="$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $TOKEN" \
            http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || true)"
  if [[ "$ITYPE" =~ ^[a-z0-9-]+\.[a-z0-9]+$ ]]; then echo "instance: $ITYPE"; fi
  echo "cpu: $(nproc) cores, mem: $(free -g | awk '/Mem:/{print $2}') GiB"
  echo "clang: $(clang --version | head -1)"
  echo "cmake: $(cmake --version | head -1)"
  echo "python: $($PY --version 2>&1)"
  [ "$DOCKER" = "1" ] && echo "docker: $(docker --version)"
  echo "budget: ${BUDGET}s, max-round: ${MAX_ROUND}, docker: ${DOCKER}"
} | tee "$ENV_TXT"

echo; echo "== [1/4] libsndfile 받기"
bash scripts/fetch_libsndfile.sh

echo; echo "== [2/4] logosfuzz run (E2E + 커버리지)"
RUN_ARGS=(--profile targets/libsndfile.json --budget "$BUDGET" --max-round "$MAX_ROUND" -o "$OUT")
[ "$DOCKER" = "1" ] || RUN_ARGS+=(--no-docker)
set +e
"$PY" -m logosfuzz.cli run "${RUN_ARGS[@]}" 2>&1 | tee "$OUT/run.log"
RUN_RC="${PIPESTATUS[0]}"
set -e

echo; echo "== [3/4] 자동차 회귀 (골든 비교 + pytest)"
"$PY" scripts/check_automotive_golden.py | tee "$OUT/automotive-regression.log"
"$PY" -m pytest -q --ignore=examples 2>&1 | tail -3 | tee -a "$OUT/automotive-regression.log"

echo; echo "== [4/4] 결과 Markdown"
if [ ! -f "$OUT/run_summary.json" ]; then
  echo "[ERROR] $OUT/run_summary.json 이 없다 - run 이 시작 전에 멈췄다 ($OUT/run.log)" >&2
  exit 1
fi
"$PY" scripts/render_run_report.py "$OUT/run_summary.json" --env "$ENV_TXT" -o "$OUT/e2e-report.md"
{
  echo
  echo "### 자동차 회귀"
  echo
  echo '```'
  cat "$OUT/automotive-regression.log"
  echo '```'
} >> "$OUT/e2e-report.md"

if [ "$RUN_RC" != "0" ]; then
  echo "[ERROR] logosfuzz run 종료 코드 $RUN_RC ($OUT/run.log, $OUT/run_summary.json)" >&2
  exit "$RUN_RC"
fi
echo; echo "완료: $OUT/e2e-report.md 를 docs/VERIFY-GENERIC-libsndfile.md 의 'EC2 실측' 에 붙인다."
