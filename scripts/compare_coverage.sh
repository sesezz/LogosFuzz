#!/usr/bin/env bash
# 유닛테스트 vs 퍼징 커버리지 비교 측정기 (C 파트 4주차 작성, 5주차 실측 반영)
# ======================================================
#
# 같은 대상에 대해 세 가지 커버리지를 재서 나란히 놓는다.
#
#   A. 유닛테스트 커버리지 — 대상 저장소가 원래 가지고 있는 *_test.cpp 를
#      bazel coverage 로 돌려서 얻는다.
#   S. 시드 커버리지      — 퍼징 전 초기 코퍼스(유닛테스트에서 뽑은 시드 포함)만
#      재생했을 때. 퍼징이 시드 위에 무엇을 더했는지 가르는 기준선이다.
#   B. 퍼징 커버리지      — LogosFuzz 하네스를 N초 퍼징한 뒤의 코퍼스를 재생.
#
# 이 비교가 답하려는 질문은 하나다. **퍼징이 유닛테스트가 못 닿는 곳에
# 닿는가.** 단순 총합 비교(퍼징 62% vs 유닛테스트 71%)는 의미가 약하다.
# 유닛테스트는 API 표면을 넓게 훑고 퍼징은 파싱 경로를 깊게 파므로, 총합만
# 보면 퍼징이 져 보이면서도 실제로는 유닛테스트가 전혀 안 밟은 분기를
# 퍼징이 밟고 있을 수 있다. 그래서 **차집합**(퍼징만 밟은 라인)을 같이 낸다.
#
# 리눅스 전용이다(Bazel + llvm 도구). WSL 이나 docker/Dockerfile 컨테이너에서
# 돌린다. baselibs 에 퍼징 오버레이(apply_overlay)가 적용돼 있어야 한다.
#
#   bash scripts/compare_coverage.sh \
#       --workspace ~/baselibs \
#       --unit-target //score/json/... \
#       --fuzz-target //score/json/fuzz:json_parser_fuzz_test \
#       --seeds-from-tests ~/baselibs/score/json \
#       --include score/json/ \
#       --out ~/coverage-compare
#
# ---------------------------------------------------------------------------
# 5주차 실측으로 바뀐 것 (baselibs 09be72c, Bazel 8.6.0, WSL Ubuntu 24.04)
# ---------------------------------------------------------------------------
#   * --config=llvm_cov 는 coverage: 전용이다. bazel build 에 붙이면
#     "Config value 'llvm_cov' is not defined" 로 죽는다. 그래서 퍼징 쪽은
#     llvm_cov 를 쓰지 않고, --config=fuzz 위에 계측 플래그를 직접 얹은 별도
#     빌드(platform_suffix=fuzz_cov)로 잰다. 퍼징 본 빌드는 계측 없이 돌려
#     속도를 지키고, 커버리지 빌드는 코퍼스 재생(-runs=0)에만 쓴다.
#   * 유닛테스트 쪽은 --config=llvm_cov 단독이다. bl-x86_64-linux 를 같이 주면
#     GCC 가 이겨 covmap 이 안 나온다(baselibs coverage.bazelrc 의 경고).
#   * bazel coverage 결과(_coverage_report.dat)는 baselibs 리포터가 만든 zip
#     이다. lcov 는 그 안의 lcov_report/lcov.dat.
#   * 시스템 llvm-profdata(18)는 clang 22 profraw(포맷 v10)를 못 읽는다.
#     Bazel 이 받아 둔 툴체인 쪽 llvm-profdata / llvm-cov 를 쓴다.

set -uo pipefail

WORKSPACE=""
UNIT_TARGET=""
FUZZ_TARGET=""
CORPUS=""
SEED_TEST_DIR=""
INCLUDE=()
OUT_DIR="./coverage-compare"
FUZZ_SECONDS=300
BAZEL="${BAZEL:-bazel}"

FUZZ_CONFIG="fuzz"
COVERAGE_CONFIG="llvm_cov"
FUZZ_COV_FLAGS=(--platform_suffix=fuzz_cov
                --copt=-fprofile-instr-generate --copt=-fcoverage-mapping
                --linkopt=-fprofile-instr-generate)

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
    sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workspace)        WORKSPACE="$2"; shift 2 ;;
        --unit-target)      UNIT_TARGET="$2"; shift 2 ;;
        --fuzz-target)      FUZZ_TARGET="$2"; shift 2 ;;
        --corpus)           CORPUS="$2"; shift 2 ;;
        --seeds-from-tests) SEED_TEST_DIR="$2"; shift 2 ;;
        --include)          INCLUDE+=(--include "$2"); shift 2 ;;
        --out)              OUT_DIR="$2"; shift 2 ;;
        --fuzz-seconds)     FUZZ_SECONDS="$2"; shift 2 ;;
        -h|--help)          usage 0 ;;
        *) echo "알 수 없는 인자: $1" >&2; usage 2 ;;
    esac
done

for required in WORKSPACE UNIT_TARGET FUZZ_TARGET; do
    if [[ -z "${!required}" ]]; then
        echo "필수 인자 누락: --${required,,}" | tr '_' '-' >&2
        usage 2
    fi
done

WORKSPACE="$(cd "${WORKSPACE}" && pwd)"
mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"

log()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf '\n[실패] %s\n' "$*" >&2; }

run_logged() {
    # run_logged <로그파일> <커맨드...>
    local logfile="$1"; shift
    printf '  $ %s\n' "$*"
    "$@" > "${logfile}" 2>&1
    local rc=$?
    if [[ ${rc} -ne 0 ]]; then
        fail "종료코드 ${rc}. 원문 마지막 30줄:"
        tail -30 "${logfile}" >&2
    fi
    return ${rc}
}

bin_path() {
    # bazel-bin 심링크는 직전 빌드 설정을 가리켜 config 가 섞이면 틀린다.
    # cquery 로 해당 설정의 실제 산출물 경로를 묻는다.
    local rel
    rel="$(${BAZEL} cquery "$@" --output=files "${FUZZ_BIN_TARGET}" 2>/dev/null | head -1)"
    [[ -n "${rel}" ]] && printf '%s/%s' "${WORKSPACE}" "${rel}"
}

FUZZ_BIN_TARGET="${FUZZ_TARGET}"
[[ "${FUZZ_BIN_TARGET}" == *_bin ]] || FUZZ_BIN_TARGET="${FUZZ_BIN_TARGET}_bin"

cd "${WORKSPACE}"

# ---------------------------------------------------------------------------
# STEP 1 - 유닛테스트 커버리지
# ---------------------------------------------------------------------------
log "STEP 1 · 유닛테스트 커버리지  (${UNIT_TARGET})"

if ! run_logged "${OUT_DIR}/unit-coverage.log" \
        "${BAZEL}" coverage "--config=${COVERAGE_CONFIG}" "${UNIT_TARGET}"; then
    fail "유닛테스트 커버리지 수집 실패. 로그: ${OUT_DIR}/unit-coverage.log"
    exit 1
fi

UNIT_REPORT="$(${BAZEL} info output_path 2>/dev/null)/_coverage/_coverage_report.dat"
if [[ ! -f "${UNIT_REPORT}" ]]; then
    fail "커버리지 리포트를 찾지 못했다: ${UNIT_REPORT}"
    exit 1
fi
PYTHONPATH="${REPO_ROOT}" python3 -c \
    'import sys; from logosfuzz.execute.coverage import extract_bazel_lcov; extract_bazel_lcov(sys.argv[1], sys.argv[2])' \
    "${UNIT_REPORT}" "${OUT_DIR}/unit.lcov" || { fail "lcov 추출 실패"; exit 1; }
echo "  -> ${OUT_DIR}/unit.lcov"

# ---------------------------------------------------------------------------
# STEP 2 - 퍼징 본 빌드 + 커버리지 빌드
# ---------------------------------------------------------------------------
log "STEP 2 · 하네스 빌드  (퍼징용 / 커버리지 계측용)"

run_logged "${OUT_DIR}/fuzz-build.log" \
    "${BAZEL}" build "--config=${FUZZ_CONFIG}" "${FUZZ_BIN_TARGET}" || exit 1
run_logged "${OUT_DIR}/fuzz-cov-build.log" \
    "${BAZEL}" build "--config=${FUZZ_CONFIG}" "${FUZZ_COV_FLAGS[@]}" "${FUZZ_BIN_TARGET}" || exit 1

FUZZ_BIN="$(bin_path "--config=${FUZZ_CONFIG}")"
COV_BIN="$(bin_path "--config=${FUZZ_CONFIG}" "${FUZZ_COV_FLAGS[@]}")"
for b in FUZZ_BIN COV_BIN; do
    if [[ -z "${!b}" || ! -x "${!b}" ]]; then
        fail "${b} 경로를 찾지 못했다 ('${!b}')"
        exit 1
    fi
    echo "  ${b}: ${!b}"
done

OUTPUT_BASE="$(${BAZEL} info output_base 2>/dev/null)"
LLVM_BIN="$(ls -d "${OUTPUT_BASE}"/external/toolchains_llvm++llvm+llvm_toolchain_llvm/bin 2>/dev/null | head -1)"
if [[ ! -x "${LLVM_BIN}/llvm-profdata" ]]; then
    fail "툴체인 llvm-profdata 를 못 찾았다 (${LLVM_BIN})"
    echo "  시스템 llvm-profdata 는 clang 22 profraw 를 못 읽으므로 대체하지 않는다." >&2
    exit 1
fi
echo "  llvm 도구: ${LLVM_BIN} ($("${LLVM_BIN}/llvm-profdata" --version | grep -o 'version [0-9.]*'))"

# ---------------------------------------------------------------------------
# STEP 3 - 초기 코퍼스 준비 (+ 유닛테스트 리터럴 시드)
# ---------------------------------------------------------------------------
log "STEP 3 · 초기 코퍼스"
SEED_DIR="${OUT_DIR}/seeds"
WORK_CORPUS="${OUT_DIR}/corpus"
rm -rf "${SEED_DIR}" "${WORK_CORPUS}"
mkdir -p "${SEED_DIR}" "${WORK_CORPUS}"

[[ -n "${CORPUS}" && -d "${CORPUS}" ]] && cp -r "${CORPUS}"/. "${SEED_DIR}/"
if [[ -n "${SEED_TEST_DIR}" ]]; then
    PYTHONPATH="${REPO_ROOT}" python3 - "${SEED_TEST_DIR}" "${SEED_DIR}" <<'PY'
import sys
from pathlib import Path
from logosfuzz.execute.exe_04_05_corpus_manager import SeedManager

src, dest = Path(sys.argv[1]), Path(sys.argv[2])
tests = sorted(p for p in src.rglob("*") if p.suffix in (".cc", ".cpp") and p.stem.endswith("_test"))
seeds = SeedManager(str(dest)).extract_seeds_from_tests("tests", tests)
for s in seeds:
    (dest / f"{s.seed_id}.bin").write_bytes(s.data)
print(f"  유닛테스트 {len(tests)}개 파일에서 시드 {len(seeds)}개 추출")
PY
fi
# 빈 코퍼스로 시작하면 libFuzzer 가 빈 입력 하나로 시작한다. 그것도 기준선이다.
find "${SEED_DIR}" -type f -exec cp {} "${WORK_CORPUS}/" \;
echo "  초기 코퍼스: $(find "${WORK_CORPUS}" -type f | wc -l)개"

# 코퍼스 디렉터리를 커버리지 바이너리에 재생해 lcov 를 만든다.
replay_lcov() {  # replay_lcov <이름> <코퍼스 디렉터리>
    local name="$1" dir="$2" raw="${OUT_DIR}/profraw-$1"
    rm -rf "${raw}" && mkdir -p "${raw}"
    LLVM_PROFILE_FILE="${raw}/%m.profraw" "${COV_BIN}" -runs=0 "${dir}" \
        > "${OUT_DIR}/replay-${name}.log" 2>&1
    shopt -s nullglob; local raws=("${raw}"/*.profraw); shopt -u nullglob
    if [[ ${#raws[@]} -eq 0 ]]; then
        fail "${name}: profraw 가 안 나왔다. 로그: ${OUT_DIR}/replay-${name}.log"
        return 1
    fi
    "${LLVM_BIN}/llvm-profdata" merge -sparse "${raws[@]}" -o "${OUT_DIR}/${name}.profdata" || return 1
    "${LLVM_BIN}/llvm-cov" export -format=lcov \
        -instr-profile="${OUT_DIR}/${name}.profdata" "${COV_BIN}" > "${OUT_DIR}/${name}.lcov" || return 1
    echo "  -> ${OUT_DIR}/${name}.lcov"
}

replay_lcov seed "${WORK_CORPUS}" || exit 1

# ---------------------------------------------------------------------------
# STEP 4 - 퍼징
# ---------------------------------------------------------------------------
log "STEP 4 · 퍼징  (${FUZZ_SECONDS}초)"
"${FUZZ_BIN}" -max_total_time="${FUZZ_SECONDS}" -print_final_stats=1 \
    -artifact_prefix="${OUT_DIR}/" "${WORK_CORPUS}" > "${OUT_DIR}/fuzz-run.log" 2>&1
FUZZ_RC=$?
# 퍼저는 크래시를 찾으면 0 이 아닌 코드로 끝난다. 그건 실패가 아니라 성과다.
echo "  퍼징 종료코드: ${FUZZ_RC} (0이 아니면 크래시를 찾았다는 뜻일 수 있다)"
grep -E '^stat::number_of_executed_units|^stat::peak_rss|cov: [0-9]+' "${OUT_DIR}/fuzz-run.log" | tail -3 | sed 's/^/  /'
echo "  퍼징 후 코퍼스: $(find "${WORK_CORPUS}" -type f | wc -l)개"

log "STEP 5 · 퍼징 코퍼스 재생"
replay_lcov fuzz "${WORK_CORPUS}" || exit 1

# ---------------------------------------------------------------------------
# STEP 6 - 비교
# ---------------------------------------------------------------------------
log "STEP 6 · 비교"
for pair in seed fuzz; do
    python3 "${REPO_ROOT}/scripts/compare_coverage.py" \
        --unit-lcov "${OUT_DIR}/unit.lcov" \
        --fuzz-lcov "${OUT_DIR}/${pair}.lcov" \
        "${INCLUDE[@]}" --exclude-harness \
        --out "${OUT_DIR}/comparison-${pair}.json" \
        --markdown "${OUT_DIR}/comparison-${pair}.md"
done

echo
echo "산출물:"
echo "  ${OUT_DIR}/comparison-fuzz.md   <- 유닛테스트 vs 퍼징 (발표자료용 표)"
echo "  ${OUT_DIR}/comparison-seed.md   <- 유닛테스트 vs 시드만 (퍼징 기여 기준선)"
echo "  ${OUT_DIR}/unit.lcov, seed.lcov, fuzz.lcov"
