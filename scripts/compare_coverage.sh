#!/usr/bin/env bash
# 유닛테스트 vs 퍼징 커버리지 비교 측정기 (C 파트 4주차)
# ======================================================
#
# 같은 대상에 대해 두 가지 커버리지를 재서 나란히 놓는다.
#
#   A. 유닛테스트 커버리지 — 대상 저장소가 원래 가지고 있는 *_test.cc 를
#      bazel coverage 로 돌려서 얻는다.
#   B. 퍼징 커버리지      — LogosFuzz 가 생성한 하네스를 퍼징해서 얻는다.
#
# 이 비교가 답하려는 질문은 하나다. **퍼징이 유닛테스트가 못 닿는 곳에
# 닿는가.** 단순 총합 비교(퍼징 62% vs 유닛테스트 71%)는 의미가 약하다.
# 유닛테스트는 API 표면을 넓게 훑고 퍼징은 파싱 경로를 깊게 파므로, 총합만
# 보면 퍼징이 져 보이면서도 실제로는 유닛테스트가 전혀 안 밟은 분기를
# 퍼징이 밟고 있을 수 있다. 그래서 **차집합**(퍼징만 밟은 라인)을 같이 낸다.
#
# 리눅스 전용이다(Bazel + llvm 도구). WSL 이나 docker/Dockerfile 컨테이너에서
# 돌린다.
#
#   bash scripts/compare_coverage.sh \
#       --workspace ~/baselibs \
#       --unit-target //score/json:json_test \
#       --fuzz-target //score/json/fuzz:json_parser_fuzz_test \
#       --corpus ~/corpus/grp_json \
#       --out ~/coverage-compare
#
# ---------------------------------------------------------------------------
# 검증 상태 (읽고 시작할 것)
# ---------------------------------------------------------------------------
# 이 스크립트는 **아직 끝까지 돌려본 적이 없다.** baselibs + Bazel 환경이
# 없어서다. 각 단계의 커맨드는 팀이 확인한 사실 위에서 조립했지만, 그
# 조합 자체는 미검증이다. 특히 2단계에서 막힐 가능성이 크다.
#
#   1단계(유닛테스트) — bazel coverage 는 baselibs 가 tools/coverage/ 에
#     자체 설정을 두고 쓰는 표준 경로다. 무난할 것으로 본다.
#
#   2단계(퍼징 커버리지) — **여기가 위험하다.** 퍼징 빌드는 --config=fuzz
#     (clang, @llvm_toolchain)를 쓰는데, 커버리지 config 를 얹었을 때
#     툴체인이 어떻게 해소되는지 확인되지 않았다. baselibs 의
#     tools/coverage/coverage.bazelrc 가 바로 그 "마지막 --extra_toolchains
#     가 이긴다" 경고를 담고 있는 파일이고, --config=fuzz 가 clang 을
#     등록하는 방식이 정확히 그 --extra_toolchains 다. 순서에 따라 clang 이
#     밀려나면 퍼징 빌드가 -fsanitize=fuzzer 링크에서 죽는다.
#
#     그래서 2단계는 config 조합을 먼저 단독으로 시험한다(STEP 2a). 거기서
#     실패하면 뒤를 진행하지 않고, 대안 두 가지를 안내하고 멈춘다.
#
# 실패하면 스크립트가 실제 커맨드와 원문 에러를 그대로 보여준다. 어디서
# 막혔는지 추측하지 않아도 되게 하려는 것이다.

set -uo pipefail

WORKSPACE=""
UNIT_TARGET=""
FUZZ_TARGET=""
CORPUS=""
OUT_DIR="./coverage-compare"
FUZZ_SECONDS=300
BAZEL="${BAZEL:-bazel}"

FUZZ_CONFIG="fuzz"
COVERAGE_CONFIG="llvm_cov"
UNIT_CONFIG="bl-x86_64-linux"

usage() {
    sed -n '2,52p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workspace)    WORKSPACE="$2"; shift 2 ;;
        --unit-target)  UNIT_TARGET="$2"; shift 2 ;;
        --fuzz-target)  FUZZ_TARGET="$2"; shift 2 ;;
        --corpus)       CORPUS="$2"; shift 2 ;;
        --out)          OUT_DIR="$2"; shift 2 ;;
        --fuzz-seconds) FUZZ_SECONDS="$2"; shift 2 ;;
        -h|--help)      usage 0 ;;
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

# ---------------------------------------------------------------------------
# STEP 1 - 유닛테스트 커버리지
# ---------------------------------------------------------------------------
log "STEP 1 · 유닛테스트 커버리지  (${UNIT_TARGET})"
cd "${WORKSPACE}"

if ! run_logged "${OUT_DIR}/unit-coverage.log" \
        "${BAZEL}" coverage "--config=${UNIT_CONFIG}" \
        --combined_report=lcov "${UNIT_TARGET}"; then
    fail "유닛테스트 커버리지 수집 실패. 로그: ${OUT_DIR}/unit-coverage.log"
    exit 1
fi

UNIT_LCOV="$(${BAZEL} info output_path 2>/dev/null)/_coverage/_coverage_report.dat"
if [[ ! -f "${UNIT_LCOV}" ]]; then
    fail "lcov 리포트를 찾지 못했다: ${UNIT_LCOV}"
    echo "  bazel coverage 가 리포트를 다른 곳에 뒀을 수 있다. 로그를 확인할 것." >&2
    exit 1
fi
cp "${UNIT_LCOV}" "${OUT_DIR}/unit.lcov"
echo "  -> ${OUT_DIR}/unit.lcov"

# ---------------------------------------------------------------------------
# STEP 2a - 퍼징 + 커버리지 config 조합이 성립하는지 먼저 확인
# ---------------------------------------------------------------------------
log "STEP 2a · config 조합 확인  (--config=${FUZZ_CONFIG} --config=${COVERAGE_CONFIG})"
echo "  퍼징 config 와 커버리지 config 가 툴체인에서 충돌하지 않는지 먼저 본다."

FUZZ_BIN_TARGET="${FUZZ_TARGET}"
[[ "${FUZZ_BIN_TARGET}" == *_bin ]] || FUZZ_BIN_TARGET="${FUZZ_BIN_TARGET}_bin"

if ! run_logged "${OUT_DIR}/fuzz-coverage-build.log" \
        "${BAZEL}" build "--config=${FUZZ_CONFIG}" "--config=${COVERAGE_CONFIG}" \
        "${FUZZ_BIN_TARGET}"; then
    cat >&2 <<'GUIDE'

  [예상했던 실패 지점이다]

  퍼징 config 와 커버리지 config 를 같이 줄 수 없다는 뜻이다. 위 로그에
  "-fsanitize=fuzzer" 나 툴체인 해소 관련 에러가 보이면, GCC 가 clang 을
  밀어낸 그 문제다.

  선택지 둘:

    (1) 커버리지 측정을 별도 빌드로 분리한다.
        퍼징은 --config=fuzz 로 돌려 코퍼스만 모으고, 커버리지는 그 코퍼스를
        커버리지 전용 빌드에 다시 먹여서 잰다. 한 번 더 빌드하는 대신 config
        충돌을 피한다.

    (2) 오버레이에 fuzz+coverage 겸용 config 를 새로 정의한다.
        build:fuzz-cov 를 만들어 clang 툴체인을 마지막에 등록하고
        -fprofile-instr-generate -fcoverage-mapping 을 직접 넣는다.
        logosfuzz/generate/bazel/overlay/bazelrc_snippet 에 추가하면 된다.

  어느 쪽이든 GEN 파트(오버레이 담당)와 상의가 필요하다.

GUIDE
    exit 1
fi
echo "  -> 조합 성립. 계속 진행한다."

# ---------------------------------------------------------------------------
# STEP 2b - 퍼징 실행 후 커버리지 수집
# ---------------------------------------------------------------------------
log "STEP 2b · 퍼징 실행  (${FUZZ_SECONDS}초)"

FUZZ_BIN="$(${BAZEL} cquery "--config=${FUZZ_CONFIG}" "--config=${COVERAGE_CONFIG}" \
            --output=files "${FUZZ_BIN_TARGET}" 2>/dev/null | head -1)"
if [[ -z "${FUZZ_BIN}" || ! -f "${FUZZ_BIN}" ]]; then
    fail "퍼저 바이너리 경로를 찾지 못했다 (cquery 결과: '${FUZZ_BIN}')"
    echo "  bazel-bin 심링크는 직전 빌드 설정을 가리켜 신뢰할 수 없다." >&2
    exit 1
fi
echo "  바이너리: ${FUZZ_BIN}"

PROFRAW_DIR="${OUT_DIR}/profraw"
rm -rf "${PROFRAW_DIR}" && mkdir -p "${PROFRAW_DIR}"

# %m: 프로세스별 온라인 병합 풀. 같은 대상을 여러 프로세스로 돌려도 충돌하지 않는다.
export LLVM_PROFILE_FILE="${PROFRAW_DIR}/%m.profraw"

FUZZ_ARGS=(-max_total_time="${FUZZ_SECONDS}" -print_final_stats=1)
[[ -n "${CORPUS}" ]] && FUZZ_ARGS+=("${CORPUS}")

# 퍼저는 크래시를 찾으면 0 이 아닌 코드로 끝난다. 그건 실패가 아니라 성과다.
"${FUZZ_BIN}" "${FUZZ_ARGS[@]}" > "${OUT_DIR}/fuzz-run.log" 2>&1
FUZZ_RC=$?
echo "  퍼징 종료코드: ${FUZZ_RC} (0이 아니면 크래시를 찾았다는 뜻일 수 있다)"

shopt -s nullglob
PROFRAWS=("${PROFRAW_DIR}"/*.profraw)
shopt -u nullglob
if [[ ${#PROFRAWS[@]} -eq 0 ]]; then
    fail "profraw 가 하나도 안 나왔다. 바이너리가 계측되지 않았다는 뜻이다."
    echo "  STEP 2a 가 통과했는데 여기서 막혔다면, 커버리지 config 가 실제로는" >&2
    echo "  계측 플래그를 걸지 않았을 수 있다. bazel cquery --output=build 로" >&2
    echo "  타깃에 적용된 copt 를 확인할 것." >&2
    exit 1
fi
echo "  profraw ${#PROFRAWS[@]}개 수집"

log "STEP 2c · 퍼징 커버리지 산출"
run_logged "${OUT_DIR}/profdata.log" \
    llvm-profdata merge -sparse "${PROFRAWS[@]}" -o "${OUT_DIR}/fuzz.profdata" || exit 1
run_logged "${OUT_DIR}/fuzz-lcov.log" \
    bash -c "llvm-cov export -format=lcov -instr-profile='${OUT_DIR}/fuzz.profdata' '${FUZZ_BIN}' > '${OUT_DIR}/fuzz.lcov'" || exit 1
llvm-cov export -format=text -instr-profile="${OUT_DIR}/fuzz.profdata" "${FUZZ_BIN}" \
    > "${OUT_DIR}/fuzz.coverage.json" 2>/dev/null
echo "  -> ${OUT_DIR}/fuzz.lcov"

# ---------------------------------------------------------------------------
# STEP 3 - 비교
# ---------------------------------------------------------------------------
log "STEP 3 · 비교"
python3 "$(dirname "$0")/compare_coverage.py" \
    --unit-lcov "${OUT_DIR}/unit.lcov" \
    --fuzz-lcov "${OUT_DIR}/fuzz.lcov" \
    --out "${OUT_DIR}/comparison.json" \
    --markdown "${OUT_DIR}/comparison.md"

echo
echo "산출물:"
echo "  ${OUT_DIR}/comparison.md     <- 발표자료에 넣을 표"
echo "  ${OUT_DIR}/comparison.json   <- 원 수치"
echo "  ${OUT_DIR}/unit.lcov, fuzz.lcov"
