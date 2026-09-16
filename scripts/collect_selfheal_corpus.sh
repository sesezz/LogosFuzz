#!/usr/bin/env bash
# GEN-03-02 자가치유 에러 코퍼스 수집기 (D 파트 1주차)
# ====================================================
#
# 두 가지를 실제로 실행해서 **원문 그대로** 모은다:
#
#   1. Bazel 파손 에러 — tests/fixtures/bazel_repro/breaks/<case>/ 를 워크스페이스
#      위에 덮어쓰고 빌드해, deps/visibility/구문 오류 등이 뱉는 문장을 수집한다.
#   2. Sanitizer 출력 — --config=asan_ubsan_lsan 으로 빌드한 하네스를 UB 종류별
#      입력으로 실행해 UBSan/ASan/LSan 진단 원문을 수집한다.
#
# 2주차 generate/bazel_errors.py 분류기가 이 코퍼스를 정답지로 쓴다.
#
# 리눅스 전용이다(Bazel + clang sanitizer). WSL 과 docker/Dockerfile.selfheal
# 컨테이너 양쪽에서 같은 명령으로 돈다:
#
#   bash scripts/collect_selfheal_corpus.sh --out-root <저장소 루트>
#
# 왜 워크스페이스를 복사하나 — Bazel 을 /mnt/c (Windows 마운트) 에서 돌리면
# 느리고 심볼릭 링크·권한이 깨진다. 항상 네이티브 FS 로 복사해서 빌드한다.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

FIXTURE_SRC="${REPO_ROOT}/tests/fixtures/bazel_repro"
OUT_ROOT="${REPO_ROOT}"
SCRATCH="${SCRATCH:-${HOME}/.cache/logosfuzz-selfheal}"
ONLY=""

usage() {
    cat <<'USAGE'
사용법: collect_selfheal_corpus.sh [옵션]

  --fixture <dir>   재현 워크스페이스 경로 (기본: <repo>/tests/fixtures/bazel_repro)
  --out-root <dir>  수집 결과를 쓸 저장소 루트 (기본: 스크립트 상위)
  --scratch <dir>   Bazel 빌드용 네이티브 작업 디렉터리 (기본: ~/.cache/logosfuzz-selfheal)
  --only <phase>    bazel | sanitizer  (기본: 둘 다)
  -h, --help        이 도움말

결과:
  <out-root>/tests/fixtures/bazel_errors/*.txt
  <out-root>/tests/fixtures/sanitizer_logs/*.txt
  각 디렉터리의 _META.json 에 bazel/clang 버전과 정규화 규칙을 남긴다.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fixture)  FIXTURE_SRC="$2"; shift 2 ;;
        --out-root) OUT_ROOT="$2";    shift 2 ;;
        --scratch)  SCRATCH="$2";     shift 2 ;;
        --only)     ONLY="$2";        shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        *) echo "알 수 없는 옵션: $1" >&2; usage; exit 2 ;;
    esac
done

BAZEL_ERR_DIR="${OUT_ROOT}/tests/fixtures/bazel_errors"
SAN_DIR="${OUT_ROOT}/tests/fixtures/sanitizer_logs"
WORK="${SCRATCH}/workspace"

command -v bazel >/dev/null 2>&1 || { echo "bazel(bazelisk) 이 PATH 에 없다" >&2; exit 1; }
command -v clang >/dev/null 2>&1 || { echo "clang 이 PATH 에 없다" >&2; exit 1; }
[[ -d "${FIXTURE_SRC}" ]] || { echo "재현 워크스페이스 없음: ${FIXTURE_SRC}" >&2; exit 1; }

BAZEL_VERSION="$(cd "${FIXTURE_SRC}" && bazel --version 2>/dev/null | tail -1)"
CLANG_VERSION="$(clang --version | head -1)"
COLLECTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "== LogosFuzz 자가치유 코퍼스 수집 =="
echo "   bazel   : ${BAZEL_VERSION}"
echo "   clang   : ${CLANG_VERSION}"
echo "   fixture : ${FIXTURE_SRC}"
echo "   scratch : ${WORK}"
echo

# --------------------------------------------------------------------------- #
# 정규화: 머신마다 달라지는 값만 걷어낸다. 에러 '문장'은 건드리지 않는다.
#
# 이걸 하는 이유 — 절대경로(=사용자 홈), 빌드 소요 시간, PID, 샌드박스 해시는
# 실행할 때마다 바뀌어서 그대로 커밋하면 diff 가 매번 깨지고 분류기 테스트가
# 머신에 종속된다. 치환 규칙은 _META.json 에 그대로 적어 둔다.
# --------------------------------------------------------------------------- #
normalize() {
    local output_base
    output_base="$(cd "${WORK}" 2>/dev/null && bazel info output_base 2>/dev/null)" || output_base=""
    sed -e "s|${WORK}|<WORKSPACE>|g" \
        -e "${output_base:+s|${output_base}|<OUTPUT_BASE>|g}" \
        -e "s|${HOME}|<HOME>|g" \
        -e "s/Elapsed time: [0-9.]*s/Elapsed time: <T>s/g" \
        -e "s/, Critical Path: [0-9.]*s/, Critical Path: <T>s/g" \
        -e "s/^\(INFO: Invocation ID: \).*/\1<UUID>/" \
        -e "s/pid=[0-9]\+/pid=<PID>/g" \
        -e "s/^==[0-9]\+==/==<PID>==/" \
        -e "s/^INFO: Seed: [0-9]*/INFO: Seed: <SEED>/" \
        -e "s/0x[0-9a-f]\{4,\}/<ADDR>/g" \
        -e "s/(BuildId: [0-9a-f]*)/(BuildId: <BUILDID>)/g" \
        -e "s/ in [0-9]\+ ms/ in <T> ms/g" \
        -e "s/(config: [0-9a-f]\+)/(config: <CONFIG>)/g" \
        -e "s/([0-9a-f]\{32,\})/(<CONFIG>)/g" \
        -e "s/\(Loading:\|Analyzing:\|\[[0-9,]* \/ [0-9,]*\]\).*//" \
        -e "s/([0-9]* packages loaded, [0-9]* targets configured)/(<N> packages loaded, <N> targets configured)/g"
}

reset_workspace() {
    rm -rf "${WORK}"
    mkdir -p "${SCRATCH}"
    cp -a "${FIXTURE_SRC}" "${WORK}"
    rm -rf "${WORK}/breaks"
}

# --------------------------------------------------------------------------- #
# 1. Bazel 파손 에러 수집
# --------------------------------------------------------------------------- #
collect_bazel_errors() {
    mkdir -p "${BAZEL_ERR_DIR}"
    local cases=()
    while IFS= read -r d; do cases+=("$(basename "$d")"); done \
        < <(find "${FIXTURE_SRC}/breaks" -mindepth 1 -maxdepth 1 -type d | sort)

    # 대조군: 정상 상태가 정말로 빌드되는지 먼저 확인한다. 이게 깨지면 아래
    # 파손 에러들이 '내가 낸 파손' 때문인지 워크스페이스가 원래 고장난 건지
    # 구분할 수 없다.
    echo "[baseline] 정상 빌드 확인 중..."
    reset_workspace
    local base_log
    base_log="$(cd "${WORK}" && bazel build --config=fuzzer //harness:json_fuzzer 2>&1)"
    local base_rc=$?
    printf '%s\n' "${base_log}" | normalize > "${BAZEL_ERR_DIR}/_baseline_ok.txt"
    if [[ ${base_rc} -ne 0 ]]; then
        echo "  !! 정상 상태가 빌드되지 않는다(rc=${base_rc}). 아래 로그 확인:" >&2
        printf '%s\n' "${base_log}" | tail -30 >&2
        return 1
    fi
    echo "  ok"

    for c in "${cases[@]}"; do
        printf '[bazel] %-22s ' "${c}"
        reset_workspace
        cp -a "${FIXTURE_SRC}/breaks/${c}/." "${WORK}/"
        local log rc
        log="$(cd "${WORK}" && bazel build --config=fuzzer //harness:json_fuzzer 2>&1)"
        rc=$?
        printf '%s\n' "${log}" | normalize > "${BAZEL_ERR_DIR}/${c}.txt"
        if [[ ${rc} -eq 0 ]]; then
            echo "경고: 빌드가 성공했다(파손이 재현되지 않음, rc=0)"
        else
            echo "수집됨 (rc=${rc})"
        fi
    done

    cat > "${BAZEL_ERR_DIR}/_META.json" <<META
{
  "purpose": "GEN-03-02 자가치유 분류기(generate/bazel_errors.py)의 정답지. deps·visibility 등을 고의로 파손해 얻은 Bazel 에러 원문.",
  "collected_at": "${COLLECTED_AT}",
  "bazel_version": "${BAZEL_VERSION}",
  "clang_version": "${CLANG_VERSION}",
  "fixture": "tests/fixtures/bazel_repro",
  "command": "bazel build --config=fuzzer //harness:json_fuzzer",
  "normalization": [
    "워크스페이스 절대경로 -> <WORKSPACE>",
    "bazel output_base -> <OUTPUT_BASE>",
    "사용자 홈 -> <HOME>",
    "Elapsed time / Critical Path 초 -> <T>",
    "Invocation ID -> <UUID>",
    "PID -> <PID>",
    "진행률 라인(Loading: / Analyzing: / [n / m]) 제거",
    "packages loaded / targets configured 개수 -> <N>",
    "libFuzzer Seed -> <SEED>",
    "16진 주소(0x....) -> <ADDR>",
    "BuildId -> <BUILDID>",
    "실행 소요 ms -> <T>",
    "Bazel config 해시 -> <CONFIG>"
  ],
  "note": "에러 문장 자체는 한 글자도 바꾸지 않았다. 위 치환은 머신마다 달라지는 값에만 적용된다."
}
META
    echo "  -> ${BAZEL_ERR_DIR}"
}

# --------------------------------------------------------------------------- #
# 2. Sanitizer 출력 수집
# --------------------------------------------------------------------------- #
# json.h 의 Case 열거형 순서와 일치해야 한다.
SAN_CASES=(
    "0:ubsan_signed_overflow"
    "1:ubsan_shift_exponent"
    "2:ubsan_null_deref"
    "3:ubsan_divide_by_zero"
    "4:ubsan_array_bounds"
    "5:ubsan_misaligned_load"
    "6:ubsan_float_cast_overflow"
    "7:ubsan_invalid_bool"
    "8:asan_heap_overflow"
    "9:lsan_memory_leak"
    "10:clean_no_diagnostic"
)

collect_sanitizer_logs() {
    mkdir -p "${SAN_DIR}"

    # 두 설정을 모두 수집한다.
    #   asan_ubsan_lsan      : UBSan 기본(복구 가능) — 진단만 찍고 실행을 계속한다.
    #   asan_ubsan_lsan_halt : -fno-sanitize-recover=undefined — UB 에서 프로세스가 죽는다.
    # 이 차이가 "UB 를 찾았는데 크래시 아티팩트가 안 생기는" 현상의 원인이라
    # 1주차에 양쪽을 다 남긴다.
    local configs=("asan_ubsan_lsan" "asan_ubsan_lsan_halt")

    for cfg in "${configs[@]}"; do
        echo "[sanitizer] --config=${cfg} 빌드 중..."
        reset_workspace
        local build_log rc
        build_log="$(cd "${WORK}" && bazel build --config="${cfg}" //harness:json_fuzzer 2>&1)"
        rc=$?
        if [[ ${rc} -ne 0 ]]; then
            echo "  !! 빌드 실패(rc=${rc}) — 로그를 남기고 이 설정은 건너뛴다" >&2
            printf '%s\n' "${build_log}" | normalize \
                > "${SAN_DIR}/_BUILD_FAILED_${cfg}.txt"
            printf '%s\n' "${build_log}" | tail -30 >&2
            continue
        fi

        local bin="${WORK}/bazel-bin/harness/json_fuzzer"
        local prefix=""
        [[ "${cfg}" == *_halt ]] && prefix="halt_"

        local seeds="${SCRATCH}/seeds"
        rm -rf "${seeds}"; mkdir -p "${seeds}"

        for entry in "${SAN_CASES[@]}"; do
            local idx="${entry%%:*}"
            local name="${entry#*:}"
            local seed="${seeds}/${name}.bin"
            # 1바이트 선택자 + 4바이트 인자(리틀엔디언 0x00000001)
            printf "$(printf '\\x%02x' "${idx}")\\x01\\x00\\x00\\x00" > "${seed}"

            printf '  %-32s ' "${prefix}${name}"
            local out
            out="$(cd "${WORK}" && \
                ASAN_OPTIONS='detect_leaks=1:abort_on_error=0:symbolize=1' \
                UBSAN_OPTIONS='print_stacktrace=1:symbolize=1' \
                timeout 60 "${bin}" "${seed}" 2>&1)"
            local run_rc=$?
            {
                printf '%s\n' "${out}"
                printf '\n[exit code] %s\n' "${run_rc}"
            } | normalize > "${SAN_DIR}/${prefix}${name}.txt"
            echo "수집됨 (exit=${run_rc})"
        done
    done

    cat > "${SAN_DIR}/_META.json" <<META
{
  "purpose": "--config=asan_ubsan_lsan 실행 후 얻은 UBSan/ASan/LSan 출력 원문. C(임세은) 3주차 sanitizer.py UBSan 파서와 4주차 signature.py UBSan 시그니처의 입력 표본.",
  "collected_at": "${COLLECTED_AT}",
  "bazel_version": "${BAZEL_VERSION}",
  "clang_version": "${CLANG_VERSION}",
  "fixture": "tests/fixtures/bazel_repro",
  "configs": {
    "asan_ubsan_lsan": "UBSan 기본(복구 가능). 진단을 찍고 실행을 계속한다 — 파일명 접두사 없음.",
    "asan_ubsan_lsan_halt": "-fno-sanitize-recover=undefined 추가. UB 에서 프로세스가 죽는다 — 파일명 접두사 'halt_'."
  },
  "runtime_env": {
    "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=0:symbolize=1",
    "UBSAN_OPTIONS": "print_stacktrace=1:symbolize=1"
  },
  "input_encoding": "1바이트 선택자(score::json::Case) + 4바이트 리틀엔디언 인자",
  "normalization": [
    "워크스페이스 절대경로 -> <WORKSPACE>",
    "bazel output_base -> <OUTPUT_BASE>",
    "사용자 홈 -> <HOME>",
    "PID -> <PID>",
    "libFuzzer Seed -> <SEED>",
    "16진 주소(0x....) -> <ADDR>",
    "BuildId -> <BUILDID>",
    "실행 소요 ms -> <T>",
    "Bazel config 해시 -> <CONFIG>"
  ]
}
META
    echo "  -> ${SAN_DIR}"
}

# --------------------------------------------------------------------------- #
rc=0
if [[ -z "${ONLY}" || "${ONLY}" == "bazel" ]]; then
    collect_bazel_errors || rc=1
    echo
fi
if [[ -z "${ONLY}" || "${ONLY}" == "sanitizer" ]]; then
    collect_sanitizer_logs || rc=1
fi

echo
echo "== 완료 (rc=${rc}) =="
exit ${rc}
