#!/usr/bin/env bash
# ANA-05-01 에러계약 위반 크래시 코퍼스 수집기 (D 파트 4주차)
# ==========================================================
#
# score::Result 의 오류 대안을 확인하지 않고 값을 꺼낼 때 어떤 크래시 로그가
# 나오는지 **실제로 실행해서 원문 그대로** 모은다. triage.py 의 에러계약 위반
# 판별(analyze/error_contract.py)이 이 코퍼스를 정답지로 쓴다.
#
# score::Result<T> 는 details::expected<T, Error> 이고 저장소가 std::variant 다.
# 오류 상태에서 value() 를 부르면 std::get<0> 이 bad_variant_access 를 던지고,
# operator* 는 noexcept 라 그 자리에서 std::terminate 로 죽는다. 어느 쪽이든
# SIGABRT 이므로 ASan 이 스택을 찍게 handle_abort=1 을 켠다.
#
# 수집하는 두 경우 — 판별이 갈리는 지점이 바로 "누가 확인을 빠뜨렸나"다:
#   harness_unchecked : 하네스가 ParseLength(...).value() 를 확인 없이 부른다
#                       -> API 는 계약대로 오류를 돌려줬다. 하네스 결함(오탐)
#   library_unchecked : 공개 API PayloadEnd 가 내부에서 *ParseLength(...) 를
#                       확인 없이 꺼낸다 -> 정상 호출로 재현되는 대상 결함(정탐)
#
# baselibs 의 실제 score/result 소스로 빌드한다(형식을 추측하지 않는다):
#
#   bash scripts/collect_error_contract_corpus.sh --baselibs <score-baselibs 체크아웃>
#
# baselibs 는 score/result 와 score/language/futurecpp 만 있으면 된다.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURE="${REPO_ROOT}/tests/fixtures/error_contract_logs"
BASELIBS=""
CXX="${CXX:-g++}"
SCRATCH="${SCRATCH:-${HOME}/.cache/logosfuzz-error-contract}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --baselibs) BASELIBS="$2"; shift 2 ;;
        --scratch) SCRATCH="$2"; shift 2 ;;
        -h|--help) sed -n 2,26p "$0"; exit 0 ;;
        *) echo "알 수 없는 옵션: $1" >&2; exit 2 ;;
    esac
done
[[ -n "${BASELIBS}" ]] || { echo "--baselibs 가 필요하다" >&2; exit 2; }
BASELIBS="$(cd "${BASELIBS}" && pwd)"

rm -rf "${SCRATCH}" && mkdir -p "${SCRATCH}"
cp -r "${FIXTURE}/repro/." "${SCRATCH}/"
cd "${SCRATCH}"

FLAGS=(-std=c++17 -g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined
       -I. -I"${BASELIBS}" -I"${BASELIBS}/score/language/futurecpp/include")
"${CXX}" "${FLAGS[@]}" -o length_fuzzer \
    harness/length_fuzzer.cc harness/standalone_main.cc score/demo/length.cc \
    "${BASELIBS}/score/result/error.cpp" "${BASELIBS}/score/result/error_domain.cpp"

printf '\x00\x07' > harness_unchecked.input   # 경로 0 + 1바이트(길이 필드 부족)
printf '\x01\x07' > library_unchecked.input   # 경로 1 + 1바이트

# 실행마다 바뀌는 값과 수집 환경 경로를 지운다(sanitizer_logs/_META.json 과 같은 규칙).
normalize() {
    sed -E \
        -e "s#${SCRATCH}#<SCRATCH>#g" \
        -e "s#${BASELIBS}#<BASELIBS>#g" \
        -e 's#==[0-9]+==#==<PID>==#g' \
        -e 's#0x[0-9a-fA-F]+#<ADDR>#g' \
        -e 's#BuildId: [0-9a-f]+#BuildId: <BUILDID>#g'
}

for case in harness_unchecked library_unchecked; do
    ASAN_OPTIONS=symbolize=1:handle_abort=1:detect_leaks=0 \
        ./length_fuzzer "${case}.input" 2>&1 | normalize > "${FIXTURE}/${case}.txt" || true
    echo "  -> ${FIXTURE}/${case}.txt"
done
