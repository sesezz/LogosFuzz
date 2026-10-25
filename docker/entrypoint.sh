#!/usr/bin/env bash
# LogosFuzz 격리 컨테이너 참고용 진입 스크립트 (EXE-04-01)
#
# 수동 디버깅용 헬퍼 (실제 퍼징 커맨드는 DockerIsolationRunner 가 주입)
#
# 사용:
#   logosfuzz-entrypoint build      //score/json/fuzz:json_parser_fuzz_test
#   logosfuzz-entrypoint binpath    //score/json/fuzz:json_parser_fuzz_test
#   logosfuzz-entrypoint regression //score/json:json
#   logosfuzz-entrypoint shell
#
# ---------------------------------------------------------------------------
# config 선택
# ---------------------------------------------------------------------------
#
# ① --config=fuzz 와 --config=bl-x86_64-linux 상호 배타 (동시 지정 시 링크 실패)
#      fuzz            = 퍼징 주경로   (clang, @llvm_toolchain)
#      bl-x86_64-linux = 회귀 게이트만 (GCC 12.2.0)
#
# ② 퍼징에 --config=asan_ubsan_lsan 미사용 (build:fuzz 가 ASan 적용)
#
# ③ 크래시 종료코드 55 (baselibs 의 exitcode=55, halt_on_error=1)
#    크래시 판정은 종료코드와 출력 파싱 병행
#
# ④ bazel run 대신 <name>_bin 직접 실행 (run 서브커맨드 없음, binpath 로 경로 획득)
#
# 주의: 첫 실행은 외부 저장소 다운로드로 네트워크 필요
# 캐시 볼륨(/bazel) 준비 후 --network none 격리 실행 가능, 첫 빌드는 장시간 소요
set -euo pipefail

FUZZ_CONFIG="${LOGOSFUZZ_FUZZ_CONFIG:-fuzz}"
REGRESSION_CONFIG="${LOGOSFUZZ_REGRESSION_CONFIG:-bl-x86_64-linux}"

CMD="${1:-shell}"
shift || true

mkdir -p /out/crashes /out/logs

# cc_fuzz_test //pkg:name 의 실제 퍼저 바이너리 타깃 //pkg:name_bin 생성
# 이미 _bin 으로 끝나면 그대로 유지
bin_label() {
    local label="$1"
    [[ "${label}" == *_bin ]] && { printf '%s' "${label}"; return; }
    printf '%s_bin' "${label}"
}

case "${CMD}" in
    build)
        TARGET="$(bin_label "${1:?bazel target required (예: //score/json/fuzz:json_parser_fuzz_test)}")"
        shift
        exec bazel build "--config=${FUZZ_CONFIG}" "$@" "${TARGET}"
        ;;
    binpath)
        # cquery 로 설정에 맞는 빌드 산출물 실제 경로 출력 (bazel-bin 심링크 미사용)
        TARGET="$(bin_label "${1:?bazel target required}")"
        shift
        exec bazel cquery "--config=${FUZZ_CONFIG}" --output=files "$@" "${TARGET}"
        ;;
    regression)
        # 퍼징 오버레이의 기존 GCC 빌드 영향 확인
        # 퍼징 타깃은 tags=["manual"] 로 //... 에서 제외
        TARGET="${1:?bazel target required}"
        shift
        exec bazel build "--config=${REGRESSION_CONFIG}" "$@" "${TARGET}"
        ;;
    query)
        exec bazel query "$@"
        ;;
    shell)
        exec bash
        ;;
    *)
        echo "알 수 없는 명령: ${CMD} (build|binpath|regression|query|shell)" >&2
        exit 2
        ;;
esac
