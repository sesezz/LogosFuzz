#!/usr/bin/env bash
# LogosFuzz 격리 컨테이너 참고용 진입 스크립트 (EXE-04-01).
#
# 실제 퍼징 실행 커맨드는 DockerIsolationRunner 가 구성해 주입한다. 이 파일은
# 수동 디버깅/문서용이며, "컨테이너 안에서 하네스를 빌드하고 실행해 크래시를
# 재현한다"를 한 줄로 재현하기 위한 헬퍼다.
#
# 사용:
#   logosfuzz-entrypoint build      //score/json/fuzz:json_parser_fuzz_test
#   logosfuzz-entrypoint binpath    //score/json/fuzz:json_parser_fuzz_test
#   logosfuzz-entrypoint regression //score/json:json
#   logosfuzz-entrypoint shell
#
# ---------------------------------------------------------------------------
# config 선택 (GEN 파트가 1주차에 실측으로 확정한 결정사항)
# ---------------------------------------------------------------------------
#
# ① --config=fuzz 와 --config=bl-x86_64-linux 는 상호 배타다.
#    둘을 같이 주면 뒤에 오는 --extra_toolchains 가 이겨 GCC 가 clang 을
#    밀어내고, GCC 에는 -fsanitize=fuzzer 가 없어 링크에서 죽는다
#    (g++ 13.3 실측: "unrecognized argument to '-fsanitize=' option: 'fuzzer'").
#      fuzz            = 퍼징 주경로   (clang, @llvm_toolchain)
#      bl-x86_64-linux = 회귀 게이트만 (GCC 12.2.0)
#
# ② 퍼징에 --config=asan_ubsan_lsan 을 쓰면 안 된다. baselibs .bazelrc 에서
#    이 config 는 test: 로만 정의돼 있어 bazel build/run 에서는
#    "config value is not defined" 로 실패한다. 오버레이의 build:fuzz 가
#    그 자리를 대신하며, run/test 가 build 를 상속하므로 세 커맨드 모두에서
#    쓸 수 있다.
#
# ③ 크래시 종료코드는 55 다(baselibs 가 ASAN_OPTIONS/UBSAN_OPTIONS 에
#    exitcode=55, halt_on_error=1 을 박아 둔다). 크래시 판정은 종료코드와
#    출력 파싱을 같이 봐야 한다.
#
# ④ EXE 계층은 bazel run 이 아니라 <name>_bin 을 직접 실행한다. cc_fuzz_test
#    가 만드는 _run 타깃은 bazel run 전용 런처라 libFuzzer 인자를 그대로
#    넘기지 못한다. 그래서 이 스크립트에도 run 서브커맨드를 두지 않는다 -
#    빌드해서 바이너리 경로를 얻고(binpath), 그 바이너리를 직접 실행한다.
#
# 주의(네트워크): 첫 실행은 외부 저장소를 받아야 하므로 네트워크가 필요하다.
# 캐시 볼륨(/bazel)을 한 번 데운 뒤부터 --network none 으로 격리 실행할 수 있다.
# cc_engine_instrumentation 이 전이(transition)라 의존 클로저 전체가
# clang+sancov 로 재컴파일되므로 첫 빌드는 길다(GEN 파트 실측: 7분 12초).
set -euo pipefail

FUZZ_CONFIG="${LOGOSFUZZ_FUZZ_CONFIG:-fuzz}"
REGRESSION_CONFIG="${LOGOSFUZZ_REGRESSION_CONFIG:-bl-x86_64-linux}"

CMD="${1:-shell}"
shift || true

mkdir -p /out/crashes /out/logs

# cc_fuzz_test //pkg:name 에서 실제 퍼저 바이너리 타깃 //pkg:name_bin 을 만든다.
# 이미 _bin 으로 끝나면 그대로 둔다.
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
        # 빌드 산출물의 실제 경로를 찍는다. bazel-bin 심링크는 직전 빌드
        # 설정을 가리키는 편의 링크라 config 가 섞이면 무효가 되므로,
        # 경로를 조립하지 않고 cquery 로 설정에 맞는 실제 경로를 질의한다.
        TARGET="$(bin_label "${1:?bazel target required}")"
        shift
        exec bazel cquery "--config=${FUZZ_CONFIG}" --output=files "$@" "${TARGET}"
        ;;
    regression)
        # 퍼징 오버레이가 기존 GCC 빌드를 깨지 않았는지 확인한다.
        # 퍼징 타깃에는 tags=["manual"] 이 붙어 있어 //... 에 딸려 들어가지
        # 않는 것이 정상이다.
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
