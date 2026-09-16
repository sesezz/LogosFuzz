#!/usr/bin/env bash
# LogosFuzz 격리 컨테이너 참고용 진입 스크립트 (EXE-04-01).
#
# 실제 실행 커맨드는 DockerIsolationRunner._in_container_cmd()가 구성하여
# `bash -lc "<cmd>"`로 주입한다. 이 파일은 수동 디버깅/문서용이며,
# 1주차 완료 기준인 "컨테이너 안에서 수동 하네스 빌드·실행·크래시 재현"을
# 한 줄로 재현하기 위한 헬퍼다.
#
# 사용:
#   logosfuzz-entrypoint build //score/json:json_fuzz_test
#   logosfuzz-entrypoint run   //score/json:json_fuzz_test -- -max_total_time=60
#   logosfuzz-entrypoint test  //score/json:json_fuzz_test
#   logosfuzz-entrypoint shell
#
# 주의(네트워크):
#   첫 실행은 외부 저장소를 받아야 하므로 네트워크가 필요하다.
#   캐시 볼륨(/bazel)을 한 번 데운 뒤부터 --network none 으로 격리 실행할 수 있다.
#
# 주의(새니타이저 config 레벨) — eclipse-score/baselibs의 .bazelrc를 직접
# 대조해 확인한 내용:
#   test:asan_ubsan_lsan --features=asan / ubsan / lsan ...
# 이 라인은 "test:" 접두사로만 정의돼 있어 `bazel test`에만 자동 적용되고,
# `bazel build`/`bazel run`에는 Bazel이 조용히 무시한다(에러 없이 그냥
# 안 켜짐). S-CORE 공식 예시도 항상 `bazel test --config=bl-x86_64-linux
# --config=asan_ubsan_lsan`로 test 커맨드를 쓴다.
# 그래서:
#   - `test`  : 원본 config 이름을 그대로 사용 (S-CORE 문서와 100% 동일)
#   - `run`   : cc_fuzz_test 바이너리를 대화식으로 직접 실행할 때 쓰므로,
#               config가 확장하는 것과 같은 --features 3개를 직접 넘긴다.
#   - `build` : 새니타이저 계측이 들어간 바이너리가 필요하면 run과 동일하게
#               --features를 직접 넘긴다. 계측 없이 빌드만 확인할 때는
#               LOGOSFUZZ_SANITIZER=0 으로 끌 수 있다.
set -euo pipefail

PLATFORM_CONFIG="${LOGOSFUZZ_PLATFORM_CONFIG:-bl-x86_64-linux}"
SANITIZER_CONFIG="${LOGOSFUZZ_SANITIZER_CONFIG:-asan_ubsan_lsan}"
SANITIZER_ON="${LOGOSFUZZ_SANITIZER:-1}"

CMD="${1:-shell}"
shift || true

platform_flags=(--config="${PLATFORM_CONFIG}")
# build/run 전용: test:-only config가 확장하는 것과 동일한 --features.
# baselibs .bazelrc가 새 새니타이저를 추가하면 여기도 같이 갱신해야 한다.
sanitizer_features=(--features=asan --features=ubsan --features=lsan)

mkdir -p /out/crashes /out/logs

case "${CMD}" in
    build)
        TARGET="${1:?bazel target required (예: //score/json:json_fuzz_test)}"
        shift
        extra=()
        [[ "${SANITIZER_ON}" == "1" ]] && extra+=("${sanitizer_features[@]}")
        exec bazel build "${platform_flags[@]}" "${extra[@]}" "$@" "${TARGET}"
        ;;
    run)
        TARGET="${1:?bazel target required}"
        shift
        extra=()
        [[ "${SANITIZER_ON}" == "1" ]] && extra+=("${sanitizer_features[@]}")
        # `--` 뒤 인자는 하네스(libFuzzer)로 그대로 전달된다.
        # 크래시 산출물은 호스트와 공유되는 /out/crashes 로 모은다.
        exec bazel run "${platform_flags[@]}" "${extra[@]}" "${TARGET}" "$@" \
            -- -artifact_prefix=/out/crashes/ -print_final_stats=1
        ;;
    test)
        # S-CORE 공식 예시와 동일한 형태: --config 조합을 그대로 쓴다.
        TARGET="${1:?bazel target required}"
        shift
        exec bazel test "${platform_flags[@]}" --config="${SANITIZER_CONFIG}" \
            --test_output=all "$@" "${TARGET}"
        ;;
    query)
        exec bazel query "$@"
        ;;
    shell)
        exec bash
        ;;
    *)
        echo "알 수 없는 명령: ${CMD} (build|run|test|query|shell)" >&2
        exit 2
        ;;
esac
