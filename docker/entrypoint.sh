#!/usr/bin/env bash
# LogosFuzz 격리 컨테이너 참고용 진입 스크립트 (EXE-04-01).
# 실제 실행 커맨드는 DockerIsolationRunner._in_container_cmd()가 엔진별로
# 구성하여 `bash -lc "<cmd>"`로 주입한다. 이 파일은 수동 디버깅/문서용.
set -euo pipefail

ENGINE="${1:-libfuzzer}"      # libfuzzer | afl++
HARNESS="${2:?harness path required}"
TIMEOUT="${3:-60}"
CORPUS="${4:-}"

export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=1:symbolize=1}"
export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1}"

mkdir -p /out/crashes
chmod +x "$HARNESS" 2>/dev/null || true

if [[ "$ENGINE" == "libfuzzer" ]]; then
    exec "$HARNESS" -max_total_time="$TIMEOUT" \
        -artifact_prefix=/out/crashes/ -print_final_stats=1 ${CORPUS:+"$CORPUS"}
else
    IN="${CORPUS:-/tmp/seed}"
    [[ -z "$CORPUS" ]] && { mkdir -p /tmp/seed && printf 'a' > /tmp/seed/seed; }
    exec afl-fuzz -i "$IN" -o /out/afl -V "$TIMEOUT" -- "$HARNESS" @@
fi
