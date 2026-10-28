#!/usr/bin/env bash
# 의도적 스택 오버플로의 AddressSanitizer 빌드 및 재현
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
out_dir="${script_dir}/build"
mkdir -p "${out_dir}"

clang -g -O1 -fno-omit-frame-pointer -fsanitize=address \
  "${script_dir}/stack_overflow.c" -o "${out_dir}/stack_overflow_asan"

# 16바이트 + 종료 NUL로 16바이트 스택 버퍼 오버플로 유발
ASAN_OPTIONS=halt_on_error=1 "${out_dir}/stack_overflow_asan" "0123456789ABCDEF"
