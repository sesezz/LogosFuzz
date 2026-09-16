#!/usr/bin/env bash
# Build and reproduce the intentional stack overflow with AddressSanitizer.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
out_dir="${script_dir}/build"
mkdir -p "${out_dir}"

clang -g -O1 -fno-omit-frame-pointer -fsanitize=address \
  "${script_dir}/stack_overflow.c" -o "${out_dir}/stack_overflow_asan"

# 16 bytes plus its terminating NUL overflow the 16-byte stack buffer.
ASAN_OPTIONS=halt_on_error=1 "${out_dir}/stack_overflow_asan" "0123456789ABCDEF"
