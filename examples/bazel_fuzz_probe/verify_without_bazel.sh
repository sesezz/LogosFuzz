#!/usr/bin/env bash
# Bazel 없이 probe.cc 만 검증한다.
#
# 확인되는 것 : probe.cc 가 커버리지 피드백을 받으면 반드시 크래시를 찾는다
# 확인 안 되는 것: rules_fuzzing 배선 (그건 bazel run //:probe_run 으로만 가능)
#
# 필요: clang, libclang-rt-<ver>-dev  (Ubuntu: apt install libclang-rt-18-dev)
#
# 주의: 퍼저는 크래시를 찾으면 0이 아닌 코드로 종료한다. 그게 정상 동작이므로
#       종료코드로 성공/실패를 판정하면 안 되고, 출력에 ASan 리포트가 있는지로
#       판정해야 한다. (pipefail 과 섞으면 전부 FAIL 로 보인다)
set -uo pipefail

cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

printf 'BOOM' > "$work/boom.bin"
fail=0

for opt in O0 O1 O2; do
  bin="$work/probe_$opt"
  if ! clang++ -g "-$opt" -fsanitize=fuzzer,address probe.cc -o "$bin" 2>"$work/build.log"; then
    echo "-$opt  빌드 실패:"
    sed 's/^/    /' "$work/build.log"
    fail=1
    continue
  fi

  # 1) 매직 입력을 직접 먹였을 때 결정적으로 터지는가
  "$bin" "$work/boom.bin" >"$work/direct.log" 2>&1 || true
  if grep -q "AddressSanitizer" "$work/direct.log"; then direct="OK"; else direct="FAIL"; fail=1; fi

  # 2) 퍼징으로 스스로 찾아내는가
  timeout 120 "$bin" -runs=2000000 >"$work/fuzz.log" 2>&1 || true
  if grep -q "ERROR: AddressSanitizer" "$work/fuzz.log"; then
    fuzz="OK"
    at="$(grep -oE '^#[0-9]+' "$work/fuzz.log" | tail -1)"
  else
    fuzz="FAIL"; at="-"; fail=1
  fi

  printf -- "-%-3s  직접입력=%-4s  퍼징발견=%-4s  발견시점=%s\n" "$opt" "$direct" "$fuzz" "$at"
done

if [ "$fail" -ne 0 ]; then
  echo "probe.cc 검증 실패"
  exit 1
fi
echo "probe.cc 검증 통과"
