#!/usr/bin/env bash
# libsndfile au.c 정수 오버플로(CVE-2022-33065 유형) 수정 후 재실행 검증 (GENERIC-B)
# ====================================================================================
#
# 원본 third_party/libsndfile 은 건드리지 않고 임시 폴더에 복사해서 au.c 의 int 덧셈을 64비트로 바꾼 뒤,
# 같은 20바이트 AU 입력으로 UBSan 경고가 사라지는지 확인한다.
#
#   bash scripts/verify_au_overflow_fix.sh
#
# 저장소 루트에서 실행. 필요 도구: clang, cmake, ninja 또는 make, python3
# 결과: 수정 전(원본 라이브러리)과 수정 후(복사본)의 UBSan 경고 개수
set -euo pipefail

SRC="third_party/libsndfile"
[ -f "$SRC/src/au.c" ] || { echo "[ERROR] $SRC 가 없다. 저장소 루트에서 실행한다." >&2; exit 1; }
[ -f "$SRC/build-fuzz/libsndfile.a" ] || { echo "[ERROR] 원본 계측 빌드($SRC/build-fuzz)가 없다. 먼저 logosfuzz run 또는 fetch_libsndfile.sh --build" >&2; exit 1; }

WORK="$(mktemp -d /tmp/au-verify.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
INPUT_B64='LnNuZFIA6QhhiYmJ5ImJYAAAJQA='     # 실측 재현 입력 (20바이트)
echo "$INPUT_B64" | base64 -d > "$WORK/au_input.bin"

echo "== 1. 복사본 만들기 (원본 보존)"
rsync -a --exclude 'build-fuzz*' --exclude '.git' "$SRC/" "$WORK/src/"

echo "== 2. au.c 수정: int 덧셈을 64비트로 계산"
python3 - "$WORK/src/src/au.c" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
old = "au_fmt.dataoffset + au_fmt.datasize"
new = "((sf_count_t) au_fmt.dataoffset + (sf_count_t) au_fmt.datasize)"
count = text.count(old)
assert count == 4, f"예상한 4곳이 아니라 {count}곳이다. au.c 가 달라졌는지 확인한다"
open(path, "w", encoding="utf-8").write(text.replace(old, new))
print(f"   {count}곳 수정")
PY
diff -u "$SRC/src/au.c" "$WORK/src/src/au.c" > "$WORK/au.patch" || true
echo "   변경 내용 (diff):"
sed 's/^/     /' "$WORK/au.patch" | head -40

echo "== 3. 수정본 빌드 (원본과 같은 계측: address,undefined)"
FLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined,fuzzer-no-link"
CC=clang CXX=clang++ CFLAGS="$FLAGS" CXXFLAGS="$FLAGS" cmake -S "$WORK/src" -B "$WORK/build" \
  -DBUILD_SHARED_LIBS=OFF -DBUILD_PROGRAMS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF \
  -DENABLE_EXTERNAL_LIBS=OFF > "$WORK/cmake.log" 2>&1 || { tail -20 "$WORK/cmake.log"; exit 1; }
cmake --build "$WORK/build" --parallel 4 > "$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log"; exit 1; }

echo "== 4. 입력을 여는 작은 프로그램 컴파일"
cat > "$WORK/open_au.c" <<'C'
#include <stdio.h>
#include <string.h>
#include <sndfile.h>
int main(int argc, char **argv) {
    SF_INFO info; memset(&info, 0, sizeof info);
    SNDFILE *f = sf_open(argv[1], SFM_READ, &info);
    printf("sf_open -> %s\n", f ? "열림" : "거부됨");
    if (f) sf_close(f);
    return 0;
}
C
clang -fsanitize=address,undefined -I "$SRC/include" "$WORK/open_au.c" "$SRC/build-fuzz/libsndfile.a" -lm -o "$WORK/open_before"
clang -fsanitize=address,undefined -I "$WORK/src/include" -I "$WORK/build" "$WORK/open_au.c" \
  "$(find "$WORK/build" -name libsndfile.a | head -1)" -lm -o "$WORK/open_after"

count() { UBSAN_OPTIONS=halt_on_error=0 ASAN_OPTIONS=detect_leaks=0 "$1" "$WORK/au_input.bin" 2>&1 | grep -c "runtime error" || true; }

echo "== 5. 같은 입력으로 비교"
BEFORE=$(count "$WORK/open_before")
AFTER=$(count "$WORK/open_after")
echo "   수정 전(원본 라이브러리) UBSan 경고: ${BEFORE}건"
UBSAN_OPTIONS=halt_on_error=0 ASAN_OPTIONS=detect_leaks=0 "$WORK/open_before" "$WORK/au_input.bin" 2>&1 \
  | grep "runtime error" | sed 's#.*/src/#     src/#' | head -4
echo "   수정 후(64비트 계산)       UBSan 경고: ${AFTER}건"

if [ "$BEFORE" -gt 0 ] && [ "$AFTER" -eq 0 ]; then
  echo "[결과] 검증 성공: 수정 전 ${BEFORE}건 -> 수정 후 0건. au.c 의 int 덧셈이 경고의 원인이다."
else
  echo "[결과] 기대와 다르다 (수정 전 ${BEFORE}건, 수정 후 ${AFTER}건). 출력을 확인한다."
  exit 1
fi
