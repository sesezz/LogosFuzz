#!/usr/bin/env bash
# GENERIC-A: libsndfile 1.2.2 소스 준비 (third_party/ 는 커밋하지 않는다)
# =====================================================================
#
# 범용 대상 libsndfile 은 score-baselibs 와 같은 원칙으로 다룬다. 업스트림 소스는
# 저장소에 넣지 않고(.gitignore 의 third_party/), 고정 커밋으로 받아 오는 이 스크립트만
# 둔다. 경로·configure 인자는 targets/libsndfile.json 을 그대로 읽으므로 프로필과
# 어긋나지 않는다.
#
#   bash scripts/fetch_libsndfile.sh              # clone + checkout + 커밋 확인
#   bash scripts/fetch_libsndfile.sh --configure  # + 프로필 configure_args 로 cmake
#   bash scripts/fetch_libsndfile.sh --build      # + sndfile 타깃 빌드(libsndfile.a)
#
# 저장소 루트에서 실행한다(프로필의 source_root 가 저장소 루트 기준이다).
# 리눅스/WSL 전용. 필요한 것: git, python3, (configure/build 시) cmake, clang, ninja 또는 make.
set -euo pipefail

PROFILE="targets/libsndfile.json"
COMMIT="72f6af15e8f85157bd622ed45b979025828b7001"   # libsndfile 1.2.2
REPO_URL="https://github.com/libsndfile/libsndfile"

STAGE="fetch"
case "${1:-}" in
  "") ;;
  --configure) STAGE="configure" ;;
  --build) STAGE="build" ;;
  *) echo "usage: $0 [--configure|--build]" >&2; exit 2 ;;
esac

[ -f "$PROFILE" ] || { echo "[ERROR] $PROFILE 이 없다. 저장소 루트에서 실행한다." >&2; exit 1; }

read_profile() {
  python3 - "$PROFILE" "$1" <<'PY'
import json, sys
build = json.load(open(sys.argv[1], encoding="utf-8"))["build"]
value = build[sys.argv[2]]
print("\n".join(value) if isinstance(value, list) else value)
PY
}

SRC="$(read_profile source_root)"
BUILD_DIR="$SRC/$(read_profile build_dir)"

if [ -d "$SRC/.git" ]; then
  echo "== 기존 체크아웃 사용: $SRC"
else
  mkdir -p "$(dirname "$SRC")"
  git clone --quiet "$REPO_URL" "$SRC"
fi
git -C "$SRC" checkout --quiet "$COMMIT"
HEAD="$(git -C "$SRC" rev-parse HEAD)"
[ "$HEAD" = "$COMMIT" ] || { echo "[ERROR] HEAD=$HEAD (기대 $COMMIT)" >&2; exit 1; }
echo "HEAD=$HEAD ($(git -C "$SRC" describe --tags 2>/dev/null || echo '?'))"

[ "$STAGE" = "fetch" ] && exit 0

mapfile -t ARGS < <(read_profile configure_args)
GEN=()
if command -v ninja >/dev/null 2>&1; then GEN=(-G Ninja); fi
echo "== configure: ${GEN[*]:-(기본 생성기)} ${ARGS[*]}"
CC="${CC:-clang}" CXX="${CXX:-clang++}" cmake -S "$SRC" -B "$BUILD_DIR" "${GEN[@]}" "${ARGS[@]}"
ls -l "$BUILD_DIR/compile_commands.json"

[ "$STAGE" = "configure" ] && exit 0

cmake --build "$BUILD_DIR" --target sndfile -j"$(nproc)"
while IFS= read -r lib; do ls -l "$SRC/$lib"; done < <(read_profile libraries)
