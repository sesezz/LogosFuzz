# 자동차(Bazel) 모드 골든 — CTR-06-01 범용화 회귀 가드

컨트롤러 범용화(빌드시스템 하드코딩 제거, `--mode generic` 추가) 전후로 **기존
`--mode bazel`(S-CORE/baselibs) 경로의 동작이 바뀌지 않았는지** 확인하기 위한
골든 산출물이다. `exp-freeze` 태그 시점의 기준값.

## 골든 범위
- 대상: `//score/json:json` (automotive, S-CORE baselibs)
- 실행: `--mode bazel ... --emit-only` (BUILD/.cc 생성까지. Bazel 실제 빌드·LLM
  은 제외 — 이 골든은 **빌드시스템 플럼빙**(build_system 필드, 어댑터 유래값,
  생성 BUILD 내용)의 회귀를 잡는다. 전체 빌드/바이너리 회귀는 범위 밖.)
- 파일:
  - `build_summary.golden.json` — build_summary (started_at/finished_at·rounds 제외 정규화)
  - `BUILD.bazel.golden` — 생성된 BUILD.bazel

## 검증 결과 (2026-10-10)
리팩터 전(dev) vs 후(feature/CTR-06-01-generic-mode) 동일 입력 실행 결과
**build_summary·BUILD 모두 완전 일치** → bazel 경로 동작 보존 확인.

## 재생성/비교 방법
```bash
printf 'extern "C" int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long n){return 0;}\n' > /tmp/h.cc
python3 -m logosfuzz.control.ctr_06_01_controller --mode bazel \
  --workspace ~/baselibs --harness /tmp/h.cc --build-target //score/json:json \
  --group ar_probe --emit-only --skip-check --build-summary /tmp/after.json
# /tmp/after.json 에서 started_at/finished_at/units[].rounds 를 뺀 뒤
# build_summary.golden.json 과, ~/baselibs/score/json/fuzz/ar_probe/BUILD.bazel 를
# BUILD.bazel.golden 과 비교한다. 차이가 없어야 회귀 없음.
```
