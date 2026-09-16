// rules_fuzzing 배선 검증용 퍼징 대상.
//
// 목적: baselibs 오버레이 작업에 들어가기 전에 "rules_fuzzing 0.8.0 이
// Bazel 8.6 에서 실제로 libFuzzer 를 돌리는가" 만 독립적으로 확인한다.
// baselibs 의 registry/lockfile/툴체인과 무관하게 수 분 안에 끝나야 한다.
//
// 이 probe 가 크래시를 찾아내면 다음이 한꺼번에 증명된다:
//   1. rules_fuzzing 0.8.0 모듈 해상도 정상 (Bazel 8.6)
//   2. clang + libFuzzer 링크 정상
//   3. cc_engine_instrumentation=libfuzzer 가 실제로 커버리지를 주입함
//   4. ASan 이 결함을 잡음
//
// "실행은 되는데 크래시를 못 찾는다" 면 3번이 안 된 것이다. 그 경우
// .bazelrc 배선을 의심해야지 하네스를 의심하면 안 된다.
//
// --- 아래 코드가 이렇게 생긴 이유 (전부 실측으로 걸러낸 함정이다) ---
//
// (a) 매직 4바이트를 한 바이트씩 비교한다
//     무작위로 "BOOM" 을 맞출 확률은 1/2^32 이다. 커버리지 피드백이 있어야만
//     한 글자씩 전진해서 도달할 수 있다. 즉 계측이 죽어 있으면 절대 못 찾는다.
//     -> 이게 이 probe 가 3번을 검증하는 방식이다.
//
// (b) 비교 사이에 volatile 기록(g_sink)을 끼운다
//     없으면 clang 이 -O1 이상에서 네 번의 비교를 32비트 비교 하나로 합친다.
//     실측: 카운터가 7개에서 1개로 줄고, 200만 회를 돌려도 못 찾았다.
//
// (c) 버퍼를 읽어서 g_sink 에 넣는다
//     없으면 malloc/memcpy/free 체인 전체가 -O1 이상에서 죽은 코드로 제거된다.
//     실측: "BOOM" 을 직접 먹여도 크래시가 나지 않았다.
//
// (d) 오버플로가 입력 길이에 의존하지 않는다 (off-by-one 고정)
//     "size > 4 일 때만 터진다" 로 만들었더니, 입력을 늘려도 커버리지가 늘지
//     않아 libFuzzer 가 4바이트에서 멈췄다. 실측: cov 7/7 에 도달하고도
//     3,200만 회 동안 크래시 0건.
//
// 검증 결과 (clang 18.1.3, -fsanitize=fuzzer,address):
//     -O0 약 49,000회 / -O1 약 23,000회 / -O2 약 82,000회 에 발견. 전부 수 초.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace {
volatile int g_sink = 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 4) {
    return 0;
  }

  if (data[0] != 'B') return 0;
  g_sink = 1;
  if (data[1] != 'O') return 0;
  g_sink = 2;
  if (data[2] != 'O') return 0;
  g_sink = 3;
  if (data[3] != 'M') return 0;
  g_sink = 4;

  char* buffer = static_cast<char*>(std::malloc(size));
  std::memcpy(buffer, data, size);
  buffer[size] = '\0';          // off-by-one heap-buffer-overflow
  g_sink = buffer[size - 1];    // 결과 관찰 -> 최적화 제거 방지
  std::free(buffer);
  return 0;
}
