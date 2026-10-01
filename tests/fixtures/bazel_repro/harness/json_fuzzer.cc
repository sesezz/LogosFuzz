// //harness:json_fuzzer — B(송서원)의 build_file_generator.py 가 만들어 낼
// cc_fuzz_test 자리의 최소 재현. libFuzzer 진입점만 있으면 충분하다.

#include <cstddef>
#include <cstdint>

#include "score/json/json.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  score::json::Dispatch(data, size);
  return 0;
}
