#include <cstddef>
#include <cstdint>

#include "score/internal/helper.h"  // deps 에 //score/internal:helper 가 없다
#include "score/json/json.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  score::json::Dispatch(data, size);
  return static_cast<int>(score::internal::Checksum(data, size) & 0u);
}
