#include <cstddef>
#include <cstdint>

#include "score/json/json.h"

namespace score {
namespace json {
// 헤더에도 없고 어디에도 정의가 없다 -> 링크 단계 undefined reference
int ParseStrict(const uint8_t* data, size_t size);
}  // namespace json
}  // namespace score

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  score::json::Dispatch(data, size);
  return score::json::ParseStrict(data, size);
}
