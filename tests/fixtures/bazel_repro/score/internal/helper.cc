#include "score/internal/helper.h"

namespace score {
namespace internal {

uint32_t Checksum(const uint8_t* data, size_t size) {
  uint32_t sum = 2166136261u;
  for (size_t i = 0; i < size; ++i) {
    sum ^= data[i];
    sum *= 16777619u;
  }
  return sum;
}

}  // namespace internal
}  // namespace score
