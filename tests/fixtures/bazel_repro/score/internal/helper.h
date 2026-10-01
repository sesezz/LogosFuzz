// //score/internal 은 //score/json 에만 공개된 내부 헬퍼다.
// 하네스가 이걸 직접 deps 에 넣으면 visibility 에러가, deps 없이 include 만 하면
// strict deps(undeclared inclusion) 에러가 난다 — 두 에러 원문 수집용이다.

#ifndef SCORE_INTERNAL_HELPER_H_
#define SCORE_INTERNAL_HELPER_H_

#include <cstddef>
#include <cstdint>

namespace score {
namespace internal {

uint32_t Checksum(const uint8_t* data, size_t size);

}  // namespace internal
}  // namespace score

#endif  // SCORE_INTERNAL_HELPER_H_
