// GEN-03-02 코퍼스 수집용 대상 라이브러리(최소 재현).
//
// data[0] 을 선택자로 써서 UB/메모리 오류 종류를 하나씩 고른다. 실제 결함을
// 흉내내는 게 목적이므로 모든 값은 퍼즈 입력에서 런타임에 들어온다 — 상수로
// 두면 컴파일러가 UB 를 전제로 코드를 통째로 접어버려 진단이 안 나온다.

#ifndef SCORE_JSON_JSON_H_
#define SCORE_JSON_JSON_H_

#include <cstddef>
#include <cstdint>

namespace score {
namespace json {

enum class Case : uint8_t {
  kSignedOverflow = 0,     // UBSan: signed integer overflow
  kShiftExponent = 1,      // UBSan: shift exponent too large
  kNullDeref = 2,          // UBSan: member access within null pointer
  kDivideByZero = 3,       // UBSan: division by zero
  kArrayBounds = 4,        // UBSan: index out of bounds
  kMisalignedLoad = 5,     // UBSan: misaligned address
  kFloatCastOverflow = 6,  // UBSan: outside the range of representable values
  kInvalidBool = 7,        // UBSan: load of value which is not valid for bool
  kHeapOverflow = 8,       // ASan:  heap-buffer-overflow
  kMemoryLeak = 9,         // LSan:  detected memory leaks
  kClean = 10,             // 진단 없음(정상 경로 대조군)
  kMaxCase = 11,
};

// 길이 필드를 캡핑하지 않고 그대로 믿는 구조체 — 소비 측과의 비대칭을 만든다.
struct Header {
  uint32_t magic;
  uint32_t length;
};

// 선택자에 따라 해당 결함 경로를 실행한다. 반환값은 최적화 방지용이다.
int Dispatch(const uint8_t* data, size_t size);

}  // namespace json
}  // namespace score

#endif  // SCORE_JSON_JSON_H_
