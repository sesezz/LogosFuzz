#include "score/json/json.h"

#include <cstdlib>
#include <cstring>

namespace score {
namespace json {
namespace {

// 컴파일러가 UB 를 전제로 코드를 접지 못하게 값을 한 번 세탁한다.
volatile int g_sink = 0;

// volatile 이라 최적화가 "항상 nullptr" 이라고 접지 못한다 — 널 역참조를
// 상수 폴딩으로 날려버리지 않고 실제로 UBSan 검사에 걸리게 하려는 것이다.
Header* volatile g_null_header = nullptr;

int32_t ReadI32(const uint8_t* data, size_t size, size_t offset) {
  int32_t v = 0;
  if (offset + sizeof(v) <= size) {
    std::memcpy(&v, data + offset, sizeof(v));
  }
  return v;
}

}  // namespace

int Dispatch(const uint8_t* data, size_t size) {
  if (size < 2) {
    return 0;
  }
  const Case selector = static_cast<Case>(data[0] % static_cast<uint8_t>(Case::kMaxCase));
  const int32_t arg = ReadI32(data, size, 1);

  switch (selector) {
    case Case::kSignedOverflow: {
      // signed integer overflow: 2147483647 + arg cannot be represented in 'int'
      int32_t acc = 2147483647;
      acc += (arg | 1);
      g_sink = acc;
      return acc;
    }

    case Case::kShiftExponent: {
      // shift exponent >= 32 is undefined for int
      const int shift = 32 + (arg & 0x7);
      int32_t v = 1;
      v <<= shift;
      g_sink = v;
      return v;
    }

    case Case::kNullDeref: {
      // member access within null pointer of type 'score::json::Header'
      Header* header = g_null_header;
      g_sink = static_cast<int>(header->length);
      return g_sink;
    }

    case Case::kDivideByZero: {
      const int32_t divisor = arg - arg;  // 런타임에 0, 컴파일 타임엔 미지
      const int32_t result = 4096 / divisor;
      g_sink = result;
      return result;
    }

    case Case::kArrayBounds: {
      int table[8] = {0, 1, 2, 3, 4, 5, 6, 7};
      const int index = 8 + (arg & 0x3);  // index 8..11 out of bounds for type 'int[8]'
      g_sink = table[index];
      return g_sink;
    }

    case Case::kMisalignedLoad: {
      // misaligned address ... for type 'const uint32_t', which requires 4 byte alignment
      alignas(4) uint8_t raw[16] = {0};
      std::memcpy(raw, data, size < sizeof(raw) ? size : sizeof(raw));
      const uint32_t* misaligned =
          reinterpret_cast<const uint32_t*>(raw + 1 + (arg & 0x1));
      g_sink = static_cast<int>(*misaligned);
      return g_sink;
    }

    case Case::kFloatCastOverflow: {
      // 1e+30 is outside the range of representable values of type 'int'
      const double huge = 1e30 + static_cast<double>(arg);
      const int narrowed = static_cast<int>(huge);
      g_sink = narrowed;
      return narrowed;
    }

    case Case::kInvalidBool: {
      // load of value 200, which is not a valid value for type 'bool'
      uint8_t raw = static_cast<uint8_t>(0xC8 | (arg & 0x1));
      bool flag = false;
      std::memcpy(&flag, &raw, sizeof(flag));
      g_sink = flag ? 1 : 0;
      return g_sink;
    }

    case Case::kHeapOverflow: {
      // ASan heap-buffer-overflow READ 1 — UBSan 이 아니라 ASan 이 잡는 경로다.
      uint8_t* buffer = static_cast<uint8_t*>(std::malloc(16));
      if (buffer == nullptr) {
        return 0;
      }
      std::memset(buffer, 0, 16);
      g_sink = buffer[16 + (arg & 0x7)];
      std::free(buffer);
      return g_sink;
    }

    case Case::kMemoryLeak: {
      // LSan: 해제하지 않고 포인터를 버린다(프로세스 종료 시 보고).
      uint8_t* leaked = static_cast<uint8_t*>(std::malloc(64));
      if (leaked == nullptr) {
        return 0;
      }
      std::memset(leaked, arg & 0xFF, 64);
      g_sink = leaked[0];
      return g_sink;
    }

    case Case::kClean:
    case Case::kMaxCase:
    default:
      g_sink = arg;
      return 0;
  }
}

}  // namespace json
}  // namespace score
