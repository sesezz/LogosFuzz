// 첫 바이트로 경로를 고른다.
//   0: 하네스가 ParseLength 결과를 has_value() 없이 value() 로 꺼낸다(하네스의 계약 위반)
//   1: 공개 API PayloadEnd 를 정상 호출한다(라이브러리 내부의 계약 위반)
#include "score/demo/length.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size < 1U)
    {
        return 0;
    }
    if (data[0] == 0U)
    {
        const auto length = score::demo::ParseLength(data + 1, size - 1);
        volatile std::uint16_t sink = length.value();
        (void)sink;
        return 0;
    }
    volatile std::size_t end = score::demo::PayloadEnd(data + 1, size - 1);
    (void)end;
    return 0;
}
