// 에러계약 위반 재현용 대상 라이브러리. score::Result 로 오류 대안을 선언한다.
#ifndef LOGOSFUZZ_FIXTURE_SCORE_DEMO_LENGTH_H
#define LOGOSFUZZ_FIXTURE_SCORE_DEMO_LENGTH_H

#include "score/result/result.h"

#include <cstddef>
#include <cstdint>

namespace score::demo
{

enum class LengthErrc : score::result::ErrorCode
{
    kTooShort = 1,
};

score::result::Error MakeError(LengthErrc code, std::string_view message = "") noexcept;

// 2바이트 리틀엔디언 길이 필드. 입력이 짧으면 kTooShort 를 반환한다(에러계약).
score::Result<std::uint16_t> ParseLength(const std::uint8_t* data, std::size_t size) noexcept;

// 라이브러리 내부 소비자. ParseLength 의 오류 대안을 확인하지 않는다(결함).
std::size_t PayloadEnd(const std::uint8_t* data, std::size_t size) noexcept;

}  // namespace score::demo

#endif
