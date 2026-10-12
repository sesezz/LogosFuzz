#include "score/demo/length.h"

namespace score::demo
{
namespace
{
class LengthErrorDomain final : public score::result::ErrorDomain
{
  public:
    std::string_view MessageFor(const score::result::ErrorCode&) const noexcept override
    {
        return "length field too short";
    }
};
constexpr LengthErrorDomain kLengthErrorDomain;
}  // namespace

score::result::Error MakeError(LengthErrc code, std::string_view message) noexcept
{
    return {static_cast<score::result::ErrorCode>(code), kLengthErrorDomain, message};
}

score::Result<std::uint16_t> ParseLength(const std::uint8_t* data, std::size_t size) noexcept
{
    if (size < 2U)
    {
        return score::MakeUnexpected(LengthErrc::kTooShort, "need 2 bytes");
    }
    return static_cast<std::uint16_t>(data[0] | (data[1] << 8U));
}

std::size_t PayloadEnd(const std::uint8_t* data, std::size_t size) noexcept
{
    const auto length = ParseLength(data, size);
    return 2U + *length;
}

}  // namespace score::demo
