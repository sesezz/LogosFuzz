// libFuzzer 런타임이 없는 환경용 드라이버(LLVM StandaloneFuzzTargetMain 과 같은 역할).
#include <cstdint>
#include <cstdio>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

int main(int argc, char** argv)
{
    for (int i = 1; i < argc; ++i)
    {
        std::FILE* f = std::fopen(argv[i], "rb");
        if (f == nullptr)
        {
            continue;
        }
        std::vector<std::uint8_t> buf;
        int c;
        while ((c = std::fgetc(f)) != EOF)
        {
            buf.push_back(static_cast<std::uint8_t>(c));
        }
        std::fclose(f);
        LLVMFuzzerTestOneInput(buf.data(), buf.size());
    }
    return 0;
}
