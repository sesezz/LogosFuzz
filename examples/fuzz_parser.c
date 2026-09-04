#include <stdint.h>
#include <stddef.h>

/*
 * parser_sample.c의 main()과 충돌하지 않도록
 * main 이름을 변경한 뒤 소스 전체를 포함한다.
 */
#define main parser_sample_main
#include "parser_sample.c"
#undef main

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct header out;

    parse_header((const char *)data, size, &out);

    return 0;
}