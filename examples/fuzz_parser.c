#include <stdint.h>
#include <stddef.h>

/*
 * parser_sample.c의 main()과 충돌 방지를 위해
 * main 이름 변경 후 소스 전체 포함
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