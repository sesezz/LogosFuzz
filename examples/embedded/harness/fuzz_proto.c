/*
 * proto_parser 수동 하네스 (GENERIC-C 임베디드 샘플 E2E 용).
 *
 * 사람이 작성한 하네스다. 자동 생성 성공으로 세지 않는다.
 * proto_create 의 NULL 반환을 확인하고, 반환 코드 계약대로 proto_parse 를 부른다.
 */
#include <stddef.h>
#include <stdint.h>

#include "proto_parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    proto_ctx_t *ctx = proto_create(32);
    if (ctx == NULL) {
        return 0;
    }
    if (proto_parse(ctx, data, size) == PROTO_OK) {
        size_t len = 0;
        const uint8_t *payload = proto_payload(ctx, &len);
        (void)payload;
    }
    proto_destroy(ctx);
    return 0;
}
