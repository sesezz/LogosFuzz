/*
 * proto_parser 수동 하네스 (GENERIC-C 임베디드 샘플 E2E 용)
 *
 * 사람이 작성한 하네스. 자동 생성 성공 집계에서 제외
 * proto_create 의 NULL 반환 확인 후 반환 코드 계약대로 proto_parse 호출
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
