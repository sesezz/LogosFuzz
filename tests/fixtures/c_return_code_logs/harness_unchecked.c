#include <stddef.h>
#include <stdint.h>
#include "proto_parser.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    proto_ctx_t *ctx = proto_create(data[0]);   /* NULL 반환 미검사 */
    proto_parse(ctx, data + 1, size - 1);
    proto_destroy(ctx);
    return 0;
}
