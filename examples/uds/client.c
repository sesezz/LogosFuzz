/* 소비자 코드. SCH-02-02 의 call_seq("실제 API 호출 순서")는 이런 코드에서
 * 관찰된 호출 순서로 만들어진다. */
#include "uds.h"

#include <stdio.h>

int read_vin(const char *path, uds_response_t *out)
{
    uds_ctx_t ctx;

    if (uds_open(&ctx, path) != 0) {
        return -1;
    }
    if (uds_session_start(&ctx, 1) != 0) {
        uds_close(&ctx);
        return -1;
    }
    if (uds_read_did(&ctx, 0xF190, out, sizeof(out->data)) != 0) {
        uds_close(&ctx);
        return -1;
    }

    uds_close(&ctx);
    return 0;
}

int main(void)
{
    uds_response_t response;

    if (read_vin("/dev/can0", &response) != 0) {
        return 1;
    }
    printf("vin len = %zu\n", response.len);
    return 0;
}
