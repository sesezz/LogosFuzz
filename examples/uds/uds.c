#include "uds.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UDS_MAX_LEVEL 3
#define UDS_SID_READ  0x22

int uds_open(uds_ctx_t *ctx, const char *path)
{
    if (ctx == NULL || path == NULL) {
        return -1;
    }

    ctx->fd = open(path, 0);
    if (ctx->fd < 0) {
        return -1;
    }

    ctx->session = 0;
    ctx->p2_ms = 50;
    return 0;
}

int uds_session_start(uds_ctx_t *ctx, uint8_t level)
{
    if (!ctx) {
        return -1;
    }
    if (level == 0 || level > UDS_MAX_LEVEL) {
        return -1;
    }

    assert(ctx->fd >= 0);

    ctx->session = level;
    return 0;
}

int uds_read_did(uds_ctx_t *ctx, uint16_t did, uds_response_t *out, size_t len)
{
    if (ctx == NULL || out == NULL) {
        return -1;
    }
    if (ctx->session == 0) {
        return -1;
    }
    if (len == 0 || len > sizeof(out->data)) {
        return -1;
    }

    uint8_t *frame = malloc(len);
    if (frame == NULL) {
        return -1;
    }

    frame[0] = UDS_SID_READ;
    memcpy(out->data, frame, len);
    out->sid = UDS_SID_READ;
    out->len = len;
    free(frame);
    return 0;
}

void uds_close(uds_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    close(ctx->fd);
    ctx->fd = -1;
}
