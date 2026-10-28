/*
 * 간단한 시리얼 프레임 파서 구현 (GENERIC-C 임베디드 샘플)
 *
 * 의도적 결함 1건: proto_parse 가 프레임 길이 필드(len)를 그대로 믿고
 * ctx->payload(capacity 바이트)에 복사. 입력 버퍼 길이는 확인하지만
 * capacity 와는 미비교 → len > capacity 프레임에서 힙 버퍼 오버플로
 * 체크섬 검사도 복사 이후라 체크섬이 틀린 프레임으로도 재현
 */
#include "proto_parser.h"

#include <stdlib.h>
#include <string.h>

#include "hal.h"

/* 응답 전송용 UART 핸들. 호스트 빌드에서는 실제 장치 없음 */
static UART_HandleTypeDef *g_uart = NULL;

proto_ctx_t *proto_create(size_t capacity)
{
    if (capacity == 0 || capacity > PROTO_MAX_CAPACITY) {
        return NULL;
    }
    proto_ctx_t *ctx = (proto_ctx_t *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->payload = (uint8_t *)malloc(capacity);
    if (ctx->payload == NULL) {
        free(ctx);
        return NULL;
    }
    ctx->capacity = capacity;
    return ctx;
}

static uint8_t checksum(const uint8_t *data, size_t len)
{
    uint8_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum = (uint8_t)(sum + data[i]);
    }
    return sum;
}

int proto_parse(proto_ctx_t *ctx, const uint8_t *frame, size_t size)
{
    /* 주의: ctx 의 NULL 여부는 미확인(문서상 호출자 책임) */
    ctx->last_tick = HAL_GetTick();

    if (frame == NULL || size < 4) {
        return PROTO_ERR_SHORT;
    }
    if (frame[0] != PROTO_SYNC) {
        return PROTO_ERR_SYNC;
    }

    uint8_t len = frame[2];
    if (size < (size_t)len + 4) {
        return PROTO_ERR_SHORT;
    }

    /* 결함: len 과 ctx->capacity 미비교 */
    memcpy(ctx->payload, &frame[3], len);
    ctx->payload_len = len;
    ctx->type = frame[1];

    if (checksum(ctx->payload, len) != frame[3 + len]) {
        return PROTO_ERR_CHECKSUM;
    }

    static const uint8_t ack[2] = {PROTO_SYNC, 0x06};
    (void)HAL_UART_Transmit(g_uart, ack, sizeof(ack), 10);
    return PROTO_OK;
}

const uint8_t *proto_payload(const proto_ctx_t *ctx, size_t *len)
{
    if (ctx == NULL || ctx->payload_len == 0) {
        if (len != NULL) {
            *len = 0;
        }
        return NULL;
    }
    if (len != NULL) {
        *len = ctx->payload_len;
    }
    return ctx->payload;
}

void proto_destroy(proto_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    free(ctx->payload);
    free(ctx);
}
