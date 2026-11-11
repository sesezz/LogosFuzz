/*
 * 간단한 시리얼 프레임 파서 (GENERIC-C 임베디드 샘플)
 *
 * 프레임 형식:
 *   [0]      SYNC (0xA5)
 *   [1]      type
 *   [2]      len  (payload 길이)
 *   [3..]    payload (len 바이트)
 *   [3+len]  checksum (payload 바이트 합의 하위 8비트)
 *
 * 오류는 음수 반환 코드(C return code 계약)로 통지. proto_create 는 잘못된
 * 용량이면 NULL 반환 → 호출자 확인 필수
 */
#ifndef LOGOSFUZZ_EXAMPLE_PROTO_PARSER_H
#define LOGOSFUZZ_EXAMPLE_PROTO_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define PROTO_SYNC 0xA5u
#define PROTO_MAX_CAPACITY 64u

enum {
    PROTO_OK = 0,
    PROTO_ERR_ARG = -1,
    PROTO_ERR_SHORT = -2,
    PROTO_ERR_SYNC = -3,
    PROTO_ERR_CHECKSUM = -4
};

typedef struct proto_ctx {
    size_t capacity;      /* payload 버퍼 용량 */
    size_t payload_len;   /* 마지막으로 받은 payload 길이 */
    uint8_t type;         /* 마지막 프레임 type */
    uint32_t last_tick;   /* 마지막 수신 시각(HAL_GetTick) */
    uint8_t *payload;     /* capacity 바이트 */
} proto_ctx_t;

/* capacity 가 0 이거나 PROTO_MAX_CAPACITY 보다 크면 NULL */
proto_ctx_t *proto_create(size_t capacity);

/* 프레임 1개 파싱. 성공 시 PROTO_OK, 실패 시 음수 코드 */
int proto_parse(proto_ctx_t *ctx, const uint8_t *frame, size_t size);

/* 마지막 payload. 없으면 NULL */
const uint8_t *proto_payload(const proto_ctx_t *ctx, size_t *len);

void proto_destroy(proto_ctx_t *ctx);

#endif /* LOGOSFUZZ_EXAMPLE_PROTO_PARSER_H */
