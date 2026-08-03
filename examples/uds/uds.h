/* EXT-01-04 예제: 헤더/구현/소비자 코드가 나뉜 다중 파일 구성.
 *
 * 통합 지식베이스가 아래를 함께 잡아내는지 보여준다.
 *   - 심볼 -> 선언 헤더 매핑 (GEN-03-02 자가치유용)
 *   - 호출 순서 (SCH-02-02 call_seq 용)
 *   - 타입 정의 위치 (unknown type name 에러 복구용)
 */
#ifndef UDS_H
#define UDS_H

#include <stddef.h>
#include <stdint.h>

typedef struct uds_ctx {
    int      fd;
    uint8_t  session;
    uint16_t p2_ms;
} uds_ctx_t;

typedef struct uds_response {
    uint8_t  sid;
    uint8_t  data[64];
    size_t   len;
} uds_response_t;

/**
 * CAN 채널을 열고 UDS 컨텍스트를 초기화한다.
 *
 * @param ctx  초기화할 컨텍스트. NULL이면 안 된다.
 * @param path CAN 인터페이스 경로.
 * @return 성공 시 0, 실패 시 음수.
 */
int uds_open(uds_ctx_t *ctx, const char *path);

/**
 * 진단 세션을 시작한다. uds_open() 이후에 호출해야 한다.
 *
 * @param ctx   열린 컨텍스트.
 * @param level 세션 레벨. 1~3 범위여야 한다.
 */
int uds_session_start(uds_ctx_t *ctx, uint8_t level);

/**
 * DID를 읽어 응답 버퍼에 담는다. 활성 세션이 필요하다.
 *
 * @param ctx 활성 세션이 있는 컨텍스트.
 * @param did 조회할 데이터 식별자.
 * @param out 응답을 담을 구조체.
 * @param len out->data 의 크기.
 */
int uds_read_did(uds_ctx_t *ctx, uint16_t did, uds_response_t *out, size_t len);

void uds_close(uds_ctx_t *ctx);

#endif /* UDS_H */
