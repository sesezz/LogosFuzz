/*
 * 최소 HAL 선언 (GENERIC-C 임베디드 샘플)
 *
 * 실제 펌웨어에서는 벤더 HAL(STM32Cube 등)이 정의 제공
 * 호스트 퍼징 빌드에는 정의가 없어 링크 단계에서 미정의 심볼 발생
 * LogosFuzz 가 stub_allowlist(HAL_*) 에 맞는 심볼만 weak 스텁으로 보충
 * 의도적으로 선언만 두고 정의는 생략
 */
#ifndef LOGOSFUZZ_EXAMPLE_HAL_H
#define LOGOSFUZZ_EXAMPLE_HAL_H

#include <stdint.h>

typedef enum {
    HAL_OK = 0,
    HAL_ERROR = 1,
    HAL_BUSY = 2,
    HAL_TIMEOUT = 3
} HAL_StatusTypeDef;

typedef struct UART_HandleTypeDef UART_HandleTypeDef;

HAL_StatusTypeDef HAL_UART_Transmit(UART_HandleTypeDef *huart, const uint8_t *data,
                                    uint16_t size, uint32_t timeout);
uint32_t HAL_GetTick(void);

#endif /* LOGOSFUZZ_EXAMPLE_HAL_H */
