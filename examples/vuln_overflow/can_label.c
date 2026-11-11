/*
 * LogosFuzz 파이프라인 검증용 의도적 취약 대상 (라이브러리 부분)
 * 입력 문자열을 경계 검사 없이 고정 크기 스택 버퍼에 복사
 * 15바이트 초과 입력 시 ASan stack-buffer-overflow 보고 발생
 */
#include <string.h>

#include "can_label.h"

int copy_can_label(const char *label) {
    char can_label[16];

    strcpy(can_label, label); /* 의도적 CWE-121 취약점 */
    return (unsigned char)can_label[0];
}
