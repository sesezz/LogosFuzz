/*
 * LogosFuzz 파이프라인 검증용 의도적 취약 ASan 스모크 테스트 대상 (CLI 진입점)
 * 취약 함수 copy_can_label 은 can_label.c (logosfuzz run 대상 라이브러리와 공용)
 * 15바이트 초과 입력 시 ASan stack-buffer-overflow 보고 발생
 */
#include <stdio.h>

#include "can_label.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <CAN-label>\n", argv[0]);
        return 2;
    }
    return copy_can_label(argv[1]);
}
