/*
 * 의도적 취약 CAN 라벨 복사 함수 선언 (CWE-121 스택 버퍼 오버플로)
 */
#ifndef LOGOSFUZZ_CAN_LABEL_H
#define LOGOSFUZZ_CAN_LABEL_H

/* NUL 종료 문자열 label 을 16바이트 스택 버퍼에 복사 후 첫 바이트 반환 */
int copy_can_label(const char *label);

#endif
