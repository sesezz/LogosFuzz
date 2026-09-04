/*
 * Deliberately vulnerable ASan smoke-test target.
 *
 * This program is only for validating the LogosFuzz pipeline.  It copies a
 * user-controlled string into a fixed-size stack buffer without a bounds
 * check.  An input longer than 15 bytes must produce an ASan
 * stack-buffer-overflow report.
 */
#include <stdio.h>
#include <string.h>

int copy_can_label(const char *label) {
    char can_label[16];

    strcpy(can_label, label); /* Intentional CWE-121 vulnerability. */
    return (unsigned char)can_label[0];
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <CAN-label>\n", argv[0]);
        return 2;
    }
    return copy_can_label(argv[1]);
}
