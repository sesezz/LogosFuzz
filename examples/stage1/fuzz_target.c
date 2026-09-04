#include <stdint.h>
#include <stddef.h>
#include <string.h>

static void vulnerable(const uint8_t *data, size_t size)
{
    char buffer[8];

    if (size >= 4 &&
        data[0] == 'F' &&
        data[1] == 'U' &&
        data[2] == 'Z' &&
        data[3] == 'Z') {

        if (size > 8) {
            memcpy(buffer, data, size);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    vulnerable(data, size);
    return 0;
}

