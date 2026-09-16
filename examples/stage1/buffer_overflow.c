#include <stdio.h>
#include <string.h>

void vulnerable_copy(const char *input)
{
    char buffer[8];

    strcpy(buffer, input);

    printf("buffer = %s\n", buffer);
}

int main(void)
{
    vulnerable_copy("AAAAAAAAAAAAAAAA");
    return 0;
}
