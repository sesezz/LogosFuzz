#include <stdlib.h>

int main(void)
{
    int *p = malloc(sizeof(int));
    free(p);
    *p = 42;
    return *p;
}
