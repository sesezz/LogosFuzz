#include <stdio.h>
#include "mylib.h"

int add(int a, int b) {
    return a + b;
}

static void helper(void) {
    printf("helper\n");
}

int main(void) {
    helper();
    printf("%d\n", add(1,2));
    return 0;
}
