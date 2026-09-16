#!/usr/bin/env bash
set -euo pipefail

mkdir -p build
cd build
cat > sample.c <<'EOF'
#include <stdio.h>
int main(void) {
    printf("hello\n");
    return 0;
}
EOF

gcc -c sample.c -o sample.o
