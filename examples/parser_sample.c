/* EXT-01-02 예제: 제약조건 추출기가 무엇을 뽑아내는지 보여주는 샘플.
 *
 * python -m src.rag_constraints build --paths examples --output build/kb.json
 * python -m src.rag_constraints context --kb build/kb.json --function parse_header
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_HEADER 256

struct header {
    char name[64];
    int  value;
};

/**
 * 입력 버퍼에서 헤더 하나를 파싱한다.
 *
 * @param buf 파싱할 입력 버퍼. NULL이면 안 된다.
 * @param len buf의 바이트 길이.
 * @param out 결과를 담을 구조체.
 * The caller must free the returned copy with free().
 */
int parse_header(const char *buf, size_t len, struct header *out)
{
    if (!buf || out == NULL) {
        return -1;
    }
    if (len == 0 || len > MAX_HEADER) {
        return -1;
    }

    assert(len <= MAX_HEADER);

    const char *sep = memchr(buf, ':', len);
    if (sep == NULL) {
        return -1;
    }

    size_t name_len = (size_t)(sep - buf);
    if (name_len >= sizeof(out->name)) {
        return -1;
    }

    memcpy(out->name, buf, name_len);
    out->name[name_len] = '\0';
    out->value = atoi(sep + 1);
    return 0;
}

/* 읽어들인 파일 내용을 새 버퍼에 담아 돌려준다. 호출자가 free() 해야 한다. */
char *read_all(const char *path, size_t *out_len)
{
    if (path == NULL) {
        return NULL;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }

    char *data = malloc(MAX_HEADER);
    if (data == NULL) {
        fclose(fp);
        return NULL;
    }

    size_t got = fread(data, 1, MAX_HEADER, fp);
    fclose(fp);
    if (out_len) {
        *out_len = got;
    }
    return data;
}

// 이름을 대상 버퍼에 복사한다. dst는 최소 64바이트여야 한다.
void copy_name(char *dst, const struct header *src)
{
    strcpy(dst, src->name);
}

int main(void)
{
    struct header header;
    const char *line = "content-length:42";

    if (parse_header(line, strlen(line), &header) != 0) {
        return 1;
    }
    printf("%s = %d\n", header.name, header.value);
    return 0;
}
