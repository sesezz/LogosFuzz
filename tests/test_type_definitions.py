"""프롬프트에 넣는 헤더 타입 정의 발췌 (GENERIC-B, libsndfile E2E 실측 기반)."""
from __future__ import annotations

from logosfuzz.generate.gen_03_01_harness_generator import type_definitions_excerpt

HEADER = """\
#ifndef LIB_H
#define LIB_H
typedef long long lib_count_t ;
typedef lib_count_t (*lib_vio_len) (void *user) ;
typedef lib_count_t (*lib_vio_read) (void *ptr, lib_count_t count, void *user) ;
struct LIB_IO
{	lib_vio_len  get_len ;
	lib_vio_read read ;
} ;
typedef struct LIB_IO LIB_IO ;
struct LIB_INFO
{	lib_count_t frames ;
	int channels ;
} ;
typedef struct LIB_INFO LIB_INFO ;
enum
{	LIB_STR_TITLE = 0x01,
	LIB_STR_ARTIST = 0x04
} ;
enum
{	LIB_MODE_READ = 0x10,
	LIB_MODE_WRITE = 0x20
} ;
enum
{	LIBC_A = 1, LIBC_B, LIBC_C, LIBC_D, LIBC_E, LIBC_F, LIBC_G, LIBC_H,
	LIBC_I, LIBC_J, LIBC_K, LIBC_L, LIBC_M, LIBC_N, LIBC_O, LIBC_P, LIBC_Q
} ;
int lib_open_virtual (LIB_IO *io, int mode, LIB_INFO *info, void *user) ;
int lib_close (void *handle) ;
void lib_free_buffer (void *buf) ;
int lib_read_all (void *handle) ;
const char *lib_get_string (void *handle, int str_type) ;
#endif
"""


def _doc(header, function, params):
    return {"function": function, "file": str(header.with_name("src.c")), "header": str(header),
            "params": [{"name": n, "type": t} for n, t in params]}


def _write(tmp_path):
    header = tmp_path / "lib.h"
    header.write_text(HEADER, encoding="utf-8")
    return header


def test_struct_callback_typedefs_and_related_types_are_included(tmp_path):
    header = _write(tmp_path)
    docs = [_doc(header, "lib_open_virtual",
                 [("io", "LIB_IO *"), ("mode", "int"), ("info", "LIB_INFO *"), ("user", "void *")])]

    text = type_definitions_excerpt(docs)

    assert "struct LIB_IO" in text and "lib_vio_read read ;" in text      # 구조체 필드
    assert "typedef lib_count_t (*lib_vio_read)" in text                  # 콜백 시그니처
    assert text.index("(*lib_vio_read)") < text.index("struct LIB_IO")   # 콜백 typedef 가 먼저
    assert "struct LIB_INFO" in text and "int channels ;" in text


def test_small_enums_give_valid_constants(tmp_path):
    header = _write(tmp_path)
    docs = [_doc(header, "lib_get_string", [("handle", "void *"), ("str_type", "int")]),
            _doc(header, "lib_open_virtual", [("io", "LIB_IO *"), ("mode", "int")])]

    text = type_definitions_excerpt(docs)

    assert "LIB_STR_TITLE" in text                    # str_type 의 유효한 값
    assert "LIB_MODE_READ" in text                    # mode 의 유효한 값
    assert "LIBC_Q" not in text                       # 멤버가 많고 이름 단서가 없는 열거형은 제외


def test_large_enum_is_included_when_the_parameter_name_hints_at_it(tmp_path):
    header = _write(tmp_path)
    docs = [_doc(header, "lib_cmd", [("handle", "void *"), ("libc", "int")])]
    assert "LIBC_Q" in type_definitions_excerpt(docs)


def test_cpp_sources_are_left_to_the_class_excerpt(tmp_path):
    header = _write(tmp_path)
    doc = _doc(header, "lib_open_virtual", [("io", "LIB_IO *")])
    doc["file"] = str(tmp_path / "src.cpp")
    assert type_definitions_excerpt([doc]) == ""


def test_missing_header_gives_empty_text(tmp_path):
    doc = _doc(tmp_path / "nope.h", "f", [("x", "LIB_IO *")])
    assert type_definitions_excerpt([doc]) == ""


def test_output_is_truncated_to_the_limit(tmp_path):
    header = _write(tmp_path)
    docs = [_doc(header, "lib_open_virtual", [("io", "LIB_IO *"), ("info", "LIB_INFO *")])]
    text = type_definitions_excerpt(docs, max_chars=200)
    assert len(text) <= 200 + len("\n// ... (truncated)")
    assert text.endswith("// ... (truncated)")


def test_release_function_declarations_are_listed(tmp_path):
    """실측: 그룹 API 에 sf_close 가 없어서 모델이 해제 호출을 주석 처리해 누수가 반복됨."""
    header = _write(tmp_path)
    docs = [_doc(header, "lib_open_virtual", [("io", "LIB_IO *")])]

    text = type_definitions_excerpt(docs)

    assert "Release functions declared in this header" in text
    assert "int lib_close (void *handle) ;" in text
    assert "void lib_free_buffer (void *buf) ;" in text
    assert "lib_read_all" not in text                  # 해제 함수가 아닌 선언은 제외
