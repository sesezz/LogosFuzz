"""GEN-03 컴파일러 `-fsanitize=` 플래그 위임 훅 단위 테스트

기본값 동작 유지 및 콜백(``link_fuzzer: bool -> list[str]``) 결과 사용 확인
"""

from logosfuzz.generate.compiler import SubprocessCompiler
from logosfuzz.generate.models import HarnessDraft


def _draft(language="c"):
    return HarnessDraft(logic_group="grpA", source="int main(){return 0;}",
                        language=language)


# --- 기본값(어댑터 미지정): 기존 동작 유지 ----------------------------------
def test_default_sanitize_flags_unchanged_compile_only():
    c = SubprocessCompiler(sanitizers="address")
    argv = c._build_argv(src_path=__import__("pathlib").Path("a.c"),
                         out_path=__import__("pathlib").Path("a.out"),
                         language="c")
    assert "-fsanitize=address" in argv
    assert "-c" in argv  # link_fuzzer=False 기본값


def test_default_sanitize_flags_unchanged_link_fuzzer():
    c = SubprocessCompiler(sanitizers="address", link_fuzzer=True)
    argv = c._build_argv(src_path=__import__("pathlib").Path("a.c"),
                         out_path=__import__("pathlib").Path("a.out"),
                         language="c")
    assert "-fsanitize=fuzzer,address" in argv
    assert "-c" not in argv  # 링크 포함이므로 오브젝트 전용 플래그 없음


def test_empty_sanitizers_emits_no_flag():
    c = SubprocessCompiler(sanitizers="")
    argv = c._build_argv(src_path=__import__("pathlib").Path("a.c"),
                         out_path=__import__("pathlib").Path("a.out"))
    assert not any(a.startswith("-fsanitize=") for a in argv)


# --- 어댑터(콜백) 지정: 콜백 결과 사용 --------------------------------------
def test_sanitize_flags_provider_overrides_default():
    calls = []

    def fake_adapter(link_fuzzer: bool):
        calls.append(link_fuzzer)
        return ["-fsanitize=undefined", "-fno-sanitize-recover=undefined"]

    c = SubprocessCompiler(sanitizers="address",  # 제공자 존재 시 무시
                           sanitize_flags_provider=fake_adapter)
    argv = c._build_argv(src_path=__import__("pathlib").Path("a.c"),
                         out_path=__import__("pathlib").Path("a.out"))
    assert "-fsanitize=undefined" in argv
    assert "-fsanitize=address" not in argv
    assert calls == [False]  # link_fuzzer 기본값 전달 여부


def test_sanitize_flags_provider_receives_link_fuzzer_flag():
    seen = []
    c = SubprocessCompiler(link_fuzzer=True,
                           sanitize_flags_provider=lambda lf: seen.append(lf) or [])
    c._build_argv(src_path=__import__("pathlib").Path("a.c"),
                 out_path=__import__("pathlib").Path("a.out"))
    assert seen == [True]
