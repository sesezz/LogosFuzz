"""GEN-03 컴파일러 어댑터 위임 단위 테스트.

`-fsanitize=` 플래그를 어댑터(BuildAdapter)에 위임할 수 있게 만든 훅이,
기본값(어댑터 없음)에서는 기존 동작을 그대로 유지하는지, 그리고 어댑터를
넘기면 실제로 그쪽 결과가 쓰이는지를 확인한다. B의 BuildAdapter 자체는
아직 저장소에 없으므로(2026-09-17 기준), 여기서는 그 인터페이스 계약
(``link_fuzzer: bool -> list[str]``)만 만족하는 콜백으로 대체해 검증한다.
"""

from logosfuzz.generate.compiler import SubprocessCompiler
from logosfuzz.generate.models import HarnessDraft


def _draft(language="c"):
    return HarnessDraft(logic_group="grpA", source="int main(){return 0;}",
                        language=language)


# --- 기본값(어댑터 미지정)은 기존 동작과 동일해야 한다 ---------------------
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
    assert "-c" not in argv  # 링크까지 하므로 오브젝트 전용 플래그는 없어야 함


def test_empty_sanitizers_emits_no_flag():
    c = SubprocessCompiler(sanitizers="")
    argv = c._build_argv(src_path=__import__("pathlib").Path("a.c"),
                         out_path=__import__("pathlib").Path("a.out"))
    assert not any(a.startswith("-fsanitize=") for a in argv)


# --- 어댑터(콜백)를 넘기면 그 결과가 그대로 쓰인다 --------------------------
def test_sanitize_flags_provider_overrides_default():
    calls = []

    def fake_adapter(link_fuzzer: bool):
        calls.append(link_fuzzer)
        return ["-fsanitize=undefined", "-fno-sanitize-recover=undefined"]

    c = SubprocessCompiler(sanitizers="address",  # 제공자가 있으면 무시돼야 함
                           sanitize_flags_provider=fake_adapter)
    argv = c._build_argv(src_path=__import__("pathlib").Path("a.c"),
                         out_path=__import__("pathlib").Path("a.out"))
    assert "-fsanitize=undefined" in argv
    assert "-fsanitize=address" not in argv
    assert calls == [False]  # link_fuzzer 기본값이 그대로 전달됐는지


def test_sanitize_flags_provider_receives_link_fuzzer_flag():
    seen = []
    c = SubprocessCompiler(link_fuzzer=True,
                           sanitize_flags_provider=lambda lf: seen.append(lf) or [])
    c._build_argv(src_path=__import__("pathlib").Path("a.c"),
                 out_path=__import__("pathlib").Path("a.out"))
    assert seen == [True]
