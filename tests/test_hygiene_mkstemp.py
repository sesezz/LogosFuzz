"""mkstemp 접미사 교정 (GENERIC-B, libsndfile 3차 실측: cov 2 로 아무것도 실행하지 않은 하네스)."""
from __future__ import annotations

from logosfuzz.generate.hygiene import fix_mkstemp_suffix, sanitize_harness

BAD = """\
char tmp_filename[] = "/tmp/fuzz_test_XXXXXX.wav";
int fd = mkstemp(tmp_filename);
if (fd == -1) return 0;
"""


def test_suffix_template_uses_mkstemps_with_the_suffix_length():
    fixed = fix_mkstemp_suffix(BAD)
    assert "mkstemps(tmp_filename, 4)" in fixed            # ".wav" 는 4글자
    assert "mkstemp(" not in fixed.replace("mkstemps(", "")


def test_plain_template_is_untouched():
    good = 'char t[] = "/tmp/fuzz_XXXXXX";\nint fd = mkstemp(t);\n'
    assert fix_mkstemp_suffix(good) == good


def test_other_names_are_not_rewritten():
    source = BAD + 'char other[] = "/tmp/o_XXXXXX";\nint g = mkstemp(other);\n'
    fixed = fix_mkstemp_suffix(source)
    assert "mkstemps(tmp_filename, 4)" in fixed and "mkstemp(other)" in fixed


def test_sanitize_harness_applies_it():
    assert "mkstemps(tmp_filename, 4)" in sanitize_harness(BAD, target_apis=["sf_open"])
