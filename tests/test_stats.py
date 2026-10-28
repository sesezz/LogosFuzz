from logosfuzz.execute.stats import LiveStats


def test_libfuzzer_line_parse():
    s = LiveStats(group="g")
    assert s.update_from_line("#2048 pulse cov: 512 ft: 900 exec/s: 1024 rss: 40Mb")
    assert s.execs == 2048
    assert s.coverage == 512
    assert s.exec_per_sec == 1024


def test_afl_lines_parse():
    s = LiveStats(group="g")
    s.update_from_line("exec speed : 900.5/sec")
    s.update_from_line("corpus count : 120")
    s.update_from_line("uniq crashes : 3")
    assert s.exec_per_sec == 900.5
    assert s.coverage == 120
    assert s.crashes == 3


def test_non_matching_line():
    s = LiveStats(group="g")
    assert not s.update_from_line("random log without metrics")


def test_rate_prefers_the_engine_number():
    s = LiveStats(group="g")
    s.update_from_line("#2048 pulse cov: 512 exec/s: 1024 rss: 40Mb")
    assert s.rate(elapsed_sec=8.0) == 1024


def test_rate_falls_back_when_engine_reports_zero():
    """libFuzzer 는 1초 미만 구간에서 exec/s: 0 을 찍는다."""
    s = LiveStats(group="g")
    s.update_from_line("#12302 NEW    cov: 7 ft: 9 exec/s: 0 rss: 37Mb")
    assert s.exec_per_sec == 0.0
    assert s.rate(elapsed_sec=0.54) == 22781.5
    assert "exec/s=   22782" in s.render(elapsed_sec=0.54)


def test_rate_is_zero_without_execs_or_time():
    s = LiveStats(group="g")
    assert s.rate(elapsed_sec=5.0) == 0.0
    s.update_from_line("#10 NEW exec/s: 0")
    assert s.rate(elapsed_sec=0.0) == 0.0
