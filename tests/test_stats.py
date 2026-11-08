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


def test_fork_mode_line_is_parsed():
    """fork 모드(-fork=N) 진행 라인 형식 "#N: ..." 파싱"""
    s = LiveStats(group="g")
    line = ("#786307: cov: 6 ft: 6 corp: 1 exec/s: 117236 "
            "oom/timeout/crash: 1/2/649 time: 8s job: 651 dft_time: 0")
    assert s.update_from_line(line)
    assert s.execs == 786307
    assert s.coverage == 6
    assert s.exec_per_sec == 117236
    assert s.crashes == 652


def test_fork_mode_crash_count_does_not_decrease():
    s = LiveStats(group="g")
    s.update_from_line("#10: cov: 3 ft: 3 corp: 1 exec/s: 0 oom/timeout/crash: 0/0/5 time: 0s")
    s.update_from_line("#20: cov: 3 ft: 3 corp: 1 exec/s: 0 oom/timeout/crash: 0/0/2 time: 0s")
    assert s.crashes == 5
