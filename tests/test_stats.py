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
