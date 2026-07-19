from logosfuzz.execute.crash_collector import CrashCollector, looks_like_crash


def test_looks_like_crash():
    assert looks_like_crash("crash-abcd")
    assert looks_like_crash("id:000001")
    assert not looks_like_crash("cov.dat")


def test_collect_and_dedup(tmp_path):
    src = tmp_path / "out" / "crashes"
    src.mkdir(parents=True)
    (src / "crash-1").write_bytes(b"AAAA")
    (src / "crash-2").write_bytes(b"AAAA")   # 동일 내용 -> 중복 제거
    (src / "crash-3").write_bytes(b"BBBB")
    (src / "cov.dat").write_bytes(b"x")       # 크래시 아님

    dest = tmp_path / "collected"
    c = CrashCollector(dest)
    saved = c.collect("grp1", [src])
    # AAAA(1건) + BBBB(1건) = 2건, cov.dat 제외
    assert len(saved) == 2
    # 재수집 시 새 파일 없음
    assert c.collect("grp1", [src]) == []
