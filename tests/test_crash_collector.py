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


def test_artifact_dropped_in_the_collect_root_is_moved(tmp_path):
    """libFuzzer 의 artifact_prefix 산출물이 두 곳에 남지 않아야 한다."""
    crashes = tmp_path / "out" / "crashes"
    crashes.mkdir(parents=True)
    (crashes / "crash-1").write_bytes(b"AAAA")

    saved = CrashCollector(crashes).collect("grp1", [crashes])

    assert saved == [crashes / "grp1" / "crash-1"]
    assert saved[0].read_bytes() == b"AAAA"
    assert not (crashes / "crash-1").exists()        # 원본은 남지 않는다
    assert [p.name for p in crashes.iterdir()] == ["grp1"]


def test_engine_state_dir_is_copied_not_moved(tmp_path):
    """AFL++ 가 계속 쓰는 디렉터리는 비워 놓지 않는다.

    파일명은 ``id:000001`` 대신 ``crash-2`` 를 쓴다 - 콜론은 Windows 에서
    파일명에 못 쓴다(대체 데이터 스트림이 되어 디렉터리에 보이지 않는다).
    이동/복사를 가르는 기준은 이름이 아니라 **어느 디렉터리에 있는지**다.
    """
    crashes = tmp_path / "out" / "crashes"
    crashes.mkdir(parents=True)
    afl = tmp_path / "out" / "afl" / "default" / "crashes"
    afl.mkdir(parents=True)
    (afl / "crash-2").write_bytes(b"BBBB")

    saved = CrashCollector(crashes).collect("grp1", [crashes, afl])

    assert len(saved) == 1
    assert (afl / "crash-2").exists()
