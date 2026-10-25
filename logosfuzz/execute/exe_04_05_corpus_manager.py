"""
EXE-04-05 : Corpus/Seed Management

Manages initial seed inputs and corpus discovered during fuzzing.

Responsibilities
----------------
1. SeedManager  : Generate/store/load initial seed inputs per Logic Group
2. CorpusManager: Save/deduplicate/prioritize interesting inputs found during fuzzing
3. SeedScheduler: Select seeds to feed to the fuzzer based on coverage novelty

Directory structure
-------------------
corpus/
  lg_1/
    seeds/        <- initial seed inputs
    corpus/       <- interesting inputs found during fuzzing
    crashes/      <- crash-triggering inputs
  lg_2/
    seeds/
    corpus/
    crashes/
"""

from __future__ import annotations
import os
import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from logosfuzz.common.logging import get_logger
from logosfuzz.common.safe_path import resolve_within, safe_component

_LOG = get_logger("EXE-04-05")


def _group_dir(base_dir: Path, group_name: str, sub: str) -> Path:
    """``<base_dir>/<그룹>/<sub>``. 그룹 이름은 디렉터리 한 칸으로 정화하여 사용"""
    return resolve_within(base_dir, safe_component(group_name), sub)


# ---------------------------------------------------------------------
# 0. C++ 문자열 리터럴 스캐너 (*_test.cc 시드 추출용)
# ---------------------------------------------------------------------

# 일반 문자열 리터럴 이스케이프 (테스트 데이터에 실제 등장하는 것만 처리)
_SIMPLE_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "0": "\0",
    "\\": "\\", '"': '"', "'": "'",
    "a": "\a", "b": "\b", "f": "\f", "v": "\v",
}


def _decode_escapes(body: str) -> str:
    """일반 문자열 리터럴 본문의 이스케이프 해석"""
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\" or i + 1 >= len(body):
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt == "x":
            # \xNN: 16진 바이트
            j = i + 2
            hex_digits = ""
            while j < len(body) and len(hex_digits) < 2 and body[j] in "0123456789abcdefABCDEF":
                hex_digits += body[j]
                j += 1
            if hex_digits:
                out.append(chr(int(hex_digits, 16)))
                i = j
                continue
        if nxt in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[nxt])
            i += 2
            continue
        # 미지원 이스케이프는 다음 글자 그대로 유지 (C++ 규칙과 동일)
        out.append(nxt)
        i += 2
    return "".join(out)


def _iter_cpp_string_literals(text: str):
    """C++ 소스의 문자열 리터럴 순차 추출 (문자 단위 상태 기계)

    1. 원시 문자열 ``R"tag( ... )tag"`` 처리
    2. 주석 안 문자열 제외
    3. 인접 리터럴 연결 (``"{" "\\"k\\": 1" "}"`` → 한 문자열)

    ``#include "..."`` 헤더 경로는 제외
    """
    i = 0
    n = len(text)
    pending: list[str] = []      # 인접 리터럴 연결용 버퍼
    at_line_start = True
    in_include_line = False

    def flush():
        if pending:
            joined = "".join(pending)
            pending.clear()
            if joined:
                return joined
        return None

    while i < n:
        ch = text[i]

        # 줄 시작의 #include 지시문 여부 확인
        if ch == "\n":
            at_line_start = True
            in_include_line = False
            i += 1
            continue
        if at_line_start and not ch.isspace():
            at_line_start = False
            if text.startswith("#include", i) or text.startswith("#", i):
                in_include_line = True

        # 주석
        if text.startswith("//", i):
            got = flush()
            if got is not None:
                yield got
            i = text.find("\n", i)
            if i == -1:
                return
            continue
        if text.startswith("/*", i):
            got = flush()
            if got is not None:
                yield got
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue

        # 원시 문자열 R"tag( ... )tag" (일반 리터럴보다 먼저 검사)
        # tag 는 16자 이하, 공백·괄호 불가 (`FOO(R, "v")` 오인 방지)
        if ch in "Rr" and i + 1 < n and text[i + 1] == '"':
            delim_end = text.find("(", i + 2, i + 2 + 17)
            tag = text[i + 2:delim_end] if delim_end != -1 else None
            if tag is not None and not any(c.isspace() or c in '()\\"' for c in tag):
                closing = ")" + tag + '"'
                body_end = text.find(closing, delim_end + 1)
                if body_end != -1:
                    body = text[delim_end + 1:body_end]
                    if not in_include_line:
                        pending.append(body)
                    i = body_end + len(closing)
                    continue
                # 닫히지 않은 원시 문자열: 잘린 파일로 간주하고 나머지 폐기
                break

        # 문자 리터럴 'x' 건너뜀 (내부 따옴표 오인 방지)
        if ch == "'":
            i += 1
            while i < n and text[i] != "'":
                i += 2 if text[i] == "\\" else 1
            i += 1
            continue

        # 일반 문자열 리터럴
        if ch == '"':
            i += 1
            start = i
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    break
                i += 1
            body = text[start:i]
            i += 1
            if not in_include_line:
                pending.append(_decode_escapes(body))
            continue

        # 리터럴 사이에 공백·줄바꿈 외 문자가 오면 연결 종료
        if not ch.isspace():
            got = flush()
            if got is not None:
                yield got
        i += 1

    got = flush()
    if got is not None:
        yield got


# ---------------------------------------------------------------------
# 1. Data Models
# ---------------------------------------------------------------------

@dataclass
class SeedEntry:
    """A single seed input."""
    seed_id: str
    group_name: str
    data: bytes
    source: str          # "initial" | "corpus" | "crash"
    coverage_gain: float = 0.0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass
class CorpusStats:
    """Statistics for a Logic Group's corpus."""
    group_name: str
    seed_count: int
    corpus_count: int
    crash_count: int
    total_coverage: float


# ---------------------------------------------------------------------
# 2. Seed Manager
# ---------------------------------------------------------------------

class SeedManager:
    """Manages initial seed inputs for each Logic Group."""

    def __init__(self, base_dir: str = "corpus"):
        self.base_dir = Path(base_dir)

    def _seed_dir(self, group_name: str) -> Path:
        d = _group_dir(self.base_dir, group_name, "seeds")
        d.mkdir(parents=True, exist_ok=True)
        return d

    def generate_initial_seeds(self, group_name: str) -> list[SeedEntry]:
        """
        Generate basic initial seeds for a Logic Group.
        Covers common edge cases: empty, single byte, max size, etc.
        """
        seed_cases = {
            "empty"     : b"",
            "single"    : b"\x00",
            "ff"        : b"\xff",
            "short"     : b"\x00\x01\x02\x03",
            "boundary"  : b"\x00" * 64,
            "max_byte"  : b"\xff" * 64,
            "random_a"  : b"\xde\xad\xbe\xef",
            "random_b"  : b"\xca\xfe\xba\xbe",
        }

        entries = []
        for name, data in seed_cases.items():
            entry = SeedEntry(
                seed_id=f"{group_name}_{name}",
                group_name=group_name,
                data=data,
                source="initial",
            )
            entries.append(entry)

        return entries

    def extract_seeds_from_tests(
        self,
        group_name: str,
        test_sources: "list[Path] | list[str]",
        *,
        min_len: int = 2,
        max_len: int = 4096,
        limit: int = 200,
    ) -> list[SeedEntry]:
        """대상 저장소 ``*_test.cc`` 의 문자열 리터럴 기반 시드 추출

        유닛 테스트에 담긴 유효 입력을 시드로 사용해 유효 형식에서 변형 시작

            "..."                   일반 문자열 (이스케이프 해석)
            R"delim( ... )delim"    원시 문자열

        Returns:
            내용 기준 중복 제거된 시드 목록
        """
        seen: set[bytes] = set()
        entries: list[SeedEntry] = []

        for source in test_sources:
            path = Path(source)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                # 읽기 실패 파일은 건너뜀
                continue

            for literal in _iter_cpp_string_literals(text):
                data = literal.encode("utf-8", errors="replace")
                if not (min_len <= len(data) <= max_len):
                    continue
                if data in seen:
                    continue
                seen.add(data)
                entries.append(SeedEntry(
                    seed_id=f"{group_name}_test_{len(entries):04d}",
                    group_name=group_name,
                    data=data,
                    source="initial",
                ))
                if len(entries) >= limit:
                    return entries

        return entries

    def save_seeds(self, entries: list[SeedEntry]) -> None:
        """Save seed entries to disk."""
        for entry in entries:
            seed_dir = self._seed_dir(entry.group_name)
            path = seed_dir / f"{safe_component(entry.seed_id)}.bin"
            path.write_bytes(entry.data)

        _LOG.info("Saved %d seeds for %s", len(entries), entries[0].group_name if entries else "")

    def load_seeds(self, group_name: str) -> list[SeedEntry]:
        """Load seed entries from disk."""
        seed_dir = self._seed_dir(group_name)
        entries = []
        for path in sorted(seed_dir.glob("*.bin")):
            data = path.read_bytes()
            entry = SeedEntry(
                seed_id=path.stem,
                group_name=group_name,
                data=data,
                source="initial",
            )
            entries.append(entry)
        return entries


# ---------------------------------------------------------------------
# 3. Corpus Manager
# ---------------------------------------------------------------------

class CorpusManager:
    """
    Manages corpus inputs discovered during fuzzing.
    Deduplicates by MD5 checksum and prioritizes by coverage gain.
    """

    def __init__(self, base_dir: str = "corpus"):
        self.base_dir = Path(base_dir)
        self._seen: dict[str, set[str]] = {}   # group_name -> set of checksums

    def _corpus_dir(self, group_name: str) -> Path:
        d = _group_dir(self.base_dir, group_name, "corpus")
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _crash_dir(self, group_name: str) -> Path:
        d = _group_dir(self.base_dir, group_name, "crashes")
        d.mkdir(parents=True, exist_ok=True)
        return d

    def add(self, entry: SeedEntry) -> bool:
        """
        Add a new corpus entry if not duplicate.
        Returns True if added, False if duplicate.
        """
        group = entry.group_name
        if group not in self._seen:
            self._seen[group] = set()

        checksum = entry.checksum
        if checksum in self._seen[group]:
            return False    # duplicate

        self._seen[group].add(checksum)

        if entry.source == "crash":
            save_dir = self._crash_dir(group)
        else:
            save_dir = self._corpus_dir(group)

        path = save_dir / f"{checksum[:8]}_{safe_component(entry.seed_id)}.bin"
        path.write_bytes(entry.data)
        return True

    def load_corpus(self, group_name: str) -> list[SeedEntry]:
        """Load all corpus entries for a group."""
        corpus_dir = self._corpus_dir(group_name)
        entries = []
        for path in sorted(corpus_dir.glob("*.bin")):
            data = path.read_bytes()
            entries.append(SeedEntry(
                seed_id=path.stem,
                group_name=group_name,
                data=data,
                source="corpus",
            ))
        return entries

    def get_stats(self, group_name: str) -> CorpusStats:
        """Return corpus statistics for a Logic Group."""
        seed_dir = _group_dir(self.base_dir, group_name, "seeds")
        corpus_dir = _group_dir(self.base_dir, group_name, "corpus")
        crash_dir = _group_dir(self.base_dir, group_name, "crashes")

        return CorpusStats(
            group_name=group_name,
            seed_count=len(list(seed_dir.glob("*.bin"))) if seed_dir.exists() else 0,
            corpus_count=len(list(corpus_dir.glob("*.bin"))) if corpus_dir.exists() else 0,
            crash_count=len(list(crash_dir.glob("*.bin"))) if crash_dir.exists() else 0,
            total_coverage=0.0,  # filled in by EXE-04-02
        )


# ---------------------------------------------------------------------
# 4. Seed Scheduler
# ---------------------------------------------------------------------

class SeedScheduler:
    """
    Selects seeds to feed to the fuzzer.
    Prioritizes seeds with higher coverage gain (novelty-first).
    """

    def __init__(self, seed_manager: SeedManager, corpus_manager: CorpusManager):
        self.seed_manager = seed_manager
        self.corpus_manager = corpus_manager

    def get_fuzzing_queue(self, group_name: str) -> list[SeedEntry]:
        """
        Build the fuzzing input queue for a Logic Group.
        Order: initial seeds first, then corpus by coverage_gain (desc).
        """
        seeds = self.seed_manager.load_seeds(group_name)
        corpus = self.corpus_manager.load_corpus(group_name)

        # Sort corpus by coverage gain (highest first)
        corpus.sort(key=lambda e: e.coverage_gain, reverse=True)

        queue = seeds + corpus
        _LOG.info("%s: %d seeds + %d corpus = %d total", group_name, len(seeds), len(corpus), len(queue))
        return queue

    def export_to_dir(self, group_name: str, target_dir: str) -> int:
        """
        Export the fuzzing queue to a directory (for libFuzzer/AFL++ corpus input).
        Returns the number of files exported.
        """
        queue = self.get_fuzzing_queue(group_name)
        out = Path(target_dir)
        out.mkdir(parents=True, exist_ok=True)

        for i, entry in enumerate(queue):
            path = out / f"input_{i:04d}.bin"
            path.write_bytes(entry.data)

        _LOG.info("%d inputs exported to %s", len(queue), target_dir)
        return len(queue)


# ---------------------------------------------------------------------
# 5. Mock Run
# ---------------------------------------------------------------------

if __name__ == "__main__":
    logic_groups = ["lg_1_uds", "lg_2_json"]

    seed_mgr = SeedManager(base_dir="corpus")
    corpus_mgr = CorpusManager(base_dir="corpus")
    scheduler = SeedScheduler(seed_mgr, corpus_mgr)

    print("=== EXE-04-05 Corpus/Seed Management ===\n")

    for group in logic_groups:
        print(f"[{group}] Initializing seeds...")

        # 1. Generate and save initial seeds
        seeds = seed_mgr.generate_initial_seeds(group)
        seed_mgr.save_seeds(seeds)

        # 2. Simulate corpus discovery during fuzzing
        mock_corpus = [
            SeedEntry(f"corp_{group}_1", group, b"\x01\x02\x03\x04\x05", "corpus", coverage_gain=0.8),
            SeedEntry(f"corp_{group}_2", group, b"\xff\xfe\xfd", "corpus", coverage_gain=0.5),
            SeedEntry(f"crash_{group}_1", group, b"\x00" * 128, "crash", coverage_gain=1.0),
        ]
        for entry in mock_corpus:
            added = corpus_mgr.add(entry)
            print(f"  [CORPUS] {entry.seed_id} -> {'added' if added else 'duplicate'}")

        # 3. Export fuzzing queue
        scheduler.export_to_dir(group, f"corpus/{group}/fuzz_input")

        # 4. Print stats
        stats = corpus_mgr.get_stats(group)
        print(f"  [STATS] seeds={stats.seed_count} corpus={stats.corpus_count} crashes={stats.crash_count}\n")
