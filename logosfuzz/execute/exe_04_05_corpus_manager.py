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


# ---------------------------------------------------------------------
# 0. C++ 문자열 리터럴 스캐너 (*_test.cc 시드 추출용)
# ---------------------------------------------------------------------

# 일반 문자열 리터럴의 이스케이프. C++ 표준 이스케이프 중 테스트 데이터에
# 실제로 나오는 것만 처리한다.
_SIMPLE_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "0": "\0",
    "\\": "\\", '"': '"', "'": "'",
    "a": "\a", "b": "\b", "f": "\f", "v": "\v",
}


def _decode_escapes(body: str) -> str:
    """일반 문자열 리터럴 본문의 이스케이프를 해석한다."""
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
            # \xNN - 16진 바이트
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
        # 모르는 이스케이프는 다음 글자를 그대로 둔다(C++ 규칙과 동일).
        out.append(nxt)
        i += 2
    return "".join(out)


def _iter_cpp_string_literals(text: str):
    """C++ 소스에서 문자열 리터럴을 순서대로 뽑아낸다.

    문자 단위로 상태를 따라가며 훑는다. 정규식 한 방으로 처리하지 않는 이유가
    셋 있다.

    1. **원시 문자열** ``R"tag( ... )tag"`` 는 내부에 따옴표가 그대로 들어간다.
       JSON 같은 입력이 테스트에 박힐 때 거의 항상 이 형태라, 일반 리터럴
       규칙으로 읽으면 중간에서 잘린다.
    2. **주석 안의 문자열**을 걸러야 한다. 주석은 입력이 아니다.
    3. **인접 리터럴은 이어 붙는다.** C++ 에서 ``"{" "\\"k\\": 1" "}"`` 는 한
       문자열이다. 이어 붙이지 않으면 여러 줄로 쪼개 쓴 JSON 테스트 데이터가
       쓸모없는 조각 세 개로 나온다.

    ``#include "..."`` 의 헤더 경로는 건너뛴다(입력이 아니라 경로다).
    """
    i = 0
    n = len(text)
    pending: list[str] = []      # 인접 리터럴 이어 붙이기용 버퍼
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

        # 줄 시작에서 #include 지시문인지 본다.
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

        # 원시 문자열 R"tag( ... )tag"  - 일반 리터럴보다 먼저 검사해야 한다.
        #
        # 구분자 tag 는 표준상 16자 이하이고 공백·괄호를 못 쓴다. 이 제한을
        # 걸어두지 않으면 `R` 뒤에 그냥 문자열이 온 코드(`FOO(R, "v")` 등)에서
        # 저 멀리 있는 여는 괄호를 tag 끝으로 잘못 잡아 파일 전체를 잘못 읽는다.
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
                # 닫히지 않은 원시 문자열. 여기서 그냥 두면 아래 일반 리터럴
                # 처리로 떨어져 `"tag(...` 를 문자열로 읽어 쓰레기 시드를 만든다.
                # 잘린 파일이라고 보고 남은 부분을 버린다.
                break

        # 문자 리터럴 'x' - 안의 따옴표가 문자열 시작으로 오인되지 않게 건너뛴다.
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

        # 리터럴들 사이에 공백·줄바꿈 말고 다른 게 오면 이어 붙이기를 끊는다.
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
        return hashlib.md5(self.data).hexdigest()


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
        d = self.base_dir / group_name / "seeds"
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
        """대상 저장소의 ``*_test.cc`` 에서 시드를 뽑는다.

        ``generate_initial_seeds`` 가 만드는 씨앗은 빈 입력·0xFF 반복 같은
        형식 없는 바이트열이다. 파서류 대상에서는 거의 전부 입력 검증 첫 줄에서
        튕겨 나가, 퍼저가 유효한 입력 형식을 스스로 찾아낼 때까지 시간을 버린다.

        반면 대상 저장소의 유닛 테스트에는 **그 API 가 실제로 받아들이는 입력**
        이 리터럴로 들어 있다. 이걸 시드로 쓰면 퍼저가 유효한 형식에서 출발해
        변형을 시작한다. libFuzzer 자동 사전과 같은 효과를 코퍼스 쪽에서 낸다.

        추출 대상은 C++ 문자열 리터럴 두 종류다.

            "..."                   일반 문자열(이스케이프 해석)
            R"delim( ... )delim"    원시 문자열 - JSON 같은 중첩 따옴표 입력이
                                    테스트에 들어갈 때 거의 항상 이 형태다

        Returns:
            추출된 시드 목록. 중복(내용 기준)은 제거된다.
        """
        seen: set[bytes] = set()
        entries: list[SeedEntry] = []

        for source in test_sources:
            path = Path(source)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                # 읽을 수 없는 파일 하나 때문에 전체 추출을 멈추지 않는다.
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
            path = seed_dir / f"{entry.seed_id}.bin"
            path.write_bytes(entry.data)

        print(f"  [SEED] Saved {len(entries)} seeds for {entries[0].group_name if entries else ''}")

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
        d = self.base_dir / group_name / "corpus"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _crash_dir(self, group_name: str) -> Path:
        d = self.base_dir / group_name / "crashes"
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

        path = save_dir / f"{checksum[:8]}_{entry.seed_id}.bin"
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
        seed_dir = self.base_dir / group_name / "seeds"
        corpus_dir = self.base_dir / group_name / "corpus"
        crash_dir = self.base_dir / group_name / "crashes"

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
        print(f"  [QUEUE] {group_name}: {len(seeds)} seeds + {len(corpus)} corpus = {len(queue)} total")
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

        print(f"  [EXPORT] {len(queue)} inputs exported to {target_dir}")
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
