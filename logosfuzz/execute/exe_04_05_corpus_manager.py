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
