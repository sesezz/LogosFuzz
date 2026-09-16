"""크래시 산출물 수집.

설계서 EXE-04-00: 새 크래시 발생 시 crashes/ 폴더에 저장.
컨테이너의 출력 디렉토리에서 크래시 파일을 찾아 그룹별로 crashes/ 아래에
복사한다. 여기서는 '수집/보존'까지만 담당하며, 크래시 시그니처화 및
중복 제거(ANA-05-04)와 정/오탐 판별(ANA-05-01)은 ANA 파트가 담당한다.
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path


# libFuzzer: crash-<sha1>, oom-, timeout-, leak-  / AFL++: id:...
_CRASH_PREFIXES = ("crash-", "oom-", "timeout-", "leak-", "id:")


def looks_like_crash(name: str) -> bool:
    return name.startswith(_CRASH_PREFIXES)


@dataclass
class CrashCollector:
    """그룹별 크래시 파일을 crashes/<group>/ 로 보존."""

    crashes_dir: Path
    _seen: set[str] = field(default_factory=set)

    def _digest(self, path: Path) -> str:
        h = hashlib.sha1()
        h.update(path.read_bytes())
        return h.hexdigest()

    def collect(self, group: str, search_dirs: list[Path]) -> list[Path]:
        """search_dirs에서 새 크래시 입력을 찾아 보존하고 경로 목록 반환.

        동일 내용(sha1) 파일은 세션 내에서 한 번만 저장한다.
        """
        dest_root = self.crashes_dir / group
        saved: list[Path] = []
        for d in search_dirs:
            if not d or not d.exists():
                continue
            for f in sorted(d.rglob("*")):
                if not f.is_file() or not looks_like_crash(f.name):
                    continue
                try:
                    digest = self._digest(f)
                except OSError:
                    continue
                if digest in self._seen:
                    continue
                self._seen.add(digest)
                dest_root.mkdir(parents=True, exist_ok=True)
                dest = dest_root / f"{f.name}"
                if dest.exists():
                    dest = dest_root / f"{digest[:12]}-{f.name}"
                shutil.copy2(f, dest)
                saved.append(dest)
        return saved
