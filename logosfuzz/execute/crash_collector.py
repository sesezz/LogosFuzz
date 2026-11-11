"""크래시 산출물 수집

설계서 EXE-04-00: 새 크래시 발생 시 crashes/ 폴더에 저장
컨테이너 출력 디렉토리의 크래시 파일을 그룹별 crashes/ 아래로 복사 (수집/보존만 담당)
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
    """그룹별 크래시 파일의 crashes/<group>/ 보존"""

    crashes_dir: Path
    _seen: set[str] = field(default_factory=set)

    def _digest(self, path: Path) -> str:
        h = hashlib.sha256()
        h.update(path.read_bytes())
        return h.hexdigest()

    def collect(self, group: str, search_dirs: list[Path]) -> list[Path]:
        """search_dirs에서 새 크래시 입력을 찾아 보존하고 경로 목록 반환.

        동일 내용(sha1) 파일은 세션 내에서 한 번만 저장한다.

        libFuzzer 는 ``artifact_prefix`` 로 받은 ``crashes/`` **바로 아래**에
        크래시 입력을 떨군다. 그걸 복사만 하면 같은 입력이 ``crashes/crash-<해시>``
        와 ``crashes/<group>/crash-<해시>`` 두 곳에 남아, 디렉터리를 세어
        크래시 수를 집계하는 쪽에서 한 건이 두 건으로 보인다. 그래서 수집
        루트에 직접 떨어진 산출물은 복사가 아니라 **이동**한다. AFL++ 의
        ``out/afl/**`` 처럼 엔진이 계속 쓰는 상태 디렉터리는 건드리지 않는다.
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
                if f.parent == self.crashes_dir:
                    shutil.move(str(f), str(dest))
                else:
                    shutil.copy2(f, dest)
                saved.append(dest)
        return saved
