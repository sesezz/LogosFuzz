"""프로필 시드를 그룹별 코퍼스 초기값으로 복사한다 (GENERIC).

``logosfuzz fuzz --profile`` 과 ``logosfuzz run`` 이 쓴다. libFuzzer 는 새 경로를 연
입력을 첫 코퍼스 디렉터리에 저장하므로, 사용자의 시드 디렉터리를 그대로 넘기면
원본이 오염된다. 그래서 출력 폴더 아래 ``corpus/<group>/`` 에 복사본을 만들어
넘기고, 퍼징이 끝나면 그 디렉터리가 "최종 코퍼스"가 된다(커버리지 재생 입력).
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Iterable, List, Sequence

from logosfuzz.config import LogicGroup


def profile_seed_paths(profile) -> List[Path]:
    """프로필 ``seeds`` 를 절대경로로. 경로는 source_root 기준이다(target_profile 규칙)."""
    return [profile.abs(s) for s in getattr(profile, "seeds", ()) or ()]


def _seed_files(paths: Iterable[Path]) -> List[Path]:
    files: List[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files.extend(sorted(f for f in p.rglob("*") if f.is_file()))
    return files


def copy_seeds(seed_paths: Sequence[Path], dest: Path) -> int:
    """시드 파일들을 ``dest`` 에 복사한다. 이름이 겹치면 내용 해시를 붙인다. 복사한 수."""
    dest.mkdir(parents=True, exist_ok=True)
    copied = 0
    for src in _seed_files(seed_paths):
        target = dest / src.name
        if target.exists():
            if target.read_bytes() == src.read_bytes():
                continue
            digest = hashlib.sha1(src.read_bytes()).hexdigest()[:12]
            target = dest / f"{src.name}-{digest}"
        shutil.copyfile(src, target)
        copied += 1
    return copied


def seed_group_corpora(groups: Sequence[LogicGroup], seed_paths: Sequence[Path],
                       corpus_root: Path) -> List[LogicGroup]:
    """그룹마다 ``corpus_root/<group>/`` 를 만들고 시드(와 기존 코퍼스)를 복사한다.

    반환하는 그룹은 ``corpus_dir`` 이 새 디렉터리를 가리킨다. 시드가 없어도 디렉터리는
    만든다 - 그래야 퍼징이 찾은 입력이 남아 최종 코퍼스로 쓸 수 있다.
    """
    seeded: List[LogicGroup] = []
    for group in groups:
        dest = Path(corpus_root) / group.name
        sources = list(seed_paths)
        if group.corpus_dir is not None and Path(group.corpus_dir).resolve() != dest.resolve():
            sources.append(Path(group.corpus_dir))
        copy_seeds(sources, dest)
        seeded.append(replace(group, corpus_dir=dest))
    return seeded
