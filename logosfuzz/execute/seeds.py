"""프로필 시드의 그룹별 코퍼스 초기값 복사 (GENERIC)

원본 시드 오염 방지를 위해 출력 폴더 ``corpus/<group>/`` 에 복사본 생성
퍼징 후 해당 디렉터리가 최종 코퍼스 (커버리지 재생 입력)
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Iterable, List, Sequence

from logosfuzz.config import LogicGroup


def profile_seed_paths(profile) -> List[Path]:
    """프로필 ``seeds`` 의 절대경로 변환 (source_root 기준)"""
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
    """시드 파일의 ``dest`` 복사 및 복사 수 반환 (이름 중복 시 내용 해시 추가)"""
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
    """그룹별 ``corpus_root/<group>/`` 생성 및 시드(와 기존 코퍼스) 복사

    반환 그룹의 ``corpus_dir`` 은 새 디렉터리 (시드가 없어도 생성)
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
