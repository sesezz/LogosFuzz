"""프로필 libFuzzer 사전(-dict)의 그룹별 배치 (GENERIC)

프로필 ``dictionary`` 파일을 ``<dict_dir>/<group>.dict`` 로 복사
DockerIsolationRunner.resolve_dict 가 이 경로를 찾아 ``-dict=`` 인자 추가
libFuzzer 는 사전 한 줄이라도 형식이 틀리면 퍼징 시작 전에 종료하므로 복사 전 형식 검사
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Dict, Iterable, Optional

_HEX = set(b"0123456789abcdefABCDEF")


def _printable_or_space(byte: int) -> bool:
    """libFuzzer 의 isprint/isspace 판정 (C 로캘 ASCII 기준)"""
    return 0x20 <= byte < 0x7F or byte in b"\t\n\v\f\r"


def parse_entry(line: bytes) -> Optional[bytes]:
    """사전 한 줄(``name="..."`` 또는 ``"..."``)의 값 바이트 반환, 형식 오류 시 None

    libFuzzer ParseOneDictionaryEntry 와 같은 규칙 (양끝 공백 제거, ``\\\\``·``\\"``·``\\xAB`` 이스케이프)
    """
    left, right = 0, len(line) - 1
    if right < 0:
        return None
    while left < right and line[left] in b" \t\n\v\f\r":
        left += 1
    while right > left and line[right] in b" \t\n\v\f\r":
        right -= 1
    if right - left < 2 or line[right] != ord('"'):
        return None
    right -= 1
    while left < right and line[left] != ord('"'):
        left += 1
    if left >= right:
        return None
    left += 1
    out = bytearray()
    pos = left
    while pos <= right:
        byte = line[pos]
        if not _printable_or_space(byte):
            return None
        if byte == ord("\\"):
            if pos + 1 <= right and line[pos + 1] in b'\\"':
                out.append(line[pos + 1])
                pos += 2
                continue
            if (pos + 3 <= right and line[pos + 1] == ord("x")
                    and line[pos + 2] in _HEX and line[pos + 3] in _HEX):
                out.append(int(line[pos + 2:pos + 4], 16))
                pos += 4
                continue
            return None
        out.append(byte)
        pos += 1
    return bytes(out)


def validate_dictionary(path: Path) -> tuple[int, str]:
    """사전 파일 검사 결과 (항목 수, 오류 사유) 반환. 정상이면 사유는 빈 문자열"""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        return 0, f"사전 파일을 읽을 수 없다: {path} ({exc.strerror or type(exc).__name__})"
    count = 0
    for line_no, raw in enumerate(data.split(b"\n"), start=1):
        stripped = raw.strip(b" \t\n\v\f\r")
        if not stripped or stripped.startswith(b"#"):
            continue
        if parse_entry(raw) is None:
            return count, f"{path}:{line_no} libFuzzer 사전 형식 아님"
        count += 1
    if count == 0:
        return 0, f"{path}: 사전 항목이 없다"
    return count, ""


def install_profile_dictionary(
    profile, group_names: Iterable[str], dict_dir: Path,
    log: Callable[[str], None] = print,
) -> Dict[str, str]:
    """프로필 사전의 ``dict_dir/<group>.dict`` 복사 및 {그룹: 사전 경로} 반환

    프로필 사전 미지정·파일 부재·형식 오류 시 경고만 남기고 빈 결과 반환 (실행 중단 없음)
    이미 있는 ``<group>.dict`` 는 사용자 지정 사전으로 보고 덮어쓰지 않음
    """
    name = getattr(profile, "dictionary", "") or ""
    if not name:
        return {}
    src = profile.abs(name)
    count, reason = validate_dictionary(src)   # 파일 부재·읽기 실패도 사유로 반환
    if reason:
        log(f"  [WARN] {reason} - 사전 없이 계속한다")
        return {}
    content = src.read_bytes()
    installed: Dict[str, str] = {}
    Path(dict_dir).mkdir(parents=True, exist_ok=True)
    for group in group_names:
        dest = Path(dict_dir) / f"{group}.dict"
        try:
            with open(dest, "xb") as fh:      # 없을 때만 생성 (검사-사용 시점 경쟁조건 방지)
                fh.write(content)
        except FileExistsError:
            pass                              # 기존 사용자 지정 사전 유지
        installed[group] = str(dest)
    log(f"  [DICT] {src.name} ({count}개 항목) -> {Path(dict_dir)}/<group>.dict ({len(installed)}개 그룹)")
    return installed
