"""libsndfile 퍼징 시드 생성 (GENERIC-B)

표준 라이브러리만으로 형식별 최소 유효 오디오 파일을 직접 만든다. 외부 파일을 복사하지 않으므로
라이선스 문제가 없고, 결정적이라 다시 만들어도 같은 바이트가 나온다.

    python scripts/make_libsndfile_seeds.py              # targets/seeds/libsndfile/ 에 생성
    python scripts/make_libsndfile_seeds.py --out DIR    # 다른 위치에 생성

시드가 없으면 퍼저가 유효한 헤더를 처음부터 만들어야 해서 대부분의 입력이 파싱 초입에서 거부된다.
형식마다 하나씩 두면 형식별 파서 코드까지 곧바로 도달한다.

생성 형식: WAV(PCM16 모노/스테레오, PCM24, float32, u-law), AIFF, AU, CAF, MAT4(libsndfile 이 쓰는 리틀엔디언 PCM16)
프로필(`targets/libsndfile.json`)의 `seeds` 는 source_root 기준 상대경로로 이 폴더를 가리킨다.
"""
from __future__ import annotations

import argparse
import io
import math
import struct
import wave
from pathlib import Path
from typing import Callable, Dict

DEFAULT_OUT = Path(__file__).resolve().parents[1] / "targets" / "seeds" / "libsndfile"
RATE = 8000
FRAMES = 32


def _sine(frames: int = FRAMES, channels: int = 1, amplitude: int = 12000) -> list:
    """결정적인 사인파 샘플(프레임 x 채널, 정수)."""
    samples = []
    for i in range(frames):
        value = int(amplitude * math.sin(2 * math.pi * 440 * i / RATE))
        samples.extend([value] * channels)
    return samples


def wav_pcm16(channels: int) -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as handle:
        handle.setnchannels(channels)
        handle.setsampwidth(2)
        handle.setframerate(RATE)
        handle.writeframes(struct.pack(f"<{FRAMES * channels}h", *_sine(channels=channels)))
    return buffer.getvalue()


def _riff(fmt_chunk: bytes, payload: bytes) -> bytes:
    body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt_chunk)) + fmt_chunk
    body += b"data" + struct.pack("<I", len(payload)) + payload
    return b"RIFF" + struct.pack("<I", len(body)) + body


def wav_pcm24() -> bytes:
    payload = b"".join(struct.pack("<i", v << 8)[:3] for v in _sine())
    fmt = struct.pack("<HHIIHH", 1, 1, RATE, RATE * 3, 3, 24)
    return _riff(fmt, payload)


def wav_float32() -> bytes:
    payload = struct.pack(f"<{FRAMES}f", *[v / 32768.0 for v in _sine()])
    fmt = struct.pack("<HHIIHH", 3, 1, RATE, RATE * 4, 4, 32)
    return _riff(fmt, payload)


def wav_ulaw() -> bytes:
    payload = bytes((i * 7 + 0x80) & 0xFF for i in range(FRAMES))
    fmt = struct.pack("<HHIIHHH", 7, 1, RATE, RATE, 1, 8, 0)
    return _riff(fmt, payload)


def aiff_pcm16() -> bytes:
    samples = struct.pack(f">{FRAMES * 2}h", *_sine(channels=2))
    # 80비트 확장 부동소수점 샘플레이트(8000 Hz)
    rate80 = bytes.fromhex("400BFA00000000000000")
    comm = struct.pack(">hIh", 2, FRAMES, 16) + rate80
    ssnd = struct.pack(">II", 0, 0) + samples
    body = b"AIFF" + b"COMM" + struct.pack(">I", len(comm)) + comm
    body += b"SSND" + struct.pack(">I", len(ssnd)) + ssnd
    return b"FORM" + struct.pack(">I", len(body)) + body


def au_pcm16() -> bytes:
    samples = struct.pack(f">{FRAMES}h", *_sine())
    header = b".snd" + struct.pack(">IIIII", 24, len(samples), 3, RATE, 1)
    return header + samples


def caf_pcm16() -> bytes:
    samples = struct.pack(f">{FRAMES}h", *_sine())
    desc = struct.pack(">dIIIIII", float(RATE), 0x6C70636D, 0x0, 2, 1, 1, 16)  # 'lpcm', 빅엔디언 정수
    data = struct.pack(">I", 0) + samples
    out = b"caff" + struct.pack(">HH", 1, 0)
    out += b"desc" + struct.pack(">q", len(desc)) + desc
    out += b"data" + struct.pack(">q", len(data)) + data
    return out


def mat4_pcm16() -> bytes:
    """libsndfile 의 `mat4_write_header` 가 만드는 리틀엔디언 PCM16 구조를 그대로 따른다."""
    samples = struct.pack(f"<{FRAMES}h", *_sine())
    rate_name = b"samplerate\x00"
    wave_name = b"wavedata\x00"
    header = struct.pack("<IIIII", 0, 1, 1, 0, len(rate_name)) + rate_name + struct.pack("<d", float(RATE))
    header += struct.pack("<IIIII", 0x1E, 1, FRAMES, 0, len(wave_name)) + wave_name
    return header + samples


SEEDS: Dict[str, Callable[[], bytes]] = {
    "pcm16_mono.wav": lambda: wav_pcm16(1),
    "pcm16_stereo.wav": lambda: wav_pcm16(2),
    "pcm24_mono.wav": wav_pcm24,
    "float32_mono.wav": wav_float32,
    "ulaw_mono.wav": wav_ulaw,
    "pcm16_stereo.aiff": aiff_pcm16,
    "pcm16_mono.au": au_pcm16,
    "pcm16_mono.caf": caf_pcm16,
    "pcm16_mono.mat": mat4_pcm16,
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="libsndfile 퍼징 시드 생성")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"출력 폴더 (기본 {DEFAULT_OUT})")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, build in SEEDS.items():
        data = build()
        (args.out / name).write_bytes(data)
        print(f"{name:20s} {len(data):4d} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
