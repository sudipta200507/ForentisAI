"""Generate the ForentisAI extension icons (simple shield on dark square).

Pure-stdlib PNG writer: no Pillow dependency. Produces 16/32/48/128 px.
Re-run only if the icons need changing:
    python scripts/extension_icons.py
"""

import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "extension" / "icons"

BG = (16, 20, 24, 255)        # dark navy
BG2 = (23, 29, 36, 255)       # slightly lighter (bottom)
ACCENT = (90, 167, 232, 255)  # brand blue
GREEN = (46, 158, 91, 255)    # check mark


def shield_mask(x: float, y: float, size: float) -> float:
    """Anti-aliased coverage of a shield shape centered in `size` box."""
    cx = size / 2.0
    top = size * 0.18
    bottom = size * 0.86
    half_w = size * 0.34
    # Shield: rounded top corners, tapered V bottom.
    progress = (y - top) / (bottom - top)
    if progress < 0 or progress > 1:
        return 0.0
    width = half_w * (1.0 - 0.75 * progress)
    dx = abs(x - cx)
    inside = width - dx
    edge = min(inside, y - top, bottom - y) if inside > 0 else inside
    return max(0.0, min(1.0, edge + 0.5))


def check_mask(x: float, y: float, size: float) -> float:
    """Anti-aliased coverage of a small check mark inside the shield."""
    cx = size / 2.0
    thickness = size * 0.085
    p1 = (cx - size * 0.13, size * 0.52)
    p2 = (cx - size * 0.03, size * 0.64)
    p3 = (cx + size * 0.16, size * 0.36)

    def seg_dist(px, py, ax, ay, bx, by):
        abx, aby = bx - ax, by - ay
        apx, apy = px - ax, py - ay
        denom = abx * abx + aby * aby
        t = 0.0 if denom == 0 else max(0.0, min(1.0, (apx * abx + apy * aby) / denom))
        dx, dy = apx - t * abx, apy - t * aby
        return (dx * dx + dy * dy) ** 0.5

    d1 = seg_dist(x, y, *p1, *p2)
    d2 = seg_dist(x, y, *p2, *p3)
    return max(0.0, min(1.0, thickness - min(d1, d2) + 0.5))


def render(size: int) -> bytes:
    rows = []
    corner = size * 0.22  # rounded-rect background
    for y in range(size):
        row = bytearray()
        for x in range(size):
            # Rounded square background with subtle vertical gradient.
            rx = min(x, size - 1 - x)
            ry = min(y, size - 1 - y)
            rounded = rx + ry >= corner
            t = y / size
            base = tuple(
                int(BG[i] + (BG2[i] - BG[i]) * t) for i in range(3)
            ) + (255,) if rounded else (0, 0, 0, 0)
            r, g, b, a = base
            # Shield + check composited over the background.
            s = shield_mask(x + 0.5, y + 0.5, size)
            if s > 0:
                c = check_mask(x + 0.5, y + 0.5, size)
                if c > 0:
                    r = int(ACCENT[0] * (1 - c) + GREEN[0] * c)
                    g = int(ACCENT[1] * (1 - c) + GREEN[1] * c)
                    b = int(ACCENT[2] * (1 - c) + GREEN[2] * c)
                else:
                    r, g, b = ACCENT[:3]
                a = int(a * s)
            row.extend((r, g, b, a))
        rows.append(bytes(row))
    return encode_png(size, rows)


def encode_png(size: int, rows: list[bytes]) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    raw = b"".join(b"\x00" + row for row in rows)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for size in (16, 32, 48, 128):
        (OUT / f"icon{size}.png").write_bytes(render(size))
        print(f"wrote {OUT / f'icon{size}.png'}")


if __name__ == "__main__":
    main()
