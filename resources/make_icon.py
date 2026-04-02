#!/usr/bin/env python3
"""
Generate app icons for iOS FFS Browser.
Produces:
  resources/icon.png   (1024x1024 master)
  resources/icon.ico   (Windows multi-size ICO: 16/32/48/64/128/256)
  resources/icon.icns  (macOS ICNS via iconutil)

Run from the project root:
  python resources/make_icon.py
"""

import os
import struct
import zlib
import shutil
import subprocess
import tempfile

OUT = os.path.dirname(os.path.abspath(__file__))

# ── Minimal PNG writer ────────────────────────────────────────────────────────

def _png_chunk(name: bytes, data: bytes) -> bytes:
    c = zlib.crc32(name + data) & 0xFFFFFFFF
    return struct.pack('>I', len(data)) + name + data + struct.pack('>I', c)

def write_png(path: str, width: int, height: int, pixels):
    """Write an RGBA PNG. pixels is a callable(x, y) -> (r,g,b,a)."""
    raw = b''
    for y in range(height):
        row = b'\x00'  # filter type None
        for x in range(width):
            r, g, b, a = pixels(x, y)
            row += bytes([r, g, b, a])
        raw += row
    compressed = zlib.compress(raw, 9)
    with open(path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        f.write(_png_chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)))
        f.write(_png_chunk(b'IDAT', compressed))
        f.write(_png_chunk(b'IEND', b''))

# ── Icon design ───────────────────────────────────────────────────────────────
# Dark navy rounded square, white iOS phone silhouette, teal magnifier overlay.

def _clamp(v): return max(0, min(255, int(v)))

def _blend(fg, bg, alpha):
    a = alpha / 255
    return tuple(_clamp(fg[i]*a + bg[i]*(1-a)) for i in range(3))

def _rounded_rect(x, y, w, h, cx, cy, r):
    """Return True if (cx,cy) is inside a rounded rectangle at (x,y,w,h) radius r."""
    ix = max(x + r, min(cx, x + w - r))
    iy = max(y + r, min(cy, y + h - r))
    return (cx - ix)**2 + (cy - iy)**2 <= r**2

def _circle(cx, cy, r, px, py):
    return (px - cx)**2 + (py - cy)**2 <= r**2

def _ring(cx, cy, r_outer, r_inner, px, py):
    d2 = (px - cx)**2 + (py - cy)**2
    return r_inner**2 <= d2 <= r_outer**2

def make_pixels(size):
    S = size
    BG   = (15,  30,  60)   # dark navy
    FG   = (240, 245, 255)  # near-white
    TEAL = (0,  200, 180)   # teal magnifier

    pad   = S * 0.08
    phone_w = S * 0.38
    phone_h = S * 0.60
    phone_x = S * 0.25
    phone_y = S * 0.20
    p_r   = S * 0.07

    # screen inset
    si = S * 0.045
    scr_x = phone_x + si
    scr_y = phone_y + si * 2.5
    scr_w = phone_w - si * 2
    scr_h = phone_h - si * 5

    # magnifier — overlapping bottom-right
    mag_cx = S * 0.67
    mag_cy = S * 0.63
    mag_r  = S * 0.20
    mag_ri = S * 0.14
    handle_w = S * 0.065

    def pixel(x, y):
        # background rounded square
        bg_r = S * 0.18
        if not _rounded_rect(pad, pad, S - pad*2, S - pad*2, x, y, bg_r):
            return (0, 0, 0, 0)  # transparent outside

        base = BG

        # phone body
        in_phone = _rounded_rect(phone_x, phone_y, phone_w, phone_h, x, y, p_r)
        # phone screen (navy cutout)
        in_screen = _rounded_rect(scr_x, scr_y, scr_w, scr_h, x, y, p_r * 0.4)
        # home button dot
        hb_cx = phone_x + phone_w / 2
        hb_cy = phone_y + phone_h - si * 1.8
        in_hb = _circle(hb_cx, hb_cy, S * 0.035, x, y)

        if in_phone and not in_screen and not in_hb:
            base = FG
        elif in_phone and in_hb:
            base = FG

        # magnifier ring (teal)
        in_ring = _ring(mag_cx, mag_cy, mag_r, mag_ri, x, y)
        # magnifier handle
        dx = x - (mag_cx + mag_r * 0.68)
        dy = y - (mag_cy + mag_r * 0.68)
        angle_dist = abs(-dx + dy) / 1.414
        along = (dx + dy) / 1.414
        in_handle = (angle_dist < handle_w / 2) and (0 < along < S * 0.20)

        if in_ring or in_handle:
            base = TEAL

        return (*base, 255)

    return pixel

def make_master(size=1024):
    path = os.path.join(OUT, 'icon.png')
    write_png(path, size, size, make_pixels(size))
    print(f'  wrote {path}')
    return path

# ── ICO writer (multi-size) ───────────────────────────────────────────────────

def make_ico(master_path):
    sizes = [16, 32, 48, 64, 128, 256]
    pngs = []
    tmp = tempfile.mkdtemp()
    try:
        for s in sizes:
            p = os.path.join(tmp, f'icon_{s}.png')
            subprocess.run(['sips', '-z', str(s), str(s), master_path, '--out', p],
                           check=True, capture_output=True)
            with open(p, 'rb') as f:
                pngs.append((s, f.read()))

        ico_path = os.path.join(OUT, 'icon.ico')
        _write_ico(ico_path, pngs)
        print(f'  wrote {ico_path}')
    finally:
        shutil.rmtree(tmp)

def _write_ico(path, pngs):
    """Write a simple ICO containing PNG-compressed images (Vista+ format)."""
    n = len(pngs)
    header = struct.pack('<HHH', 0, 1, n)
    offset = 6 + n * 16
    entries = b''
    data_chunks = b''
    for s, data in pngs:
        w = h = s if s < 256 else 0
        entries += struct.pack('<BBBBHHII', w, h, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
        data_chunks += data
    with open(path, 'wb') as f:
        f.write(header + entries + data_chunks)

# ── ICNS (macOS) ──────────────────────────────────────────────────────────────

def make_icns(master_path):
    iconset = tempfile.mkdtemp(suffix='.iconset')
    icns_path = os.path.join(OUT, 'icon.icns')
    try:
        specs = [
            (16, '16x16'), (32, '16x16@2x'),
            (32, '32x32'), (64, '32x32@2x'),
            (128, '128x128'), (256, '128x128@2x'),
            (256, '256x256'), (512, '256x256@2x'),
            (512, '512x512'), (1024, '512x512@2x'),
        ]
        for s, name in specs:
            out = os.path.join(iconset, f'icon_{name}.png')
            subprocess.run(['sips', '-z', str(s), str(s), master_path, '--out', out],
                           check=True, capture_output=True)
        subprocess.run(['iconutil', '-c', 'icns', iconset, '-o', icns_path],
                       check=True, capture_output=True)
        print(f'  wrote {icns_path}')
    finally:
        shutil.rmtree(iconset)

if __name__ == '__main__':
    print('Generating icons...')
    master = make_master(1024)
    make_ico(master)
    make_icns(master)
    print('Done.')
