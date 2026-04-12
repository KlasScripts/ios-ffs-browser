"""streaming_zip.py — forward-scanning index for streaming zip archives.

Standard zipfile requires a central directory at the end of the file.
Cellebrite FFS zips are written with bit 3 set (streaming/on-the-fly),
meaning sizes are zero in the local headers and written in data descriptor
records *after* each file's data.  There is no usable central directory.

StreamingZipIndex scans the file once from the beginning, building a
name → entry table.  The result is saved as a small JSON sidecar file
(same path as the zip with a .zidx extension) so the scan only runs once.

Supported compression methods
------------------------------
  0  ZIP_STORED   — scan for PK\\x07\\x08 data descriptor and validate
  8  ZIP_DEFLATED — decompress in a tight loop to find the boundary

Usage
-----
    idx = StreamingZipIndex.open(zip_path, progress_cb=lambda done, total: ...)
    entry = idx.get_entry(zip_path, "filesystem1/private/var/mobile/sms.db")
    data  = entry.read()
"""

import json
import os
import struct
import zlib

from zip_entry import ZipEntry

# ── Constants ─────────────────────────────────────────────────────────────────

_LFH_SIG  = b'PK\x03\x04'   # local file header
_DD_SIG   = b'PK\x07\x08'   # data descriptor (optional signature)
_SCAN_CHUNK = 1 << 20        # 1 MB read buffer for descriptor scanning
_DECOMP_CHUNK = 1 << 16      # 64 KB decompression chunk


# ── Forward scanner ───────────────────────────────────────────────────────────

def _parse_zip64_extra(extra: bytes, has_uncomp: bool, has_comp: bool
                       ) -> tuple[int, int]:
    """Extract uncomp_size and comp_size from the ZIP64 extended info field."""
    i = 0
    uncomp = comp = -1
    while i + 4 <= len(extra):
        eid, elen = struct.unpack_from('<HH', extra, i)
        if eid == 0x0001:
            vals = struct.unpack_from('<' + 'Q' * (elen // 8), extra, i + 4)
            idx = 0
            if has_uncomp and idx < len(vals):
                uncomp = vals[idx]; idx += 1
            if has_comp and idx < len(vals):
                comp = vals[idx]; idx += 1
            break
        i += 4 + elen
    return uncomp, comp


def _lfh_valid(f, offset: int) -> bool:
    """Return True if offset looks like a plausible outer local file header.

    Checks:
    1. LFH signature present
    2. fname_len in a sane range (1–1024)
    3. extra_len not absurd (≤ 65536)
    4. The filename bytes are printable ASCII / valid path characters
       (no null bytes, no control characters below 0x20 except none)

    Condition 4 is the key discriminator against false positives inside
    large binary files (ML weights, databases, etc.)."""
    pos = f.tell()
    f.seek(offset)
    hdr = f.read(30)
    if len(hdr) < 30 or hdr[:4] != _LFH_SIG:
        f.seek(pos)
        return False
    fname_len = struct.unpack_from('<H', hdr, 26)[0]
    extra_len = struct.unpack_from('<H', hdr, 28)[0]
    if not (1 <= fname_len <= 1024 and extra_len <= 65536):
        f.seek(pos)
        return False
    fname_bytes = f.read(fname_len)
    f.seek(pos)
    if len(fname_bytes) < fname_len:
        return False
    # All bytes must be printable ASCII (0x20–0x7e) or '/' separators
    return all(0x20 <= b <= 0x7e for b in fname_bytes)


def _find_descriptor_stored(f, data_start: int) -> tuple[int, int, int]:
    """Locate the data descriptor after a ZIP_STORED streaming entry.

    Strategy: scan forward for the next outer local file header (PK\\x03\\x04)
    and work backwards to find the data descriptor.  Two descriptor formats
    are tried immediately before each candidate LFH:

    ZIP64    (24 bytes):  sig(4) + crc(4) + comp(8) + uncomp(8)
    Standard (16 bytes):  sig(4) + crc(4) + comp(4) + uncomp(4)

    For a STORED entry comp == uncomp == distance from data_start to the
    descriptor signature.  The LFH is validated (sensible fname_len /
    extra_len) to reject false positives from nested zip files in the data.

    Returns (comp_size, uncomp_size, offset_after_descriptor).
    Raises ValueError if no valid boundary is found."""
    f.seek(data_start)
    # sliding window — keep a 27-byte tail so we can read back into the
    # previous chunk for the descriptor that precedes a straddling LFH.
    # 27 = max(24 descriptor bytes) + 3 overlap to catch the LFH sig.
    overlap = 27
    buf = b''
    buf_base = data_start

    at_eof = False
    while True:
        chunk = f.read(_SCAN_CHUNK)
        if not chunk:
            at_eof = True
        else:
            buf += chunk

        search_start = 0
        while True:
            # At EOF: look for the descriptor at the very end of buf
            # (no following LFH — the descriptor is the last meaningful data)
            if at_eof:
                # Try ZIP64: descriptor is the last 24 bytes before any trailing nulls
                trimmed = buf.rstrip(b'\x00')
                if len(trimmed) >= 24 and trimmed[-24:-20] == _DD_SIG:
                    dd_off = len(trimmed) - 24
                    expected = buf_base + dd_off - data_start
                    crc, comp, uncomp = struct.unpack_from('<IQQ', trimmed, dd_off + 4)
                    if comp == expected and uncomp == expected:
                        return comp, uncomp, buf_base + dd_off + 24
                # Try standard: last 16 bytes
                if len(trimmed) >= 16 and trimmed[-16:-12] == _DD_SIG:
                    dd_off = len(trimmed) - 16
                    expected = buf_base + dd_off - data_start
                    crc, comp, uncomp = struct.unpack_from('<III', trimmed, dd_off + 4)
                    if comp == expected and uncomp == expected:
                        return comp, uncomp, buf_base + dd_off + 16
                raise ValueError("Streaming entry: reached EOF without data descriptor")

            idx = buf.find(_LFH_SIG, search_start)
            if idx == -1:
                break

            abs_lfh = buf_base + idx

            # Validate this is a real outer LFH (not a nested zip header)
            if not _lfh_valid(f, abs_lfh):
                search_start = idx + 1
                continue

            # Try ZIP64 descriptor: 24 bytes before the LFH
            if idx >= 24:
                dd_idx = idx - 24
                if buf[dd_idx:dd_idx + 4] == _DD_SIG:
                    expected = abs_lfh - 24 - data_start
                    crc, comp, uncomp = struct.unpack_from('<IQQ', buf, dd_idx + 4)
                    if comp == expected and uncomp == expected:
                        return comp, uncomp, abs_lfh

            # Try standard descriptor: 16 bytes before the LFH
            if idx >= 16:
                dd_idx = idx - 16
                if buf[dd_idx:dd_idx + 4] == _DD_SIG:
                    expected = abs_lfh - 16 - data_start
                    crc, comp, uncomp = struct.unpack_from('<III', buf, dd_idx + 4)
                    if comp == expected and uncomp == expected:
                        return comp, uncomp, abs_lfh

            search_start = idx + 1

        if at_eof:
            raise ValueError("Streaming entry: reached EOF without data descriptor")

        # Discard all but the overlap tail; advance buf_base accordingly
        tail = buf[-overlap:]
        buf_base += len(buf) - overlap
        buf = tail


def _find_descriptor_deflated(f, data_start: int) -> tuple[int, int, int]:
    """Decompress a ZIP_DEFLATED streaming entry to find its boundary.

    Returns (comp_size, uncomp_size, offset_after_descriptor)."""
    f.seek(data_start)
    dec = zlib.decompressobj(wbits=-15)
    comp_read = 0
    uncomp_size = 0

    while True:
        chunk = f.read(_DECOMP_CHUNK)
        if not chunk:
            raise ValueError("Streaming deflated entry: EOF before stream end")
        out = dec.decompress(chunk)
        uncomp_size += len(out)
        if dec.unused_data:
            # decompressor stopped inside this chunk — the rest is the descriptor
            comp_read += len(chunk) - len(dec.unused_data)
            break
        comp_read += len(chunk)

    # data descriptor: optional PK\x07\x08 + crc(4) + comp + uncomp
    # Sizes may be 4-byte (standard) or 8-byte (ZIP64).
    abs_after_data = data_start + comp_read
    f.seek(abs_after_data)
    peek = f.read(4)
    if peek == _DD_SIG:
        # Peek at next 8 bytes to distinguish ZIP64 from standard
        desc = f.read(20)   # crc(4) + up to comp(8) + uncomp(8)
        # If the 4-byte comp matches comp_read it's standard; else ZIP64
        crc, comp4, uncomp4 = struct.unpack_from('<III', desc, 0)
        if comp4 == comp_read:
            after = abs_after_data + 16   # sig(4) + crc(4) + comp(4) + uncomp(4)
        else:
            after = abs_after_data + 24   # sig(4) + crc(4) + comp(8) + uncomp(8)
    else:
        # No signature — try 4-byte variant
        desc = f.read(8)
        crc, comp4, uncomp4 = struct.unpack_from('<III', peek + desc[:8], 0)
        if comp4 == comp_read:
            after = abs_after_data + 12
        else:
            after = abs_after_data + 20   # ZIP64 no-sig: crc(4) + comp(8) + uncomp(8)

    return comp_read, uncomp_size, after


def _find_next_lfh(f, start: int) -> int | None:
    """Scan forward from *start* for the next valid outer local file header.

    Returns the absolute offset of the LFH, or None if EOF is reached."""
    f.seek(start)
    overlap = 3
    buf = b''
    buf_base = start

    while True:
        chunk = f.read(_SCAN_CHUNK)
        if not chunk:
            # Check the tail of buf for a straddling signature
            idx = buf.find(_LFH_SIG)
            while idx != -1:
                if _lfh_valid(f, buf_base + idx):
                    return buf_base + idx
                idx = buf.find(_LFH_SIG, idx + 1)
            return None
        buf += chunk

        search_start = 0
        while True:
            idx = buf.find(_LFH_SIG, search_start)
            if idx == -1:
                break
            if _lfh_valid(f, buf_base + idx):
                return buf_base + idx
            search_start = idx + 1

        tail = buf[-overlap:]
        buf_base += len(buf) - overlap
        buf = tail


def _scan(zip_path: str, progress_cb=None) -> dict:
    """Scan *zip_path* forward and return {name: [data_offset, comp, uncomp, method]}."""
    file_size = os.path.getsize(zip_path)
    entries = {}

    with open(zip_path, 'rb') as f:
        offset = 0
        while True:
            f.seek(offset)
            sig = f.read(4)
            if sig != _LFH_SIG:
                break

            hdr = f.read(26)
            if len(hdr) < 26:
                break

            flags     = struct.unpack_from('<H', hdr, 2)[0]
            method    = struct.unpack_from('<H', hdr, 4)[0]
            comp_size = struct.unpack_from('<I', hdr, 14)[0]
            uncomp    = struct.unpack_from('<I', hdr, 18)[0]
            fname_len = struct.unpack_from('<H', hdr, 22)[0]
            extra_len = struct.unpack_from('<H', hdr, 24)[0]

            fname = f.read(fname_len).decode('utf-8', errors='replace')
            extra = f.read(extra_len)

            data_offset = offset + 4 + 26 + fname_len + extra_len
            streaming = bool(flags & 0x0008)

            if not streaming:
                # Sizes are known — handle ZIP64
                actual_comp   = comp_size
                actual_uncomp = uncomp
                if comp_size == 0xFFFFFFFF or uncomp == 0xFFFFFFFF:
                    u, c = _parse_zip64_extra(extra,
                                              uncomp    == 0xFFFFFFFF,
                                              comp_size == 0xFFFFFFFF)
                    if u >= 0: actual_uncomp = u
                    if c >= 0: actual_comp   = c
                entries[fname] = [data_offset, actual_comp, actual_uncomp, method]
                offset = data_offset + actual_comp
            else:
                # Bit 3 set — find the real sizes
                try:
                    if method == 0:   # STORED
                        comp, uncomp_real, after = _find_descriptor_stored(f, data_offset)
                    else:             # DEFLATED (and others)
                        comp, uncomp_real, after = _find_descriptor_deflated(f, data_offset)
                except ValueError:
                    # Truncated/incomplete entry — skip it and try to resume
                    # by scanning forward for the next valid LFH
                    after = _find_next_lfh(f, data_offset)
                    if after is None:
                        break   # genuinely no more entries
                    offset = after
                    continue
                entries[fname] = [data_offset, comp, uncomp_real, method]
                offset = after

            if progress_cb and len(entries) % 5000 == 0:
                progress_cb(offset, file_size)

    return entries


# ── Index class ───────────────────────────────────────────────────────────────

class StreamingZipIndex:
    """In-memory index of a streaming zip, optionally persisted as a sidecar."""

    _SIDECAR_EXT = '.zidx'

    def __init__(self, zip_path: str, entries: dict) -> None:
        self.zip_path = zip_path
        self._entries = entries          # name → [data_offset, comp, uncomp, method]

    # ── Construction ──────────────────────────────────────────────────────────

    @classmethod
    def open(cls, zip_path: str, progress_cb=None) -> "StreamingZipIndex":
        """Return a StreamingZipIndex for *zip_path*.

        Loads the sidecar index if it exists and is newer than the zip;
        otherwise scans the zip and saves the sidecar."""
        sidecar = zip_path + cls._SIDECAR_EXT
        if os.path.exists(sidecar):
            if os.path.getmtime(sidecar) >= os.path.getmtime(zip_path):
                with open(sidecar, 'r', encoding='utf-8') as f:
                    entries = json.load(f)
                return cls(zip_path, entries)

        entries = _scan(zip_path, progress_cb)
        try:
            with open(sidecar, 'w', encoding='utf-8') as f:
                json.dump(entries, f, separators=(',', ':'))
        except OSError:
            pass  # read-only media — index lives in memory only

        return cls(zip_path, entries)

    # ── Query interface ───────────────────────────────────────────────────────

    def namelist(self) -> list[str]:
        return list(self._entries.keys())

    def __contains__(self, name: str) -> bool:
        return name in self._entries

    def get_entry(self, name: str) -> ZipEntry:
        """Return a ZipEntry for *name*, or raise KeyError."""
        row = self._entries[name]
        data_offset, comp, uncomp, method = row
        return ZipEntry.from_parts(
            zip_path      = self.zip_path,
            physical_path = name,
            data_offset   = data_offset,
            file_size     = uncomp,
            compress_type = method,
        )
