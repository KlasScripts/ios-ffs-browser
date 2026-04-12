"""zip_entry.py — lightweight wrapper around a single zip archive entry.

ZipEntry is the object passed to every viewer.  It encapsulates the two
read strategies so callers never have to know which one applies:

* ZIP_STORED   → seek directly into the raw zip file (zero decompression).
* ZIP_DEFLATED → fall back to zipfile.ZipFile.open() (standard decompress).

Two construction paths are supported:
* ZipEntry(zip_path, physical_path, zinfo)  — from a zipfile.ZipInfo
* ZipEntry.from_parts(...)                  — from a StreamingZipIndex entry

The sqlite_uri() helper exposes the SQLite "file:?offset=&immutable=1" URI
so a SQLite viewer can open a database that lives inside a zip with no
extraction at all, provided it is stored uncompressed (which is almost
always true for iOS FFS archives).
"""

import struct
import zipfile


class ZipEntry:
    """A handle to one file inside a zip archive."""

    def __init__(self, zip_path: str, physical_path: str,
                 zinfo: zipfile.ZipInfo) -> None:
        self.zip_path      = zip_path
        self.physical_path = physical_path
        self._file_size    = zinfo.file_size
        self._compress_type = zinfo.compress_type
        # data_offset is resolved lazily from the local header
        self._header_offset = zinfo.header_offset
        self._data_offset: int | None = None

    @classmethod
    def from_parts(cls, zip_path: str, physical_path: str,
                   data_offset: int, file_size: int,
                   compress_type: int) -> "ZipEntry":
        """Construct a ZipEntry from raw values (e.g. from StreamingZipIndex)."""
        obj = object.__new__(cls)
        obj.zip_path       = zip_path
        obj.physical_path  = physical_path
        obj._file_size     = file_size
        obj._compress_type = compress_type
        obj._header_offset = None   # not available from streaming index
        obj._data_offset   = data_offset   # already known — no header re-read needed
        return obj

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def file_size(self) -> int:
        return self._file_size

    @property
    def is_stored(self) -> bool:
        return self._compress_type == zipfile.ZIP_STORED

    # ── Offset resolution ─────────────────────────────────────────────────────

    @property
    def data_offset(self) -> int:
        """Byte offset of the raw entry data within the zip file.

        For ZipInfo-based entries: computed once from the local file header
        (header_offset + 30 + filename_len + extra_len).
        For streaming-index entries: already known at construction time."""
        if self._data_offset is None:
            with open(self.zip_path, 'rb') as f:
                f.seek(self._header_offset + 26)
                fname_len, extra_len = struct.unpack('<HH', f.read(4))
            self._data_offset = self._header_offset + 30 + fname_len + extra_len
        return self._data_offset

    # ── Reading ───────────────────────────────────────────────────────────────

    def read(self, limit: int | None = None) -> bytes:
        """Return up to *limit* bytes from the start of the entry.

        Uses a direct file seek for STORED entries; falls back to
        zipfile decompression for compressed entries."""
        size = self._file_size if limit is None else min(self._file_size, limit)
        if self.is_stored:
            with open(self.zip_path, 'rb') as f:
                f.seek(self.data_offset)
                return f.read(size)
        with zipfile.ZipFile(self.zip_path) as z:
            with z.open(self.physical_path) as f:
                return f.read(size) if limit is not None else f.read()

    def read_at(self, offset: int, limit: int) -> bytes:
        """Read *limit* bytes starting at *offset* within the entry data.

        Only supported for ZIP_STORED entries — raises ValueError otherwise.
        Used by the hex viewer to page in additional data on scroll."""
        if not self.is_stored:
            raise ValueError("read_at requires a ZIP_STORED entry")
        with open(self.zip_path, 'rb') as f:
            f.seek(self.data_offset + offset)
            return f.read(limit)

    # ── SQLite helper ─────────────────────────────────────────────────────────

    def sqlite_uri(self) -> str | None:
        """Return a SQLite URI that opens this entry in-place (STORED only).

        Example result:
            file:/path/to/archive.zip?offset=12345&immutable=1

        Returns None for compressed entries — caller must extract first."""
        if not self.is_stored:
            return None
        return f"file:{self.zip_path}?offset={self.data_offset}&immutable=1"
