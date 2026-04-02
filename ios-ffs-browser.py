import sys
import os
import re
import time
import struct
import zipfile
import msgpack
import json
import subprocess
import plistlib
import pathlib
from adapters import graykey as graykey_adapter
from datetime import datetime, timezone
from PySide6.QtWidgets import (QApplication, QMainWindow, QTreeView, QTableView, QVBoxLayout,
                              QHBoxLayout, QWidget, QHeaderView, QPushButton,
                              QFileDialog, QProgressBar, QMenu, QDialog,
                              QRadioButton, QButtonGroup, QComboBox, QSplitter, QStatusBar,
                              QLineEdit, QLabel, QPlainTextEdit, QFrame, QTextEdit)
from PySide6.QtGui import (QStandardItemModel, QStandardItem, QAction, QFont,
                           QCursor, QColor, QTextCharFormat, QTextCursor, QFontMetricsF,
                           QIcon)
from PySide6.QtCore import Qt, QThread, Signal, QSortFilterProxyModel, QTimer, QEvent, QModelIndex, QAbstractTableModel

SETTINGS_FILE = "forensic_settings.json"
RECENT_FILE = "recent_archives.json"
NEW_ARCHIVE_SENTINEL = "<Open New FFS...>"
EDIT_FILTER_MODE = 1

# Files that exist only to carry container metadata; a folder containing
# nothing but these is treated as "Metadata Only" rather than user content.
# Hex viewer layout constants — must stay in sync with _render_hex()
# Format: "XXXXXXXX  [GRP0]  [GRP1]  …  [GRP7]  ASCII…"
# Each group: "XX XX XX XX" = 11 chars; groups separated by 2 spaces.
_HEX_OFFSET_COLS  = 10   # width of "XXXXXXXX  "
_HEX_GROUP_STRIDE = 13   # 11 chars/group + 2-char separator
_HEX_GROUPS       = 8
_HEX_BYTES_PER_ROW = 32
_HEX_ASCII_START  = _HEX_OFFSET_COLS + _HEX_GROUPS * _HEX_GROUP_STRIDE - 2 + 2
# = 10 + 8*13 - 2 + 2 = 114  (subtract trailing sep that doesn't exist, add "  " before ASCII)

INITIAL_HEX_BYTES = 16384   # bytes shown immediately on open
HEX_PAGE_BYTES    = 32768   # bytes loaded per scroll page
MAX_HEX_HIGHLIGHT_BYTES = 512   # cap on simultaneous byte highlights
FRAME_BUDGET_SECS = 0.016   # ~16 ms per batch (one frame budget)

# Precomputed table: maps each byte value to its printable ASCII char or '.'
_ASCII_XLAT = bytes(b if 32 <= b < 127 else ord('.') for b in range(256))

def resource_path(relative):
    """Works both in development and when bundled by PyInstaller."""
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative)
  
def _hex_col_to_byte(col: int) -> int | None:
    """Map a column index within a hex line to its byte index (0-31), or None."""
    if col < _HEX_OFFSET_COLS:
        return None
    rel   = col - _HEX_OFFSET_COLS
    group = rel // _HEX_GROUP_STRIDE
    within = rel % _HEX_GROUP_STRIDE
    if group >= _HEX_GROUPS or within >= 11:
        return None
    b_in_grp = within // 3
    return (group * 4 + b_in_grp) if b_in_grp < 4 else None


def _ascii_col_to_byte(col: int) -> int | None:
    """Map a column index in the ASCII section of a hex line to its byte index, or None."""
    if col < _HEX_ASCII_START:
        return None
    b = col - _HEX_ASCII_START
    return b if b < _HEX_BYTES_PER_ROW else None


_SYSTEM_METADATA_NAMES: frozenset = frozenset({
    ".com.apple.mobile_container_manager.metadata.plist",
    ".com.apple.FairPlay.MachineIdentifier",
    ".com.apple.springboard.shortcuts",
})
_TREE_PLACEHOLDER = "__placeholder__"
_UUID_RE = re.compile(
    r'^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
)
CLEAN_MODE = 2

FORENSIC_SHORTCUTS = [
    ("App Data", "mobile/Containers/Data/Application"),
    ("App Data Plugins", "mobile/Containers/Data/PluginKitPlugin"),
    ("App Data Shared", "mobile/Containers/Shared/AppGroup"),
    None,  # separator
    ("Communications", [
        ("SMS / iMessage",          "mobile/Library/SMS"),
        ("Call History",            "wireless/Library/CallHistoryDatabase"),
        ("Contacts",                "mobile/Library/AddressBook"),
        ("Mail",                    "mobile/Library/Mail"),
        ("Voicemail",               "wireless/Library/Voicemail"),
    ]),
    ("Media", [
        ("Photos (DCIM)",           "mobile/Media/DCIM"),
        ("Photo Library Data",      "mobile/Media/PhotoData"),
        ("Voice Memos",             "mobile/Media/Recordings"),
    ]),
    ("Browsing & Web", [
        ("Safari",                  "mobile/Library/Safari"),
        ("Safari Downloads — iOS 13+","mobile/Library/Safari/Downloads"),
        ("Safari Reading List",     "mobile/Library/Safari/ReadingListArchives"),
    ]),
    ("System & Device", [
        ("Biome — iOS 14+",         "mobile/Library/Biome"),
        ("KnowledgeC — iOS 9+",     "mobile/Library/CoreDuet/Knowledge"),
        ("Health",                  "mobile/Library/Health"),
        ("Calendar",                "mobile/Library/Calendar"),
        ("Notes",                   "mobile/Library/NoteStore"),
        ("Reminders",               "mobile/Library/Reminders"),
        ("Location History",        "mobile/Library/Caches/com.apple.routined"),
        ("Keychain",                "private/var/Keychains"),
        ("Wi-Fi Networks",          "wireless/Library/Preferences"),
        ("Device Logs",             "mobile/Library/Logs"),
        ("Unified Logs — iOS 10+",          "private/var/db/diagnostics"),
        ("Unified Logs UUID Text — iOS 10+","private/var/db/uuidtext"),
    ]),
    ("Installed Apps", [
        ("App Executables",             "mobile/Containers/Bundle/Application"),
        ("Crash Reports",           "mobile/Library/Logs/CrashReporter"),
    ]),
]

PICTURE_EXTENSIONS = {
    '.jpg', '.jpeg', '.heic', '.heif', '.png', '.gif',
    '.bmp', '.tiff', '.tif', '.webp', '.raw', '.cr2', '.nef', '.dng',
}
VIDEO_EXTENSIONS = {
    '.mp4', '.mov', '.avi', '.mkv', '.m4v', '.wmv',
    '.flv', '.webm', '.3gp', '.mts', '.m2ts', '.mpg', '.mpeg',
}
DATABASE_EXTENSIONS = {
    '.db', '.sqlite', '.sqlite3', '.db3',
    '.db-wal', '.db-shm', '.db-journal',
    '.sqlite-wal', '.sqlite-shm', '.sqlite-journal',
}
LOG_EXTENSIONS = {
    '.log', '.ips', '.crash', '.clslog', '.logarchive',
}
DOCUMENT_EXTENSIONS = {
    '.pdf', '.txt', '.rtf', '.csv',
    '.doc', '.docx', '.pages', '.numbers', '.key',
    '.xls', '.xlsx', '.ppt', '.pptx',
}
AUDIO_EXTENSIONS = {
    '.mp3', '.m4a', '.aac', '.wav', '.flac', '.aiff', '.aif',
    '.caf', '.opus', '.ogg', '.amr', '.wma',
}
ARCHIVE_EXTENSIONS = {
    '.zip', '.gz', '.tar', '.bz2', '.xz', '.ipa',
    '.tgz', '.tbz', '.zst', '.aar',
}
WEB_DATA_EXTENSIONS = {
    '.html', '.htm', '.json', '.xml', '.js', '.css', '.ts',
    '.yaml', '.yml', '.toml',
}
CERTIFICATE_EXTENSIONS = {
    '.pem', '.cer', '.crt', '.der', '.p12', '.p7s', '.p8', '.pfx',
}


def _get_file_type(name, is_folder):
    if is_folder:
        return 'Folder'
    ext = os.path.splitext(name)[1].lower()
    # Check multi-part extensions first (.db-wal etc.)
    lower_name = name.lower()
    for db_ext in ('.db-wal', '.db-shm', '.db-journal',
                   '.sqlite-wal', '.sqlite-shm', '.sqlite-journal'):
        if lower_name.endswith(db_ext):
            return 'Database'
    if ext in PICTURE_EXTENSIONS:       return 'Picture'
    if ext in VIDEO_EXTENSIONS:         return 'Video'
    if ext in DATABASE_EXTENSIONS:      return 'Database'
    if ext == '.plist':                 return 'Property List'
    if ext in LOG_EXTENSIONS:           return 'Log'
    if ext in DOCUMENT_EXTENSIONS:      return 'Document'
    if ext in AUDIO_EXTENSIONS:         return 'Audio'
    if ext in ARCHIVE_EXTENSIONS:       return 'Archive'
    if ext in WEB_DATA_EXTENSIONS:      return 'Web / Data'
    if ext in CERTIFICATE_EXTENSIONS:   return 'Certificate'
    return 'Other'


def _detect_cellebrite_prefix(zip_names: frozenset) -> str:
    """Return the filesystemN prefix that contains the user partition.
    Checks for folders unique to the iOS user partition (mobile, wireless).
    Tries filesystem1 through filesystem9; falls back to filesystem2."""
    for n in range(1, 10):
        prefix = f"filesystem{n}"
        for root in ('mobile', 'wireless'):
            if f"{prefix}/{root}/" in zip_names or f"{prefix}/{root}" in zip_names:
                return prefix
    return "filesystem2"


def _make_cellebrite_path(prefix: str):
    """Return a path resolver that maps ui_paths to physical zip paths under prefix."""
    def _resolve(ui_path: str) -> str:
        parts = []
        for part in ui_path.split('/'):
            if '-' in part:
                suffix = part.split('-')[-1]
                if len(suffix) >= 32 and all(c in '0123456789abcdefABCDEF' for c in suffix):
                    parts.append(suffix)
                    continue
            parts.append(part)
        return f"{prefix}/{'/'.join(parts)}"
    return _resolve


def _graykey_path(ui_path: str) -> str:
    """Resolve a ui_path to its physical location inside a Graykey zip."""
    return '/private/var/' + ui_path


def _load_json_file(path, default):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def _make_item(text):
    item = QStandardItem(text)
    item.setEditable(False)
    return item


class ExtractorWorker(QThread):
    file_count = Signal(int)          # total files, emitted once before loop
    progress   = Signal(int, int)     # (current, total)
    status     = Signal(str)
    finished   = Signal(bool, str, str)

    def __init__(self, zip_path, export_tasks, dest_dir, folder_map, path_resolver):
        super().__init__()
        self.zip_path = zip_path
        self.export_tasks = export_tasks
        self.dest_dir = dest_dir
        self.folder_map = folder_map
        self.path_resolver = path_resolver
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        _CHUNK = 1024 * 1024  # 1 MB copy buffer
        try:
            self.status.emit("Initializing extraction...")

            # Build the file queue and pre-fetch all ZipInfo in one pass
            with zipfile.ZipFile(self.zip_path, 'r') as z:
                final_queue = []
                for ui_logical_path, base_parent in self.export_tasks:
                    if ui_logical_path in self.folder_map:
                        children = self._get_all_children(ui_logical_path)
                        for child in children:
                            rel = os.path.relpath(child, start=base_parent)
                            final_queue.append((child, rel))
                    else:
                        rel = os.path.basename(ui_logical_path)
                        final_queue.append((ui_logical_path, rel))

                total = len(final_queue)
                if total == 0:
                    self.finished.emit(False, "No files found to export.", "")
                    return

                # Pre-fetch ZipInfo for every file (one central-directory lookup each)
                zip_infos = {}
                for ui_path, _ in final_queue:
                    phys = self.path_resolver(ui_path)
                    try:
                        zip_infos[phys] = z.getinfo(phys)
                    except KeyError:
                        pass

            self.file_count.emit(total)

            # Single raw file handle stays open for all STORED reads
            with open(self.zip_path, 'rb') as raw_f, \
                 zipfile.ZipFile(self.zip_path, 'r') as z:

                for i, (ui_path, rel_path) in enumerate(final_queue):
                    if self._cancelled:
                        self.finished.emit(False, "Export cancelled.", "")
                        return

                    physical_path = self.path_resolver(ui_path)
                    path_segments = list(os.path.split(rel_path))
                    if path_segments[1].startswith('.'):
                        path_segments[1] = '_' + path_segments[1][1:]
                    sanitized_rel = os.path.join(*path_segments)
                    dest_path = os.path.join(self.dest_dir, sanitized_rel)
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

                    if i % 50 == 0 or i == total - 1:
                        self.status.emit(sanitized_rel)

                    zinfo = zip_infos.get(physical_path)
                    if zinfo is None:
                        continue

                    try:
                        if zinfo.compress_type == zipfile.ZIP_STORED:
                            raw_f.seek(zinfo.header_offset + 26)
                            fname_len, extra_len = struct.unpack('<HH', raw_f.read(4))
                            raw_f.seek(zinfo.header_offset + 30 + fname_len + extra_len)
                            remaining = zinfo.file_size
                            with open(dest_path, 'wb') as target:
                                while remaining > 0:
                                    chunk = raw_f.read(min(_CHUNK, remaining))
                                    if not chunk:
                                        break
                                    target.write(chunk)
                                    remaining -= len(chunk)
                        else:
                            with z.open(physical_path) as source, \
                                 open(dest_path, 'wb') as target:
                                while chunk := source.read(_CHUNK):
                                    target.write(chunk)
                    except KeyError:
                        continue

                    self.progress.emit(i + 1, total)

            self.finished.emit(True, f"Successfully exported {total} items.", self.dest_dir)
        except Exception as e:
            self.finished.emit(False, f"Export Failed: {str(e)}", "")

    def _get_all_children(self, path, visited=None):
        if visited is None:
            visited = set()
        if path in visited:
            return []
        visited.add(path)
        children = []
        if path in self.folder_map:
            for sub_path in self.folder_map[path]:
                if sub_path in self.folder_map:
                    children.extend(self._get_all_children(sub_path, visited))
                else:
                    children.append(sub_path)
        else:
            children.append(path)
        return children


class ZipMetadataWorker(QThread):
    status_update = Signal(str)
    metadata_ready = Signal(dict, dict, dict, object, object, object)

    def __init__(self, zip_path):
        super().__init__()
        self.zip_path = zip_path

    def run(self):
        try:
            self.status_update.emit("Opening Archive...")
            with zipfile.ZipFile(self.zip_path, 'r') as z:
                zip_names = frozenset(z.namelist())
                self.status_update.emit("Mapping Bundle IDs to GUIDs...")
                guid_to_bundle = {}
                meta_name = ".com.apple.mobile_container_manager.metadata.plist"

                meta_files = (f for f in zip_names if f.endswith(meta_name))
                for mp in meta_files:
                    try:
                        guid = mp.split('/')[-2]
                        with z.open(mp) as f:
                            plist = plistlib.loads(f.read())
                            bid = plist.get("MCMMetadataIdentifier")
                            if bid:
                                guid_to_bundle[guid] = bid
                    except (KeyError, OSError, plistlib.InvalidFileException):
                        continue

                if graykey_adapter._is_graykey(z):
                    self.status_update.emit("Graykey archive detected — extracting metadata...")
                    raw_data = graykey_adapter.extract_metadata(self.zip_path)
                    # Strip '/private/var/' prefix so ui_paths match Cellebrite paths
                    # (e.g. '/private/var/mobile/...' → 'mobile/...')
                    _GK_PREFIX = '/private/var/'
                    raw_data = {
                        k[len(_GK_PREFIX):] if k.startswith(_GK_PREFIX) else k.lstrip('/'): v
                        for k, v in raw_data.items()
                    }
                    path_resolver = _graykey_path
                else:
                    self.status_update.emit("Reading metadata.msgpack...")
                    with z.open('metadata2/metadata.msgpack') as f:
                        raw_data = msgpack.unpack(f)
                    prefix = _detect_cellebrite_prefix(zip_names)
                    path_resolver = _make_cellebrite_path(prefix)

            self.status_update.emit(f"Building folder tree ({len(raw_data):,} entries)...")
            ui_metadata = {}
            # Use sets for O(1) child-membership checks during orphan reconnection.
            folder_map_sets: dict[str, set] = {}

            for ui_path, meta in raw_data.items():
                ui_metadata[ui_path] = meta
                parent_path = ui_path.rsplit('/', 1)[0] if '/' in ui_path else ""
                folder_map_sets.setdefault(parent_path, set()).add(ui_path)

            # Reconnect orphaned directories whose intermediate parents have no
            # explicit zip entry (common in Graykey archives).
            # Using set membership keeps this O(n·depth) instead of O(n²).
            self.status_update.emit("Resolving folder hierarchy...")
            for path in list(folder_map_sets.keys()):
                current = path
                while current:
                    parent = current.rsplit('/', 1)[0] if '/' in current else ""
                    if parent not in folder_map_sets:
                        folder_map_sets[parent] = {current}
                    elif current not in folder_map_sets[parent]:   # O(1) set check
                        folder_map_sets[parent].add(current)
                    else:
                        break
                    current = parent

            # Convert sets → lists now that all mutations are done.
            folder_map = {k: list(v) for k, v in folder_map_sets.items()}

            # Find UUID-shaped container folders (in the three known locations)
            # that have no bundle ID mapping — their metadata.plist is absent
            # or unreadable, which may indicate a corrupt/incomplete download.
            _CONTAINER_PARENTS = (
                "mobile/Containers/Data/Application",
                "mobile/Containers/Data/PluginKitPlugin",
                "mobile/Containers/Shared/AppGroup",
            )
            missing_plist_paths = [
                p for p in folder_map
                if p.rsplit('/', 1)[0] in _CONTAINER_PARENTS
                and _UUID_RE.match(p.split('/')[-1])
                and p.split('/')[-1] not in guid_to_bundle
            ]

            self.metadata_ready.emit(ui_metadata, folder_map, guid_to_bundle, zip_names, path_resolver, missing_plist_paths)
        except Exception as e:
            self.status_update.emit(f"Error: {str(e)}")


def _stored_entry_offset(zip_path: str, physical_path: str,
                          zf: zipfile.ZipFile | None = None):
    """Return (data_offset, file_size) for a ZIP_STORED entry.
    Returns (None, file_size) if the entry is compressed.
    Pass an already-open ZipFile as *zf* to avoid re-parsing the central directory."""
    if zf is not None:
        zinfo = zf.getinfo(physical_path)
        file_size     = zinfo.file_size
        compress_type = zinfo.compress_type
        header_offset = zinfo.header_offset
    else:
        with zipfile.ZipFile(zip_path, 'r') as z:
            zinfo = z.getinfo(physical_path)
            file_size     = zinfo.file_size
            compress_type = zinfo.compress_type
            header_offset = zinfo.header_offset
    if compress_type != zipfile.ZIP_STORED:
        return None, file_size
    # Local file header: 30 fixed bytes + filename_len + extra_len
    with open(zip_path, 'rb') as raw:
        raw.seek(header_offset + 26)
        fname_len, extra_len = struct.unpack('<HH', raw.read(4))
    return header_offset + 30 + fname_len + extra_len, file_size


class HexLoadWorker(QThread):
    progress    = Signal(int, int)   # bytes_read, total_bytes
    load_complete = Signal(bytes)
    error       = Signal(str)

    CHUNK = 8192
    LIMIT = 65536

    def __init__(self, zip_path, physical_path, total_size):
        super().__init__()
        self.zip_path      = zip_path
        self.physical_path = physical_path
        self.total_bytes   = min(total_size, self.LIMIT) if total_size > 0 else self.LIMIT

    def run(self):
        try:
            data = bytearray()
            with zipfile.ZipFile(self.zip_path, 'r') as z:
                with z.open(self.physical_path) as f:
                    while len(data) < self.LIMIT:
                        chunk = f.read(self.CHUNK)
                        if not chunk:
                            break
                        data.extend(chunk)
                        self.progress.emit(len(data), self.total_bytes)
            self.load_complete.emit(bytes(data[:self.LIMIT]))
        except Exception as e:
            self.error.emit(str(e))


_FILTER_CHUNK = 8000   # rows processed per frame during incremental filter


class FileTableModel(QAbstractTableModel):
    """Lightweight table model backed by a plain Python list.
    Dramatically faster than QStandardItemModel for large row counts:
    no per-cell QStandardItem allocation, sort() runs as a native
    Python list sort, and filtering is incremental (chunked per frame)
    so the visible row count decreases live while filtering runs."""

    filter_progress = Signal(int, int)   # (visible, total)
    filter_done     = Signal(int, int)   # (visible, total)

    _GREY_COLOR = QColor(Qt.GlobalColor.darkGray)
    _BOLD_FONT  = QFont("Arial", weight=QFont.Weight.Bold)

    def __init__(self, headers, parent=None):
        super().__init__(parent)
        self._headers  = list(headers)
        self._all_rows = []   # all rows, never modified by filtering
        self._rows     = []   # currently visible (filtered) rows
        self._files_col = self._headers.index('Files') if 'Files' in self._headers else -1
        self._filter_gen = 0  # bump to cancel an in-flight filter

    # ── required overrides ──────────────────────────────────────────────────

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._headers)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self._rows):
            return None
        row = self._rows[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            cols = row[0]
            return cols[col] if col < len(cols) else None
        if role == Qt.ItemDataRole.UserRole:
            return row[1]
        if role == Qt.ItemDataRole.UserRole + 1:
            return row[2]
        if role == Qt.ItemDataRole.ForegroundRole:
            return self._GREY_COLOR if row[4] else None
        if role == Qt.ItemDataRole.FontRole:
            return self._BOLD_FONT if row[3] else None
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self._headers[section] if 0 <= section < len(self._headers) else None
        return None

    # ── bulk mutation ────────────────────────────────────────────────────────

    def append_rows_batch(self, rows):
        """Append rows to both _all_rows and _rows (no active filter)."""
        if not rows:
            return
        first = len(self._rows)
        last  = first + len(rows) - 1
        self.beginInsertRows(QModelIndex(), first, last)
        self._all_rows.extend(rows)
        self._rows.extend(rows)
        self.endInsertRows()

    # ── filtering ────────────────────────────────────────────────────────────

    def set_filter(self, text, col):
        """Start an incremental filter. Clears visible rows immediately, then
        adds matching rows in chunks so the UI count updates live."""
        self._filter_gen += 1
        my_gen = self._filter_gen
        needle = text.lower()
        ncols  = self.columnCount()
        check_cols = list(range(ncols)) if col < 0 else [col]
        total  = len(self._all_rows)

        # Clear visible rows immediately
        self.beginResetModel()
        self._rows = []
        self.endResetModel()

        if not needle:
            # No filter — restore all rows in one shot
            self.beginInsertRows(QModelIndex(), 0, total - 1)
            self._rows = list(self._all_rows)
            self.endInsertRows()
            self.filter_done.emit(total, total)
            return

        source = self._all_rows
        idx = [0]

        def _chunk():
            if self._filter_gen != my_gen:
                return  # superseded
            end = min(idx[0] + _FILTER_CHUNK, total)
            matched = [
                r for r in source[idx[0]:end]
                if any(r[0][c].lower().find(needle) != -1
                       for c in check_cols if c < len(r[0]))
            ]
            if matched:
                first = len(self._rows)
                last  = first + len(matched) - 1
                self.beginInsertRows(QModelIndex(), first, last)
                self._rows.extend(matched)
                self.endInsertRows()
            idx[0] = end
            self.filter_progress.emit(len(self._rows), total)
            if idx[0] < total:
                QTimer.singleShot(0, _chunk)
            else:
                self.filter_done.emit(len(self._rows), total)

        QTimer.singleShot(0, _chunk)

    # ── sorting ──────────────────────────────────────────────────────────────

    def sort(self, column, order=Qt.SortOrder.AscendingOrder):
        """Sort both _all_rows and _rows so sort survives re-filtering."""
        self.layoutAboutToBeChanged.emit()
        reverse = (order == Qt.SortOrder.DescendingOrder)
        key = (lambda r: r[2]) if column == self._files_col else \
              (lambda r: r[0][column].lower() if column < len(r[0]) and r[0][column] else '')
        self._all_rows.sort(key=key, reverse=reverse)
        self._rows.sort(key=key, reverse=reverse)
        self.layoutChanged.emit()


class MultiColumnFilterProxy(QSortFilterProxyModel):
    """Thin proxy used only for sort delegation — filtering is now handled
    inside FileTableModel so filterAcceptsRow always returns True."""

    def sort(self, column, order=Qt.SortOrder.AscendingOrder):
        src = self.sourceModel()
        if src is not None:
            src.sort(column, order)
            self.invalidate()

    def set_filter(self, text, col):
        src = self.sourceModel()
        if src is not None:
            src.set_filter(text, col)


class ExportProgressDialog(QDialog):
    cancel_requested = Signal()

    def __init__(self, dest_dir: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Exporting Files")
        self.setMinimumWidth(540)
        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        )
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self._running = True

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)

        dest_label = QLabel(f"<b>Destination:</b> {dest_dir}")
        dest_label.setWordWrap(True)
        layout.addWidget(dest_label)

        self._count_label = QLabel("Preparing export…")
        layout.addWidget(self._count_label)

        self._bar = QProgressBar()
        self._bar.setRange(0, 0)   # indeterminate until file_count arrives
        layout.addWidget(self._bar)

        self._status_label = QLabel()
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.clicked.connect(self._on_cancel)
        btn_row.addWidget(self._cancel_btn)
        self._ok_btn = QPushButton("OK")
        self._ok_btn.setVisible(False)
        self._ok_btn.setDefault(True)
        self._ok_btn.clicked.connect(self.accept)
        btn_row.addWidget(self._ok_btn)
        layout.addLayout(btn_row)

    # --- slots wired to ExtractorWorker signals ---

    def on_file_count(self, total: int):
        self._count_label.setText(f"Exporting {total:,} files…")
        self._bar.setRange(0, total)

    def on_progress(self, current: int, total: int):
        self._bar.setValue(current)
        self._count_label.setText(f"Exporting {current:,} of {total:,} files…")

    def on_status(self, msg: str):
        self._status_label.setText(msg)

    def on_finished(self, success: bool, message: str, _dest: str):
        self._running = False
        self._bar.setRange(0, max(self._bar.maximum(), 1))
        self._bar.setValue(self._bar.maximum())
        self._cancel_btn.setVisible(False)
        self._ok_btn.setVisible(True)
        if success:
            self._count_label.setText(f"Export complete — {message}")
            self._status_label.setText(
                "Note: Any hidden files whose names began with '.' have been "
                "renamed with a leading '_' so they remain visible on all platforms."
            )
        else:
            self._count_label.setText(message)
            self._status_label.setText("")

    def _on_cancel(self):
        self._cancel_btn.setEnabled(False)
        self._count_label.setText("Cancelling…")
        self._status_label.setText("")
        self.cancel_requested.emit()

    def reject(self):
        # Block Esc / window-close while export is in progress
        if self._running:
            self._on_cancel()
        else:
            super().reject()


class FastZipBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("iOS FFS Browser")
        self.setWindowIcon(QIcon(resource_path(os.path.join("resources", "icon.png"))))
        self.resize(1350, 850)

        self.zip_path = ""
        self.full_metadata = {}
        self.folder_map = {}
        self.guid_to_bundle = {}
        self.zip_names: frozenset = frozenset()
        self._real_content_cache: dict = {}
        self._zip_handle: zipfile.ZipFile | None = None
        self._hex_worker: QThread | None = None
        self._path_resolver = _make_cellebrite_path("filesystem2")
        self.hidden_paths = self.load_settings()
        self.recent_paths = self.load_recent_list()
        self._view_path = ""
        self._view_is_recursive = False
        self._rebuild_pending = False
        self._load_gen = 0
        self._hide_empty_folders = False
        self._missing_plist_paths: set = set()
        self._tree_populating = False


        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(6, 6, 6, 4)
        layout.setSpacing(4)

        # ── Archive bar ──────────────────────────────────────────────────
        archive_bar = QHBoxLayout()
        self.archive_dropdown = QComboBox()
        self.update_dropdown_ui()
        self.archive_dropdown.activated.connect(self._on_dropdown_activated)
        self.archive_dropdown.view().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.archive_dropdown.view().customContextMenuRequested.connect(self._on_recent_context_menu)
        self.action_btn = QPushButton("Load FFS")
        self.action_btn.clicked.connect(self.handle_action_button)
        self.open_export_btn = QPushButton("Open Export Folder")
        self.open_export_btn.clicked.connect(self.ensure_and_open_export_dir)
        self.folder_view_btn = QPushButton("Folder View ▾")
        self.folder_view_btn.clicked.connect(self._show_view_mode_menu)
        archive_bar.addWidget(self.archive_dropdown, 3)
        archive_bar.addWidget(self.action_btn, 1)
        archive_bar.addWidget(self.open_export_btn, 1)
        archive_bar.addWidget(self.folder_view_btn)
        layout.addLayout(archive_bar)

        # ── Folder view mode — hidden behind a menu button ───────────────
        self.view_group = QButtonGroup(self)
        self._view_mode_menu = QMenu(self)
        for i, text in enumerate(["All Folders", "Customise Filter", "Simplified View"]):
            act = self._view_mode_menu.addAction(text)
            act.setCheckable(True)
            act.setChecked(i == CLEAN_MODE)
            act.setData(i)
            rb = QRadioButton()  # kept for button-group logic; not shown in UI
            if i == CLEAN_MODE: rb.setChecked(True)
            self.view_group.addButton(rb, i)
        self._view_mode_menu.addSeparator()
        self._hide_empty_act = self._view_mode_menu.addAction("Hide Empty && Metadata-Only Folders")
        self._hide_empty_act.setCheckable(True)
        self._hide_empty_act.setChecked(False)
        self._view_mode_menu.triggered.connect(self._on_view_mode_action)

        _section_style = (
            "font-weight: bold; padding: 3px 6px;"
            "border-bottom: 1px solid palette(mid);"
        )
        _status_style = "color: grey; padding: 1px 6px;"

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self._reset_tree_model()
        self.tree_view = QTreeView()
        self.tree_view.setModel(self.tree_model)
        self.tree_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_view.customContextMenuRequested.connect(self.show_tree_context_menu)
        self.tree_view.clicked.connect(self.on_folder_selected)
        self.tree_view.expanded.connect(self._on_tree_item_expanded)
        self.tree_view.setToolTip("Right-click a folder to export")

        tree_header = QLabel("Folder Tree")
        tree_header.setStyleSheet(_section_style)
        self.jump_btn = QPushButton("Jump to ▾")
        self.jump_btn.clicked.connect(self._show_jump_menu)
        self.collapse_btn = QPushButton("Collapse")
        self.collapse_btn.clicked.connect(self._collapse_tree)
        tree_top = QHBoxLayout()
        tree_top.addWidget(tree_header)
        tree_top.addStretch()
        tree_top.addWidget(self.jump_btn)
        tree_top.addWidget(self.collapse_btn)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(2)
        left_layout.addLayout(tree_top)
        left_layout.addWidget(self.tree_view)
        self.splitter.addWidget(left_panel)

        self.file_headers = ['Name', 'Created', 'Modified', 'Type', 'Size (Bytes)', 'Files', 'Path']
        self.proxy_model = MultiColumnFilterProxy()
        self._set_file_model(FileTableModel(self.file_headers))

        self.file_view = QTableView()
        self.file_view.setModel(self.proxy_model)
        self.file_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.file_view.setSortingEnabled(True)
        self.file_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_view.customContextMenuRequested.connect(self.show_table_context_menu)
        self.file_view.doubleClicked.connect(self.handle_table_double_click)
        self.file_view.clicked.connect(self.on_file_selected)

        filter_bar = QHBoxLayout()
        filter_bar.setContentsMargins(0, 2, 0, 2)
        filter_bar.addWidget(QLabel("Filter:"))
        self.filter_col_combo = QComboBox()
        self.filter_col_combo.setMaximumWidth(140)
        self._update_filter_columns(self.file_headers)
        filter_bar.addWidget(self.filter_col_combo)
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Type to filter rows...")
        self.filter_input.returnPressed.connect(self._apply_filter)
        filter_bar.addWidget(self.filter_input)
        self.filter_go_btn = QPushButton("Go")
        self.filter_go_btn.setMaximumWidth(40)
        self.filter_go_btn.clicked.connect(self._apply_filter)
        self.filter_clear_btn = QPushButton("Clear")
        self.filter_clear_btn.setMaximumWidth(50)
        self.filter_clear_btn.clicked.connect(self._clear_filter)
        filter_bar.addWidget(self.filter_go_btn)
        filter_bar.addWidget(self.filter_clear_btn)

        browser_header = QLabel("File Browser")
        browser_header.setStyleSheet(_section_style)

        self.show_selected_btn = QPushButton("Show Selected Files")
        self.show_selected_btn.setVisible(False)
        self.show_selected_btn.clicked.connect(self._rebuild_file_view_from_checked)

        self.deselect_all_btn = QPushButton("Deselect All")
        self.deselect_all_btn.setVisible(False)
        self.deselect_all_btn.clicked.connect(self._deselect_all_files)

        browser_top = QHBoxLayout()
        browser_top.addWidget(browser_header)
        browser_top.addStretch()
        browser_top.addWidget(self.show_selected_btn)
        browser_top.addWidget(self.deselect_all_btn)

        self.table_status_label = QLabel()
        self.table_status_label.setStyleSheet(_status_style)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(2)
        right_layout.addLayout(browser_top)
        right_layout.addWidget(self.table_status_label)
        right_layout.addLayout(filter_bar)
        right_layout.addWidget(self.file_view)

        self.splitter.addWidget(right_panel)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 2)

        # Hex viewer panel
        hex_header = QLabel("Hex Preview")
        hex_header.setStyleSheet(_section_style)
        self.hex_label = QLabel("No file selected")
        self.hex_label.setStyleSheet(_status_style)
        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        _hex_font = QFont("Menlo", 14)
        _hex_font.setStyleHint(QFont.StyleHint.Monospace)
        self.hex_view.setFont(_hex_font)
        self.hex_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.hex_view.setStyleSheet("")
        self.hex_view.document().setDocumentMargin(10)
        self.hex_view.setPlaceholderText("Double-click a file to preview it here, or right-click and choose 'Preview in Hex Viewer'.")
        self.hex_view.selectionChanged.connect(self._on_hex_selection_changed)
        self.hex_view.viewport().installEventFilter(self)
        self.hex_view.verticalScrollBar().valueChanged.connect(self._on_hex_scroll)
        self._fitting_hex_font = False
        self._hex_loading_more = False
        self._hex_data_offset: int | None = None
        self._hex_file_size: int = 0
        self._hex_bytes_loaded: int = 0
        self._hex_ui_path: str = ""
        self.hex_progress_bar = QProgressBar()
        self.hex_progress_bar.hide()

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)

        hex_panel = QWidget()
        hex_layout = QVBoxLayout(hex_panel)
        hex_layout.setContentsMargins(0, 0, 0, 0)
        hex_layout.setSpacing(2)
        hex_layout.addWidget(sep)
        hex_layout.addWidget(hex_header)
        hex_layout.addWidget(self.hex_label)
        hex_layout.addWidget(self.hex_progress_bar)
        hex_layout.addWidget(self.hex_view, stretch=1)

        self.outer_splitter = QSplitter(Qt.Orientation.Vertical)
        self.outer_splitter.addWidget(self.splitter)
        self.outer_splitter.addWidget(hex_panel)
        self.outer_splitter.setStretchFactor(0, 2)
        self.outer_splitter.setStretchFactor(1, 1)

        layout.addWidget(self.outer_splitter)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.hide()
        self.status_bar.addPermanentWidget(self.progress_bar)
        self.status_bar.showMessage("Ready")

    def _set_file_model(self, model):
        """Set the file model, connect its filter signals, and update the proxy."""
        self.file_model = model
        self.proxy_model.setSourceModel(model)
        model.filter_progress.connect(self._on_filter_progress)
        model.filter_done.connect(self._on_filter_done)

    def _on_filter_progress(self, visible, total):
        self.table_status_label.setText(f"{visible:,} of {total:,} items (filtering…)")

    def _on_filter_done(self, visible, total):
        if visible == total:
            self.table_status_label.setText(f"{total:,} items")
        else:
            self.table_status_label.setText(f"{visible:,} of {total:,} items (filtered)")
        col_name = self.filter_col_combo.currentText()
        text = self.filter_input.text()
        if text:
            self._log(f"Filter applied: \"{text}\" in {col_name} — {visible:,} of {total:,} rows visible")

    def _apply_filter(self):
        col = self.filter_col_combo.currentIndex() - 1  # index 0 = "All Columns" → -1
        text = self.filter_input.text()
        total = self.file_model.rowCount()
        self.table_status_label.setText(f"0 of {total:,} items (filtering…)")
        self.proxy_model.set_filter(text, col)

    def _clear_filter(self):
        self.filter_input.clear()
        self.proxy_model.set_filter("", -1)
        self._log(f"Filter cleared in: {self._view_path}")

    def _log_filter_final(self):
        text = self.filter_input.text()
        col_name = self.filter_col_combo.currentText()
        if text:
            visible = self.proxy_model.rowCount()
            total = self.file_model.rowCount()
            self._log(f"Filter applied: \"{text}\" in {col_name} — {visible} of {total} rows visible")
        else:
            self._log(f"Filter cleared in: {self._view_path}")

    def _get_zip_handle(self) -> zipfile.ZipFile:
        """Return the shared ZipFile handle, opening it lazily on first use."""
        if self._zip_handle is None:
            self._zip_handle = zipfile.ZipFile(self.zip_path, 'r')
        return self._zip_handle

    def _in_zip(self, ui_path) -> bool:
        return self._path_resolver(ui_path) in self.zip_names

    def _is_empty_folder_entry(self, ui_path) -> bool:
        """True when the ZIP contains a bare directory entry for this path (trailing slash)."""
        return (self._path_resolver(ui_path) + "/") in self.zip_names

    def _folder_content_status(self, folder_path) -> str:
        """Classify a folder recursively as 'content', 'metadata_only', or 'empty'.
        Results are memoized per archive load."""
        if folder_path in self._real_content_cache:
            return self._real_content_cache[folder_path]
        has_metadata = False
        for child in self.folder_map.get(folder_path, []):
            if child in self.folder_map:
                child_status = self._folder_content_status(child)
                if child_status == "content":
                    self._real_content_cache[folder_path] = "content"
                    return "content"
                if child_status == "metadata_only":
                    has_metadata = True
            else:
                if self._in_zip(child):
                    if child.split('/')[-1] in _SYSTEM_METADATA_NAMES:
                        has_metadata = True
                    else:
                        self._real_content_cache[folder_path] = "content"
                        return "content"
        result = "metadata_only" if has_metadata else "empty"
        self._real_content_cache[folder_path] = result
        return result

    def _bundle_for_path(self, path):
        """Return the bundle ID for the nearest GUID ancestor of path, or None."""
        parts = [p for p in path.split('/') if p]
        for part in parts:
            if part in self.guid_to_bundle:
                return self.guid_to_bundle[part]
        return None

    def _refresh_table_status(self):
        total = self.file_model.rowCount()
        visible = self.proxy_model.rowCount()
        is_filtered = bool(self.filter_input.text())
        parts = []
        if self._view_path:
            parts.append(self._view_path)
        bundle = self._bundle_for_path(self._view_path) if self._view_path else None
        if bundle:
            parts.append(bundle)
        if is_filtered:
            parts.append(f"{visible} of {total} items (filtered)")
        else:
            parts.append(f"{total} items")
        self.table_status_label.setText("  |  ".join(parts))

    def _update_filter_columns(self, headers):
        self.filter_col_combo.blockSignals(True)
        self.filter_col_combo.clear()
        self.filter_col_combo.addItem("All Columns")
        for h in headers:
            self.filter_col_combo.addItem(h)
        self.filter_col_combo.blockSignals(False)

    def _zip_stem(self):
        """Return (parent_dir, stem) for the currently loaded archive."""
        p = pathlib.Path(self.zip_path)
        return p.parent, p.stem

    def _get_export_dir(self):
        parent, stem = self._zip_stem()
        return str(parent / f"{stem}_Export")

    def _get_log_path(self):
        parent, stem = self._zip_stem()
        return str(parent / f"{stem}_audit_log.txt")

    def _log(self, message):
        if not self.zip_path:
            return
        ts = datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        try:
            with open(self._get_log_path(), 'a', encoding='utf-8') as f:
                f.write(f"[{ts}] {message}\n")
        except OSError:
            pass

    def _reset_tree_model(self):
        self.tree_model = QStandardItemModel()
        self.tree_model.setHorizontalHeaderLabels(['Folder Structure'])
        self.tree_model.itemChanged.connect(self.on_tree_item_changed)

    def handle_table_double_click(self, index):
        source = self.proxy_model.mapToSource(index)
        ui_path = self.file_model.index(source.row(), 0).data(Qt.ItemDataRole.UserRole)
        if ui_path in self.folder_map:
            self.navigate_tree_to_path(ui_path)
        elif ui_path and self._in_zip(ui_path):
            self._load_hex_preview(ui_path)

    def navigate_tree_to_path(self, target_path):
        # The visible root "/ [Full Filesystem]" sits under the invisible root
        invisible_root = self.tree_model.invisibleRootItem()
        if invisible_root.rowCount() == 0:
            return
        current = invisible_root.child(0)  # "/ [Full Filesystem]"
        self._ensure_children_loaded(current)
        self.tree_view.expand(self.tree_model.indexFromItem(current))
        parts = [p for p in target_path.split('/') if p]

        for part in parts:
            found = False
            for row in range(current.rowCount()):
                child = current.child(row)
                child_path = child.data(Qt.ItemDataRole.UserRole)
                if child_path is not None and child_path.split('/')[-1] == part:
                    self._ensure_children_loaded(child)
                    self.tree_view.expand(self.tree_model.indexFromItem(child))
                    current = child
                    found = True
                    break
            if not found: break

        new_idx = self.tree_model.indexFromItem(current)
        self.tree_view.setCurrentIndex(new_idx)
        self.tree_view.scrollTo(new_idx, QTreeView.ScrollHint.PositionAtCenter)
        self._view_is_recursive = False
        self.on_folder_selected(new_idx)

    def on_file_selected(self, index):
        source = self.proxy_model.mapToSource(index)
        ui_path = self.file_model.index(source.row(), 0).data(Qt.ItemDataRole.UserRole)
        if not ui_path:
            return
        self.status_bar.showMessage(ui_path)
        is_folder = ui_path in self.folder_map
        self._log(f"{'Folder' if is_folder else 'File'} selected: {ui_path}")

    def _load_hex_preview(self, ui_path):
        if self._hex_worker is not None and self._hex_worker.isRunning():
            self._hex_worker.terminate()
            self._hex_worker.wait()

        self._hex_data_offset = None
        self._hex_file_size   = 0
        self._hex_bytes_loaded = 0
        self._hex_ui_path = ui_path

        physical_path = self._path_resolver(ui_path)
        total_size = self.full_metadata.get(ui_path, {}).get('size', 0)

        self.hex_view.clear()
        self.hex_progress_bar.hide()

        try:
            data_offset, file_size = _stored_entry_offset(
                self.zip_path, physical_path, self._get_zip_handle())
        except Exception as e:
            self._on_hex_error(str(e))
            return

        self._hex_file_size = file_size or total_size

        if data_offset is not None:
            # STORED entry — seek directly, display first page instantly
            self._hex_data_offset = data_offset
            try:
                with open(self.zip_path, 'rb') as raw:
                    raw.seek(data_offset)
                    chunk = raw.read(min(INITIAL_HEX_BYTES, self._hex_file_size or INITIAL_HEX_BYTES))
            except Exception as e:
                self._on_hex_error(str(e))
                return
            self._hex_bytes_loaded = len(chunk)
            self.hex_view.setPlainText(self._render_hex(chunk))
            self._fit_hex_font()
            self._update_hex_label()
        else:
            # Compressed — fall back to threaded worker
            self.hex_label.setText(f"Loading: {ui_path}")
            self.hex_progress_bar.setRange(0, max(total_size, 1))
            self.hex_progress_bar.setValue(0)
            self.hex_progress_bar.show()
            self._hex_worker = HexLoadWorker(self.zip_path, physical_path, total_size)
            self._hex_worker.progress.connect(self._on_hex_progress)
            self._hex_worker.load_complete.connect(self._on_hex_ready)
            self._hex_worker.error.connect(self._on_hex_error)
            self._hex_worker.start()

    def _update_hex_label(self):
        shown = self._hex_bytes_loaded
        total = self._hex_file_size
        label = f"{self._hex_ui_path}  —  {shown:,} / {total:,} bytes shown"
        if shown < total:
            label += "  (scroll for more)"
        self.hex_label.setText(label)

    def _on_hex_scroll(self, value):
        if self._hex_data_offset is None or self._hex_loading_more:
            return
        if self._hex_file_size > 0 and self._hex_bytes_loaded >= self._hex_file_size:
            return
        scrollbar = self.hex_view.verticalScrollBar()
        if value < scrollbar.maximum() - 5:
            return
        self._hex_loading_more = True
        try:
            remaining = (self._hex_file_size - self._hex_bytes_loaded) if self._hex_file_size > 0 else HEX_PAGE_BYTES
            with open(self.zip_path, 'rb') as raw:
                raw.seek(self._hex_data_offset + self._hex_bytes_loaded)
                chunk = raw.read(min(HEX_PAGE_BYTES, remaining))
        except Exception as e:
            self._log(f"Hex scroll load error: {e}")
            self._hex_loading_more = False
            return
        if not chunk:
            self._hex_loading_more = False
            return
        new_text = self._render_hex(chunk, self._hex_bytes_loaded)
        self._hex_bytes_loaded += len(chunk)
        cursor = self.hex_view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText("\n" + new_text)
        self._update_hex_label()
        self._hex_loading_more = False

    def _on_hex_progress(self, done, total):
        self.hex_progress_bar.setRange(0, max(total, 1))
        self.hex_progress_bar.setValue(done)

    def _on_hex_ready(self, data):
        self.hex_progress_bar.hide()
        truncated = len(data) == HexLoadWorker.LIMIT
        self.hex_label.setText(
            f"{self._hex_ui_path}  —  {len(data):,} bytes shown"
            + ("  (truncated to 64 KB)" if truncated else "")
        )
        self.hex_view.setPlainText(self._render_hex(data))
        self._fit_hex_font()
        self._log(f"Hex preview: {self._hex_ui_path}")

    def _on_hex_error(self, msg):
        self.hex_progress_bar.hide()
        self.hex_label.setText(f"Cannot preview: {msg}")
        self.hex_view.clear()

    @staticmethod
    def _render_hex(data: bytes, base_offset: int = 0) -> str:
        # C-level operations for the two heaviest parts
        ascii_str = data.translate(_ASCII_XLAT).decode('latin-1')
        h = data.hex()
        rows = []
        n = len(data)
        for i in range(0, n, 32):
            o = i * 2
            if n - i >= 32:
                # Fast path: full 32-byte row — no inner loops
                s = h[o:o + 64]
                hex_part = (
                    f"{s[0:2]} {s[2:4]} {s[4:6]} {s[6:8]}"
                    f"  {s[8:10]} {s[10:12]} {s[12:14]} {s[14:16]}"
                    f"  {s[16:18]} {s[18:20]} {s[20:22]} {s[22:24]}"
                    f"  {s[24:26]} {s[26:28]} {s[28:30]} {s[30:32]}"
                    f"  {s[32:34]} {s[34:36]} {s[36:38]} {s[38:40]}"
                    f"  {s[40:42]} {s[42:44]} {s[44:46]} {s[46:48]}"
                    f"  {s[48:50]} {s[50:52]} {s[52:54]} {s[54:56]}"
                    f"  {s[56:58]} {s[58:60]} {s[60:62]} {s[62:64]}"
                )
            else:
                # Partial last row
                row_len = n - i
                s = h[o:o + row_len * 2]
                grps = []
                for g in range(8):
                    gs = g * 8
                    if gs >= len(s):
                        grps.append('')
                        continue
                    b = s[gs:min(gs + 8, len(s))]
                    grps.append(' '.join(b[j:j + 2] for j in range(0, len(b), 2)))
                hex_part = '  '.join(f'{g:<11}' for g in grps)
            rows.append(f"{base_offset + i:08x}  {hex_part}  {ascii_str[i:i + 32]}")
        return '\n'.join(rows)

    def eventFilter(self, obj, event):
        if obj is self.hex_view.viewport() and event.type() == QEvent.Type.Resize:
            QTimer.singleShot(0, self._fit_hex_font)
        return super().eventFilter(obj, event)

    def _fit_hex_font(self):
        """Compute and apply the largest font size that fits a full hex line.
        Always defers one event-loop tick so the viewport has settled after
        setPlainText / resize before we measure."""
        QTimer.singleShot(0, self._do_fit_hex_font)

    # A representative worst-case hex line — all bytes 0xff, full 32-byte row.
    # Used as the measurement string for font fitting so we measure actual
    # rendered characters rather than the widest possible glyph ('W').
    # ── Change _HEX_REF_SIZE to adjust the hex viewer font size ──────────────
    _HEX_REF_SIZE = 15.0   # reference point size; scale up/down to taste

    # Full 32-byte hex line at worst-case values — used for measurement.
    _HEX_SAMPLE_LINE = (
        "ffffffff  "
        "ff ff ff ff  ff ff ff ff  ff ff ff ff  ff ff ff ff  "
        "ff ff ff ff  ff ff ff ff  ff ff ff ff  ff ff ff ff  "
        "................................"
    )

    def _do_fit_hex_font(self):
        if self._fitting_hex_font:
            return
        vp_width = self.hex_view.viewport().width()
        if vp_width <= 0:
            return
        self._fitting_hex_font = True
        try:
            # Measure the text width directly with QFontMetricsF at the
            # reference size — synchronous, no layout pass required.
            # Then add the document's left+right margins to get total content width.
            ref_font = QFont("Menlo", self._HEX_REF_SIZE)
            ref_font.setStyleHint(QFont.StyleHint.Monospace)
            fm = QFontMetricsF(ref_font)
            text_width = fm.horizontalAdvance(self._HEX_SAMPLE_LINE)
            if text_width <= 0:
                return
            doc_margin = self.hex_view.document().documentMargin()
            content_width = text_width + 2 * doc_margin
            new_size = self._HEX_REF_SIZE * (vp_width / content_width)
            new_size = max(6.0, min(new_size, 32.0))
            ref_font.setPointSizeF(new_size)
            self.hex_view.setFont(ref_font)
        finally:
            self._fitting_hex_font = False

    def _on_hex_selection_changed(self):
        cursor = self.hex_view.textCursor()
        if not cursor.hasSelection():
            self.hex_view.setExtraSelections([])
            return

        doc = self.hex_view.document()
        sel_start = min(cursor.position(), cursor.anchor())
        sel_end   = max(cursor.position(), cursor.anchor())

        hl_fmt = QTextCharFormat()
        hl_fmt.setBackground(QColor(255, 190, 0, 140))

        extra_sels = []
        start_block = doc.findBlock(sel_start)
        end_block   = doc.findBlock(max(sel_end - 1, sel_start))
        total_bytes = 0

        block = start_block
        while block.isValid():
            bpos  = block.position()
            btext = block.text()
            blen  = len(btext)

            cs = max(0, sel_start - bpos)
            ce = min(blen, sel_end - bpos)

            selected = set()
            for col in range(cs, ce):
                b = _hex_col_to_byte(col)
                if b is None:
                    b = _ascii_col_to_byte(col)
                if b is not None:
                    selected.add(b)

            total_bytes += len(selected)
            if total_bytes > MAX_HEX_HIGHLIGHT_BYTES:
                break

            for b in selected:
                hex_col   = _HEX_OFFSET_COLS + (b // 4) * _HEX_GROUP_STRIDE + (b % 4) * 3
                ascii_col = _HEX_ASCII_START + b
                for col, width in ((hex_col, 2), (ascii_col, 1)):
                    if col + width > blen:
                        continue
                    es = QTextEdit.ExtraSelection()
                    es.format = hl_fmt
                    tc = QTextCursor(doc)
                    tc.setPosition(bpos + col)
                    tc.setPosition(bpos + col + width, QTextCursor.MoveMode.KeepAnchor)
                    es.cursor = tc
                    extra_sels.append(es)

            if block == end_block:
                break
            block = block.next()

        self.hex_view.setExtraSelections(extra_sels)

    def on_folder_selected(self, index):
        item = self.tree_model.itemFromIndex(index)
        if not item: return
        folder_path = item.data(Qt.ItemDataRole.UserRole)
        self.status_bar.showMessage(f"{folder_path}    |    Tip: Right-click to export")
        self._log(f"Folder viewed: {folder_path}")

        # Clicking a folder name always shows that folder — clears ticked view
        self._view_is_recursive = False

        children = self.folder_map.get(folder_path, [])
        has_bundles = any(p.split('/')[-1] in self.guid_to_bundle for p in children)

        if has_bundles:
            headers = self.file_headers + ['UUID']
        else:
            headers = self.file_headers

        new_model = FileTableModel(headers)
        self._update_filter_columns(headers)
        self.filter_input.clear()
        self.proxy_model.set_filter("", -1)
        self._view_path = folder_path
        self._view_is_recursive = False

        batch = []
        for path in sorted(children):
            name = path.split('/')[-1]
            meta = self.full_metadata.get(path, {})
            is_folder = path in self.folder_map

            # Determine type label and whether to grey out
            if is_folder:
                status = self._folder_content_status(path)
                if self._hide_empty_folders and status in ("empty", "metadata_only") \
                        and path not in self._missing_plist_paths:
                    continue
                if status == "content":
                    file_type = _get_file_type(name, True)
                    grey_row = False
                elif status == "metadata_only":
                    file_type = "Folder - Metadata Only"
                    grey_row = True
                else:
                    file_type = "Empty Folder"
                    grey_row = True
            elif self._in_zip(path):
                file_type = _get_file_type(name, False)
                grey_row = False
            elif self._is_empty_folder_entry(path):
                if self._hide_empty_folders:
                    continue
                file_type = "Empty Folder"
                grey_row = True
            else:
                file_type = "Not in Zip"
                grey_row = True

            fc = self._count_files_recursive(path) if is_folder else -1
            cols = [
                self._display_name(name),
                self.format_ts(meta.get('ctime')),
                self.format_ts(meta.get('mtime')),
                file_type,
                f"{meta.get('size', 0):,}",
                f"{fc:,}" if is_folder else "",
                self._display_path(path),
            ]
            if has_bundles:
                cols.append(name if name in self.guid_to_bundle else "")

            batch.append((cols, path, fc, is_folder and not grey_row, grey_row))

        new_model.append_rows_batch(batch)
        self._set_file_model(new_model)

        self.file_view.resizeColumnsToContents()
        self._refresh_table_status()

    def _display_name(self, segment: str) -> str:
        """Return the bundle ID for a GUID segment, otherwise the segment itself."""
        return self.guid_to_bundle.get(segment, segment)

    def _display_path(self, path: str) -> str:
        """Replace GUID segments in a full path with bundle IDs for display."""
        return '/'.join(self._display_name(seg) for seg in path.split('/'))

    def _count_files_recursive(self, folder_path: str, visited: set = None) -> int:
        """Return the total number of files under folder_path (recursive, no double-counting)."""
        if visited is None:
            visited = set()
        if folder_path in visited:
            return 0
        visited.add(folder_path)
        count = 0
        for child in self.folder_map.get(folder_path, []):
            if child in self.folder_map:
                count += self._count_files_recursive(child, visited)
            else:
                count += 1
        return count

    def format_ts(self, ts):
        if not ts: return ""
        try:
            # APFS stores timestamps as nanoseconds since epoch
            if ts > 1e10:
                ts = ts / 1e9
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except (ValueError, OSError, OverflowError):
            return str(ts)

    def ensure_and_open_export_dir(self):
        if not self.zip_path: return
        dest_dir = self._get_export_dir()
        try:
            os.makedirs(dest_dir, exist_ok=True)
            self.open_path(dest_dir)
        except OSError as e:
            self.status_bar.showMessage(f"Cannot open export folder: {e}")

    def show_tree_context_menu(self, point):
        index = self.tree_view.indexAt(point)
        if not index.isValid(): return
        self.tree_view.setCurrentIndex(index)
        item = self.tree_model.itemFromIndex(index)
        folder_path = item.data(Qt.ItemDataRole.UserRole) if item else None
        menu = QMenu(self)
        mode = self.view_group.checkedId()
        if mode in (0, CLEAN_MODE) and folder_path is not None:
            checked_paths = set()
            self._collect_checked_paths(item, checked_paths)
            is_ticked = bool(checked_paths)
            if is_ticked:
                rec_act = QAction("☐ Recursively Deselect", self)
                rec_act.triggered.connect(lambda: self._recursive_untick_folder(index))
            else:
                rec_act = QAction("☑ Recursively Add All Files", self)
                rec_act.triggered.connect(lambda: self._recursive_tick_folder(index))
            menu.addAction(rec_act)
            menu.addSeparator()
        export_act = QAction("📁 Export Folder (Recursive)", self)
        export_act.triggered.connect(lambda: self.handle_export_request(is_tree=True))
        menu.addAction(export_act)
        menu.exec(self.tree_view.viewport().mapToGlobal(point))

    def _recursive_tick_folder(self, index):
        """Tick the folder and all its descendants."""
        item = self.tree_model.itemFromIndex(index)
        if item is None:
            return
        self._tree_populating = True
        self._ensure_all_descendants_loaded(item)
        self._tree_populating = False
        self.tree_model.blockSignals(True)
        if item.isCheckable():
            item.setCheckState(Qt.CheckState.Checked)
        self._cascade_check(item, Qt.CheckState.Checked)
        self.tree_model.blockSignals(False)
        self.tree_view.viewport().update()
        if not self._rebuild_pending:
            self._rebuild_pending = True
            QTimer.singleShot(0, self._deferred_rebuild)

    def _recursive_untick_folder(self, index):
        """Untick the folder and all its descendants."""
        item = self.tree_model.itemFromIndex(index)
        if item is None:
            return
        self.tree_model.blockSignals(True)
        if item.isCheckable():
            item.setCheckState(Qt.CheckState.Unchecked)
        self._cascade_check(item, Qt.CheckState.Unchecked)
        self.tree_model.blockSignals(False)
        self.tree_view.viewport().update()
        if not self._rebuild_pending:
            self._rebuild_pending = True
            QTimer.singleShot(0, self._deferred_rebuild)

    # ------------------------------------------------------------------ #
    #  Checkbox-driven file-view helpers (All Folders / Simplified modes) #
    # ------------------------------------------------------------------ #

    def _cascade_check(self, parent_item, state):
        """Propagate check state to all descendants of parent_item."""
        for row in range(parent_item.rowCount()):
            child = parent_item.child(row)
            if child is None:
                continue
            if child.isCheckable():
                child.setCheckState(state)
            self._cascade_check(child, state)

    def _collect_checked_paths(self, parent_item, result):
        for row in range(parent_item.rowCount()):
            item = parent_item.child(row)
            if item is None:
                continue
            if item.isCheckable() and item.checkState() == Qt.CheckState.Checked:
                path = item.data(Qt.ItemDataRole.UserRole)
                if path is not None:
                    result.add(path)
            self._collect_checked_paths(item, result)

    def _rebuild_file_view_from_checked(self):
        checked = set()
        self._collect_checked_paths(self.tree_model.invisibleRootItem(), checked)
        self._view_path = ""
        self._view_is_recursive = bool(checked)
        if checked:
            self.tree_view.clearSelection()
            self.tree_view.setCurrentIndex(QModelIndex())

        # Bump generation — any in-flight batch will see the change and abort
        self._load_gen += 1
        my_gen = self._load_gen

        # Swap in an empty model immediately so the checkbox tick feels instant
        self._set_file_model(FileTableModel(self.file_headers))

        if not checked:
            # Fall back to showing the currently highlighted folder, if any
            idx = self.tree_view.currentIndex()
            if idx.isValid():
                self.on_folder_selected(idx)
            else:
                self.table_status_label.setText("0 items")
                self.status_bar.showMessage("No folders selected")
            return

        folders = sorted(checked)
        total_folders = len(folders)
        state = {'idx': 0, 'count': 0}
        self.table_status_label.setText("0 items  (loading…)")
        self.status_bar.showMessage(f"Loading…  0 files  (0 of {total_folders} folders)")

        def _process_batch():
            if my_gen != self._load_gen:
                return  # superseded by a newer rebuild — stop silently

            # Process as many folders as fit within ~16 ms (one frame budget)
            deadline = time.monotonic() + FRAME_BUDGET_SECS
            batch_rows = []

            while state['idx'] < total_folders:
                folder = folders[state['idx']]
                state['idx'] += 1
                for child in self.folder_map.get(folder, []):
                    is_folder = child in self.folder_map
                    if is_folder and self._hide_empty_folders and \
                            self._folder_content_status(child) in ("empty", "metadata_only") \
                            and child not in self._missing_plist_paths:
                        continue
                    name = child.split('/')[-1]
                    meta = self.full_metadata.get(child, {})
                    if is_folder:
                        status = self._folder_content_status(child)
                        if status == "content":
                            file_type = _get_file_type(name, True)
                            grey_row = False
                        elif status == "metadata_only":
                            file_type = "Folder - Metadata Only"
                            grey_row = True
                        else:
                            file_type = "Empty Folder"
                            grey_row = True
                    elif self._in_zip(child):
                        file_type = _get_file_type(name, False)
                        grey_row = False
                    elif self._is_empty_folder_entry(child):
                        if self._hide_empty_folders:
                            continue
                        file_type = "Empty Folder"
                        grey_row = True
                    else:
                        file_type = "Not in Zip"
                        grey_row = True
                    fc = self._count_files_recursive(child) if is_folder else -1
                    cols = [
                        self._display_name(name),
                        self.format_ts(meta.get('ctime')),
                        self.format_ts(meta.get('mtime')),
                        file_type,
                        f"{meta.get('size', 0):,}",
                        f"{fc:,}" if is_folder else "",
                        self._display_path(child),
                    ]
                    batch_rows.append((cols, child, fc, is_folder and not grey_row, grey_row))
                    state['count'] += 1
                if time.monotonic() >= deadline:
                    break  # yield back to the event loop

            self.file_model.append_rows_batch(batch_rows)
            self.status_bar.showMessage(
                f"Loading…  {state['count']:,} files  "
                f"({state['idx']} of {total_folders} folders)")
            self.table_status_label.setText(f"{state['count']:,} items  (loading…)")

            if state['idx'] < total_folders:
                QTimer.singleShot(0, _process_batch)
            else:
                self.file_view.resizeColumnsToContents()
                self._refresh_table_status()
                self.status_bar.showMessage(
                    f"{state['count']:,} files from {total_folders:,} selected folders")

        QTimer.singleShot(0, _process_batch)

    def show_table_context_menu(self, point):
        index = self.file_view.indexAt(point)
        if not index.isValid(): return
        if not self.file_view.selectionModel().isSelected(index):
            self.file_view.selectRow(index.row())
        menu = QMenu(self)
        count = len(self.file_view.selectionModel().selectedRows())
        export_act = QAction(f"💾 Export Selected ({count} items)", self)
        export_act.triggered.connect(lambda: self.handle_export_request(is_tree=False))
        menu.addAction(export_act)

        source = self.proxy_model.mapToSource(index)
        ui_path = self.file_model.index(source.row(), 0).data(Qt.ItemDataRole.UserRole)

        if ui_path and ui_path not in self.folder_map and self._in_zip(ui_path):
            hex_act = QAction("🔍 Preview in Hex Viewer", self)
            hex_act.triggered.connect(lambda: self._load_hex_preview(ui_path))
            menu.addAction(hex_act)

        if ui_path and '/' in ui_path:
            parent_path = ui_path.rsplit('/', 1)[0]
            parent_act = QAction("📂 Open Parent Folder in Tree", self)
            parent_act.triggered.connect(lambda: self.navigate_tree_to_path(parent_path))
            menu.addAction(parent_act)

        menu.exec(self.file_view.viewport().mapToGlobal(point))

    def handle_export_request(self, is_tree=True):
        if not self.zip_path: return
        QApplication.setOverrideCursor(QCursor(Qt.CursorShape.WaitCursor))
        tasks = []

        if is_tree:
            idx = self.tree_view.currentIndex()
            ui_path = self.tree_model.itemFromIndex(idx).data(Qt.ItemDataRole.UserRole)
            base_parent = ui_path.rsplit('/', 1)[0] if '/' in ui_path else ""
            tasks.append((ui_path, base_parent))
        else:
            selected_rows = self.file_view.selectionModel().selectedRows()
            for idx in selected_rows:
                source = self.proxy_model.mapToSource(idx)
                ui_path = self.file_model.index(source.row(), 0).data(Qt.ItemDataRole.UserRole)
                base_parent = ui_path.rsplit('/', 1)[0] if ui_path in self.folder_map and '/' in ui_path else ui_path
                tasks.append((ui_path, base_parent))

        dest_dir = self._get_export_dir()
        dlg = ExportProgressDialog(dest_dir, parent=self)

        self.ex_worker = ExtractorWorker(self.zip_path, tasks, dest_dir, self.folder_map, self._path_resolver)
        self.ex_worker.file_count.connect(dlg.on_file_count)
        self.ex_worker.progress.connect(dlg.on_progress)
        self.ex_worker.status.connect(dlg.on_status)
        self.ex_worker.finished.connect(dlg.on_finished)
        self.ex_worker.finished.connect(self.on_export_finished)
        dlg.cancel_requested.connect(self.ex_worker.cancel)

        self.ex_worker.start()
        dlg.exec()

    def on_export_finished(self, success, message, dest_path):
        QApplication.restoreOverrideCursor()
        if success:
            self._log(f"Export succeeded: {message} → {dest_path}")
        else:
            self._log(f"Export failed: {message}")

    def open_path(self, path):
        if sys.platform == 'win32': os.startfile(path)
        elif sys.platform == 'darwin': subprocess.Popen(['open', path])
        else: subprocess.Popen(['xdg-open', path])

    def _collapse_tree(self):
        self.tree_view.collapseAll()
        # Keep the root node expanded so the top-level folders are visible
        root = self.tree_model.item(0)
        if root:
            self.tree_view.expand(self.tree_model.indexFromItem(root))

    def _show_view_mode_menu(self):
        self._view_mode_menu.exec(
            self.folder_view_btn.mapToGlobal(self.folder_view_btn.rect().bottomLeft()))

    def _on_view_mode_action(self, action):
        if action is self._hide_empty_act:
            self._hide_empty_folders = action.isChecked()
            self.reload_tree_entirely()
            return
        mode = action.data()
        for act in self._view_mode_menu.actions():
            if act.data() is not None:
                act.setChecked(act.data() == mode)
        btn = self.view_group.button(mode)
        if btn:
            btn.setChecked(True)
        self.reload_tree_entirely()

    def _show_jump_menu(self):
        menu = QMenu(self)
        self._build_jump_menu(menu, FORENSIC_SHORTCUTS)
        menu.exec(self.jump_btn.mapToGlobal(self.jump_btn.rect().bottomLeft()))

    def _build_jump_menu(self, menu, items):
        for item in items:
            if item is None:
                menu.addSeparator()
            elif isinstance(item[1], list):
                submenu = menu.addMenu(item[0])
                self._build_jump_menu(submenu, item[1])
            else:
                name, path = item
                act = QAction(name, self)
                act.triggered.connect(lambda _, p=path: self.navigate_tree_to_path(p))
                menu.addAction(act)

    def _on_dropdown_activated(self, index):
        text = self.archive_dropdown.itemText(index)
        if text == NEW_ARCHIVE_SENTINEL:
            self._open_new_ffs()
        elif text:
            self.start_loading(text)

    def _open_new_ffs(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open ZIP", "", "ZIP (*.zip)")
        if path:
            self.save_recent_list(path)
            self.start_loading(path)

    def handle_action_button(self):
        selection = self.archive_dropdown.currentText()
        if selection == NEW_ARCHIVE_SENTINEL or not selection:
            self._open_new_ffs()
        else:
            self.start_loading(selection)

    def start_loading(self, zip_path):
        self.zip_path = zip_path
        self._log(f"SESSION START — Archive loaded: {zip_path}")
        self._reset_tree_model()
        self.tree_view.setModel(self.tree_model)
        self.show_selected_btn.setVisible(False)
        self.deselect_all_btn.setVisible(False)
        # Clear the file browser immediately so the previous archive's
        # content is not shown while the new one is loading.
        self._set_file_model(FileTableModel(self.file_headers))
        self._update_filter_columns(self.file_headers)
        self.table_status_label.setText("")
        self._view_path = ""
        self.progress_bar.setRange(0, 0)
        self.progress_bar.show()
        self.worker = ZipMetadataWorker(zip_path)
        self.worker.status_update.connect(self.status_bar.showMessage)
        self.worker.metadata_ready.connect(self.on_metadata_ready)
        self.worker.start()

    def on_metadata_ready(self, data, folder_map, guid_map, zip_names, path_resolver, missing_plist_paths):
        self.full_metadata = data
        self.folder_map = folder_map
        self.guid_to_bundle = guid_map
        self.zip_names = zip_names
        self._path_resolver = path_resolver
        self._missing_plist_paths = set(missing_plist_paths)
        self._real_content_cache = {}
        if self._zip_handle:
            self._zip_handle.close()
            self._zip_handle = None   # opened lazily on first hex-preview request
        self.progress_bar.setRange(0, 100)
        self.reload_tree_entirely()
        if missing_plist_paths:
            self._warn_and_select_missing(missing_plist_paths)

    def _warn_and_select_missing(self, paths):
        from PySide6.QtWidgets import QMessageBox
        count = len(paths)
        msg = QMessageBox(self)
        msg.setWindowTitle("Archive Integrity Warning")
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setText(
            f"{count} UUID folder{'s' if count != 1 else ''} "
            f"{'are' if count != 1 else 'is'} missing the expected\n"
            f".com.apple.mobile_container_manager.metadata.plist file.\n\n"
            f"This may indicate a corrupt or incomplete download. The bundle ID\n"
            f"cannot be resolved for these folders — they are displayed using\n"
            f"their raw UUID. The affected folders have been selected so you\n"
            f"can press \"Show Selected Items\" to review them."
        )
        msg.setDetailedText("\n".join(sorted(paths)))
        msg.exec()
        self._tick_items_by_path(set(paths))

    def _tick_items_by_path(self, path_set):
        """Check the tree item for every path in path_set.
        Descends only the branches needed, loading lazily as it goes."""
        for path in path_set:
            self._tick_single_path(path)
        self.tree_view.viewport().update()
        self._update_selected_btn()
        self._rebuild_file_view_from_checked()

    def _tick_single_path(self, target_path):
        """Navigate to target_path in the tree, loading lazily, and tick the item."""
        invisible_root = self.tree_model.invisibleRootItem()
        if invisible_root.rowCount() == 0:
            return
        current = invisible_root.child(0)  # "/ [Full Filesystem]"
        self._ensure_children_loaded(current)
        parts = [p for p in target_path.split('/') if p]
        for part in parts:
            found = False
            for row in range(current.rowCount()):
                child = current.child(row)
                child_path = child.data(Qt.ItemDataRole.UserRole)
                if child_path is not None and child_path.split('/')[-1] == part:
                    self._ensure_children_loaded(child)
                    current = child
                    found = True
                    break
            if not found:
                return
        if current.isCheckable():
            current.setCheckState(Qt.CheckState.Checked)

    def reload_tree_entirely(self):
        if not self.folder_map: return
        self._reset_tree_model()
        self.tree_view.setModel(self.tree_model)
        mode = self.view_group.checkedId()
        self.tree_model.blockSignals(True)
        root_item = QStandardItem("/ [Full Filesystem]")
        root_item.setData("", Qt.ItemDataRole.UserRole)
        root_item.setEditable(False)
        root_item.setFont(QFont("Arial", weight=QFont.Weight.Bold))
        if mode in (0, CLEAN_MODE):
            root_item.setCheckable(True)
            root_item.setCheckState(Qt.CheckState.Unchecked)
        self.tree_model.invisibleRootItem().appendRow(root_item)
        self._populate_tree_children(root_item, "", mode)
        self.tree_view.expand(self.tree_model.indexFromItem(root_item))
        self.tree_model.blockSignals(False)
        self.progress_bar.hide()
        self.status_bar.showMessage(f"Loaded: {os.path.basename(self.zip_path)}")

    def _populate_tree_children(self, parent_item, parent_path, mode):
        """Add immediate folder children of parent_path to parent_item.
        Each child that itself has children gets a placeholder so the tree
        shows an expand arrow; actual grandchildren are loaded on demand."""
        children = sorted(self.folder_map.get(parent_path, []))
        for p in children:
            if p not in self.folder_map:
                continue
            if mode == CLEAN_MODE and self.is_path_hidden(p):
                continue
            name = p.split('/')[-1]
            item = QStandardItem(self._display_name(name))
            item.setData(p, Qt.ItemDataRole.UserRole)
            item.setEditable(False)
            if mode == EDIT_FILTER_MODE:
                item.setCheckable(True)
                if self.is_path_hidden(p):
                    item.setCheckState(Qt.CheckState.Unchecked)
                    item.setForeground(QColor("#cc2222"))
                else:
                    item.setCheckState(Qt.CheckState.Checked)
            elif mode in (0, CLEAN_MODE):
                item.setCheckable(True)
                item.setCheckState(Qt.CheckState.Unchecked)
            parent_item.appendRow(item)
            # Add a placeholder so Qt shows the expand arrow without
            # loading all grandchildren upfront.
            if self.folder_map.get(p):
                placeholder = QStandardItem()
                placeholder.setData(_TREE_PLACEHOLDER, Qt.ItemDataRole.UserRole)
                placeholder.setEditable(False)
                item.appendRow(placeholder)

    def is_path_hidden(self, path):
        for rule in self.hidden_paths:
            if path.startswith(rule): return True
        return False

    def _on_tree_item_expanded(self, index):
        """Lazy-load children when a tree node is expanded for the first time."""
        item = self.tree_model.itemFromIndex(index)
        if item is None or item.rowCount() != 1:
            return
        placeholder = item.child(0)
        if placeholder is None or placeholder.data(Qt.ItemDataRole.UserRole) != _TREE_PLACEHOLDER:
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        if path is None:
            return
        mode = self.view_group.checkedId()
        self._tree_populating = True
        item.removeRow(0)
        self._populate_tree_children(item, path, mode)
        self._tree_populating = False

    def _ensure_children_loaded(self, item):
        """If item still holds only a placeholder, replace it with real children."""
        if item.rowCount() == 1:
            placeholder = item.child(0)
            if placeholder and placeholder.data(Qt.ItemDataRole.UserRole) == _TREE_PLACEHOLDER:
                path = item.data(Qt.ItemDataRole.UserRole)
                if path is not None:
                    mode = self.view_group.checkedId()
                    self._tree_populating = True
                    item.removeRow(0)
                    self._populate_tree_children(item, path, mode)
                    self._tree_populating = False

    def _ensure_all_descendants_loaded(self, item):
        """Recursively force-load every level under item (used for recursive tick)."""
        self._ensure_children_loaded(item)
        for row in range(item.rowCount()):
            child = item.child(row)
            if child is not None:
                self._ensure_all_descendants_loaded(child)

    def on_tree_item_changed(self, item):
        if self._tree_populating:
            return
        mode = self.view_group.checkedId()
        if mode == EDIT_FILTER_MODE:
            path = item.data(Qt.ItemDataRole.UserRole)
            if path is None:
                return
            excluded = (item.checkState() == Qt.CheckState.Unchecked)
            if excluded:
                self.hidden_paths.add(path)
            else:
                self.hidden_paths.discard(path)
            # Update text colour to reflect state; block signals to avoid re-entry
            self.tree_model.blockSignals(True)
            if excluded:
                item.setForeground(QColor("#cc2222"))
            else:
                item.setData(None, Qt.ItemDataRole.ForegroundRole)  # restore default
            self.tree_model.blockSignals(False)
            self.save_settings()
        elif mode in (0, CLEAN_MODE):
            # Single folder tick — expand to show unticked children
            if item.checkState() == Qt.CheckState.Checked:
                self.tree_view.expand(self.tree_model.indexFromItem(item))
            self.tree_view.viewport().update()
            if not self._rebuild_pending:
                self._rebuild_pending = True
                QTimer.singleShot(0, self._deferred_rebuild)

    def _update_selected_btn(self):
        """Recount ticked folders and update the status label and deselect button."""
        checked = set()
        self._collect_checked_paths(self.tree_model.invisibleRootItem(), checked)
        if not checked:
            self.show_selected_btn.setVisible(False)
            self.deselect_all_btn.setVisible(False)
            return
        item_count = sum(len(self.folder_map.get(folder, [])) for folder in checked)
        self.show_selected_btn.setText(f"Show {item_count:,} Selected Items")
        self.show_selected_btn.setVisible(True)
        self.deselect_all_btn.setVisible(True)

    def _deselect_all_files(self):
        """Untick all folders in the tree and clear the file browser."""
        self.tree_model.blockSignals(True)
        root = self.tree_model.invisibleRootItem()
        self._cascade_check(root, Qt.CheckState.Unchecked)
        self.tree_model.blockSignals(False)
        self.tree_view.viewport().update()
        self._view_is_recursive = False
        self._update_selected_btn()
        # Show the highlighted folder if one is selected, otherwise clear
        idx = self.tree_view.currentIndex()
        if idx.isValid():
            self.on_folder_selected(idx)
        else:
            self._set_file_model(FileTableModel(self.file_headers))
            self._update_filter_columns(self.file_headers)
            self._refresh_table_status()

    def _deferred_rebuild(self):
        self._rebuild_pending = False
        self._update_selected_btn()
        self._rebuild_file_view_from_checked()

    def save_settings(self):
        with open(resource_path(SETTINGS_FILE), 'w', encoding='utf-8') as f:
            json.dump(list(self.hidden_paths), f)

    def load_settings(self):
        return set(_load_json_file(resource_path(SETTINGS_FILE), []))

    def _on_recent_context_menu(self, point):
        view = self.archive_dropdown.view()
        index = view.indexAt(point)
        if not index.isValid():
            return
        text = self.archive_dropdown.itemText(index.row())
        if not text or text == NEW_ARCHIVE_SENTINEL:
            return
        menu = QMenu(self)
        act = QAction(f"Remove from recent list", self)
        act.triggered.connect(lambda: self._remove_recent(text))
        menu.addAction(act)
        menu.exec(view.viewport().mapToGlobal(point))

    def _remove_recent(self, path):
        if path in self.recent_paths:
            self.recent_paths.remove(path)
            with open(RECENT_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.recent_paths, f)
            self.update_dropdown_ui()

    def load_recent_list(self):
        return _load_json_file(RECENT_FILE, [])

    def save_recent_list(self, path):
        if path in self.recent_paths: self.recent_paths.remove(path)
        self.recent_paths.insert(0, path)
        self.recent_paths = self.recent_paths[:5]
        with open(RECENT_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.recent_paths, f)
        self.update_dropdown_ui()

    def update_dropdown_ui(self):
        self.archive_dropdown.clear()
        self.archive_dropdown.addItem(NEW_ARCHIVE_SENTINEL)
        for p in self.recent_paths: self.archive_dropdown.addItem(p)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(resource_path(os.path.join("resources", "icon.png"))))
    window = FastZipBrowser()
    window.show()
    sys.exit(app.exec())