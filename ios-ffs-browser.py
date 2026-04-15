import sys
import os
import re
import time
import sqlite3
import struct
import zipfile
import json
import subprocess
import plistlib
import pathlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from adapters import FfsAdapter
from zip_entry import ZipEntry
from streaming_zip import StreamingZipIndex
from datetime import datetime, timezone
from PySide6.QtWidgets import (QApplication, QMainWindow, QTreeView, QTableView, QVBoxLayout,
                              QHBoxLayout, QWidget, QHeaderView, QPushButton,
                              QFileDialog, QProgressBar, QMenu, QDialog,
                              QRadioButton, QButtonGroup, QComboBox, QSplitter, QStatusBar,
                              QLineEdit, QLabel, QPlainTextEdit, QFrame, QTextEdit,
                              QTabWidget, QScrollArea, QGridLayout, QSizePolicy,
                              QStyledItemDelegate, QStyle)
from PySide6.QtGui import (QStandardItemModel, QStandardItem, QAction, QFont,
                           QCursor, QColor, QTextCharFormat, QTextCursor, QFontMetricsF,
                           QIcon, QPixmap, QImage, QFontDatabase, QTextDocument)
from PySide6.QtCore import (Qt, QThread, Signal, QSortFilterProxyModel, QTimer, QEvent,
                             QModelIndex, QAbstractTableModel, QBuffer, QIODevice)

SETTINGS_FILE        = "forensic_settings.json"
FFS_ARCHIVES_FILE    = "ffs_archives.json"
DEVICE_LABELS_FILE   = "device_labels.json"
HARDWARE_MODELS_FILE = "hardware_models.json"
NEW_ARCHIVE_SENTINEL = "<Open New FFS...>"   # kept for back-compat with saved data; no longer shown in dropdown

# Hardware identifier → marketing name mapping for common iOS devices
_HW_MODEL_NAMES = {
    # iPhone
    'iPhone12,1':'iPhone 11','iPhone12,3':'iPhone 11 Pro','iPhone12,5':'iPhone 11 Pro Max',
    'iPhone13,1':'iPhone 12 mini','iPhone13,2':'iPhone 12','iPhone13,3':'iPhone 12 Pro',
    'iPhone13,4':'iPhone 12 Pro Max',
    'iPhone14,4':'iPhone 13 mini','iPhone14,5':'iPhone 13','iPhone14,2':'iPhone 13 Pro',
    'iPhone14,3':'iPhone 13 Pro Max',
    'iPhone14,7':'iPhone 14','iPhone14,8':'iPhone 14 Plus','iPhone15,2':'iPhone 14 Pro',
    'iPhone15,3':'iPhone 14 Pro Max',
    'iPhone15,4':'iPhone 15','iPhone15,5':'iPhone 15 Plus','iPhone16,1':'iPhone 15 Pro',
    'iPhone16,2':'iPhone 15 Pro Max',
    'iPhone17,3':'iPhone 16','iPhone17,4':'iPhone 16 Plus','iPhone17,1':'iPhone 16 Pro',
    'iPhone17,2':'iPhone 16 Pro Max',
    'iPhone10,1':'iPhone 8','iPhone10,4':'iPhone 8','iPhone10,2':'iPhone 8 Plus',
    'iPhone10,5':'iPhone 8 Plus','iPhone10,3':'iPhone X','iPhone10,6':'iPhone X',
    'iPhone11,2':'iPhone XS','iPhone11,4':'iPhone XS Max','iPhone11,6':'iPhone XS Max',
    'iPhone11,8':'iPhone XR',
    'iPhone9,1':'iPhone 7','iPhone9,3':'iPhone 7','iPhone9,2':'iPhone 7 Plus',
    'iPhone9,4':'iPhone 7 Plus',
    'iPhone8,1':'iPhone 6s','iPhone8,2':'iPhone 6s Plus','iPhone8,4':'iPhone SE (1st gen)',
    'iPhone12,8':'iPhone SE (2nd gen)','iPhone14,6':'iPhone SE (3rd gen)',
    # iPad (selection)
    'iPad13,18':'iPad (10th gen)','iPad13,19':'iPad (10th gen)',
    'iPad14,3':'iPad Pro 11" (4th gen)','iPad14,4':'iPad Pro 11" (4th gen)',
    'iPad14,5':'iPad Pro 12.9" (6th gen)','iPad14,6':'iPad Pro 12.9" (6th gen)',
    'iPad13,4':'iPad Pro 11" (3rd gen)','iPad13,5':'iPad Pro 11" (3rd gen)',
    'iPad13,6':'iPad Pro 11" (3rd gen)','iPad13,7':'iPad Pro 11" (3rd gen)',
    'iPad13,8':'iPad Pro 12.9" (5th gen)','iPad13,9':'iPad Pro 12.9" (5th gen)',
    'iPad13,10':'iPad Pro 12.9" (5th gen)','iPad13,11':'iPad Pro 12.9" (5th gen)',
    'iPad11,6':'iPad (8th gen)','iPad11,7':'iPad (8th gen)',
    'iPad12,1':'iPad (9th gen)','iPad12,2':'iPad (9th gen)',
    'iPad13,16':'iPad Air (5th gen)','iPad13,17':'iPad Air (5th gen)',
    'iPad11,3':'iPad Air (3rd gen)','iPad11,4':'iPad Air (3rd gen)',
    'iPad13,1':'iPad Air (4th gen)','iPad13,2':'iPad Air (4th gen)',
    'iPad14,8':'iPad Air 11" (M2)','iPad14,9':'iPad Air 11" (M2)',
    'iPad14,10':'iPad Air 13" (M2)','iPad14,11':'iPad Air 13" (M2)',
    # iPod
    'iPod9,1':'iPod touch (7th gen)',
}
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
HIT_WINDOW_BEFORE = 8192    # bytes before a search hit to load initially
HIT_WINDOW_AFTER  = 8192    # bytes after a search hit to load initially
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



def _load_json_file(path, default):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


# Board-ID → [make, model] mapping loaded from hardware_models.json.
# Keys are Apple internal hardware board identifiers (e.g. "D22AP").
_HW_BOARD_NAMES: dict = _load_json_file(resource_path(HARDWARE_MODELS_FILE), {})


def _read_plist_from_zip(z: zipfile.ZipFile, *candidates) -> dict:
    """Try each candidate path in the zip and return the first successfully
    parsed plist as a dict, or {} if none found."""
    names = frozenset(z.namelist())
    for path in candidates:
        if path in names:
            try:
                return plistlib.loads(z.read(path))
            except Exception:
                pass
    return {}


def _plist_find(d, key, _depth=0):
    """Recursively search a plist dict for the first occurrence of key."""
    if not isinstance(d, dict) or _depth > 6:
        return None
    if key in d:
        v = d[key]
        return v if isinstance(v, str) and v else None
    for v in d.values():
        result = _plist_find(v, key, _depth + 1)
        if result:
            return result
    return None


def _read_device_info(zip_path: str) -> str:
    """Return a short label like 'Apple iPhone 14 Pro · iOS 17.4.1' extracted
    from the FFS zip, or '' if the info cannot be determined."""
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            adapter = FfsAdapter.detect(z)

            _mg_suffix = ('containers/Shared/SystemGroup/'
                          'systemgroup.com.apple.mobilegestaltcache/Library/Caches/'
                          'com.apple.MobileGestalt.plist')

            mg_plist = _read_plist_from_zip(z, *adapter.user_candidates(_mg_suffix))

            # ── iOS version ───────────────────────────────────────────────────
            ios_version = _plist_find(mg_plist, 'ProductVersion') or ''
            if not ios_version:
                sv = _read_plist_from_zip(z,
                    *adapter.system_candidates(
                        'System/Library/CoreServices/SystemVersion.plist'),
                    *adapter.user_candidates('run/SystemVersion.plist'),
                )
                ios_version = sv.get('ProductVersion', '')

            # ── Hardware model identifier ─────────────────────────────────────
            pref = _read_plist_from_zip(z, *adapter.user_candidates(
                'preferences/SystemConfiguration/preferences.plist'))
            hw_id = pref.get('Model', '')
            if not hw_id:
                hw_id = _plist_find(mg_plist, 'ProductType') or ''
            if not hw_id:
                hw_id = _plist_find(mg_plist, 'HardwareModel') or ''

            if not hw_id:
                model_name = ''
            elif hw_id in _HW_BOARD_NAMES:
                entry = _HW_BOARD_NAMES[hw_id]
                model_name = f"{entry[0]} {entry[1]}"
            elif hw_id in _HW_MODEL_NAMES:
                model_name = _HW_MODEL_NAMES[hw_id]
            else:
                model_name = hw_id

            if model_name and ios_version:
                return f'{model_name} · iOS {ios_version}'
            if ios_version:
                return f'iOS {ios_version}'
            if model_name:
                return model_name
            return ''
    except Exception:
        return ''


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
            self._streaming_index = None   # set below if zipfile cannot open it

            try:
                z_ctx = zipfile.ZipFile(self.zip_path, 'r')
                z_ctx.__enter__()
                use_streaming = False
            except zipfile.BadZipFile:
                # Streaming zip with no central directory (e.g. old Cellebrite Premium)
                self.status_update.emit("Streaming zip detected — building index...")
                self._streaming_index = StreamingZipIndex.open(
                    self.zip_path,
                    progress_cb=lambda done, total: self.status_update.emit(
                        f"Indexing archive: {done / max(total, 1):.0%}"),
                )
                z_ctx = None
                use_streaming = True

            try:
                if use_streaming:
                    zip_names = frozenset(self._streaming_index.namelist())
                    adapter = FfsAdapter.detect_from_names(zip_names)
                    guid_to_bundle = {}   # no plist reads during streaming index scan
                    self.status_update.emit("Reading metadata.msgpack...")
                    import msgpack as _msgpack
                    for _mp_path in ("metadata2/metadata.msgpack", "metadata1/metadata.msgpack"):
                        if _mp_path in self._streaming_index:
                            msgpack_entry = self._streaming_index.get_entry(_mp_path)
                            break
                    else:
                        raise KeyError("metadata.msgpack not found in metadata1/ or metadata2/")
                    raw_data = _msgpack.unpackb(msgpack_entry.read(), raw=False)
                    if adapter.old_layout:
                        _PV = "private/var/"
                        raw_data = {
                            (k[len(_PV):] if k.startswith(_PV) else k): v
                            for k, v in raw_data.items()
                        }
                else:
                    z = z_ctx
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

                    adapter = FfsAdapter.detect(z)
                    if adapter.format == FfsAdapter.FORMAT_GRAYKEY:
                        self.status_update.emit("Graykey archive detected — extracting metadata...")
                    else:
                        self.status_update.emit("Reading metadata.msgpack...")
                    raw_data = adapter.load_metadata(self.zip_path, z)
            finally:
                if z_ctx is not None:
                    z_ctx.__exit__(None, None, None)

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

            self.metadata_ready.emit(ui_metadata, folder_map, guid_to_bundle, zip_names, adapter, missing_plist_paths)
        except Exception as e:
            self.status_update.emit(f"Error: {str(e)}")



MEDIA_EXTENSIONS = frozenset({
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.heic', '.heif',
    '.tiff', '.tif', '.mov', '.mp4', '.m4v', '.3gp', '.avi',
})
VIDEO_THUMB_EXTENSIONS = frozenset({'.mov', '.mp4', '.m4v', '.3gp', '.avi'})
THUMB_SIZE = 160   # thumbnail box size in pixels


def _find_ffmpeg() -> str | None:
    """Return the absolute path to ffmpeg, or None if not found.
    Checks PATH first, then the fixed Homebrew locations for Apple Silicon
    and Intel Macs, since subprocess does not inherit the shell PATH when
    launched from a GUI app or PyInstaller bundle."""
    if not hasattr(_find_ffmpeg, '_result'):
        import shutil
        candidate = shutil.which('ffmpeg')
        if candidate is None:
            # Homebrew on Apple Silicon is /opt/homebrew; Intel is /usr/local
            for p in ('/opt/homebrew/bin/ffmpeg', '/usr/local/bin/ffmpeg'):
                if os.path.isfile(p):
                    candidate = p
                    break
        if candidate:
            try:
                subprocess.run([candidate, '-version'],
                               capture_output=True, timeout=3, check=True)
            except Exception:
                candidate = None
        _find_ffmpeg._result = candidate
    return _find_ffmpeg._result


def _video_frame_bytes(video_data: bytes) -> bytes | None:
    """Extract a frame from video bytes via ffmpeg, returning PNG bytes or None.

    MOV/MP4 containers store the moov atom at the end by default, which means
    ffmpeg cannot seek when reading from a plain stdin pipe.  Passing
    -probesize and -analyzeduration large enough forces ffmpeg to buffer the
    whole stream before decoding, so it can locate the moov atom without
    needing a seekable file descriptor."""
    ffmpeg = _find_ffmpeg()
    print(f'[video_thumb] ffmpeg={ffmpeg!r}  data_len={len(video_data)}', flush=True)
    if not ffmpeg:
        return None
    for seek in ('00:00:01', '00:00:00'):
        try:
            result = subprocess.run(
                [ffmpeg, '-hide_banner', '-loglevel', 'error',
                 '-probesize', '100M',
                 '-analyzeduration', '100M',
                 '-ss', seek,
                 '-i', 'pipe:0',
                 '-vframes', '1',
                 '-f', 'image2',
                 '-vcodec', 'png',
                 'pipe:1'],
                input=video_data,
                capture_output=True,
                timeout=30,
            )
            print(f'[video_thumb] seek={seek} rc={result.returncode} '
                  f'stdout_len={len(result.stdout)} '
                  f'stderr={result.stderr[:200]!r}', flush=True)
            if result.returncode == 0 and result.stdout:
                return result.stdout
        except Exception as e:
            print(f'[video_thumb] seek={seek} exception={e!r}', flush=True)
    return None


def _thumb_cache_path() -> str:
    """Return the path to the persistent thumbnail cache database."""
    if sys.platform == 'win32':
        base = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
    else:
        base = os.environ.get('XDG_CACHE_HOME', os.path.join(os.path.expanduser('~'), '.cache'))
    d = os.path.join(base, 'ios-ffs-browser')
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, 'thumbcache.db')


def _open_case_db(cache_dir: str | None = None) -> sqlite3.Connection:
    """Open (or create) the per-case database with WAL mode for safe access.

    Tables:
      thumbnails    — cached media thumbnails
      search_results — saved keyword search hits
    """
    if cache_dir is not None:
        os.makedirs(cache_dir, exist_ok=True)
        db_path = os.path.join(cache_dir, 'casedata.db')
    else:
        # Fallback: shared location when no case dir is configured
        base = os.environ.get('LOCALAPPDATA', os.path.expanduser('~')) \
               if sys.platform == 'win32' \
               else os.environ.get('XDG_CACHE_HOME',
                                   os.path.join(os.path.expanduser('~'), '.cache'))
        d = os.path.join(base, 'ios-ffs-browser')
        os.makedirs(d, exist_ok=True)
        db_path = os.path.join(d, 'casedata.db')
    conn = sqlite3.connect(db_path, timeout=5)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS thumbnails (
            zip_path   TEXT    NOT NULL,
            ui_path    TEXT    NOT NULL,
            file_size  INTEGER NOT NULL,
            thumb_size INTEGER NOT NULL,
            data       BLOB    NOT NULL,
            PRIMARY KEY (zip_path, ui_path, file_size, thumb_size)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS search_results (
            zip_path  TEXT    NOT NULL,
            keyword   TEXT    NOT NULL,
            filename  TEXT    NOT NULL,
            offset    INTEGER NOT NULL,
            context   TEXT    NOT NULL
        )
    ''')
    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_search_results
        ON search_results (zip_path, keyword)
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS recent_searches (
            term       TEXT    NOT NULL,
            used_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            PRIMARY KEY (term)
        )
    ''')
    conn.commit()
    return conn


_THUMB_BATCH_COMMIT = 20  # inserts to accumulate before a single db.commit()


class ThumbnailWorker(QThread):
    """Loads thumbnails from the cache DB or the ZIP, emits (ui_path, QImage).

    Single-threaded by design: QImage.loadFromData() and img.scaled() are Qt
    Python-binding calls that hold the GIL, so a ThreadPoolExecutor would only
    serialise them anyway while adding GIL-contention overhead and forcing a
    fresh ZipFile.open() (= full central-directory parse) per thread per file.
    One thread with one open ZipFile handle is measurably faster.
    """
    thumbnail_ready = Signal(str, object)   # ui_path, QImage
    finished_all    = Signal()

    def __init__(self, zip_path, items, path_resolver, thumb_size, zip_info_map,
                 streaming_index=None, cache_dir=None):
        super().__init__()
        self.zip_path        = zip_path
        self.items           = items
        self.path_resolver   = path_resolver
        self.thumb_size      = thumb_size
        self.zip_info_map    = zip_info_map
        self.streaming_index = streaming_index
        self.cache_dir       = cache_dir
        self._stop           = False

    def stop(self):
        self._stop = True

    @staticmethod
    def _encode_jpeg(img):
        buf = QBuffer()
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        img.save(buf, 'JPEG', 85)
        data = bytes(buf.data())
        buf.close()
        return data

    def run(self):
        db = _open_case_db(self.cache_dir)
        try:
            # ── 1. Bulk-load only the thumbnails needed for the current item set ──
            # Using IN (...) rather than loading the full archive avoids pulling
            # thousands of BLOB rows into memory when only a folder subset is shown.
            # SQLite IN() limit is 999, so chunk large sets.
            cached = {}
            _CHUNK = 900
            items_list = list(self.items)
            for i in range(0, len(items_list), _CHUNK):
                chunk = items_list[i:i + _CHUNK]
                placeholders = ','.join('?' * len(chunk))
                for r in db.execute(
                    f'SELECT ui_path, file_size, data FROM thumbnails '
                    f'WHERE zip_path=? AND thumb_size=? AND ui_path IN ({placeholders})',
                    (self.zip_path, self.thumb_size, *chunk)
                ):
                    cached[(r[0], r[1])] = r[2]

            pending = []

            def _read_physical(physical: str) -> bytes:
                if self.streaming_index is not None:
                    return self.streaming_index.get_entry(physical).read()
                with zipfile.ZipFile(self.zip_path, 'r') as z:
                    return z.read(physical)

            # For normal zips keep a single open handle across all reads
            _zf = None if self.streaming_index is not None else zipfile.ZipFile(self.zip_path, 'r')
            try:
                for ui_path in self.items:
                    if self._stop:
                        return

                    physical  = self.path_resolver(ui_path)
                    file_size = self.zip_info_map.get(physical, 0)

                    # ── 2. Cache hit ──────────────────────────────────────────
                    ext = os.path.splitext(physical)[1].lower()
                    blob = cached.get((ui_path, file_size))
                    if blob:
                        # A genuine ffmpeg-extracted frame is always > 10 KB as
                        # JPEG.  A blob smaller than this for a video means it
                        # was stored before ffmpeg was available (the codec
                        # decoded garbage from the raw container bytes).
                        # Discard it and re-extract.
                        stale = (ext in VIDEO_THUMB_EXTENSIONS
                                 and len(blob) < 10_000)
                        if not stale:
                            img = QImage()
                            if img.loadFromData(blob):
                                self.thumbnail_ready.emit(ui_path, img)
                                continue
                        try:
                            db.execute(
                                'DELETE FROM thumbnails WHERE '
                                'zip_path=? AND ui_path=? AND '
                                'file_size=? AND thumb_size=?',
                                (self.zip_path, ui_path,
                                 file_size, self.thumb_size))
                            db.commit()
                        except sqlite3.Error:
                            pass

                    # ── 3. Cache miss: read from zip ──────────────────────────
                    try:
                        data = _zf.read(physical) if _zf is not None else _read_physical(physical)
                    except Exception:
                        continue

                    if ext in VIDEO_THUMB_EXTENSIONS:
                        data = _video_frame_bytes(data)
                        if not data:
                            continue

                    img = QImage()
                    if not img.loadFromData(data):
                        continue
                    img = img.scaled(self.thumb_size, self.thumb_size,
                                     Qt.AspectRatioMode.KeepAspectRatio,
                                     Qt.TransformationMode.SmoothTransformation)
                    self.thumbnail_ready.emit(ui_path, img)

                    # ── 4. Batch-write to cache ───────────────────────────────
                    jpeg = self._encode_jpeg(img)
                    if jpeg:
                        pending.append((self.zip_path, ui_path, file_size,
                                        self.thumb_size, jpeg))
                        if len(pending) >= _THUMB_BATCH_COMMIT:
                            try:
                                db.executemany(
                                    'INSERT OR REPLACE INTO thumbnails '
                                    '(zip_path,ui_path,file_size,thumb_size,data) '
                                    'VALUES (?,?,?,?,?)', pending)
                                db.commit()
                            except sqlite3.Error:
                                pass
                            pending.clear()

            finally:
                if _zf is not None:
                    _zf.close()

            if pending:
                try:
                    db.executemany(
                        'INSERT OR REPLACE INTO thumbnails '
                        '(zip_path,ui_path,file_size,thumb_size,data) '
                        'VALUES (?,?,?,?,?)', pending)
                    db.commit()
                except sqlite3.Error:
                    pass

        finally:
            db.close()
        self.finished_all.emit()


class HexLoadWorker(QThread):
    """Fallback worker for compressed zip entries — reads via zipfile decompression."""
    progress      = Signal(int, int)   # bytes_read, total_bytes
    load_complete = Signal(bytes)
    error         = Signal(str)

    CHUNK = 8192
    LIMIT = 65536

    def __init__(self, entry: ZipEntry):
        super().__init__()
        self.entry       = entry
        self.total_bytes = min(entry.file_size, self.LIMIT) if entry.file_size > 0 else self.LIMIT

    def run(self):
        try:
            data = bytearray()
            with zipfile.ZipFile(self.entry.zip_path, 'r') as z:
                with z.open(self.entry.physical_path) as f:
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
        self._sort_col: int = -1
        self._sort_order: Qt.SortOrder = Qt.SortOrder.AscendingOrder

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
        self._sort_col = column
        self._sort_order = order
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


class ClickableThumb(QWidget):
    """A thumbnail container that emits clicked(ui_path) when pressed."""
    clicked = Signal(str)

    def __init__(self, ui_path: str, parent=None):
        super().__init__(parent)
        self._ui_path = ui_path
        # NoFocus prevents Qt from drawing a dotted focus rectangle over the widget.
        # WA_StyledBackground ensures the background is always painted before children,
        # which stops see-through paint artifacts while thumbnails are loading.
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._ui_path)
        super().mousePressEvent(event)

    def set_selected(self, selected: bool):
        if selected:
            self.setStyleSheet(
                "ClickableThumb { background-color: #1e4080; "
                "border: 2px solid #4d94ff; border-radius: 4px; }")
        else:
            self.setStyleSheet("ClickableThumb { background-color: transparent; }")


class KeywordSearchWorker(QThread):
    """Search all STORED entries in a zip for a keyword using multiple threads.

    Emits:
        result_found(filename, offset_in_file, context_str)
        progress(files_done, files_total)
        finished(total_hits)
    """

    result_found  = Signal(str, int, str)   # name, offset-in-file, context
    progress      = Signal(int, int)        # done, total
    finished      = Signal(int)             # total hits
    status_update = Signal(str)             # free-text status line

    _CHUNK      = 1 * 1024 * 1024   # 1 MB read chunks
    _CTX_BYTES  = 40                # bytes either side of hit for context

    def __init__(self, zip_path: str, keyword: str,
                 streaming_index=None, entries=None, scope="all", parent=None):
        super().__init__(parent)
        self.zip_path         = zip_path
        self.keyword          = keyword.encode('utf-8', errors='replace')
        self.streaming_index  = streaming_index  # None for normal zip
        self._stop            = threading.Event()
        self._prebuilt_entries = entries
        self._scope           = scope
        self.entries: list = []   # full index, populated in run() and available after worker finishes

    def stop(self):
        self._stop.set()

    def _build_entries(self) -> list:
        """Build (name, data_offset, file_size) list inside the worker thread
        so local-header seeks never block the GUI."""
        entries = []
        if self.streaming_index is not None:
            for name in self.streaming_index.namelist():
                try:
                    entry = self.streaming_index.get_entry(name)
                    if entry.is_stored and entry.file_size > 0:
                        entries.append((name, entry.data_offset, entry.file_size))
                except Exception:
                    pass
        else:
            try:
                with zipfile.ZipFile(self.zip_path, 'r') as z:
                    stored = [
                        (info.filename, info.header_offset, info.file_size)
                        for info in z.infolist()
                        if info.compress_type == zipfile.ZIP_STORED and info.file_size > 0
                    ]
            except Exception:
                stored = []
            # Resolve data_offset for all entries with a single open file handle
            # instead of opening the zip once per entry (critical for large archives).
            try:
                with open(self.zip_path, 'rb') as fh:
                    for name, header_offset, file_size in stored:
                        if self._stop.is_set():
                            return entries
                        fh.seek(header_offset + 26)
                        fname_len, extra_len = struct.unpack('<HH', fh.read(4))
                        data_offset = header_offset + 30 + fname_len + extra_len
                        entries.append((name, data_offset, file_size))
            except Exception:
                pass
        return entries

    def run(self):
        if self._prebuilt_entries is not None:
            entries = self._prebuilt_entries
        else:
            self.status_update.emit("Preparing search index…")
            full_entries = self._build_entries()
            self.entries = full_entries   # expose full index for caching
            if self._scope == "app_data":
                entries = [e for e in full_entries if "mobile/Containers" in e[0]]
            else:
                entries = full_entries
        self.status_update.emit(f"Index ready — {len(entries):,} files to search")
        kw        = self.keyword
        kw_len    = len(kw)
        total     = len(entries)
        hits      = 0
        done      = 0
        n_threads = min(8, os.cpu_count() or 4)

        def search_entry(_name, data_offset, file_size):
            if self._stop.is_set():
                return []
            results = []
            overlap = kw_len - 1
            chunk   = self._CHUNK
            pos     = 0
            try:
                with open(self.zip_path, 'rb') as fh:
                    fh.seek(data_offset)
                    buf_start = 0
                    leftover  = b''
                    while pos < file_size and not self._stop.is_set():
                        read_len = min(chunk, file_size - pos)
                        raw      = fh.read(read_len)
                        if not raw:
                            break
                        block      = leftover + raw
                        block_base = buf_start
                        idx        = 0
                        while True:
                            idx = block.find(kw, idx)
                            if idx == -1:
                                break
                            file_offset = block_base + idx
                            ctx_start   = max(0, idx - self._CTX_BYTES)
                            ctx_end     = min(len(block), idx + kw_len + self._CTX_BYTES)
                            ctx_bytes   = block[ctx_start:ctx_end]
                            before      = ctx_bytes[:idx - ctx_start]
                            after       = ctx_bytes[idx - ctx_start + kw_len:]
                            hit_text    = kw.decode('utf-8', errors='replace')
                            context     = (
                                before.decode('utf-8', errors='replace')
                                + f'[{hit_text}]'
                                + after.decode('utf-8', errors='replace')
                            )
                            results.append((file_offset, context))
                            idx += kw_len
                        leftover  = block[-overlap:] if overlap > 0 else b''
                        buf_start = block_base + len(block) - len(leftover)
                        pos      += read_len
            except OSError:
                pass
            return results

        with ThreadPoolExecutor(max_workers=n_threads) as pool:
            futures = {
                pool.submit(search_entry, name, off, size): name
                for name, off, size in entries
            }
            for fut in as_completed(futures):
                if self._stop.is_set():
                    break
                name = futures[fut]
                done += 1
                self.progress.emit(done, total)
                try:
                    for file_offset, context in fut.result():
                        hits += 1
                        self.result_found.emit(name, file_offset, context)
                except Exception:
                    pass

        self.finished.emit(hits)


class CaseSettingsDialog(QDialog):
    """Shown the first time an FFS zip is opened.

    Lets the user choose the base folder that will hold the per-zip case folder.
    The case folder is created as  <base>/<zip_stem>/  and stores:
      • casedata.db    — thumbnails and search results
      • Export/        — extracted files
    """

    def __init__(self, zip_path: str, last_base: str | None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Case Folder Settings")
        self.setModal(True)
        self.setMinimumWidth(560)

        self._accepted_dir: str | None = None

        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        layout.addWidget(QLabel(
            "<b>Choose where to store the cache and exports for this FFS archive.</b><br>"
            "A subfolder will be created inside the base location you select."
        ))

        # Base folder row
        base_row = QHBoxLayout()
        base_row.addWidget(QLabel("Base folder:"))
        self._base_edit = QLineEdit()
        self._base_edit.setPlaceholderText("Select a folder…")
        if last_base and os.path.isdir(last_base):
            self._base_edit.setText(last_base)
        self._base_edit.textChanged.connect(self._update_preview)
        base_row.addWidget(self._base_edit, 1)
        browse_btn = QPushButton("Browse…")
        browse_btn.setFixedWidth(80)
        browse_btn.clicked.connect(self._browse)
        base_row.addWidget(browse_btn)
        layout.addLayout(base_row)

        # Case folder name row
        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Case folder name:"))
        self._name_edit = QLineEdit()
        self._name_edit.setText(pathlib.Path(zip_path).stem)
        self._name_edit.textChanged.connect(self._update_preview)
        name_row.addWidget(self._name_edit, 1)
        layout.addLayout(name_row)

        # Preview
        self._preview_label = QLabel()
        self._preview_label.setWordWrap(True)
        layout.addWidget(self._preview_label)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._save_btn = QPushButton("Save Settings")
        self._save_btn.setDefault(True)
        self._save_btn.clicked.connect(self._on_save)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(self._save_btn)
        layout.addLayout(btn_row)

        # Populate preview now that _save_btn exists
        self._update_preview()

    def _browse(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Base Folder",
                                                  self._base_edit.text())
        if folder:
            self._base_edit.setText(folder)

    def _update_preview(self):
        base = self._base_edit.text().strip()
        name = self._name_edit.text().strip()
        if not base or not name:
            self._preview_label.setText("<i>No folder selected.</i>")
            self._save_btn.setEnabled(False)
            return
        case_dir  = os.path.join(base, name)
        cache_loc = os.path.join(case_dir, 'casedata.db')
        export_loc = os.path.join(case_dir, 'Export', '')
        exists_note = " <b>(already exists)</b>" if os.path.isdir(case_dir) else ""
        self._preview_label.setText(
            f"<b>Case folder:</b> {case_dir}{exists_note}<br>"
            f"<b>Thumbnail cache:</b> {cache_loc}<br>"
            f"<b>Export folder:</b> {export_loc}"
        )
        self._save_btn.setEnabled(True)

    def _on_save(self):
        base = self._base_edit.text().strip()
        name = self._name_edit.text().strip()
        if not base or not name:
            return
        case_dir = os.path.join(base, name)
        if os.path.isdir(case_dir):
            from PySide6.QtWidgets import QMessageBox
            ans = QMessageBox.question(
                self,
                "Case Folder Already Exists",
                f"A folder named <b>{name}</b> already exists at this location.<br><br>"
                f"<b>{case_dir}</b><br><br>"
                "Use the existing folder? (Cache and exports will be shared.)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if ans != QMessageBox.StandardButton.Yes:
                return
        self._accepted_dir = case_dir
        self.accept()

    @property
    def case_dir(self) -> str | None:
        return self._accepted_dir


class SearchContextDelegate(QStyledItemDelegate):
    """Renders the Context column (col 2) with the search term highlighted."""

    CONTEXT_COL = 2
    _HL_BG  = "#ffeb3b"   # highlight background (yellow)
    _HL_FG  = "#000000"   # highlight foreground

    def __init__(self, get_term, parent=None):
        super().__init__(parent)
        self._get_term = get_term   # callable → current search term string

    def paint(self, painter, option, index):
        if index.column() != self.CONTEXT_COL:
            super().paint(painter, option, index)
            return

        text = index.data(Qt.ItemDataRole.DisplayRole) or ''
        term = self._get_term()
        if not term or not text:
            super().paint(painter, option, index)
            return

        self.initStyleOption(option, index)

        # Draw the item background / selection highlight (no text yet)
        style = option.widget.style() if option.widget else QApplication.style()
        option.text = ''
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, option, painter, option.widget)

        # Build HTML: escape both, then re-insert highlighted spans
        import html as _html, re as _re
        escaped = _html.escape(text)
        pattern = _re.compile(_re.escape(_html.escape(term)), _re.IGNORECASE)
        highlighted = pattern.sub(
            lambda m: (f'<span style="background:{self._HL_BG};color:{self._HL_FG};">'
                       f'{m.group()}</span>'),
            escaped
        )

        # Choose foreground colour based on selection state
        if option.state & QStyle.StateFlag.State_Selected:
            fg = option.palette.highlightedText().color().name()
        else:
            fg = option.palette.text().color().name()

        doc = QTextDocument()
        doc.setDefaultStyleSheet(f'body {{ color: {fg}; }}')
        doc.setHtml(f'<body>{highlighted}</body>')
        doc.setTextWidth(option.rect.width())

        text_rect = style.subElementRect(
            QStyle.SubElement.SE_ItemViewItemText, option, option.widget)

        painter.save()
        painter.translate(text_rect.topLeft())
        painter.setClipRect(text_rect.translated(-text_rect.topLeft()))
        doc.drawContents(painter)
        painter.restore()

    def sizeHint(self, option, index):
        sh = super().sizeHint(option, index)
        return sh


class SearchProgressDialog(QDialog):
    """Modal progress dialog shown during a keyword search.

    Displays a scrolling log of status messages followed by live
    progress counters.  The Cancel button stops the worker but leaves
    any hits already found intact so the user can review them.
    """

    cancelled = Signal()

    def __init__(self, term: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Keyword Search")
        self.setModal(True)
        self.setMinimumWidth(480)
        self.setMinimumHeight(260)
        self._interrupted = False

        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        layout.addWidget(QLabel(f"<b>Searching for:</b> {term}"))

        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setFixedHeight(100)
        self._log.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        layout.addWidget(self._log)

        self._progress_label = QLabel("Starting…")
        layout.addWidget(self._progress_label)

        self._bar = QProgressBar()
        self._bar.setRange(0, 0)   # indeterminate until we know total
        layout.addWidget(self._bar)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.clicked.connect(self._on_cancel)
        btn_row.addWidget(self._cancel_btn)
        layout.addLayout(btn_row)

    # ── Slots called by the worker signals ────────────────────────────────────

    def append_status(self, text: str):
        self._log.appendPlainText(text)
        self._log.verticalScrollBar().setValue(
            self._log.verticalScrollBar().maximum())

    def update_progress(self, done: int, total: int, hits: int):
        if self._bar.maximum() != total:
            self._bar.setRange(0, total)
        self._bar.setValue(done)
        self._progress_label.setText(
            f"Checked {done:,} / {total:,} files  |  "
            f"hits in {hits:,} file{'s' if hits != 1 else ''} so far")

    def mark_finished(self, n_files: int, total_hits: int):
        self._bar.setValue(self._bar.maximum())
        self._progress_label.setText(
            f"Complete — {total_hits:,} hit{'s' if total_hits != 1 else ''} "
            f"across {n_files:,} file{'s' if n_files != 1 else ''}")
        self._cancel_btn.setText("Close")

    def mark_interrupted(self, n_files: int):
        self._interrupted = True
        self._progress_label.setText(
            f"Partial search — interrupted  "
            f"({n_files:,} file{'s' if n_files != 1 else ''} with hits)")
        self._cancel_btn.setText("Close")

    @property
    def was_interrupted(self) -> bool:
        return self._interrupted

    # ── Internal ──────────────────────────────────────────────────────────────

    def _on_cancel(self):
        if self._cancel_btn.text() == "Close":
            self.accept()
        else:
            self.cancelled.emit()
            # Button text changes to "Close" once the worker finishes and
            # mark_interrupted() is called; don't close yet so the user
            # can read the final status.

    def closeEvent(self, event):
        """Block the window-close button while searching is in progress."""
        if self._cancel_btn.text() not in ("Close",):
            self.cancelled.emit()
            event.ignore()
        else:
            super().closeEvent(event)


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
        self._streaming_index: StreamingZipIndex | None = None
        self._hex_worker: QThread | None = None
        self._adapter = FfsAdapter(FfsAdapter.FORMAT_CELLEBRITE, "filesystem2", "filesystem1")
        self.hidden_paths = self.load_settings()
        # ffs_archives: ordered list of {"path": ..., "case_dir": ...}, most-recent first
        self._ffs_archives: list = _load_json_file(FFS_ARCHIVES_FILE, [])
        self.recent_paths: list = [e['path'] for e in self._ffs_archives if 'path' in e]
        self.device_labels: dict = _load_json_file(DEVICE_LABELS_FILE, {})
        self._case_dir: str | None = None   # case folder for the currently loaded zip

        # ── Menu bar ──────────────────────────────────────────────────────
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("File")
        open_act = QAction("Open FFS...", self)
        open_act.setShortcut("Ctrl+O")
        open_act.triggered.connect(self._open_new_ffs)
        file_menu.addAction(open_act)
        file_menu.addSeparator()
        self._recent_menu = file_menu.addMenu("Recently Opened FFS")
        self._recent_menu.aboutToShow.connect(self._populate_recent_menu)
        self._view_path = ""
        self._view_is_recursive = False
        self._checked_folders: set = set()
        self._rebuild_pending = False
        self._selected_file_path: str | None = None
        self._selected_media_path: str | None = None
        self._thumb_widgets: dict = {}
        self._pending_media_selection: str | None = None
        self._media_context = None   # tracks what is currently loaded in the media grid
        self._media_total_files: int | None = None
        self._media_sort_desc: str = ""
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
        self.archive_dropdown.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.archive_dropdown.setMinimumContentsLength(60)
        self.archive_dropdown.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.archive_dropdown.setMaximumWidth(9999)  # fills available space but never forces window wider
        self.update_dropdown_ui()
        self.archive_dropdown.activated.connect(self._on_dropdown_activated)
        self.archive_dropdown.view().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.archive_dropdown.view().customContextMenuRequested.connect(self._on_recent_context_menu)
        self.action_btn = QPushButton("Open FFS")
        self.action_btn.clicked.connect(self._open_new_ffs)
        self.open_export_btn = QPushButton("Open Export Folder")
        self.open_export_btn.clicked.connect(self.ensure_and_open_export_dir)
        self.folder_view_btn = QPushButton("Folder View ▾")
        self.folder_view_btn.clicked.connect(self._show_view_mode_menu)
        self.action_btn.setFixedWidth(90)
        self.open_export_btn.setFixedWidth(150)
        self.folder_view_btn.setFixedWidth(110)
        archive_bar.addWidget(self.archive_dropdown, 1)
        archive_bar.addWidget(self.action_btn)
        archive_bar.addWidget(self.open_export_btn)
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
        # Interactive: column width is fixed until the user drags it.
        # Long names get a horizontal scrollbar rather than pushing the splitter.
        self.tree_view.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.tree_view.header().setStretchLastSection(True)
        self.tree_view.header().setDefaultSectionSize(260)
        self.tree_view.setMinimumWidth(0)
        self.tree_view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

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
        left_panel.setMinimumWidth(0)
        left_panel.setMaximumWidth(600)
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

        self.show_selected_btn = QPushButton("Show Selected Files")
        self.show_selected_btn.setVisible(False)
        self.show_selected_btn.clicked.connect(self._rebuild_file_view_from_checked)

        self.deselect_all_btn = QPushButton("Deselect All")
        self.deselect_all_btn.setVisible(False)
        self.deselect_all_btn.clicked.connect(self._deselect_all_files)

        self.table_status_label = QLabel()
        self.table_status_label.setStyleSheet(_status_style)

        # ── File Browser tab ────────────────────────────────────────────────
        file_tab = QWidget()
        file_tab_layout = QVBoxLayout(file_tab)
        file_tab_layout.setContentsMargins(0, 4, 0, 0)
        file_tab_layout.setSpacing(2)

        sel_bar = QHBoxLayout()
        sel_bar.addWidget(self.table_status_label)
        sel_bar.addStretch()
        sel_bar.addWidget(self.show_selected_btn)
        sel_bar.addWidget(self.deselect_all_btn)
        file_tab_layout.addLayout(sel_bar)
        file_tab_layout.addLayout(filter_bar)
        file_tab_layout.addWidget(self.file_view)

        # ── Media Browser tab ───────────────────────────────────────────────
        self._thumb_worker: ThumbnailWorker | None = None
        self._media_status = QLabel("Select a folder to view media")
        self._media_status.setStyleSheet(_status_style)

        self._media_grid_widget = QWidget()
        self._media_grid = QGridLayout(self._media_grid_widget)
        self._media_grid.setSpacing(8)
        self._media_grid.setContentsMargins(8, 8, 8, 8)

        # Wrap the grid in a container that has a stretch spacer below it.
        # This stops QScrollArea (widgetResizable=True) from stretching the grid
        # widget to fill the viewport, which would make QGridLayout divide the
        # viewport height equally among rows and cause jiggling during loading.
        _media_container = QWidget()
        _media_container_layout = QVBoxLayout(_media_container)
        _media_container_layout.setContentsMargins(0, 0, 0, 0)
        _media_container_layout.setSpacing(0)
        _media_container_layout.addWidget(self._media_grid_widget)
        _media_container_layout.addStretch()

        self._media_scroll = QScrollArea()
        self._media_scroll.setWidgetResizable(True)
        self._media_scroll.setWidget(_media_container)
        media_scroll = self._media_scroll

        media_tab = QWidget()
        media_tab_layout = QVBoxLayout(media_tab)
        media_tab_layout.setContentsMargins(0, 4, 0, 0)
        media_tab_layout.setSpacing(2)
        media_tab_layout.addWidget(self._media_status)
        media_tab_layout.addWidget(media_scroll, stretch=1)

        # ── Keyword search tab ───────────────────────────────────────────────
        search_tab = QWidget()
        search_tab_layout = QVBoxLayout(search_tab)
        search_tab_layout.setContentsMargins(4, 4, 4, 4)
        search_tab_layout.setSpacing(4)

        # Controls row
        search_ctrl = QHBoxLayout()
        self.search_recent_combo = QComboBox()
        self.search_recent_combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.search_recent_combo.setMinimumContentsLength(20)
        self.search_recent_combo.setMaximumWidth(260)
        self.search_recent_combo.setToolTip("Recent searches")
        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("Enter keyword…")
        self.search_field.returnPressed.connect(self._start_keyword_search)
        self.search_btn  = QPushButton("Search")
        self.search_btn.setFixedWidth(80)
        self.search_btn.clicked.connect(self._start_keyword_search)
        self.search_stop_btn = QPushButton("Stop")
        self.search_stop_btn.setFixedWidth(60)
        self.search_stop_btn.setEnabled(False)
        self.search_stop_btn.clicked.connect(self._stop_keyword_search)
        self.search_status = QLabel("No search running")
        self.search_scope_combo = QComboBox()
        self.search_scope_combo.addItem("All Files",  userData="all")
        self.search_scope_combo.addItem("App Data",   userData="app_data")
        self.search_scope_combo.setToolTip(
            "All Files — search every stored file in the archive\n"
            "App Data  — search only files under mobile/Containers"
        )
        search_ctrl.addWidget(QLabel("Recent:"))
        search_ctrl.addWidget(self.search_recent_combo)
        search_ctrl.addSpacing(8)
        search_ctrl.addWidget(QLabel("Search:"))
        search_ctrl.addWidget(self.search_field, 1)
        search_ctrl.addWidget(self.search_scope_combo)
        search_ctrl.addWidget(self.search_btn)
        search_ctrl.addWidget(self.search_stop_btn)
        search_tab_layout.addLayout(search_ctrl)
        search_tab_layout.addWidget(self.search_status)

        # Results tree: Name | Hits | Context | Offset
        self.search_results_model = QStandardItemModel()
        self.search_results_model.setHorizontalHeaderLabels(
            ["Name", "Hits", "Context", "Offset"])
        self.search_results_view = QTreeView()
        self.search_results_view.setModel(self.search_results_model)
        self.search_results_view.setEditTriggers(QTreeView.EditTrigger.NoEditTriggers)
        self.search_results_view.setSelectionBehavior(QTreeView.SelectionBehavior.SelectRows)
        self.search_results_view.setAlternatingRowColors(True)
        self.search_results_view.setUniformRowHeights(True)
        self.search_results_view.header().setStretchLastSection(False)
        self.search_results_view.header().resizeSection(0, 220)
        self.search_results_view.header().resizeSection(1, 50)
        self.search_results_view.header().resizeSection(2, 260)
        self.search_results_view.header().resizeSection(3, 90)
        self.search_results_view.selectionModel().selectionChanged.connect(
            self._on_search_row_selected)
        self._search_context_delegate = SearchContextDelegate(
            lambda: self.search_field.text().strip())
        self.search_results_view.setItemDelegate(self._search_context_delegate)
        self.search_results_view.expanded.connect(self._on_search_tree_expanded)
        search_tab_layout.addWidget(self.search_results_view, stretch=1)

        self._search_worker: KeywordSearchWorker | None = None
        self._search_progress_dlg: SearchProgressDialog | None = None
        self._pending_hex_jump: tuple | None = None   # (offset, keyword) set while hex loads
        self._search_entries: list | None = None   # cached zip entry index, built once per archive
        # Node lookup dicts for building the tree during a live search
        self._search_folder_items: dict[str, QStandardItem] = {}
        self._search_file_items:   dict[str, QStandardItem] = {}
        self._recent_searches: list = []   # populated from casedata.db when a case is loaded
        self._refresh_search_recent_combo()
        self.search_recent_combo.activated.connect(self._on_search_recent_selected)

        # ── Tab widget ──────────────────────────────────────────────────────
        self.center_tabs = QTabWidget()
        self.center_tabs.addTab(file_tab, "File Browser")
        self.center_tabs.addTab(media_tab, "Media Browser")
        self.center_tabs.addTab(search_tab, "Keyword Search")
        self.center_tabs.currentChanged.connect(self._on_center_tab_changed)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        right_layout.addWidget(self.center_tabs)

        self.splitter.addWidget(right_panel)
        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 1)

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
        self._hex_entry: ZipEntry | None = None
        self._thumb_cols = 1
        self._hex_file_size: int = 0
        self._hex_bytes_loaded: int = 0
        self._hex_view_start: int = 0    # file offset of the first byte currently displayed
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

    def _get_zip_handle(self) -> zipfile.ZipFile | None:
        """Return the shared ZipFile handle, opening it lazily on first use.
        Returns None for streaming zips — use _streaming_index instead."""
        if self._streaming_index is not None:
            return None
        if self._zip_handle is None:
            self._zip_handle = zipfile.ZipFile(self.zip_path, 'r')
        return self._zip_handle

    def _in_zip(self, ui_path) -> bool:
        return self._adapter.resolve(ui_path) in self.zip_names

    def _is_empty_folder_entry(self, ui_path) -> bool:
        """True when the ZIP contains a bare directory entry for this path (trailing slash)."""
        return (self._adapter.resolve(ui_path) + "/") in self.zip_names

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

    # ── Media browser ────────────────────────────────────────────────────────

    def _on_center_tab_changed(self, index):
        if index == 2:
            self._update_search_status_bar()
            return
        if index == 1:
            # Determine pending selection from the file browser
            if self._selected_file_path and \
                    os.path.splitext(self._selected_file_path)[1].lower() in MEDIA_EXTENSIONS:
                self._pending_media_selection = self._selected_file_path
            else:
                self._pending_media_selection = None

            # Context is the exact ordered tuple of media paths currently visible.
            # Any change — folder, selection, filter, sort — produces a different tuple
            # and triggers a reload. Same paths in same order means no reload needed.
            new_context = tuple(
                r[1] for r in self.file_model._rows
                if r[1] not in self.folder_map
                and os.path.splitext(r[1])[1].lower() in MEDIA_EXTENSIONS
            )

            if new_context == self._media_context:
                # Nothing changed — thumbnails already loaded, just re-apply selection
                if self._pending_media_selection and \
                        self._pending_media_selection in self._thumb_widgets:
                    self._on_thumb_clicked(self._pending_media_selection)
                    self._media_scroll.ensureWidgetVisible(
                        self._thumb_widgets[self._pending_media_selection])
                self._pending_media_selection = None
                return

            self._load_media_from_file_model()
        elif index == 0:
            # Switching back to File Browser — select the media file that was selected
            if self._selected_media_path:
                self._select_file_in_table(self._selected_media_path)

    def _load_media_from_file_model(self):
        """Load the media tab using exactly the current visible file model rows —
        same order, same filter, same selection — so media mirrors the file browser."""
        model = self.file_model

        # All non-folder rows currently visible (respects filter + sort)
        total_files = sum(1 for r in model._rows if r[1] not in self.folder_map)
        media_paths = [
            r[1] for r in model._rows
            if r[1] not in self.folder_map
            and os.path.splitext(r[1])[1].lower() in MEDIA_EXTENSIONS
        ]

        # Store the ordered tuple as context so tab-switching is cheap
        self._media_context = tuple(media_paths)

        # Build sort description
        if 0 <= model._sort_col < len(model._headers):
            arrow = "↑" if model._sort_order == Qt.SortOrder.AscendingOrder else "↓"
            sort_desc = f", sorted by {model._headers[model._sort_col]} {arrow}"
        else:
            sort_desc = ""

        self._start_thumbnail_load(media_paths, total_files, sort_desc)

    def _start_thumbnail_load(self, media_paths, total_files=None, sort_desc=""):
        """Stop any running thumb worker, clear the grid, pre-place all containers,
        then start the worker which only sets pixmaps — the grid never changes shape."""
        if self._thumb_worker and self._thumb_worker.isRunning():
            self._thumb_worker.stop()
            self._thumb_worker.wait()

        while self._media_grid.count():
            item = self._media_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._thumb_widgets = {}
        self._thumb_img_labels: dict = {}   # ui_path -> QLabel (pixmap slot)
        self._selected_media_path = None

        if not media_paths or not self.zip_path:
            self._media_status.setText(
                "No media files" if self.zip_path else "Select a folder to view media")
            return

        self._media_total_files = total_files
        self._media_sort_desc = sort_desc
        of_total = f" of {total_files:,} file(s)" if total_files is not None else ""
        self._media_status.setText(f"Loading {len(media_paths):,} media file(s){of_total}…")
        n_cols = max(1, self._media_grid_widget.width() // (THUMB_SIZE + 16))
        self._thumb_cols = n_cols

        # ── Pre-place every container in the grid before the worker starts ──────
        # All grid positions are fixed from the start.  The worker only sets pixmaps
        # on already-placed labels, so QGridLayout never recalculates during loading.
        self._media_grid_widget.setUpdatesEnabled(False)
        for i, ui_path in enumerate(media_paths):
            row, col = divmod(i, n_cols)
            name = ui_path.split('/')[-1]

            container = ClickableThumb(ui_path)
            container.setFixedSize(THUMB_SIZE + 8, THUMB_SIZE + 28)
            container.clicked.connect(self._on_thumb_clicked)

            v = QVBoxLayout(container)
            v.setContentsMargins(2, 2, 2, 2)
            v.setSpacing(2)

            img_label = QLabel()
            img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            img_label.setFixedSize(THUMB_SIZE, THUMB_SIZE)
            img_label.setToolTip(ui_path)

            name_label = QLabel()
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            name_label.setFixedWidth(THUMB_SIZE + 4)
            name_label.setWordWrap(False)
            name_label.setStyleSheet("font-size: 10px;")
            fm = name_label.fontMetrics()
            name_label.setText(
                fm.elidedText(name, Qt.TextElideMode.ElideMiddle, THUMB_SIZE + 4))
            name_label.setToolTip(ui_path)

            v.addWidget(img_label)
            v.addWidget(name_label)

            self._thumb_widgets[ui_path] = container
            self._thumb_img_labels[ui_path] = img_label
            self._media_grid.addWidget(container, row, col)

        self._media_grid_widget.setUpdatesEnabled(True)
        # ────────────────────────────────────────────────────────────────────────

        zip_info_map = {
            self._adapter.resolve(p): self.full_metadata.get(p, {}).get('size', 0)
            for p in media_paths
        }

        self._thumb_worker = ThumbnailWorker(
            self.zip_path, media_paths, self._adapter.resolve, THUMB_SIZE, zip_info_map,
            streaming_index=self._streaming_index, cache_dir=self._case_dir)
        self._thumb_worker.thumbnail_ready.connect(self._on_thumbnail_ready)
        self._thumb_worker.finished_all.connect(self._on_thumbnails_done)
        self._thumb_worker.start()

    def _on_thumbnail_ready(self, ui_path, img):
        """Grid position is already fixed — convert QImage to QPixmap and set it."""
        img_label = self._thumb_img_labels.get(ui_path)
        if img_label is not None:
            img_label.setPixmap(QPixmap.fromImage(img))

    def _on_thumb_clicked(self, ui_path):
        """Highlight thumbnail, show path in status bar, and pre-select in File Browser."""
        if self._selected_media_path and self._selected_media_path in self._thumb_widgets:
            self._thumb_widgets[self._selected_media_path].set_selected(False)
        self._selected_media_path = ui_path
        if ui_path in self._thumb_widgets:
            self._thumb_widgets[ui_path].set_selected(True)
        self.status_bar.showMessage(ui_path)
        self._select_file_in_table(ui_path)

    def _on_thumbnails_done(self):
        count = self._media_grid.count()
        of_total = f" of {self._media_total_files:,} file(s)" \
            if self._media_total_files is not None else ""
        self._media_status.setText(
            f"{count:,} media file(s){of_total}{self._media_sort_desc}")
        # Auto-select any pending file (set when switching from File Browser)
        if self._pending_media_selection and \
                self._pending_media_selection in self._thumb_widgets:
            self._on_thumb_clicked(self._pending_media_selection)
            self._media_scroll.ensureWidgetVisible(
                self._thumb_widgets[self._pending_media_selection])
        self._pending_media_selection = None

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
        if self._case_dir:
            return os.path.join(self._case_dir, 'Export')
        parent, stem = self._zip_stem()
        return str(parent / f"{stem}_Export")

    def _get_or_ask_case_dir(self, zip_path: str) -> str | None:
        """Return the case dir for *zip_path*, asking the user if not yet set."""
        existing = self._archive_entry(zip_path)
        if existing and existing.get('case_dir'):
            return existing['case_dir']
        # Determine default base from the most recent archive that has a case_dir
        last_base = None
        for e in self._ffs_archives:
            if e.get('case_dir'):
                last_base = os.path.dirname(e['case_dir'])
                break
        dlg = CaseSettingsDialog(zip_path, last_base, parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return None
        case_dir = dlg.case_dir
        self._upsert_archive(zip_path, case_dir)
        return case_dir

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
        def _scroll():
            self.tree_view.scrollTo(new_idx, QTreeView.ScrollHint.PositionAtCenter)
            self.tree_view.horizontalScrollBar().setValue(0)
        QTimer.singleShot(0, _scroll)
        self._view_is_recursive = False
        self.on_folder_selected(new_idx)

    def on_file_selected(self, index):
        source = self.proxy_model.mapToSource(index)
        ui_path = self.file_model.index(source.row(), 0).data(Qt.ItemDataRole.UserRole)
        if not ui_path:
            return
        self._selected_file_path = ui_path
        self.status_bar.showMessage(ui_path)
        is_folder = ui_path in self.folder_map
        self._log(f"{'Folder' if is_folder else 'File'} selected: {ui_path}")

    def _select_file_in_table(self, ui_path):
        """Find ui_path in the current file model and select that row."""
        for row in range(self.file_model.rowCount()):
            if self.file_model.index(row, 0).data(Qt.ItemDataRole.UserRole) == ui_path:
                proxy_idx = self.proxy_model.mapFromSource(self.file_model.index(row, 0))
                if proxy_idx.isValid():
                    self.file_view.setCurrentIndex(proxy_idx)
                    self.file_view.scrollTo(proxy_idx)
                break

    def _load_hex_preview(self, ui_path):
        if self._hex_worker is not None and self._hex_worker.isRunning():
            self._hex_worker.terminate()
            self._hex_worker.wait()

        self._hex_entry        = None
        self._hex_file_size    = 0
        self._hex_bytes_loaded = 0
        self._hex_view_start   = 0
        self._hex_ui_path      = ui_path

        physical_path = self._adapter.resolve(ui_path)

        self.hex_view.clear()
        self.hex_progress_bar.hide()

        try:
            if self._streaming_index is not None:
                entry = self._streaming_index.get_entry(physical_path)
            else:
                zinfo = self._get_zip_handle().getinfo(physical_path)
                entry = ZipEntry(self.zip_path, physical_path, zinfo)
        except Exception as e:
            self._on_hex_error(str(e))
            return

        self._hex_file_size = entry.file_size or self.full_metadata.get(ui_path, {}).get('size', 0)

        if entry.is_stored:
            # STORED entry — seek directly into the zip, display first page instantly
            self._hex_entry = entry
            try:
                chunk = entry.read(min(INITIAL_HEX_BYTES, self._hex_file_size or INITIAL_HEX_BYTES))
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
            self.hex_progress_bar.setRange(0, max(self._hex_file_size, 1))
            self.hex_progress_bar.setValue(0)
            self.hex_progress_bar.show()
            self._hex_worker = HexLoadWorker(entry)
            self._hex_worker.progress.connect(self._on_hex_progress)
            self._hex_worker.load_complete.connect(self._on_hex_ready)
            self._hex_worker.error.connect(self._on_hex_error)
            self._hex_worker.start()

    def _update_hex_label(self):
        view_end = self._hex_view_start + self._hex_bytes_loaded
        total    = self._hex_file_size
        if self._hex_view_start > 0:
            label = (f"{self._hex_ui_path}  —  "
                     f"bytes {self._hex_view_start:,}–{view_end:,} of {total:,}")
        else:
            label = f"{self._hex_ui_path}  —  {view_end:,} / {total:,} bytes shown"
        hints = []
        if self._hex_view_start > 0:
            hints.append("scroll up for earlier")
        if total == 0 or view_end < total:
            hints.append("scroll down for more")
        if hints:
            label += f"  ({', '.join(hints)})"
        self.hex_label.setText(label)

    def _on_hex_scroll(self, value):
        if self._hex_entry is None or self._hex_loading_more:
            return
        scrollbar = self.hex_view.verticalScrollBar()
        view_end  = self._hex_view_start + self._hex_bytes_loaded

        # ── Scroll backward: prepend earlier bytes ────────────────────────────
        if value <= 5 and self._hex_view_start > 0:
            self._hex_loading_more = True
            back_start = max(0, ((self._hex_view_start - HEX_PAGE_BYTES) // 32) * 32)
            back_len   = self._hex_view_start - back_start
            try:
                chunk = self._hex_entry.read_at(back_start, back_len)
            except Exception as e:
                self._log(f"Hex scroll load error: {e}")
                self._hex_loading_more = False
                return
            if chunk:
                new_text  = self._render_hex(chunk, back_start)
                old_max   = scrollbar.maximum()
                old_val   = scrollbar.value()
                cursor    = QTextCursor(self.hex_view.document())
                cursor.movePosition(QTextCursor.MoveOperation.Start)
                cursor.insertText(new_text + "\n")
                self._hex_view_start   = back_start
                self._hex_bytes_loaded += len(chunk)
                # Shift scroll position down by the number of lines just added
                scrollbar.setValue(old_val + (scrollbar.maximum() - old_max))
                self._update_hex_label()
            self._hex_loading_more = False
            return

        # ── Scroll forward: append later bytes ───────────────────────────────
        if value < scrollbar.maximum() - 5:
            return
        if self._hex_file_size > 0 and view_end >= self._hex_file_size:
            return
        self._hex_loading_more = True
        remaining = (self._hex_file_size - view_end) if self._hex_file_size > 0 else HEX_PAGE_BYTES
        try:
            chunk = self._hex_entry.read_at(view_end, min(HEX_PAGE_BYTES, remaining))
        except Exception as e:
            self._log(f"Hex scroll load error: {e}")
            self._hex_loading_more = False
            return
        if not chunk:
            self._hex_loading_more = False
            return
        new_text = self._render_hex(chunk, view_end)
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
        self._hex_bytes_loaded = len(data)
        truncated = len(data) == HexLoadWorker.LIMIT
        self.hex_label.setText(
            f"{self._hex_ui_path}  —  {len(data):,} bytes shown"
            + ("  (truncated to 64 KB)" if truncated else "")
        )
        self.hex_view.setPlainText(self._render_hex(data))
        self._fit_hex_font()
        self._log(f"Hex preview: {self._hex_ui_path}")
        if self._pending_hex_jump:
            jump_to, keyword = self._pending_hex_jump
            QTimer.singleShot(0, lambda: self._jump_to_hex_offset(jump_to, keyword))

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

        # Refresh media tab if it's currently visible
        if self.center_tabs.currentIndex() == 1:
            self._load_media_from_file_model()

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
        self._checked_folders = checked
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
                if self.center_tabs.currentIndex() == 1:
                    self._load_media_from_file_model()

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

        self.ex_worker = ExtractorWorker(self.zip_path, tasks, dest_dir, self.folder_map, self._adapter.resolve)
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
        if index == 0:
            return
        path = self.archive_dropdown.itemData(index)
        if not path:
            return
        if os.path.isfile(path):
            self.start_loading(path)

    def _open_new_ffs(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open ZIP", "", "ZIP (*.zip)")
        if path:
            self.start_loading(path)

    def start_loading(self, zip_path):
        case_dir = self._get_or_ask_case_dir(zip_path)
        if case_dir is None:
            return   # user cancelled the dialog
        self._case_dir = case_dir
        self._search_entries = None   # clear cached index for the new archive
        self.zip_path = zip_path
        self._load_recent_searches_from_db()
        self._log(f"SESSION START — Archive loaded: {zip_path}")
        self._reset_tree_model()
        self.tree_view.setModel(self.tree_model)
        self.show_selected_btn.setVisible(False)
        self.deselect_all_btn.setVisible(False)
        # Stop any running thumbnail worker from the previous archive
        if self._thumb_worker and self._thumb_worker.isRunning():
            self._thumb_worker.stop()
            self._thumb_worker.wait()
        while self._media_grid.count():
            item = self._media_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._media_status.setText("Select a folder to view media")
        # Clear the file browser immediately so the previous archive's
        # content is not shown while the new one is loading.
        self._set_file_model(FileTableModel(self.file_headers))
        self._update_filter_columns(self.file_headers)
        self.table_status_label.setText("")
        self._view_path = ""
        self._checked_folders = set()
        self._selected_file_path = None
        self._selected_media_path = None
        self._pending_media_selection = None
        self._media_context = None
        self.progress_bar.setRange(0, 0)
        self.progress_bar.show()
        self.worker = ZipMetadataWorker(zip_path)
        self.worker.status_update.connect(self.status_bar.showMessage)
        self.worker.metadata_ready.connect(self.on_metadata_ready)
        self.worker.start()

    def on_metadata_ready(self, data, folder_map, guid_map, zip_names, adapter, missing_plist_paths):
        self.full_metadata = data
        self.folder_map = folder_map
        self.guid_to_bundle = guid_map
        self.zip_names = zip_names
        self._adapter = adapter
        self._missing_plist_paths = set(missing_plist_paths)
        self._real_content_cache = {}
        if self._zip_handle:
            self._zip_handle.close()
            self._zip_handle = None   # opened lazily on first hex-preview request
        self._streaming_index = getattr(self.worker, '_streaming_index', None)
        self.progress_bar.setRange(0, 100)
        self.save_recent_list(self.zip_path)
        fmt_label = "GrayKey" if adapter.format == FfsAdapter.FORMAT_GRAYKEY else "Cellebrite"
        self.reload_tree_entirely()
        self.tree_model.setHorizontalHeaderLabels([f"Folder Structure — {fmt_label}"])
        # Fetch device label after the archive is fully processed, so the
        # dropdown shows only the filepath until loading is complete.
        if self.zip_path not in self.device_labels:
            QTimer.singleShot(0, lambda: self._fetch_and_store_label(self.zip_path))
        if missing_plist_paths:
            # Only warn about UUID folders that actually have content in the zip.
            # Metadata-only or empty folders have no extractable files so the
            # missing plist does not affect the user.
            actionable = [p for p in missing_plist_paths
                          if self._folder_content_status(p) == "content"]
            if actionable:
                self._warn_and_select_missing(actionable)

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
        if hasattr(self, '_adapter'):
            fmt_label = "GrayKey" if self._adapter.format == FfsAdapter.FORMAT_GRAYKEY else "Cellebrite"
            self.tree_model.setHorizontalHeaderLabels([f"Folder Structure — {fmt_label}"])
        self.progress_bar.hide()
        self.status_bar.showMessage(f"Loaded: {os.path.basename(self.zip_path)}")
        QTimer.singleShot(0, self._fit_splitter_to_tree)

    def _fit_splitter_to_tree(self):
        """Resize the splitter so the tree panel is wide enough to show its
        content without horizontal scrolling.  The user can drag it smaller."""
        self.tree_view.resizeColumnToContents(0)
        col_w = self.tree_view.columnWidth(0)
        # resizeColumnToContents only measures loaded rows (top-level due to
        # lazy loading), so enforce a sensible minimum of 280px.
        tree_w = max(col_w, 280) + self.tree_view.verticalScrollBar().sizeHint().width() + 12
        total = self.splitter.width()
        if total > 0:
            self.splitter.setSizes([tree_w, max(total - tree_w, 200)])

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
            if self._hide_empty_folders and \
                    self._folder_content_status(p) in ("empty", "metadata_only"):
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
        row = index.row()
        path = self.archive_dropdown.itemData(row)
        if not path:
            return
        menu = QMenu(self)
        act = QAction("Remove from recent list", self)
        act.triggered.connect(lambda: self._remove_recent(path))
        menu.addAction(act)
        menu.exec(view.viewport().mapToGlobal(point))

    # ── ffs_archives helpers ──────────────────────────────────────────────────

    def _archive_entry(self, path: str) -> dict | None:
        """Return the archive entry for *path*, or None if not present."""
        for e in self._ffs_archives:
            if e.get('path') == path:
                return e
        return None

    def _save_ffs_archives(self):
        """Persist the in-memory _ffs_archives list to disk."""
        try:
            with open(FFS_ARCHIVES_FILE, 'w', encoding='utf-8') as f:
                json.dump(self._ffs_archives, f, indent=2)
        except OSError:
            pass

    def _upsert_archive(self, path: str, case_dir: str | None = None):
        """Move *path* to front of _ffs_archives (max 5), optionally setting case_dir."""
        # Remove existing entry for this path
        self._ffs_archives = [e for e in self._ffs_archives if e.get('path') != path]
        entry: dict = {'path': path}
        if case_dir is not None:
            entry['case_dir'] = case_dir
        self._ffs_archives.insert(0, entry)
        self._ffs_archives = self._ffs_archives[:5]
        self.recent_paths = [e['path'] for e in self._ffs_archives]
        self._save_ffs_archives()

    def _remove_recent(self, path):
        self._ffs_archives = [e for e in self._ffs_archives if e.get('path') != path]
        self.recent_paths = [e['path'] for e in self._ffs_archives]
        self._save_ffs_archives()
        self.update_dropdown_ui()

    def save_recent_list(self, path):
        if not self._archive_entry(path):
            self._upsert_archive(path, self._case_dir)
        self.update_dropdown_ui()

    def _fetch_and_store_label(self, path):
        label = _read_device_info(path)
        self.device_labels[path] = label
        try:
            with open(DEVICE_LABELS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.device_labels, f)
        except OSError:
            pass
        self.update_dropdown_ui()

    def update_dropdown_ui(self):
        self.archive_dropdown.blockSignals(True)
        self.archive_dropdown.clear()
        # Header item — always index 0, not selectable
        self.archive_dropdown.addItem("Recently Opened FFS")
        model = self.archive_dropdown.model()
        item = model.item(0)
        from PySide6.QtCore import Qt as _Qt
        item.setFlags(item.flags() & ~(_Qt.ItemFlag.ItemIsSelectable | _Qt.ItemFlag.ItemIsEnabled))
        for p in self.recent_paths:
            label = self.device_labels.get(p, '')
            display = f'{label}  —  {p}' if label else p
            self.archive_dropdown.addItem(display, userData=p)
        self.archive_dropdown.setCurrentIndex(0)
        self.archive_dropdown.blockSignals(False)
        # Re-select the currently loaded archive if any
        if self.zip_path:
            for i in range(1, self.archive_dropdown.count()):
                if self.archive_dropdown.itemData(i) == self.zip_path:
                    self.archive_dropdown.setCurrentIndex(i)
                    break

    def _populate_recent_menu(self):
        self._recent_menu.clear()
        if not self.recent_paths:
            empty_act = QAction("No recently opened archives", self)
            empty_act.setEnabled(False)
            self._recent_menu.addAction(empty_act)
            return
        for p in self.recent_paths:
            label = self.device_labels.get(p, '')
            display = f'{label}  —  {p}' if label else p
            act = QAction(display, self)
            act.triggered.connect(lambda _checked, path=p: self.start_loading(path))
            self._recent_menu.addAction(act)
        self._recent_menu.addSeparator()
        clear_act = QAction("Clear Recent List", self)
        clear_act.triggered.connect(self._clear_recent_list)
        self._recent_menu.addAction(clear_act)

    def _clear_recent_list(self):
        self._ffs_archives.clear()
        self.recent_paths.clear()
        self._save_ffs_archives()
        self.update_dropdown_ui()

    # ── Keyword search ────────────────────────────────────────────────────────

    def _refresh_search_recent_combo(self):
        self.search_recent_combo.blockSignals(True)
        self.search_recent_combo.clear()
        self.search_recent_combo.addItem("Recent searches…")
        model = self.search_recent_combo.model()
        item  = model.item(0)
        from PySide6.QtCore import Qt as _Qt
        item.setFlags(item.flags() & ~(_Qt.ItemFlag.ItemIsSelectable | _Qt.ItemFlag.ItemIsEnabled))
        for term in self._recent_searches:
            self.search_recent_combo.addItem(term)
        self.search_recent_combo.blockSignals(False)

    def _on_search_row_selected(self):
        indexes = self.search_results_view.selectionModel().selectedRows(0)
        if not indexes:
            return
        item = self.search_results_model.itemFromIndex(indexes[0])
        if not item:
            return
        _PATH_ROLE   = Qt.ItemDataRole.UserRole
        _OFFSET_ROLE = Qt.ItemDataRole.UserRole + 1
        _PHYS_ROLE   = Qt.ItemDataRole.UserRole + 2
        path     = item.data(_PATH_ROLE) or ''
        offset   = item.data(_OFFSET_ROLE)
        physical = item.data(_PHYS_ROLE)

        if physical and offset is not None:
            # Hit node — load file in hex viewer and jump to offset
            keyword = self.search_field.text().strip()
            self.status_bar.showMessage(f'{path}  —  offset: {offset:,}')
            self._open_hex_from_search(physical, path, offset, keyword)
        elif physical:
            # File node — just update status bar
            self.status_bar.showMessage(path)
        else:
            # Folder node
            self.status_bar.showMessage(path)

    def _strip_archive_prefix(self, path: str) -> str:
        """Strip the archive-format prefix so display paths start from the
        user-partition root (e.g. 'mobile/Containers/...' not
        'filesystem2/mobile/Containers/...')."""
        p = path.lstrip('/')
        prefix = self._adapter.user_prefix + '/'
        if p.startswith(prefix):
            p = p[len(prefix):]
        # Old-layout Cellebrite and GrayKey still have 'private/var/' after the prefix
        if p.startswith('private/var/'):
            p = p[len('private/var/'):]
        return p

    def _hits_cell_for(self, item: QStandardItem) -> QStandardItem | None:
        """Return the Hits (column 1) sibling of *item*."""
        parent = item.parent()
        if parent is None:
            return self.search_results_model.item(item.row(), 1)
        return parent.child(item.row(), 1)

    def _search_add_hit(self, filename: str, offset: int, context: str):
        """Insert one hit into the fully-nested path tree.

        Every path segment becomes its own folder node so the tree mirrors the
        real directory hierarchy.  GUID segments are replaced with bundle IDs.
        Each folder node's Hits column accumulates all hits beneath it.
        Full display paths are stored as Qt.UserRole data for the status bar."""
        _PATH_ROLE = Qt.ItemDataRole.UserRole

        folder   = filename.rsplit('/', 1)[0] if '/' in filename else ''
        basename = filename.rsplit('/', 1)[-1]

        # Build the clean display path (GUIDs → bundle IDs, archive prefix stripped)
        display_folder   = self._strip_archive_prefix(self._display_path(folder))
        display_basename = self._display_name(basename)
        full_file_path   = (display_folder + '/' + display_basename) if display_folder else display_basename

        # ── Folder nodes — one per path segment ──────────────────────────────
        segments = display_folder.split('/') if display_folder else []
        parent   = self.search_results_model.invisibleRootItem()
        cumulative = ''
        ancestor_hits_cells: list[QStandardItem] = []

        for seg in segments:
            cumulative = (cumulative + '/' + seg) if cumulative else seg
            if cumulative not in self._search_folder_items:
                folder_item = QStandardItem(f'📁  {seg}/')
                folder_item.setEditable(False)
                folder_item.setData(cumulative + '/', _PATH_ROLE)
                hits_item = QStandardItem('0')
                hits_item.setEditable(False)
                row = [folder_item, hits_item, QStandardItem(''), QStandardItem('')]
                for cell in row:
                    cell.setEditable(False)
                parent.appendRow(row)
                self._search_folder_items[cumulative] = folder_item
            folder_item = self._search_folder_items[cumulative]
            ancestor_hits_cells.append(self._hits_cell_for(folder_item))
            parent = folder_item

        # ── File node ─────────────────────────────────────────────────────────
        if filename not in self._search_file_items:
            file_item = QStandardItem(f'📄  {display_basename}')
            file_item.setEditable(False)
            file_item.setData(full_file_path, _PATH_ROLE)
            file_item.setData(filename, Qt.ItemDataRole.UserRole + 2)   # physical zip path
            file_hits = QStandardItem('0')
            file_hits.setEditable(False)
            row = [file_item, file_hits, QStandardItem(''), QStandardItem('')]
            for cell in row:
                cell.setEditable(False)
            parent.appendRow(row)
            self._search_file_items[filename] = file_item
        file_item = self._search_file_items[filename]

        # ── Hit node  (cols: Name | Hits | Context | Offset) ─────────────────
        hit_item = QStandardItem('')
        hit_item.setData(full_file_path, _PATH_ROLE)
        hit_item.setData(offset, Qt.ItemDataRole.UserRole + 1)
        hit_item.setData(filename, Qt.ItemDataRole.UserRole + 2)         # physical zip path
        hit_row = [hit_item, QStandardItem(''), QStandardItem(context), QStandardItem(str(offset))]
        for cell in hit_row:
            cell.setEditable(False)
        file_item.appendRow(hit_row)

        # ── Increment hit counts: file node + every ancestor folder ──────────
        for hits_cell in [self._hits_cell_for(file_item)] + ancestor_hits_cells:
            if hits_cell:
                hits_cell.setText(str(int(hits_cell.text()) + 1))

    def _open_hex_from_search(self, physical_path: str, display_label: str,
                               jump_to: int | None, keyword: str):
        """Load *physical_path* into the hex viewer.
        If *jump_to* is given, only the window around that offset is read so
        that very large files never freeze the UI.  Scrolling backward/forward
        from the hit loads more data on demand."""
        if self._hex_worker is not None and self._hex_worker.isRunning():
            self._hex_worker.terminate()
            self._hex_worker.wait()

        self._hex_entry        = None
        self._hex_file_size    = 0
        self._hex_bytes_loaded = 0
        self._hex_view_start   = 0
        self._hex_ui_path      = display_label
        self._pending_hex_jump = (jump_to, keyword) if jump_to is not None else None

        self.hex_view.clear()
        self.hex_progress_bar.hide()

        try:
            if self._streaming_index is not None:
                entry = self._streaming_index.get_entry(physical_path)
            else:
                zinfo = self._get_zip_handle().getinfo(physical_path)
                entry = ZipEntry(self.zip_path, physical_path, zinfo)
        except Exception as e:
            self._on_hex_error(str(e))
            return

        self._hex_file_size = entry.file_size

        if entry.is_stored:
            self._hex_entry = entry
            if jump_to is not None:
                # Windowed load: only read a small region around the hit
                kw_len    = len(keyword.encode('utf-8', errors='replace')) if keyword else 0
                win_start = max(0, ((jump_to - 10) // 32) * 32)
                win_end   = ((jump_to + kw_len + HIT_WINDOW_AFTER + 31) // 32) * 32
                if self._hex_file_size > 0:
                    win_end = min(win_end, self._hex_file_size)
                try:
                    chunk = entry.read_at(win_start, win_end - win_start)
                except Exception as e:
                    self._on_hex_error(str(e))
                    return
                self._hex_view_start = win_start
            else:
                try:
                    chunk = entry.read(min(INITIAL_HEX_BYTES, self._hex_file_size or INITIAL_HEX_BYTES))
                except Exception as e:
                    self._on_hex_error(str(e))
                    return
                self._hex_view_start = 0
            self._hex_bytes_loaded = len(chunk)
            self.hex_view.setPlainText(self._render_hex(chunk, self._hex_view_start))
            self._fit_hex_font()
            self._update_hex_label()
            if jump_to is not None:
                QTimer.singleShot(0, lambda jt=jump_to, kw=keyword: self._jump_to_hex_offset(jt, kw))
        else:
            # Compressed — worker loads the full file; jump fires in _on_hex_ready
            self.hex_label.setText(f"Loading: {display_label}")
            self.hex_progress_bar.setRange(0, max(self._hex_file_size, 1))
            self.hex_progress_bar.setValue(0)
            self.hex_progress_bar.show()
            self._hex_worker = HexLoadWorker(entry)
            self._hex_worker.progress.connect(self._on_hex_progress)
            self._hex_worker.load_complete.connect(self._on_hex_ready)
            self._hex_worker.error.connect(self._on_hex_error)
            self._hex_worker.start()

    def _jump_to_hex_offset(self, offset: int, keyword: str):
        """Scroll the hex view so *offset* is visible, then highlight the keyword."""
        self._pending_hex_jump = None
        line  = (offset - self._hex_view_start) // _HEX_BYTES_PER_ROW
        doc   = self.hex_view.document()
        block = doc.findBlockByLineNumber(line)
        if block.isValid():
            cursor = QTextCursor(block)
            self.hex_view.setTextCursor(cursor)
            self.hex_view.ensureCursorVisible()
            # nudge the view up so the hit isn't right at the bottom edge
            sb = self.hex_view.verticalScrollBar()
            visible = self.hex_view.viewport().height() // max(
                1, self.hex_view.fontMetrics().lineSpacing())
            sb.setValue(max(0, sb.value() - visible // 3))
        if keyword:
            kw_bytes = keyword.encode('utf-8', errors='replace')
            self._highlight_hex_range(offset, len(kw_bytes))

    def _highlight_hex_range(self, start_offset: int, length: int):
        """Highlight *length* bytes at *start_offset* in both the hex and ASCII columns."""
        doc    = self.hex_view.document()
        hl_fmt = QTextCharFormat()
        hl_fmt.setBackground(QColor(255, 235, 0, 210))   # yellow highlight

        view_end   = self._hex_view_start + self._hex_bytes_loaded
        extra_sels = []
        for i in range(min(length, MAX_HEX_HIGHLIGHT_BYTES)):
            byte_pos = start_offset + i
            if byte_pos < self._hex_view_start or byte_pos >= view_end:
                break
            line  = (byte_pos - self._hex_view_start) // _HEX_BYTES_PER_ROW
            b     = byte_pos % _HEX_BYTES_PER_ROW
            block = doc.findBlockByLineNumber(line)
            if not block.isValid():
                break
            bpos  = block.position()
            blen  = len(block.text())
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

        self.hex_view.setExtraSelections(extra_sels)

    def _on_search_tree_expanded(self):
        """Resize all columns to content whenever a node is expanded."""
        for col in range(self.search_results_model.columnCount()):
            self.search_results_view.resizeColumnToContents(col)

    def _update_search_status_bar(self):
        """Sync the status bar to the current search state."""
        if self.center_tabs.currentIndex() != 2:
            return
        term = self.search_field.text().strip()
        if not term:
            self.status_bar.showMessage("Keyword Search")
            return
        n_files = len(self._search_file_items)
        if self._search_worker and self._search_worker.isRunning():
            self.status_bar.showMessage(
                f"Searching: '{term}'  |  hits in {n_files:,} file{'s' if n_files != 1 else ''} so far")
        else:
            if n_files:
                self.status_bar.showMessage(
                    f"Search: '{term}'  |  hits in {n_files:,} file{'s' if n_files != 1 else ''}")
            else:
                self.status_bar.showMessage(f"Search: '{term}'  |  No results")

    def _on_search_recent_selected(self, index):
        if index == 0:
            return
        term = self.search_recent_combo.itemText(index)
        self.search_field.setText(term)
        # Load from DB if cached, otherwise run a fresh search
        if self._load_search_from_db(term):
            self._update_search_status_bar()
            return
        self._start_keyword_search()

    def _save_recent_search(self, term: str):
        db = self._open_case_db_conn()
        if db:
            try:
                db.execute(
                    'INSERT INTO recent_searches (term, used_at) VALUES (?, strftime(\'%s\',\'now\'))'
                    ' ON CONFLICT(term) DO UPDATE SET used_at=excluded.used_at',
                    (term,)
                )
                db.commit()
                rows = db.execute(
                    'SELECT term FROM recent_searches ORDER BY used_at DESC LIMIT 20'
                ).fetchall()
                self._recent_searches = [r[0] for r in rows]
            finally:
                db.close()
        self._refresh_search_recent_combo()

    def _load_recent_searches_from_db(self):
        """Reload the recent-searches list from the current case DB."""
        db = self._open_case_db_conn()
        if db:
            try:
                rows = db.execute(
                    'SELECT term FROM recent_searches ORDER BY used_at DESC LIMIT 20'
                ).fetchall()
                self._recent_searches = [r[0] for r in rows]
            finally:
                db.close()
        else:
            self._recent_searches = []
        self._refresh_search_recent_combo()

    def _open_case_db_conn(self) -> sqlite3.Connection | None:
        """Open casedata.db for the current archive, or None if not available."""
        if not self._case_dir:
            return None
        try:
            return _open_case_db(self._case_dir)
        except OSError:
            return None

    def _load_search_from_db(self, term: str) -> bool:
        """Populate the results table from the DB for *term*.
        Returns True if cached results were found, False otherwise."""
        db = self._open_case_db_conn()
        if db is None:
            return False
        try:
            rows = db.execute(
                'SELECT filename, offset, context FROM search_results '
                'WHERE zip_path=? AND keyword=? ORDER BY rowid',
                (self.zip_path, term)
            ).fetchall()
        finally:
            db.close()
        if not rows:
            return False
        self.search_results_model.clear()
        self.search_results_model.setHorizontalHeaderLabels(
            ["Name", "Hits", "Context", "Offset"])
        self._search_folder_items.clear()
        self._search_file_items.clear()
        for filename, offset, context in rows:
            self._search_add_hit(filename, offset, context)
        total = len(rows)
        self.search_status.setText(
            f"'{term}' — {total:,} hit{'s' if total != 1 else ''} (loaded from cache)")
        return True

    def _start_keyword_search(self):
        term = self.search_field.text().strip()
        if not term or not self.zip_path:
            return
        self._stop_keyword_search()
        self.search_results_model.clear()
        self.search_results_model.setHorizontalHeaderLabels(
            ["Name", "Hits", "Context", "Offset"])
        self._search_folder_items.clear()
        self._search_file_items.clear()
        self._save_recent_search(term)
        # Clear any stale cached results for this term so they get re-saved fresh
        db = self._open_case_db_conn()
        if db:
            try:
                db.execute('DELETE FROM search_results WHERE zip_path=? AND keyword=?',
                           (self.zip_path, term))
                db.commit()
            finally:
                db.close()
        scope = self.search_scope_combo.currentData()
        # If we have a cached index, apply the scope filter immediately so the
        # worker skips the build step entirely.  Otherwise pass None and let
        # the worker build the full index first; the scope filter is applied
        # after the build inside the worker (see below).
        if self._search_entries is not None and scope == "app_data":
            scoped_entries = [e for e in self._search_entries
                              if "mobile/Containers" in e[0]]
        elif self._search_entries is not None:
            scoped_entries = self._search_entries
        else:
            scoped_entries = None   # worker will build the full index

        scope_label = "App Data" if scope == "app_data" else "all files"
        self.search_status.setText(f"Searching {scope_label} for '{term}'…")
        self.search_btn.setEnabled(False)
        self.search_stop_btn.setEnabled(True)

        # Create and show the modal progress dialog
        self._search_progress_dlg = SearchProgressDialog(term, parent=self)
        self._search_progress_dlg.cancelled.connect(self._cancel_keyword_search)

        self._search_worker = KeywordSearchWorker(
            self.zip_path, term,
            streaming_index=self._streaming_index,
            entries=scoped_entries,
            scope=scope)
        self._search_worker.status_update.connect(self._search_progress_dlg.append_status)
        self._search_worker.result_found.connect(self._on_search_result)
        self._search_worker.progress.connect(self._on_search_progress)
        self._search_worker.finished.connect(self._on_search_finished)
        self._search_worker.start()

        self._search_progress_dlg.exec()   # blocks until dialog is closed

    def _cancel_keyword_search(self):
        """Stop the running worker; keep existing hits for review."""
        if self._search_worker and self._search_worker.isRunning():
            self._search_worker.stop()
            # Don't wait here — _on_search_finished will fire and close the dialog

    def _stop_keyword_search(self):
        if self._search_worker and self._search_worker.isRunning():
            self._search_worker.stop()
            self._search_worker.wait()
        self.search_btn.setEnabled(True)
        self.search_stop_btn.setEnabled(False)

    def _on_search_result(self, name: str, offset: int, context: str):
        self._search_add_hit(name, offset, context)
        # Persist hit to DB
        db = self._open_case_db_conn()
        if db:
            try:
                term = self.search_field.text().strip()
                db.execute(
                    'INSERT INTO search_results (zip_path, keyword, filename, offset, context) '
                    'VALUES (?,?,?,?,?)',
                    (self.zip_path, term, name, offset, context)
                )
                db.commit()
            finally:
                db.close()

    def _on_search_progress(self, done: int, total: int):
        hits = len(self._search_file_items)
        self.search_status.setText(
            f"Searching… {done:,}/{total:,} files  |  hits in {hits:,} file{'s' if hits != 1 else ''} so far")
        self._update_search_status_bar()
        if self._search_progress_dlg:
            self._search_progress_dlg.update_progress(done, total, hits)

    def _on_search_finished(self, total_hits: int):
        if self._search_entries is None and self._search_worker is not None:
            self._search_entries = self._search_worker.entries or None
        self.search_btn.setEnabled(True)
        self.search_stop_btn.setEnabled(False)
        term    = self.search_field.text().strip()
        n_files = len(self._search_file_items)
        dlg = self._search_progress_dlg
        if dlg:
            if dlg.was_interrupted:
                dlg.mark_interrupted(n_files)
                self.search_status.setText(
                    f"'{term}' — partial search, interrupted  "
                    f"({n_files:,} file{'s' if n_files != 1 else ''} with hits)")
            else:
                dlg.mark_finished(n_files, total_hits)
                self.search_status.setText(
                    f"'{term}' — hits in {n_files:,} file{'s' if n_files != 1 else ''} across archive")
        else:
            self.search_status.setText(
                f"'{term}' — hits in {n_files:,} file{'s' if n_files != 1 else ''} across archive")
        self._update_search_status_bar()
        for col in range(self.search_results_model.columnCount()):
            self.search_results_view.resizeColumnToContents(col)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(resource_path(os.path.join("resources", "icon.png"))))
    window = FastZipBrowser()
    window.show()
    sys.exit(app.exec())