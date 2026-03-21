import sys
import os
import zipfile
import msgpack
import json
import subprocess
import plistlib
from datetime import datetime, timezone
from PySide6.QtWidgets import (QApplication, QMainWindow, QTreeView, QTableView, QVBoxLayout,
                              QHBoxLayout, QWidget, QHeaderView, QPushButton,
                              QFileDialog, QProgressBar, QMenu, QMessageBox,
                              QRadioButton, QButtonGroup, QComboBox, QSplitter, QStatusBar,
                              QGroupBox, QLineEdit, QLabel, QPlainTextEdit, QFrame, QTextEdit)
from PySide6.QtGui import (QStandardItemModel, QStandardItem, QAction, QFont,
                           QCursor, QColor, QTextCharFormat, QTextCursor, QFontMetricsF)
from PySide6.QtCore import Qt, QThread, Signal, QSortFilterProxyModel, QTimer, QEvent

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


def _ui_path_to_physical(ui_path):
    parts = []
    for part in ui_path.split('/'):
        if '-' in part:
            suffix = part.split('-')[-1]
            if len(suffix) >= 32 and all(c in '0123456789abcdefABCDEF' for c in suffix):
                parts.append(suffix)
                continue
        parts.append(part)
    return f"filesystem2/{'/'.join(parts)}"


def _load_json_file(path, default):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except:
        return default


def _make_item(text):
    item = QStandardItem(text)
    item.setEditable(False)
    return item


class ExtractorWorker(QThread):
    progress = Signal(int)
    status = Signal(str)
    finished = Signal(bool, str, str)

    def __init__(self, zip_path, export_tasks, dest_dir, folder_map):
        super().__init__()
        self.zip_path = zip_path
        self.export_tasks = export_tasks
        self.dest_dir = dest_dir
        self.folder_map = folder_map

    def run(self):
        try:
            self.status.emit("Initializing extraction...")
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

                for i, (ui_path, rel_path) in enumerate(final_queue):
                    physical_path = _ui_path_to_physical(ui_path)
                    path_segments = list(os.path.split(rel_path))
                    filename = path_segments[1]
                    if filename.startswith('.'):
                        path_segments[1] = '_' + filename[1:]

                    sanitized_rel = os.path.join(*path_segments)
                    dest_path = os.path.join(self.dest_dir, sanitized_rel)

                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    self.status.emit(f"Exporting: {sanitized_rel}")

                    try:
                        with z.open(physical_path) as source, open(dest_path, 'wb') as target:
                            while chunk := source.read(1024 * 1024):
                                target.write(chunk)
                    except KeyError:
                        continue

                    self.progress.emit(int(((i + 1) / total) * 100))

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
    metadata_ready = Signal(dict, dict, dict, object)

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
                            if bid: guid_to_bundle[guid] = bid
                    except: continue

                self.status_update.emit("Reading metadata.msgpack...")
                with z.open('metadata2/metadata.msgpack') as f:
                    raw_data = msgpack.unpack(f)

            self.status_update.emit("Generating tree...")
            ui_metadata = {}
            folder_map = {}

            for ui_path, meta in raw_data.items():
                ui_metadata[ui_path] = meta
                parent_path = ui_path.rsplit('/', 1)[0] if '/' in ui_path else ""
                if parent_path not in folder_map:
                    folder_map[parent_path] = []
                folder_map[parent_path].append(ui_path)

            self.metadata_ready.emit(ui_metadata, folder_map, guid_to_bundle, zip_names)
        except Exception as e:
            self.status_update.emit(f"Error: {str(e)}")


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


class MultiColumnFilterProxy(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self._filter_text = ""
        self._filter_col = -1  # -1 = all columns

    def set_filter(self, text, col):
        self._filter_text = text.lower()
        self._filter_col = col
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        if not self._filter_text:
            return True
        model = self.sourceModel()
        cols = range(model.columnCount()) if self._filter_col < 0 else [self._filter_col]
        return any(
            (item := model.item(source_row, c)) is not None and self._filter_text in item.text().lower()
            for c in cols
        )


class FastZipBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cellebrite FFS Explorer (Linux Friendly)")
        self.resize(1350, 850)

        self.zip_path = ""
        self.full_metadata = {}
        self.folder_map = {}
        self.guid_to_bundle = {}
        self.zip_names: frozenset = frozenset()
        self._real_content_cache: dict = {}
        self.hidden_paths = self.load_settings()
        self.recent_paths = self.load_recent_list()
        self._view_path = ""
        self._view_is_recursive = False
        self._filter_log_timer = QTimer(self)
        self._filter_log_timer.setSingleShot(True)
        self._filter_log_timer.setInterval(1500)
        self._filter_log_timer.timeout.connect(self._log_filter_final)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(5, 5, 5, 2)
        layout.setSpacing(5)

        top_controls = QHBoxLayout()

        folder_view_box = QGroupBox("Folder View")
        folder_view_layout = QHBoxLayout(folder_view_box)
        folder_view_layout.setContentsMargins(6, 4, 6, 4)
        self.view_group = QButtonGroup(self)
        for i, text in enumerate(["All Folders", "Customise Filter", "Simplified View"]):
            rb = QRadioButton(text)
            if i == CLEAN_MODE: rb.setChecked(True)
            folder_view_layout.addWidget(rb)
            self.view_group.addButton(rb, i)
        self.view_group.buttonClicked.connect(self.reload_tree_entirely)
        top_controls.addWidget(folder_view_box)

        top_controls.addStretch()
        self.jump_btn = QPushButton("Jump to ▾")
        self.jump_btn.clicked.connect(self._show_jump_menu)
        top_controls.addWidget(self.jump_btn)
        layout.addLayout(top_controls)

        top_bar = QHBoxLayout()
        self.archive_dropdown = QComboBox()
        self.update_dropdown_ui()
        self.archive_dropdown.activated.connect(self._on_dropdown_activated)
        self.action_btn = QPushButton("Load FFS")
        self.action_btn.clicked.connect(self.handle_action_button)
        self.open_export_btn = QPushButton("Open Export Folder")
        self.open_export_btn.clicked.connect(self.ensure_and_open_export_dir)

        top_bar.addWidget(self.archive_dropdown, 3)
        top_bar.addWidget(self.action_btn, 1)
        top_bar.addWidget(self.open_export_btn, 1)
        layout.addLayout(top_bar)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self._reset_tree_model()
        self.tree_view = QTreeView()
        self.tree_view.setModel(self.tree_model)
        self.tree_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_view.customContextMenuRequested.connect(self.show_tree_context_menu)
        self.tree_view.clicked.connect(self.on_folder_selected)
        self.tree_view.setToolTip("Right-click a folder to export or view all files recursively")
        self.splitter.addWidget(self.tree_view)

        self.file_model = QStandardItemModel()
        self.file_headers = ['Name', 'Created', 'Modified', 'Type', 'Size (Bytes)', 'Path']
        self.file_model.setHorizontalHeaderLabels(self.file_headers)

        self.proxy_model = MultiColumnFilterProxy()
        self.proxy_model.setSourceModel(self.file_model)

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
        self.filter_input.setClearButtonEnabled(True)
        filter_bar.addWidget(self.filter_input)
        self.filter_input.textChanged.connect(self._apply_filter)
        self.filter_col_combo.currentIndexChanged.connect(self._apply_filter)

        _section_style = (
            "font-weight: bold; padding: 3px 6px;"
            "border-bottom: 1px solid palette(mid);"
        )
        _status_style = "color: grey; padding: 1px 6px;"

        browser_header = QLabel("File Browser")
        browser_header.setStyleSheet(_section_style)
        self.table_status_label = QLabel()
        self.table_status_label.setStyleSheet(_status_style)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(2)
        right_layout.addWidget(browser_header)
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
        self.hex_view.setPlaceholderText("Double-click a file to preview it here, or right-click and choose 'Preview in Hex Viewer'.")
        self.hex_view.selectionChanged.connect(self._on_hex_selection_changed)
        self.hex_view.viewport().installEventFilter(self)
        self._fitting_hex_font = False
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

    def _apply_filter(self):
        col = self.filter_col_combo.currentIndex() - 1  # index 0 = "All Columns" → -1
        text = self.filter_input.text()
        self.proxy_model.set_filter(text, col)
        self._refresh_table_status()
        self._filter_log_timer.start()  # restarts if already running

    def _log_filter_final(self):
        text = self.filter_input.text()
        col_name = self.filter_col_combo.currentText()
        if text:
            visible = self.proxy_model.rowCount()
            total = self.file_model.rowCount()
            self._log(f"Filter applied: \"{text}\" in {col_name} — {visible} of {total} rows visible")
        else:
            self._log(f"Filter cleared in: {self._view_path}")

    def _in_zip(self, ui_path) -> bool:
        return _ui_path_to_physical(ui_path) in self.zip_names

    def _is_empty_folder_entry(self, ui_path) -> bool:
        """True when the ZIP contains a bare directory entry for this path (trailing slash)."""
        return (_ui_path_to_physical(ui_path) + "/") in self.zip_names

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
        if self._view_is_recursive:
            parts.append("recursive")
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

    def _get_export_dir(self):
        zip_dir = os.path.dirname(self.zip_path)
        zip_name = os.path.splitext(os.path.basename(self.zip_path))[0]
        return os.path.join(zip_dir, f"{zip_name}_Export")

    def _get_log_path(self):
        zip_dir = os.path.dirname(self.zip_path)
        zip_name = os.path.splitext(os.path.basename(self.zip_path))[0]
        return os.path.join(zip_dir, f"{zip_name}_audit_log.txt")

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
        ui_path = self.file_model.item(source.row(), 0).data(Qt.ItemDataRole.UserRole)
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
        self.tree_view.expand(self.tree_model.indexFromItem(current))
        parts = [p for p in target_path.split('/') if p]

        for part in parts:
            found = False
            for row in range(current.rowCount()):
                child = current.child(row)
                if child.text() == part:
                    self.tree_view.expand(self.tree_model.indexFromItem(child))
                    current = child
                    found = True
                    break
            if not found: break

        new_idx = self.tree_model.indexFromItem(current)
        self.tree_view.setCurrentIndex(new_idx)
        self.tree_view.scrollTo(new_idx, QTreeView.ScrollHint.PositionAtCenter)
        self.on_folder_selected(new_idx)

    def on_file_selected(self, index):
        source = self.proxy_model.mapToSource(index)
        ui_path = self.file_model.item(source.row(), 0).data(Qt.ItemDataRole.UserRole)
        if not ui_path:
            return
        self.status_bar.showMessage(ui_path)
        is_folder = ui_path in self.folder_map
        self._log(f"{'Folder' if is_folder else 'File'} selected: {ui_path}")

    def _load_hex_preview(self, ui_path):
        # Cancel any in-flight load
        if hasattr(self, '_hex_worker') and self._hex_worker.isRunning():
            self._hex_worker.terminate()
            self._hex_worker.wait()

        physical_path = _ui_path_to_physical(ui_path)
        total_size = self.full_metadata.get(ui_path, {}).get('size', 0)

        self.hex_view.clear()
        self.hex_label.setText(f"Loading: {ui_path}")
        self.hex_progress_bar.setRange(0, max(total_size, 1))
        self.hex_progress_bar.setValue(0)
        self.hex_progress_bar.show()

        self._hex_ui_path = ui_path
        self._hex_worker = HexLoadWorker(self.zip_path, physical_path, total_size)
        self._hex_worker.progress.connect(self._on_hex_progress)
        self._hex_worker.load_complete.connect(self._on_hex_ready)
        self._hex_worker.error.connect(self._on_hex_error)
        self._hex_worker.start()

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
    def _render_hex(data: bytes) -> str:
        lines = []
        for offset in range(0, len(data), 32):
            chunk = data[offset:offset + 32]
            groups = [
                " ".join(f"{b:02x}" for b in chunk[g * 4:(g + 1) * 4])
                for g in range(8)
            ]
            hex_part  = "  ".join(f"{g:<11}" for g in groups)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset:08x}  {hex_part}  {ascii_part}")
        return "\n".join(lines)

    def eventFilter(self, obj, event):
        if obj is self.hex_view.viewport() and event.type() == QEvent.Type.Resize:
            self._fit_hex_font()
        return super().eventFilter(obj, event)

    def _fit_hex_font(self):
        if self._fitting_hex_font:
            return
        vp_width = self.hex_view.viewport().width()
        if vp_width <= 0:
            return
        font = self.hex_view.font()
        char_w = QFontMetricsF(font).maxWidth()
        if char_w <= 0:
            return
        line_chars = _HEX_ASCII_START + _HEX_BYTES_PER_ROW  # 146
        new_size = font.pointSizeF() * (vp_width / (char_w * line_chars))
        new_size = max(6.0, min(new_size, 32.0))
        if abs(new_size - font.pointSizeF()) < 0.1:
            return
        self._fitting_hex_font = True
        try:
            font.setPointSizeF(new_size)
            self.hex_view.setFont(font)
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
            if total_bytes > 512:
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
        self.status_bar.showMessage(f"{folder_path}    |    Tip: Right-click to export or view all files recursively")
        self._log(f"Folder viewed: {folder_path}")

        children = self.folder_map.get(folder_path, [])
        has_bundles = any(p.split('/')[-1] in self.guid_to_bundle for p in children)

        if has_bundles:
            headers = [self.file_headers[0], 'Bundle ID'] + self.file_headers[1:]
        else:
            headers = self.file_headers

        new_model = QStandardItemModel()
        new_model.setHorizontalHeaderLabels(headers)
        self._update_filter_columns(headers)
        self.filter_input.clear()
        self._view_path = folder_path
        self._view_is_recursive = False

        for path in sorted(children):
            name = path.split('/')[-1]
            meta = self.full_metadata.get(path, {})

            is_folder = path in self.folder_map
            bold_font = QFont("Segoe UI", weight=QFont.Weight.Bold)

            # Determine type label and whether to grey out
            if is_folder:
                status = self._folder_content_status(path)
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
                file_type = "Empty Folder"
                grey_row = True
            else:
                file_type = "Not in Zip"
                grey_row = True

            name_item = QStandardItem(name)
            name_item.setData(path, Qt.ItemDataRole.UserRole)
            name_item.setEditable(False)

            row_items = [name_item]

            if has_bundles:
                row_items.append(_make_item(self.guid_to_bundle.get(name, "")))

            row_items.extend([
                _make_item(self.format_ts(meta.get('ctime'))),
                _make_item(self.format_ts(meta.get('mtime'))),
                _make_item(file_type),
                _make_item(f"{meta.get('size', 0):,}"),
                _make_item(path),
            ])

            if is_folder and not grey_row:
                for item in row_items:
                    item.setFont(bold_font)
            if grey_row:
                grey = QColor(Qt.GlobalColor.darkGray)
                for item in row_items:
                    item.setForeground(grey)

            new_model.appendRow(row_items)

        self.file_model = new_model
        self.proxy_model.setSourceModel(self.file_model)

        self.file_view.resizeColumnsToContents()
        self._refresh_table_status()

    def format_ts(self, ts):
        if not ts: return ""
        try:
            # APFS stores timestamps as nanoseconds since epoch
            if ts > 1e10:
                ts = ts / 1e9
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
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
        ui_path = self.tree_model.itemFromIndex(index).data(Qt.ItemDataRole.UserRole)
        menu = QMenu(self)
        export_act = QAction("📁 Export Folder (Recursive)", self)
        export_act.triggered.connect(lambda: self.handle_export_request(is_tree=True))
        menu.addAction(export_act)
        view_act = QAction("🔍 View Files Recursive", self)
        view_act.triggered.connect(lambda: self.show_recursive_files(ui_path))
        menu.addAction(view_act)
        menu.exec(self.tree_view.viewport().mapToGlobal(point))

    def show_recursive_files(self, folder_path):
        display_path = folder_path if folder_path else "/ [Full Filesystem]"
        all_files = []
        self._collect_descendants(folder_path, all_files)
        files = [p for p in all_files if p not in self.folder_map]

        if len(files) > 10_000:
            answer = QMessageBox.question(
                self, "Large Recursive View",
                f"This folder contains approximately {len(files):,} files.\n\n"
                "Loading this many rows may take a while and use significant memory.\n\n"
                "Do you want to continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        self._update_filter_columns(self.file_headers)
        self.filter_input.clear()
        self._view_path = display_path
        self._view_is_recursive = True
        self._log(f"Recursive view: {display_path} ({len(files)} files)")

        total = len(files)
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(0)
        self.progress_bar.show()
        self.status_bar.showMessage(f"Loading {total:,} files recursively from: {display_path}")

        new_model = QStandardItemModel()
        new_model.setHorizontalHeaderLabels(self.file_headers)

        for i, path in enumerate(sorted(files)):
            name = path.split('/')[-1]
            meta = self.full_metadata.get(path, {})
            name_item = QStandardItem(name)
            name_item.setData(path, Qt.ItemDataRole.UserRole)
            name_item.setEditable(False)
            if self._in_zip(path):
                file_type = _get_file_type(name, False)
                grey_row = False
            elif self._is_empty_folder_entry(path):
                file_type = "Empty Folder"
                grey_row = True
            else:
                file_type = "Not in Zip"
                grey_row = True
            row_items = [name_item]
            row_items.extend([
                _make_item(self.format_ts(meta.get('ctime'))),
                _make_item(self.format_ts(meta.get('mtime'))),
                _make_item(file_type),
                _make_item(f"{meta.get('size', 0):,}"),
                _make_item(path),
            ])
            if grey_row:
                grey = QColor(Qt.GlobalColor.darkGray)
                for item in row_items:
                    item.setForeground(grey)
            new_model.appendRow(row_items)
            if i % 500 == 0:
                self.progress_bar.setValue(i)
                QApplication.processEvents()

        self.file_model = new_model
        self.proxy_model.setSourceModel(self.file_model)
        self.progress_bar.hide()
        self.file_view.resizeColumnsToContents()
        self._refresh_table_status()
        self.status_bar.showMessage(f"Done — {total:,} files loaded from: {display_path}")

    def _collect_descendants(self, path, result, visited=None):
        if visited is None:
            visited = set()
        if path in visited:
            return
        visited.add(path)
        for child in self.folder_map.get(path, []):
            result.append(child)
            if child in self.folder_map:
                self._collect_descendants(child, result, visited)

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
        ui_path = self.file_model.item(source.row(), 0).data(Qt.ItemDataRole.UserRole)

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
                ui_path = self.file_model.item(source.row(), 0).data(Qt.ItemDataRole.UserRole)
                base_parent = ui_path.rsplit('/', 1)[0] if ui_path in self.folder_map and '/' in ui_path else ui_path
                tasks.append((ui_path, base_parent))

        self.progress_bar.setValue(0)
        self.progress_bar.show()

        self.ex_worker = ExtractorWorker(self.zip_path, tasks, self._get_export_dir(), self.folder_map)
        self.ex_worker.status.connect(self.status_bar.showMessage)
        self.ex_worker.progress.connect(self.progress_bar.setValue)
        self.ex_worker.finished.connect(self.on_export_finished)
        self.ex_worker.start()

    def on_export_finished(self, success, message, dest_path):
        QApplication.restoreOverrideCursor()
        self.progress_bar.hide()
        if success:
            self._log(f"Export succeeded: {message} → {dest_path}")
            QMessageBox.information(self, "Export Complete", f"{message}\n\nNote: Hidden files (starting with '.') have been renamed with '_' for visibility.")
        else:
            self._log(f"Export failed: {message}")
            QMessageBox.critical(self, "Export Failed", message)

    def open_path(self, path):
        if sys.platform == 'win32': os.startfile(path)
        elif sys.platform == 'darwin': subprocess.Popen(['open', path])
        else: subprocess.Popen(['xdg-open', path])

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
        self.progress_bar.setRange(0, 0)
        self.progress_bar.show()
        self.worker = ZipMetadataWorker(zip_path)
        self.worker.status_update.connect(self.status_bar.showMessage)
        self.worker.metadata_ready.connect(self.on_metadata_ready)
        self.worker.start()

    def on_metadata_ready(self, data, folder_map, guid_map, zip_names):
        self.full_metadata = data
        self.folder_map = folder_map
        self.guid_to_bundle = guid_map
        self.zip_names = zip_names
        self._real_content_cache = {}
        self.progress_bar.setRange(0, 100)
        self.reload_tree_entirely()

    def reload_tree_entirely(self):
        if not self.folder_map: return
        self._reset_tree_model()
        self.tree_view.setModel(self.tree_model)
        mode = self.view_group.checkedId()
        self.tree_model.blockSignals(True)
        root_item = QStandardItem("/ [Full Filesystem]")
        root_item.setData("", Qt.ItemDataRole.UserRole)
        root_item.setEditable(False)
        root_item.setFont(QFont("Segoe UI", weight=QFont.Weight.Bold))
        self.tree_model.invisibleRootItem().appendRow(root_item)
        self._build_tree_recursive(root_item, "", mode)
        self.tree_view.expand(self.tree_model.indexFromItem(root_item))
        self.tree_model.blockSignals(False)
        self.progress_bar.hide()
        self.status_bar.showMessage(f"Loaded: {os.path.basename(self.zip_path)}")

    def _build_tree_recursive(self, parent_item, parent_path, mode):
        children = sorted(self.folder_map.get(parent_path, []))
        for p in children:
            if p in self.folder_map:
                if mode == CLEAN_MODE and self.is_path_hidden(p): continue
                name = p.split('/')[-1]
                item = QStandardItem(name)
                item.setData(p, Qt.ItemDataRole.UserRole)
                item.setEditable(False)
                if mode == EDIT_FILTER_MODE:
                    item.setCheckable(True)
                    item.setCheckState(
                        Qt.CheckState.Unchecked if self.is_path_hidden(p) else Qt.CheckState.Checked
                    )
                parent_item.appendRow(item)
                self._build_tree_recursive(item, p, mode)

    def is_path_hidden(self, path):
        for rule in self.hidden_paths:
            if path.startswith(rule): return True
        return False

    def on_tree_item_changed(self, item):
        if self.view_group.checkedId() != EDIT_FILTER_MODE:
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        if path is None:
            return
        if item.checkState() == Qt.CheckState.Unchecked:
            self.hidden_paths.add(path)
        else:
            self.hidden_paths.discard(path)
        self.save_settings()

    def save_settings(self):
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(list(self.hidden_paths), f)

    def load_settings(self):
        return set(_load_json_file(SETTINGS_FILE, []))

    def load_recent_list(self):
        return _load_json_file(RECENT_FILE, [])

    def save_recent_list(self, path):
        if path in self.recent_paths: self.recent_paths.remove(path)
        self.recent_paths.insert(0, path)
        self.recent_paths = self.recent_paths[:5]
        with open(RECENT_FILE, 'w') as f: json.dump(self.recent_paths, f)
        self.update_dropdown_ui()

    def update_dropdown_ui(self):
        self.archive_dropdown.clear()
        self.archive_dropdown.addItem(NEW_ARCHIVE_SENTINEL)
        for p in self.recent_paths: self.archive_dropdown.addItem(p)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FastZipBrowser()
    window.show()
    sys.exit(app.exec())
