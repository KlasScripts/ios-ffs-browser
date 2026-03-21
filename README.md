# ios-ffs-browser

A PySide6 desktop app for browsing iOS Full File System (FFS) extractions produced by **Cellebrite UFED**.

> GrayKey and other extraction formats are not yet supported — see [Planned Support](#planned-support).

---

## How Cellebrite FFS ZIPs are structured

Cellebrite packages FFS extractions as a ZIP with two components:

- **`filesystem2/`** — the extracted file system tree
- **`metadata2/metadata.msgpack`** — a MessagePack dictionary keyed by logical path, containing timestamps (`ctime`, `mtime`) and file sizes for every entry

File metadata is not stored in the ZIP entries themselves — it lives entirely in the msgpack sidecar. This structure is Cellebrite-specific, which is why GrayKey support requires separate work.

---

## Features

- Browse a Cellebrite FFS ZIP without extracting it
- Folder tree with UUID-to-bundle-ID resolution for app containers
- Jump-to shortcuts for key forensic locations (Biome, KnowledgeC, SMS, Safari, Keychain, etc.)
- File table with timestamps and sizes sourced from the msgpack metadata
- Inline hex viewer (up to 64 KB per file)
- Column filtering, recursive export, and per-session audit logging
- Three view modes: All Folders, Customise Filter, Simplified View

---

## Requirements

```
pip install PySide6 msgpack
```

---

## Usage

```bash
python ios-ffs-browser.py
```

---

## Planned Support

**GrayKey** uses a different ZIP layout and does not use a msgpack metadata sidecar. Adding support will require a separate parser, with format detection at load time.
