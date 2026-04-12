"""ffs.py — format-agnostic adapter for iOS Full File System (FFS) extractions.

FfsAdapter is the single place where Cellebrite and GrayKey differences
are handled: format detection, path resolution (ui_path → physical zip path),
candidate-path generation for plist lookups, and metadata loading.

Usage
-----
    with zipfile.ZipFile(zip_path) as z:
        adapter = FfsAdapter.detect(z)

    # Resolve a ui_path to its physical zip entry
    adapter.resolve("mobile/Library/SMS/sms.db")

    # Generate candidate paths for a user-partition file
    adapter.user_candidates("preferences/SystemConfiguration/preferences.plist")

    # Generate candidate paths for a system-partition file
    adapter.system_candidates("System/Library/CoreServices/SystemVersion.plist")

    # Load the full metadata dict
    raw = adapter.load_metadata(zip_path, z)
"""

import zipfile

import msgpack

from adapters import graykey as _gk

# ── Cellebrite partition detection ────────────────────────────────────────────

def _has_prefix(zip_names: frozenset, prefix: str) -> bool:
    """Return True if any entry in zip_names starts with *prefix* (with or without
    a trailing slash), or is exactly *prefix*.  Handles zips that omit explicit
    directory entries by checking file entries that live under the prefix."""
    slash = prefix if prefix.endswith("/") else prefix + "/"
    bare  = prefix.rstrip("/")
    if bare in zip_names or slash in zip_names:
        return True
    return any(n.startswith(slash) for n in zip_names)


def _detect_user_prefix(zip_names: frozenset) -> tuple[str, bool]:
    """Return (user_prefix, old_layout) for the Cellebrite user partition.

    Two Cellebrite layouts exist:
    - New: filesystemN/mobile/  — msgpack keys are bare (mobile/...)
           → ('filesystemN', False)
    - Old: filesystemN/private/var/mobile/  — msgpack keys include private/var/
           → ('filesystemN', True)

    Falls back to ('filesystem2', False).

    New-layout is checked across ALL filesystem numbers first, because some
    iOS system partitions (filesystem1) contain a small number of stub entries
    under private/var/mobile/ that would otherwise trigger a false old-layout
    match before the real user partition (filesystem2) is examined."""
    # Pass 1: new layout — mobile/wireless directly under filesystemN
    for n in range(1, 10):
        prefix = f"filesystem{n}"
        for root in ("mobile", "wireless"):
            if _has_prefix(zip_names, f"{prefix}/{root}"):
                return prefix, False
    # Pass 2: old layout — private/var/mobile under filesystemN
    for n in range(1, 10):
        prefix = f"filesystem{n}"
        for root in ("mobile", "wireless"):
            if _has_prefix(zip_names, f"{prefix}/private/var/{root}"):
                return prefix, True
    return "filesystem2", False


def _detect_system_prefix(zip_names: frozenset) -> str:
    """Return the filesystemN folder that contains the iOS system partition.
    Identified by the presence of System/Library, which is unique to the
    system partition.  Falls back to 'filesystem1'."""
    for n in range(1, 10):
        prefix = f"filesystem{n}"
        if (
            f"{prefix}/System/Library/CoreServices/SystemVersion.plist" in zip_names
            or _has_prefix(zip_names, f"{prefix}/System/Library")
            or _has_prefix(zip_names, f"{prefix}/System")
        ):
            return prefix
    return "filesystem1"


# ── Adapter ───────────────────────────────────────────────────────────────────

class FfsAdapter:
    """Encapsulates all format-specific behaviour for a single FFS extraction."""

    FORMAT_GRAYKEY    = "graykey"
    FORMAT_CELLEBRITE = "cellebrite"

    def __init__(self, fmt: str, user_prefix: str, sys_prefix: str,
                 old_layout: bool = False) -> None:
        self.format      = fmt
        self.user_prefix = user_prefix   # e.g. 'filesystem2' or 'filesystem1'
        self.sys_prefix  = sys_prefix    # e.g. 'filesystem1' (Cellebrite only)
        self.old_layout  = old_layout    # True = old Cellebrite: keys include private/var/

    # ── Detection ─────────────────────────────────────────────────────────────

    @classmethod
    def detect(cls, z: zipfile.ZipFile) -> "FfsAdapter":
        """Inspect an open ZipFile and return the matching adapter."""
        if _gk._is_graykey(z):
            return cls(cls.FORMAT_GRAYKEY, "private/var", "")
        return cls.detect_from_names(frozenset(z.namelist()))

    @classmethod
    def detect_from_names(cls, zip_names: frozenset) -> "FfsAdapter":
        """Detect format from a set of zip entry names (no ZipFile required).

        Always returns a Cellebrite adapter — use this when the zip cannot
        be opened by zipfile (e.g. streaming zips with no central directory),
        where GrayKey can be ruled out."""
        user_prefix, old_layout = _detect_user_prefix(zip_names)
        return cls(
            cls.FORMAT_CELLEBRITE,
            user_prefix,
            _detect_system_prefix(zip_names),
            old_layout,
        )

    # ── Path resolution ───────────────────────────────────────────────────────

    def resolve(self, ui_path: str) -> str:
        """Map a ui_path (as stored in metadata) to its physical zip entry path.

        For GrayKey this is a simple prefix prepend.
        For Cellebrite, GUID-style path segments (containing a 32-char hex
        suffix after the last '-') are reduced to that suffix alone, matching
        the physical layout inside the zip.
        """
        if self.format == self.FORMAT_GRAYKEY:
            return "/private/var/" + ui_path

        parts = []
        for part in ui_path.split("/"):
            if "-" in part:
                suffix = part.split("-")[-1]
                if len(suffix) >= 32 and all(
                    c in "0123456789abcdefABCDEF" for c in suffix
                ):
                    parts.append(suffix)
                    continue
            parts.append(part)
        if self.old_layout:
            return f"{self.user_prefix}/private/var/{'/'.join(parts)}"
        return f"{self.user_prefix}/{'/'.join(parts)}"

    # ── Candidate-path generators ─────────────────────────────────────────────

    def user_candidates(self, *suffixes: str) -> list[str]:
        """Return ordered candidate zip paths for user-partition files.

        For each suffix the list covers the most-likely path first so that
        _read_plist_from_zip() finds the entry on the first hit.

        Old-layout Cellebrite archives store files under
        filesystemN/private/var/<suffix>, so both the plain and the
        private/var-infixed paths are tried."""
        candidates: list[str] = []
        if self.format == self.FORMAT_GRAYKEY:
            for s in suffixes:
                candidates.append(f"private/var/{s}")
                candidates.append(f"/private/var/{s}")
                candidates.append(s)
                candidates.append(f"/{s}")
        elif self.old_layout:
            for s in suffixes:
                candidates.append(f"{self.user_prefix}/private/var/{s}")
                candidates.append(s)
                candidates.append(f"/{s}")
        else:
            for s in suffixes:
                candidates.append(f"{self.user_prefix}/{s}")
                candidates.append(s)
                candidates.append(f"/{s}")
        return candidates

    def system_candidates(self, *suffixes: str) -> list[str]:
        """Return ordered candidate zip paths for system-partition files.

        GrayKey extractions do not have a separate system-partition prefix so
        bare and leading-slash paths are tried directly."""
        candidates: list[str] = []
        if self.format == self.FORMAT_GRAYKEY:
            for s in suffixes:
                candidates.append(s)
                candidates.append(f"/{s}")
        else:
            for s in suffixes:
                candidates.append(f"{self.sys_prefix}/{s}")
                candidates.append(s)
                candidates.append(f"/{s}")
        return candidates

    # ── Metadata loading ──────────────────────────────────────────────────────

    def load_metadata(self, zip_path: str, z: zipfile.ZipFile) -> dict:
        """Return the raw metadata dict for this extraction.

        For GrayKey the metadata is parsed from the zip's extra fields.
        For Cellebrite it is unpacked from metadata2/metadata.msgpack.
        In both cases the returned keys are ui_paths with the
        '/private/var/' prefix stripped."""
        if self.format == self.FORMAT_GRAYKEY:
            raw = _gk.extract_metadata(zip_path)
            _GK_PREFIX = "/private/var/"
            return {
                (k[len(_GK_PREFIX):] if k.startswith(_GK_PREFIX) else k.lstrip("/")): v
                for k, v in raw.items()
            }
        else:
            for candidate in ("metadata2/metadata.msgpack", "metadata1/metadata.msgpack"):
                try:
                    with z.open(candidate) as f:
                        raw = msgpack.unpack(f)
                except KeyError:
                    continue
                if self.old_layout:
                    # Strip the 'private/var/' prefix so ui_paths are bare
                    # (matching new-layout Cellebrite and GrayKey)
                    _PV = "private/var/"
                    return {
                        (k[len(_PV):] if k.startswith(_PV) else k): v
                        for k, v in raw.items()
                    }
                return raw
            raise KeyError("metadata.msgpack not found in metadata1/ or metadata2/")
