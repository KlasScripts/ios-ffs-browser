# ios_ffs_browser.spec
# -*- mode: python ; coding: utf-8 -*-

import sys
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

a = Analysis(
    ['ios-ffs-browser.py'],
    pathex=[],
    binaries=[],
    datas=[
        # Bundle the forensic settings JSON next to the exe
        ('forensic_settings.json', '.'),
    ],
    hiddenimports=[
        # msgpack sometimes needs explicit nudging
        'msgpack',
        'msgpack.fallback',
        # PySide6 platform plugin — needed on Windows
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Trim things you definitely don't need
        'matplotlib',
        'numpy',
        'scipy',
        'PIL',
        'tkinter',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,          # onedir mode — keeps Qt DLLs alongside exe
    name='ios-ffs-browser',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,                       # compress binaries — set False if UPX causes AV flags
    console=False,                  # no console window (GUI app)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='icon.ico',              # uncomment and add an .ico file if you have one
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ios-ffs-browser',         # output folder name inside dist/
)
