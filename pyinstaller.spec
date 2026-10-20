# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Specification File for CHARLO Testing Agent.
Generates a standalone native Windows binary package.
"""

import sys
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

hidden_imports = [
    'charlo',
    'charlo.core',
    'charlo.core.models',
    'charlo.core.registry',
    'charlo.core.engine',
    'charlo.core.scoring',
    'charlo.analyzers',
    'charlo.analyzers.apk_analyzer',
    'charlo.analyzers.exe_analyzer',
    'charlo.analyzers.web_analyzer',
    'charlo.checks',
    'charlo.checks.base',
    'charlo.checks.definitions',
    'charlo.checks.apk_checks',
    'charlo.checks.exe_checks',
    'charlo.checks.web_checks',
    'charlo.reporting',
    'charlo.reporting.html_reporter',
    'charlo.reporting.json_reporter',
    'charlo.database',
    'charlo.database.storage',
    'charlo.ui',
    'charlo.ui.styles',
    'charlo.ui.main_window',
    'pefile',
    'requests',
    'jinja2',
    'PySide6',
    'PySide6.QtCore',
    'PySide6.QtGui',
    'PySide6.QtWidgets',
]

datas = []

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    exclude_binaries=True,
    name='CharloTestingAgent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # Set to False for native Windows GUI app
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='CharloTestingAgent',
)
