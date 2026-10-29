#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打包 EXE：把 privacy_audit_gui.py 打包成单文件免安装 GUI 程序。

用法：python build_exe.py
产物：dist/privacy_audit_tool.exe

依赖自举：PyInstaller 缺失时自动安装到 vendor/（与主工具一致的零手工依赖设计）。
exe 首次运行会在自身所在目录创建 bin/ reports/ 等运行目录
（bin 缓存 frida-server，reports 输出报告），拷走单个 exe 即可便携分发。
"""
import os
import subprocess
import sys
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
VENDOR_DIR = TOOL_DIR / 'vendor'
DIST_DIR = TOOL_DIR / 'dist'
MIRROR = 'https://pypi.tuna.tsinghua.edu.cn/simple'


def _try_import():
    try:
        import PyInstaller  # noqa: F401
        return True
    except ImportError:
        return False


def ensure_pyinstaller():
    if _try_import():
        return True
    if str(VENDOR_DIR) not in sys.path and VENDOR_DIR.exists():
        sys.path.insert(0, str(VENDOR_DIR))
        if _try_import():
            return True
    print(f'[打包] 首次打包，自动安装 PyInstaller -> {VENDOR_DIR}')
    flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    r = subprocess.run([sys.executable, '-m', 'pip', 'install', '-q',
                        '-i', MIRROR, '--target', str(VENDOR_DIR), 'pyinstaller'],
                       capture_output=True, text=True, timeout=600, creationflags=flags)
    if r.returncode != 0:
        print('[打包] PyInstaller 安装失败：' + (r.stderr or '')[:500])
        return False
    return True


def main():
    if not ensure_pyinstaller():
        sys.exit(1)

    env = dict(os.environ)
    env['PYTHONPATH'] = str(VENDOR_DIR) + os.pathsep + env.get('PYTHONPATH', '')
    args = [
        sys.executable, '-m', 'PyInstaller',
        '--noconfirm', '--clean', '--onefile', '--windowed',
        '--name', 'privacy_audit_tool',
        # frida / tkinterdnd2 含二进制扩展与 tcl 数据文件，需整体收集进 exe
        '--collect-all', 'frida',
        '--collect-all', 'tkinterdnd2',
        '--distpath', str(DIST_DIR),
        '--workpath', str(TOOL_DIR / 'build'),
        '--specpath', str(TOOL_DIR),
        str(TOOL_DIR / 'privacy_audit_gui.py'),
    ]
    print('[打包] 开始构建（首次约需几分钟）...')
    r = subprocess.run(args, env=env)
    if r.returncode != 0:
        sys.exit(1)

    exe = DIST_DIR / ('privacy_audit_tool.exe' if os.name == 'nt' else 'privacy_audit_tool')
    if not exe.exists():
        print('[打包] 未找到产物: ' + str(exe))
        sys.exit(1)
    print(f'[打包] 完成: {exe}（{exe.stat().st_size / 1024 / 1024:.1f} MB）')
    print('[打包] exe 首次运行会在其所在目录生成 bin/ reports/ 等运行目录，单文件即可分发。')


if __name__ == '__main__':
    main()
