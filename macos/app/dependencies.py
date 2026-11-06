from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

PACKAGES = ('pkg-config', 'luajit')
COMMANDS = ('cc', 'make', 'patch', 'curl', 'pkg-config')


def brew_command():
    return shutil.which('brew') or next((path for path in ('/opt/homebrew/bin/brew', '/usr/local/bin/brew') if os.access(path, os.X_OK)), None)


def add_brew_path():
    brew = brew_command()
    if brew:
        bin_dir = str(Path(brew).resolve().parent)
        os.environ['PATH'] = bin_dir + os.pathsep + os.environ.get('PATH', '')


def missing_dependencies():
    add_brew_path()
    missing = [name for name in COMMANDS if not shutil.which(name)]
    if 'cc' in missing or 'pkg-config' in missing:
        return missing
    flags = subprocess.run(['pkg-config', '--cflags', '--libs', 'luajit'], capture_output=True, text=True, timeout=15)
    if flags.returncode:
        return missing + ['LuaJIT (pkg-config luajit)']
    source = '#include <lua.h>\n#include <zlib.h>\nint main(void) { return 0; }\n'
    with tempfile.TemporaryDirectory(prefix='.ig-deps-') as temporary:
        checked = subprocess.run(['cc', '-x', 'c', '-', '-o', str(Path(temporary) / 'probe'), '-lz'] + shlex.split(flags.stdout),
                                 input=source, text=True, capture_output=True, timeout=30)
    if checked.returncode:
        missing.append('заголовки/библиотеки LuaJIT и zlib: ' + checked.stderr.strip()[-1500:])
    return missing


def ensure_dependencies(skip=False):
    missing = missing_dependencies()
    if not missing:
        print('Зависимости уже установлены.', flush=True)
        return
    brew = brew_command()
    if brew and not skip and 'cc' not in missing:
        command = [brew, 'install', *PACKAGES]
        user = os.environ.get('SUDO_USER')
        if os.geteuid() == 0 and user and user != 'root':
            command = ['/usr/bin/sudo', '-u', user, *command]
        subprocess.run(command, check=True)
        missing = missing_dependencies()
    if missing:
        raise RuntimeError('Не установлены зависимости:\n- ' + '\n- '.join(missing) +
                           '\nУстановите Xcode Command Line Tools, pkg-config и luajit, затем повторите INSTALL.sh. '
                           'Homebrew: brew install pkg-config luajit. --skip-deps не отключает проверку.')
