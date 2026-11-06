#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import sys
import uuid

SCHEMA = 'igareck.zapret2.macos.install.v1'
CONTROL = frozenset(('DELETE.sh', 'remove_installation.py', 'installation.json'))
RETAIN = CONTROL | frozenset(('cli_ui.py', 'app_paths.py', 'LICENSE.txt', 'diagnostics.py'))


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def read_identity(root):
    marker = root / 'installation.json'
    if marker.is_symlink() or not marker.is_file():
        raise RuntimeError('Не найден собственный маркер установленной программы.')
    identity = json.loads(marker.read_text(encoding='utf-8'))
    if identity.get('schema') != SCHEMA or identity.get('prefix') != str(root) or not re.fullmatch(r'[0-9a-f]{32}', identity.get('id', '')):
        raise RuntimeError('Удаление разрешено только из собственной установленной папки.')
    for relative in identity['files']:
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts or not path.parts:
            raise RuntimeError('Некорректный путь в маркере установки.')
    return identity


def write_identity(root, identity):
    temporary = root / ('installation.json.' + uuid.uuid4().hex + '.tmp')
    try:
        temporary.write_text(json.dumps(identity, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        temporary.chmod(0o600)
        os.replace(temporary, root / 'installation.json')
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def runtime_lock():
    descriptor = os.open('/var/run/igareck-zapret2-public.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Уже работает macOS-оболочка Igareck. Остановите её через Ctrl+C перед удалением.')
        yield


def check_purge_root(root):
    protected = {'/', '/opt', '/usr', '/usr/local', '/var', '/var/lib', '/var/log', '/etc',
                 '/bin', '/sbin', '/tmp', '/private', '/System', '/Applications', '/Users', '/Library'}
    if str(root) in protected or len(root.parts) < 3:
        raise RuntimeError('Полное удаление системной/общей папки запрещено.')
    result = os.popen('/sbin/mount').read()
    for line in result.splitlines():
        match = re.search(r' on (.*) \(', line)
        if match:
            mount = Path(match.group(1))
            if mount == root or root in mount.parents:
                raise RuntimeError('В папке установки есть точка монтирования: ' + str(mount))


def purge_tree(root):
    for path in root.iterdir():
        if path.name in CONTROL:
            continue
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    for name in ('DELETE.sh', 'remove_installation.py', 'installation.json'):
        (root / name).unlink(missing_ok=True)
    root.rmdir()


def uninstall(root, purge=False, yes=False):
    root = Path(root).resolve()
    identity = read_identity(root)
    if purge:
        check_purge_root(root)
        print('ПОЛНОЕ УДАЛЕНИЕ: ' + str(root))
        print('Будут удалены ВСЕ файлы внутри этой папки, включая логи, изменённые и добавленные файлы.')
    if not yes:
        prompt = 'Остановите Zapret2. Для ' + ('полного ' if purge else '') + 'удаления введите УДАЛИТЬ или DELETE: '
        if input(prompt).strip().upper() not in ('УДАЛИТЬ', 'DELETE'):
            print('Удаление отменено.')
            return
    with runtime_lock():
        if not identity.get('standard_uninstalled'):
            from darwin_session import Session
            Session(root).recover()
        if identity.get('shortcuts'):
            from desktop_integration import remove_shortcuts
            remove_shortcuts(identity['shortcuts'])
            identity['shortcuts'] = None
        if identity.get('global_command'):
            from global_command import remove as remove_global_command
            remove_global_command(identity['global_command'])
            identity['global_command'] = None
        identity['standard_uninstalled'] = True
        write_identity(root, identity)
        if purge:
            check_purge_root(root)
            purge_tree(root)
            print('Полностью удалено: ' + str(root))
            return
        for relative, expected in identity['files'].items():
            if relative in RETAIN:
                continue
            path = root / relative
            if not path.resolve().is_relative_to(root):
                continue
            if path.is_file() and not path.is_symlink() and digest(path) == expected:
                path.unlink()
        for path in sorted(root.rglob('*'), key=lambda item: len(item.parts), reverse=True):
            if path.is_dir() and not path.is_symlink():
                try:
                    path.rmdir()
                except OSError:
                    pass
    print('Неизменённые файлы программы удалены. Логи и изменённые файлы сохранены.')
    print('Полное удаление оставшейся папки: sudo bash ' + shlex.quote(str(root / 'DELETE.sh')) + ' --purge')


def main():
    parser = argparse.ArgumentParser(description='Удаление Igareck CLI macOS 1.0')
    parser.add_argument('--purge', action='store_true')
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('--prefix')
    args = parser.parse_args()
    if args.prefix and not args.purge:
        parser.error('--prefix разрешён только вместе с --purge.')
    if os.geteuid() != 0:
        parser.error('Запустите через sudo bash DELETE.sh.')
    code = 0
    try:
        from cli_ui import show_header
        show_header(Path(__file__).resolve().parent)
        uninstall(Path(args.prefix).expanduser() if args.prefix else Path(__file__).resolve().parent, args.purge, args.yes)
    except KeyboardInterrupt:
        print('\nУдаление прервано.')
        code = 130
    except Exception as error:
        from diagnostics import report_exception
        report_exception(Path(__file__).resolve().parent, error, 'uninstaller')
        code = 1
    if os.environ.get('IGARECK_TERMINAL_WINDOW') == '1' and sys.stdin.isatty():
        try:
            input('\nНажмите Enter, чтобы закрыть окно.\n')
        except (EOFError, KeyboardInterrupt):
            pass
    return code


if __name__ == '__main__':
    def terminate(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGHUP, terminate)
    raise SystemExit(main())
