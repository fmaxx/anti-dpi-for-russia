from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import sys

MARKER = '# igareck-macos-shortcut-v1 '


def graphical_user():
    name = os.environ.get('SUDO_USER') or os.environ.get('USER')
    if not name or name == 'root' or os.environ.get('SSH_CONNECTION'):
        return None
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        return None
    return {'username': name, 'home': account.pw_dir, 'uid': account.pw_uid, 'gid': account.pw_gid}


def choose_shortcuts(user, value=None):
    if user is None:
        return False
    if value is not None:
        return value == 'yes'
    if not sys.stdin.isatty():
        return False
    while True:
        answer = input('Создать ярлыки и инструкции на Рабочем Столе? Да/Yes или Нет/No: ').strip().casefold()
        if answer in ('да', 'yes'):
            return True
        if answer in ('нет', 'no'):
            return False


def launcher_bytes(root, install_id, action):
    target = root / ('START.sh' if action == 'start' else 'DELETE.sh')
    metadata = json.dumps({'id': install_id, 'prefix': str(root), 'action': action}, separators=(',', ':'))
    return ('#!/bin/sh\n' + MARKER + metadata + '\nexec /bin/bash ' + shlex.quote(str(target)) + '\n').encode()


def create_shortcuts(user, root, install_id):
    root = Path(root)
    folder = Path(user['home']) / 'Desktop' / 'Igareck_AntiDPI'
    folder.mkdir(parents=True, exist_ok=True)
    record = {'schema': 'igareck.macos.shortcuts.v1', 'folder': str(folder), 'files': {}}
    try:
        for action, name in (('start', 'START_Igareck_AntiDPI.command'), ('delete', 'DELETE_Igareck_AntiDPI.command')):
            path = folder / name
            if path.exists():
                raise RuntimeError('Ярлык уже занят: ' + str(path))
            data = launcher_bytes(root, install_id, action)
            path.write_bytes(data)
            path.chmod(0o755)
            os.chown(path, user['uid'], user['gid'])
            record['files'][name] = sha256(data).hexdigest()
        for name in ('README_Установка_macOS_v1.0.txt', 'README_Стратегии_macOS_v1.0.txt'):
            data = (root / name).read_bytes()
            path = folder / name
            if path.exists():
                raise RuntimeError('Файл уже занят: ' + str(path))
            path.write_bytes(data)
            os.chown(path, user['uid'], user['gid'])
            record['files'][name] = sha256(data).hexdigest()
        os.chown(folder, user['uid'], user['gid'])
        return record
    except Exception:
        remove_shortcuts(record)
        raise


def remove_shortcuts(record):
    if record.get('schema') != 'igareck.macos.shortcuts.v1':
        raise RuntimeError('Некорректный маркер ярлыков.')
    folder = Path(record['folder'])
    for name, expected in record.get('files', {}).items():
        path = folder / name
        if Path(name).name != name or path.is_symlink() or not path.is_file():
            continue
        if sha256(path.read_bytes()).hexdigest() == expected:
            path.unlink()
    try:
        folder.rmdir()
    except OSError:
        pass
