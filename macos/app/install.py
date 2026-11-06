#!/usr/bin/env python3
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import zipfile

from app_paths import FILE_LAYOUT, resource_path

SOURCE = Path(__file__).resolve().parent
FILES = tuple(FILE_LAYOUT)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def extract_source(archive, destination, archive_root):
    if not archive_root or '/' in archive_root or '\\' in archive_root or archive_root in ('.', '..'):
        raise RuntimeError('Некорректный корень официального архива.')
    destination = Path(destination)
    records = []
    seen = set()
    total = 0

    def target(name, size, directory):
        nonlocal total
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or '\\' in name or not path.parts or path.parts[0] != archive_root:
            raise RuntimeError('Недопустимый элемент исходного архива: ' + name)
        relative = Path(*path.parts[1:])
        if len(path.parts) == 1:
            if not directory:
                raise RuntimeError('Корень исходного архива должен быть папкой.')
            return None
        key = relative.as_posix()
        if key in seen:
            raise RuntimeError('Повторяющийся элемент исходного архива: ' + name)
        seen.add(key)
        total += size
        if total > 100 * 1024 * 1024 or len(seen) > 20000:
            raise RuntimeError('Непредвиденный размер исходников.')
        return destination / relative

    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as stream:
            for member in stream.infolist():
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise RuntimeError('Недопустимый элемент исходного ZIP: ' + member.filename)
                path = target(member.filename, member.file_size, member.is_dir())
                if path is not None:
                    records.append((member, path))
            for member, path in records:
                if member.is_dir():
                    path.mkdir(parents=True, exist_ok=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with stream.open(member) as source, path.open('xb') as output:
                        shutil.copyfileobj(source, output)
        return
    with tarfile.open(archive) as stream:
        for member in stream.getmembers():
            if not (member.isfile() or member.isdir()):
                raise RuntimeError('Недопустимый элемент исходного архива: ' + member.name)
            path = target(member.name, member.size, member.isdir())
            if path is not None:
                records.append((member, path))
        for member, path in records:
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(member) as source, path.open('xb') as output:
                    shutil.copyfileobj(source, output)
                path.chmod(member.mode & 0o777)


def choose_prefix(value):
    while True:
        answer = value or (input('Папка установки [/opt/igareck-antidpi]: ').strip() if sys.stdin.isatty() else '')
        path = Path(answer or '/opt/igareck-antidpi').expanduser().resolve()
        if path == Path('/') or (path.exists() and (not path.is_dir() or any(path.iterdir()))):
            print('Папка уже занята, выберите другую папку или удалите текущую установку.')
            if value or not sys.stdin.isatty():
                raise RuntimeError('Укажите новую пустую папку через --prefix.')
            continue
        return path


def installation_summary(prefix, shortcuts, global_command=None):
    from cli_ui import color
    print('\n' + color('Установлено в:', '92') + ' ' + str(prefix))
    if shortcuts:
        print(color('Ярлыки и инструкции:', '92') + ' ' + shortcuts['folder'])
    print(color('Запуск:', '92') + ' sudo bash ' + shlex.quote(str(prefix / 'START.sh')))
    if global_command:
        print(color('Запуск из любой папки:', '92') + ' igareck-antidpi')
    print(color('Стандартное удаление:', '91') + ' sudo bash ' + shlex.quote(str(prefix / 'DELETE.sh')))
    print(color('Полное удаление:', '91') + ' sudo bash ' + shlex.quote(str(prefix / 'DELETE.sh')) + ' --purge\n')


def install(args):
    if sys.platform != 'darwin':
        raise RuntimeError('Установщик предназначен только для macOS.')
    version = subprocess.run(['/usr/bin/sw_vers', '-productVersion'], capture_output=True, text=True, check=True).stdout.strip()
    if int(version.split('.')[0]) < 26:
        raise RuntimeError('Требуется macOS 26 или новее; текущая версия: ' + version)
    if sys.version_info < (3, 9):
        raise RuntimeError('Нужен Python 3.9 или новее.')
    if args.engine != 'compatible':
        raise RuntimeError('macOS-транспорт проверен только с закреплённым коммитом Zapret2. Используйте --engine compatible.')
    from cli_ui import show_intro, color
    from desktop_integration import graphical_user, choose_shortcuts, create_shortcuts, remove_shortcuts
    from source_download import select_source
    from global_command import prepare, register, remove as remove_global_command

    show_intro(SOURCE, installing=True)
    print(color('Enter устанавливает в /opt/igareck-antidpi.', '94'))
    prefix = choose_prefix(args.prefix)
    desktop_user = graphical_user()
    create_desktop = choose_shortcuts(desktop_user, args.shortcuts)
    command_plan = prepare(args.global_command)
    print('----------------------')
    print('\nУстановка: ' + str(prefix) + '\n484 стратегии: 45 Golden + 439 Silver. IPv4 TCP/TLS; macOS PF/pflog + BPF.')
    from dependencies import ensure_dependencies
    ensure_dependencies(args.skip_deps)
    meta = select_source(json.loads(resource_path(SOURCE, 'upstream.json').read_text()), 'compatible')
    prefix.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.ig-', dir=prefix.parent))
    stage.chmod(0o755)
    complete = False
    try:
        for name in FILES:
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(resource_path(SOURCE, name), target)
        from darwin_session import check_environment
        check_environment(stage)
        from source_download import download
        with (stage / 'source-download.log').open('w', encoding='utf-8') as log:
            archive = download(meta, stage / 's.arc', log=log)
        unpacked = stage / 's'
        unpacked.mkdir(mode=0o700)
        extract_source(archive, unpacked, meta['archive_root'])
        if not (unpacked / 'nfq2/Makefile').is_file() or not (unpacked / 'lua/zapret-lib.lua').is_file():
            raise RuntimeError('В официальных исходниках не найдены nfqws2 и Lua-библиотека.')
        (stage / 'upstream-selected.json').write_text(json.dumps(meta, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        for name in ('darwin.c', 'darwin.h'):
            shutil.copy2(stage / name, unpacked / 'nfq2' / name)
        patch_text = (stage / 'zapret2-darwin.patch').read_text(encoding='utf-8')
        patched = subprocess.run(['patch', '-p1'], cwd=unpacked, input=patch_text, text=True, capture_output=True)
        if patched.returncode:
            raise RuntimeError('Не удалось применить macOS patch к pinned Zapret2: ' + patched.stdout + patched.stderr)
        print('Сборка macws2 под текущий macOS/CPU. Подробности: ' + str(stage / 'build.log'), flush=True)
        with (stage / 'build.log').open('w') as log:
            result = subprocess.run(['make', '-C', str(unpacked / 'nfq2'), '-j' + str(min(os.cpu_count() or 2, 8)),
                                     'macos', 'MINSIZE=-ffunction-sections -fdata-sections', 'LDFLAGS=-Wl,-dead_strip'],
                                    stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            print((stage / 'build.log').read_text()[-8000:])
            raise RuntimeError('Ошибка компиляции macws2, см. сообщения выше.')
        engine = stage / 'engine'
        engine.mkdir()
        shutil.copy2(unpacked / 'nfq2/macws2', engine / 'macws2')
        shutil.copytree(unpacked / 'lua', engine / 'lua')
        shutil.copy2(unpacked / 'docs/LICENSE.txt', engine / 'LICENSE_Bol-Van.txt')
        from igareck import load_catalogue, engine_arguments
        for path in stage.rglob('*'):
            if path == unpacked or unpacked in path.parents:
                continue
            if path.is_dir():
                path.chmod(0o755)
            elif path.is_file() and path.name != 'build.log':
                path.chmod(0o755 if path.name == 'macws2' or path.suffix == '.sh' else 0o644)
        data = load_catalogue(stage)
        print('Проверяю параметры всех 484 стратегий...', flush=True)
        with (stage / 'parameters-check.log').open('w') as log:
            for row in data['ProfileRows']:
                checked = subprocess.run(engine_arguments(stage, row) + ['--dry-run'], cwd=engine,
                                         stdout=log, stderr=subprocess.STDOUT)
                if checked.returncode:
                    log.flush()
                    print((stage / 'parameters-check.log').read_text()[-8000:])
                    raise RuntimeError(f'Проверка параметров/Lua стратегии {row["Number"]} завершилась с кодом {checked.returncode}.')
        shutil.rmtree(unpacked)
        archive.unlink()
        for path in stage.rglob('*'):
            if path.is_file():
                path.chmod(0o755 if path.suffix == '.sh' or path.name == 'macws2' else 0o644)
        (stage / '_state').mkdir(mode=0o700)
        (stage / 'logs').mkdir(mode=0o700)
        for name in ('build.log', 'parameters-check.log', 'source-download.log', 'engine-environment.json'):
            shutil.move(stage / name, stage / 'logs' / name)
        identity = {'schema': 'igareck.zapret2.macos.install.v1', 'version': '1.0', 'prefix': str(prefix),
                    'id': uuid.uuid4().hex, 'upstream_commit': meta['commit'], 'upstream_selection': 'compatible',
                    'shortcuts': None, 'global_command': None,
                    'files': {path.relative_to(stage).as_posix(): digest(path) for path in stage.rglob('*')
                              if path.is_file() and path.relative_to(stage).parts[0] not in ('logs', '_state', '__pycache__')}}
        (stage / 'installation.json').write_text(json.dumps(identity, ensure_ascii=False, indent=2) + '\n')
        if prefix.exists():
            prefix.rmdir()
        stage.chmod(0o755)
        os.replace(stage, prefix)
        complete = True
        if create_desktop:
            shortcuts = None
            try:
                shortcuts = create_shortcuts(desktop_user, prefix, identity['id'])
                identity['shortcuts'] = shortcuts
            except Exception as error:
                identity['shortcuts'] = None
                if shortcuts:
                    remove_shortcuts(shortcuts)
                print('Программа установлена, но создать ярлыки не удалось: ' + str(error))
        command_record = None
        try:
            command_record = register(prefix, identity['id'], command_plan)
            identity['global_command'] = command_record
        except Exception as error:
            identity['global_command'] = None
            if command_record:
                remove_global_command(command_record)
            print('Программа установлена, но создать глобальную команду не удалось: ' + str(error))
        (prefix / 'installation.json').write_text(json.dumps(identity, ensure_ascii=False, indent=2) + '\n')
        installation_summary(prefix, identity['shortcuts'], identity['global_command'])
    finally:
        if not complete:
            saved = Path('/var/log/igareck-zapret2') / ('install_failed_' + time.strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:8])
            try:
                saved.mkdir(parents=True)
                for name in ('build.log', 'parameters-check.log', 'source-download.log', 'engine-environment.json'):
                    if (stage / name).exists():
                        shutil.copy2(stage / name, saved / name)
                print('Логи неудачной установки: ' + str(saved))
            finally:
                shutil.rmtree(stage, ignore_errors=True)
    if not args.no_launch and sys.stdin.isatty():
        subprocess.run([sys.executable, str(prefix / 'igareck.py'), '--skip-intro'], check=False)


def uninstall(args):
    from remove_installation import uninstall as remove
    remove(SOURCE, purge=args.purge, yes=args.yes)


if __name__ == '__main__':
    def terminate(_signal, _frame):
        for item in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
            signal.signal(item, signal.SIG_IGN)
        raise KeyboardInterrupt
    signal.signal(signal.SIGHUP, terminate)
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description='Установка/удаление Igareck CLI macOS 1.0')
    parser.add_argument('action', nargs='?', choices=('install', 'uninstall'), default='install')
    parser.add_argument('--prefix')
    parser.add_argument('--engine', choices=('compatible', 'latest'), default='compatible')
    parser.add_argument('--shortcuts', choices=('yes', 'no'))
    parser.add_argument('--global-command', choices=('yes', 'no'))
    parser.add_argument('--skip-deps', action='store_true')
    parser.add_argument('--no-launch', action='store_true')
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('--purge', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Запустите через sudo bash INSTALL.sh / DELETE.sh.')
    exit_code = 0
    try:
        install(args) if args.action == 'install' else uninstall(args)
    except KeyboardInterrupt:
        print('\nУстановка остановлена.')
        exit_code = 130
    except Exception as error:
        from diagnostics import report_exception
        report_exception(SOURCE, error, 'installer')
        exit_code = 1
    if os.environ.get('IGARECK_TERMINAL_WINDOW') == '1' and sys.stdin.isatty() and args.no_launch and exit_code != 130:
        try:
            input('\nНажмите Enter, чтобы закрыть окно.\n')
        except (EOFError, KeyboardInterrupt):
            pass
    raise SystemExit(exit_code)
