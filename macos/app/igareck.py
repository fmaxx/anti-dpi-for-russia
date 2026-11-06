#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import re
import select
from queue import SimpleQueue, Empty
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import termios
import threading
import time
import tty
from urllib.parse import urljoin

import cli_ui
from app_paths import resource_path
from darwin_session import Session, atomic_json, choose_interface, run, stop_process

ROOT = Path(__file__).resolve().parent
PACKETS = 32
THRESHOLD = 100 * 1024
VERSION = cli_ui.VERSION


def load_catalogue(root=ROOT):
    data = json.loads(resource_path(root, 'catalogue.json').read_text(encoding='utf-8'))
    rows, families = data['ProfileRows'], data['FamilyRows']
    if [row['Number'] for row in rows] != list(range(1, 485)) or len(families) != 23:
        raise RuntimeError('Повреждён каталог: ожидаются 484 стратегии и 23 семейства.')
    for family in families:
        group = [row for row in rows if row['Family'] == family['Number']]
        if len(group) != family['Count'] or [row['Number'] for row in group] != list(range(family['First'], family['Last'] + 1)):
            raise RuntimeError('Повреждены границы семейства.')
    return data


def recipe_range(value):
    match = re.fullmatch(r'\s*(\d+)(?:\s*-\s*(\d+))?\s*', value)
    if not match:
        raise ValueError('Введите номер или диапазон, например 1-50.')
    first, last = int(match[1]), int(match[2] or match[1])
    if not 1 <= first <= last <= 484:
        raise ValueError('Допустимые номера: 1–484.')
    return list(range(first, last + 1))


def port_ranges(value):
    value = str(value).strip().casefold()
    if value in ('', 'all', 'все'):
        return [(0, 65535)]
    value = value.replace('–', '-').replace('—', '-')
    ranges = []
    for part in value.split(','):
        match = re.fullmatch(r'\s*([0-9]{1,5})(?:\s*-\s*([0-9]{1,5}))?\s*', part)
        if not match:
            raise ValueError('Введите порты 0–65535, диапазоны, комбинацию через запятую или все/all.')
        first, last = int(match[1]), int(match[2] or match[1])
        if not 0 <= first <= last <= 65535:
            raise ValueError('Порты: 0–65535; начало диапазона не должно быть больше конца.')
        ranges.append((first, last))
    merged = []
    for first, last in sorted(ranges):
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(last, merged[-1][1]))
        else:
            merged.append((first, last))
    return merged


def parse_ports(value):
    ranges = port_ranges(value)
    if ranges == [(0, 65535)]:
        return 'all'
    return ','.join(str(a) if a == b else f'{a}-{b}' for a, b in ranges)


def choose_ports(session, explicit=None):
    if explicit is not None:
        session.scope = parse_ports(explicit)
        return session.scope
    print('\n----------------------\n')
    print(cli_ui.color('Выберите порты назначения TCP, трафик которых будет перехватываться Zapret2.', '96'))
    cli_ui.paragraphs(['', 'Либо определенный номер порта, например 443, 80 и т.д.',
        'Либо диапазон, например 0–1023',
        'Либо комбинацию через запятую: 53, 80, 443, 1000-2000',
        'Либо "все/all" для любых TCP-портов (нужно для подписок VPN).', ''])
    while True:
        answer = input('Ваш выбор [Enter = все порты]: ')
        try:
            session.scope = parse_ports(answer)
            print()
            return session.scope
        except ValueError as error:
            print(error)


def engine_arguments(root, row, queue=20000, scope='all'):
    engine = Path(root) / 'engine'
    args = [str(engine / 'macws2'), '--port=1',
            '--lua-init=@' + str(engine / 'lua/zapret-lib.lua'),
            '--lua-init=@' + str(engine / 'lua/zapret-antidpi.lua')]
    if any(a.startswith('--lua-desync=fake:') and 'blob=reasm_data' in a and ':tls_mod=' in a for a in row['Args']):
        args.append('--lua-init=@' + str(Path(root) / 'actual_tls_guard.lua'))
    if row['Init']:
        args.append('--lua-init=' + row['Init'])
    scope = parse_ports(scope)
    args += ['--filter-tcp=' + ('0-65535' if scope == 'all' else scope), '--filter-l7=tls',
             '--ipset-exclude=' + str(Path(root) / 'lists/ips-exclude.txt')]
    return args + row['Args']


class Keyboard:
    def __enter__(self):
        self.old = termios.tcgetattr(sys.stdin) if sys.stdin.isatty() else None
        if self.old:
            tty.setcbreak(sys.stdin.fileno())
        return self

    def key(self, timeout=.1):
        if not self.old:
            time.sleep(timeout)
            return None
        if not select.select([sys.stdin], [], [], timeout)[0]:
            return None
        value = os.read(sys.stdin.fileno(), 32).decode(errors='ignore')
        if value == '\x1b' and select.select([sys.stdin], [], [], .06)[0]:
            value += os.read(sys.stdin.fileno(), 32).decode(errors='ignore')
        return {'\x1bOP': 'switch', '\x1b[11~': 'switch', 's': 'switch',
                '\x1bOQ': 'restart', '\x1b[12~': 'restart', 'r': 'restart',
                '\x1bOR': 'adapter', '\x1b[13~': 'adapter', 'i': 'adapter',
                'q': 'quit', '\x1b': 'escape'}.get(value)

    def __exit__(self, *_):
        if self.old:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old)


def colored(text, code='93'):
    return cli_ui.color(text, code)


def show_table(data):
    cli_ui.catalogue(data)


def activate(session, row):
    queue = session.start(row)
    try:
        print(f'\n{"Golden" if row["Number"] <= 45 else "Silver"} #{row["Number"]}: {row["Name"]}')
        print('Интерфейс: ' + session.interface + '; IPv4 TLS/TCP; порты ' + session.scope)
        print(colored(f'\nСЕЙЧАС РАБОТАЕТ СТРАТЕГИЯ {row["Number"]}!\n\n'
                      'ЧТОБЫ СМЕНИТЬ СТРАТЕГИЮ — нажмите F1 (или s)\n'
                      'ЧТОБЫ ПЕРЕЗАГРУЗИТЬ ТЕКУЩУЮ СТРАТЕГИЮ — нажмите F2 (или r)\n'
                      'ЧТОБЫ СМЕНИТЬ СЕТЕВОЙ АДАПТЕР/ПОРТ — нажмите F3 (или i)\n'
                      'ЧТОБЫ ПОЛНОСТЬЮ ОСТАНОВИТЬ РАБОТУ AntiDPI/ZAPRET2 - нажмите CTRL+C (или q)'))
        with Keyboard() as keyboard:
            while True:
                if session.processes[queue][0].poll() is not None:
                    raise RuntimeError('macws2 завершился. Проверьте logs/macws2_*.log.')
                key = keyboard.key()
                if key in ('switch', 'restart', 'adapter', 'quit'):
                    return key
    finally:
        session.stop(queue)


def final_headers(raw, initial):
    status, headers, effective = 0, {}, initial
    for block in re.split(rb'\r?\n\r?\n', raw):
        lines = block.decode('iso-8859-1').splitlines()
        if not lines or not lines[0].startswith('HTTP/'):
            continue
        fields = lines[0].split()
        if len(fields) < 2 or not fields[1].isdigit():
            continue
        status = int(fields[1])
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                name, value = line.split(':', 1)
                headers[name.lower()] = value.strip()
        if 300 <= status < 400 and headers.get('location'):
            effective = urljoin(effective, headers['location'])
    return status, headers, effective


def queue_snapshot(queue):
    return {}


def youtube_attempt(session, ports, number, attempt, stop):
    directory = getattr(session, 'scan_logs', session.logs)
    base = directory / f'YouTube_p{number:04}_r{attempt}'
    request_path = base.with_suffix('.request.json')
    error_path = base.with_suffix('.stderr')
    result_path = base.with_suffix('.result.json')
    atomic_json(request_path, {'interface': session.interface, 'ports': ports, 'timeout': 25})
    argv = [sys.executable, str(session.root / 'engine_guard.py'), str(os.getpid()), sys.executable, '-B',
            str(session.root / 'youtube_probe.py'), str(request_path)]
    started = time.monotonic()
    queue = next((entry['queue'] for entry in session.entries if entry['number'] == number), None)
    with error_path.open('wb') as errors:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=errors)
        try:
            while process.poll() is None and not stop.is_set() and time.monotonic() - started < 28:
                time.sleep(.05)
            if process.poll() is None:
                stop_process(process)
                result = {'pass': False, 'bytes': 0, 'http': 0,
                          'reason': 'CANCELLED' if stop.is_set() else 'TIMEOUT',
                          'seconds': round(time.monotonic() - started, 3), 'technical': False}
                process.communicate()
            else:
                output, _ = process.communicate()
                try:
                    result = json.loads(output.decode('utf-8'))
                    if not isinstance(result, dict) or 'pass' not in result:
                        raise ValueError('Некорректный результат')
                except (ValueError, UnicodeDecodeError) as error:
                    result = {'pass': False, 'technical': True, 'bytes': 0, 'http': 0, 'reason': 'PROBE_PROCESS_ERROR',
                              'error': str(error) + '; ' + error_path.read_text(errors='replace')[-2000:],
                              'exit_code': process.returncode}
        finally:
            stop_process(process)
            if process.stdout is not None:
                process.stdout.close()
    result.update(number=number, attempt=attempt, ports=list(ports), queue=queue)
    atomic_json(result_path, result)
    if result.get('technical'):
        raise RuntimeError('Техническая ошибка проверки YouTube: ' + result['reason'] + '; ' +
                           result.get('error', '') + '. Лог: ' + str(result_path))
    return result


def reserve_ports(excluded=()):
    for first in range(10000, 30000, 64):
        if (first, first + 63) in excluded:
            continue
        held = []
        try:
            for port in range(first, first + 64):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                held.append(sock)
                sock.bind(('0.0.0.0', port))
            return first, first + 63
        except OSError:
            pass
        finally:
            for sock in held:
                sock.close()
    raise RuntimeError('Не найден блок свободных TCP-портов.')


def scan(session, rows, numbers, parallel):
    if not 1 <= parallel <= 5:
        raise ValueError('Число параллелей должно быть от 1 до 5.')
    if not any(a <= 443 <= b for a, b in port_ranges(getattr(session, 'scope', 'all'))):
        print('Проверка YouTube требует TCP-порт 443; выбранные порты его не включают.')
        return []
    print('Перед проверкой выключите VPN/TUN. Для остановки нажмите Esc.\n----------------------')
    numbers = list(numbers)
    session.scan_logs = session.logs / ('YouTube_' + session.stamp + '_' + uuid.uuid4().hex[:6])
    session.scan_logs.mkdir(mode=0o700)
    atomic_json(session.scan_logs / 'scan.json', {'version': VERSION, 'interface': session.interface,
                'numbers': numbers, 'parallel': parallel, 'threshold': THRESHOLD,
                'backend': 'Python SSL, IPv4, HTTP/1.1; macOS PF/pflog + BPF'})
    stop = threading.Event()
    found = []
    pending = iter(numbers)
    jobs = {}
    used = set()
    finished = SimpleQueue()
    log = session.scan_logs / 'results.jsonl'
    completed = 0
    interrupted = False

    def worker(number, ports):
        results = []
        for attempt in (1, 2):
            if stop.is_set():
                break
            results.append(youtube_attempt(session, ports, number, attempt, stop))
        return results

    def emit(number, results):
        nonlocal completed
        successes = sum(result['pass'] for result in results)
        status = ('PASS' if successes == 2 else 'UNSTABLE' if successes else 'CANCELLED'
                  if not results or any(result.get('reason') == 'CANCELLED' for result in results) else 'FAIL')
        with log.open('a', encoding='utf-8') as file:
            file.write(json.dumps({'number': number, 'status': status, 'attempts': results}, ensure_ascii=False) + '\n')
        completed += 1
        if successes:
            print(cli_ui.color((', ' if found else '') + f'{number} ({status})', '92'), end='', flush=True)
            found.append(number)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as pool, Keyboard() as keyboard:
            try:
                while True:
                    while not stop.is_set() and len(jobs) < parallel:
                        number = next(pending, None)
                        if number is None:
                            break
                        ports = reserve_ports(used)
                        queue = session.start(rows[number], ports)
                        used.add(ports)
                        future = pool.submit(worker, number, ports)
                        jobs[future] = (number, queue, ports)
                        future.add_done_callback(finished.put)
                    if not jobs:
                        break
                    if keyboard.key(.08) in ('escape', 'quit'):
                        interrupted = True
                        stop.set()
                    while True:
                        try:
                            future = finished.get_nowait()
                        except Empty:
                            break
                        if future not in jobs:
                            continue
                        number, queue, ports = jobs.pop(future)
                        try:
                            emit(number, future.result())
                        finally:
                            session.stop(queue)
                            used.remove(ports)
                    for number, queue, ports in jobs.values():
                        if session.processes[queue][0].poll() is not None:
                            raise RuntimeError(f'macws2 стратегии {number} завершился; проверка остановлена, см. логи.')
            finally:
                stop.set()
                cleanup_error = None
                for future, (number, queue, ports) in list(jobs.items()):
                    try:
                        emit(number, future.result(timeout=8))
                    except Exception as error:
                        cleanup_error = error
                    finally:
                        try:
                            session.stop(queue)
                        except Exception as error:
                            cleanup_error = error
                if cleanup_error is not None and sys.exc_info()[0] is None:
                    raise cleanup_error
    except BaseException as error:
        atomic_json(session.scan_logs / 'technical_error.json', {'error': str(error), 'type': type(error).__name__})
        raise
    finally:
        atomic_json(session.scan_logs / 'summary.json', {'requested': len(numbers), 'completed': completed,
                    'interrupted': interrupted, 'found': found})
        shutil.make_archive(str(session.scan_logs), 'zip', str(session.scan_logs))
        print()
        del session.scan_logs
    if not found:
        if interrupted:
            print('Проверка остановлена пользователем.')
        print('Рабочие стратегии не найдены')
    print('----------------------')
    return found


def ask_parallel():
    while True:
        answer = input('Параллельная проверка: введите число одновременно проверяемых стратегий [от 1 до 5]: ').strip()
        if answer in ('1', '2', '3', '4', '5'):
            return int(answer)


def main():
    parser = argparse.ArgumentParser(description='Igareck + Zapret2 CLI 1.0 — macOS 26+')
    parser.add_argument('action', nargs='?', default='menu', choices=('menu', 'start', 'youtube', 'list', 'show', 'check-engine', 'recover'))
    parser.add_argument('--skip-intro', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--strategy', type=int)
    parser.add_argument('--interface')
    parser.add_argument('--recipes', default='1-484')
    parser.add_argument('--parallel', type=int, choices=range(1, 6))
    parser.add_argument('--scope', type=parse_ports, help='TCP-порты: all/все, 443, 0-1023 или 53,80,443,1000-2000')
    args = parser.parse_args()
    data = load_catalogue()
    rows = {row['Number']: row for row in data['ProfileRows']}
    if args.action == 'list':
        show_table(data)
        return
    if args.action == 'show':
        if args.strategy not in rows:
            parser.error('Укажите --strategy от 1 до 484.')
        print(json.dumps(rows[args.strategy], ensure_ascii=False, indent=2))
        return
    if args.action == 'check-engine':
        for number in recipe_range(args.recipes):
            result = run(engine_arguments(ROOT, rows[number]) + ['--dry-run'])
            if result.returncode:
                raise RuntimeError(f'Стратегия {number}: ' + result.stdout + result.stderr)
        print('Параметры всех выбранных стратегий приняты macws2.')
        return
    if args.action != 'recover' and not args.skip_intro:
        cli_ui.show_intro(ROOT)
    with Session(ROOT) as session:
        if args.action == 'recover':
            print('Собственные оставшиеся PF-правила, процессы и pflog-интерфейсы удалены.')
            return
        choose_interface(session, args.interface)
        choose_ports(session, args.scope if args.scope is not None else 'all' if not sys.stdin.isatty() else None)
        if args.action == 'youtube':
            scan(session, rows, recipe_range(args.recipes), args.parallel or ask_parallel())
            return
        show_table(data)
        number = args.strategy
        while True:
            if number is None:
                answer = cli_ui.selection_prompt()
                if answer == '0':
                    return
                if answer.lower() == 'youtube':
                    try:
                        numbers = recipe_range(input('Введите номер стратегии или диапазон (например 1-50): '))
                    except ValueError as error:
                        print(error)
                        continue
                    scan(session, rows, numbers, ask_parallel())
                    continue
                number = int(answer) if answer.isdigit() else None
            if number not in rows:
                if args.action == 'start':
                    parser.error('Укажите --strategy от 1 до 484.')
                print('Допустимые номера: 1–484.')
                number = None
                continue
            key = activate(session, rows[number])
            if key == 'quit':
                return
            if key == 'restart':
                print(f'\nПЕРЕЗАГРУЗКА СТРАТЕГИИ {number}...')
                continue
            print(colored(f'\nСТРАТЕГИЯ {number} ОСТАНОВЛЕНА!\n', '91'))
            if key == 'adapter':
                choose_interface(session)
                session.transport = None
                choose_ports(session)
                continue
            number = None


if __name__ == '__main__':
    def terminate(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGHUP, terminate)
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print('\nZapret2 остановлен.')
    except Exception as error:
        from diagnostics import report_exception
        report_exception(ROOT, error, 'runtime')
        if os.environ.get('IGARECK_TERMINAL_WINDOW') == '1' and sys.stdin.isatty():
            try:
                input('\nНажмите Enter, чтобы закрыть окно.\n')
            except (EOFError, KeyboardInterrupt):
                pass
        raise SystemExit(1)
