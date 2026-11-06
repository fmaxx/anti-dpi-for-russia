from __future__ import annotations

import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid

LOCK_PATH = '/var/run/igareck-zapret2-public.lock'


def run(argv, **kwargs):
    kwargs.setdefault('env', dict(os.environ, LC_ALL='C'))
    return subprocess.run([str(x) for x in argv], text=True, capture_output=True, timeout=20, **kwargs)


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.chmod(0o600)
    os.replace(temporary, path)


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def process_stamp(pid):
    result = run(['ps', '-p', str(pid), '-o', 'lstart='])
    return result.stdout.strip() if result.returncode == 0 else None


def process_matches(pid, root):
    result = run(['ps', '-p', str(pid), '-o', 'command='])
    expected = str(root / 'engine_guard.py')
    return result.returncode == 0 and expected in result.stdout and str(root / 'engine/macws2') in result.stdout


def port_set(scope):
    from igareck import port_ranges
    return '{ ' + ', '.join(str(a) if a == b else f'{a}:{b}' for a, b in port_ranges(scope)) + ' }'


def pf_rules(anchor, interface, entries, networks, scope='all'):
    if not re.fullmatch(r'com\.apple/igareck_[0-9a-f]{12}', anchor):
        raise ValueError('Некорректный PF-anchor.')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface):
        raise ValueError('Некорректный интерфейс.')
    networks = list(ipaddress.collapse_addresses(ipaddress.IPv4Network(x) for x in networks))
    ports = port_set(scope)
    lines = ['table <excluded> persist { ' + ', '.join(str(n) for n in networks) + ' }',
             'pass quick on lo0 all']
    for entry in entries:
        pflog = entry['pflog']
        if not re.fullmatch(r'pflog(?:[9]|[12][0-9]|3[01])', pflog):
            raise ValueError('Некорректный pflog-интерфейс.')
        source = ''
        reply_source = ''
        if entry.get('ports'):
            source_ports = '{ ' + str(entry['ports'][0]) + ':' + str(entry['ports'][1]) + ' }'
            source = ' port ' + source_ports
            reply_source = ' port ' + source_ports
        lines.append(f'block out log (all, to {pflog}) quick on {interface} inet proto tcp from any{source} to ! <excluded> port {ports} no state')
        lines.append(f'pass in log (all, to {pflog}) on {interface} inet proto tcp from ! <excluded> port {ports} to any{reply_source} flags S/SA no state')
    return '\n'.join(lines) + '\n'


def parse_ifconfig(text):
    items = []
    blocks = re.split(r'(?m)^(?=\S)', text)
    for block in blocks:
        lines = block.splitlines()
        if not lines:
            continue
        match = re.match(r'^([A-Za-z0-9_.-]+): flags=([0-9a-f]+)<([^>]*)>.*? mtu (\d+)', lines[0])
        if not match:
            continue
        name, flags, flag_names, mtu = match.group(1), int(match.group(2), 16), match.group(3), int(match.group(4))
        addresses = re.findall(r'(?m)^\s+inet (\d+\.\d+\.\d+\.\d+) ', block)
        mac = re.search(r'(?m)^\s+ether ([0-9a-f:]+)', block)
        items.append({'name': name, 'index': socket.if_nametoindex(name) if name else 0,
                      'addresses': addresses, 'up': bool(flags & 1), 'running': 'RUNNING' in flag_names,
                      'active': 'status: active' in block, 'mtu': mtu,
                      'mac': mac.group(1) if mac else None})
    return items


def tunnel(name):
    return name.startswith(('utun', 'ipsec', 'ppp', 'gif', 'stf', 'tun', 'tap', 'wg'))


def interfaces():
    result = run(['/sbin/ifconfig', '-a'])
    if result.returncode:
        raise RuntimeError('ifconfig: ' + result.stderr.strip())
    excluded = ('lo', 'awdl', 'llw', 'anpi', 'bridge', 'ap', 'nan')
    return [{'index': item['index'], 'name': item['name'], 'addresses': item['addresses'],
             'description': 'Wi-Fi / Ethernet', 'mtu': item['mtu'], 'mac': item['mac']}
            for item in parse_ifconfig(result.stdout)
            if item['up'] and item['running'] and item['active'] and item['addresses'] and item['mac']
            and not tunnel(item['name']) and not item['name'].startswith(excluded)]


def default_interface(items):
    result = run(['/bin/netstat', '-rn', '-f', 'inet'])
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[0] == 'default' and fields[-1] in {item['name'] for item in items}:
                return fields[-1]
    return items[0]['name'] if items else None


def route_gateway(interface):
    result = run(['/bin/netstat', '-rn', '-f', 'inet'])
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0] == 'default' and fields[-1] == interface and re.fullmatch(r'[0-9.]+', fields[1]):
            return fields[1]
    raise RuntimeError('Не найден IPv4-шлюз для интерфейса ' + interface + '. Выберите физический адаптер с маршрутом по умолчанию.')


def arp_mac(gateway, interface):
    expression = re.compile(r'\?\s+\(' + re.escape(gateway) + r'\)\s+at\s+([0-9a-f:]+)\s+(?:on\s+' + re.escape(interface) + r')?', re.I)
    def lookup():
        result = run(['/usr/sbin/arp', '-n', gateway])
        match = expression.search(result.stdout)
        return match.group(1) if match and 'no entry' not in result.stdout.lower() else None
    cached = lookup()
    if cached:
        return cached
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(1)
            probe.sendto(b'\0', (gateway, 9))
    except OSError:
        pass
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        time.sleep(.1)
        cached = lookup()
        if cached:
            return cached
    raise RuntimeError(f'Не удалось определить MAC шлюза {gateway} на {interface}.')


def choose_interface(session, explicit=None):
    items = interfaces()
    if explicit:
        matches = [item for item in items if item['name'] == explicit]
        if len(matches) != 1:
            raise RuntimeError('Интерфейс не найден среди активных физических IPv4-интерфейсов: ' + explicit)
        session.interface = explicit
        return explicit
    if not items:
        raise RuntimeError('Не найден активный физический IPv4-интерфейс. Проверьте сеть.')
    previous = json.loads(session.config.read_text()).get('name') if session.config.exists() else None
    recommended = default_interface(items)
    default = next(item for item in items if item['name'] == (previous if any(x['name'] == previous for x in items) else recommended))
    import cli_ui
    print(cli_ui.color('\nВыберите активный Интернет-адаптер для работы AntiDPI Стратегий', '96'))
    width = cli_ui.columns()
    adapter_width = min(35, max(12, (width - 18) // 3))
    description_width = max(12, (width - adapter_width - 18) // 2)
    cli_ui.table(['Индекс', 'Адаптер (Up)', 'Описание'],
                 [[str(item['index']), item['name'], item['description'] + '; IPv4: ' + ', '.join(item['addresses'])] for item in items],
                 [6, adapter_width, description_width])
    rec = next(item for item in items if item['name'] == recommended)
    print('Активные индексы: ' + ', '.join(str(item['index']) for item in items) + '. Рекомендуется: ' + str(rec['index']) + '.')
    if previous:
        print('Прошлый выбор: ' + previous + (' (доступен).' if any(item['name'] == previous for item in items) else ' (сейчас недоступен).'))
    print(cli_ui.color('Enter использует прошлый/рекомендуемый адаптер. Либо введите индекс из списка.', '96'))
    while True:
        answer = input(f'Индекс основного адаптера [Enter = {default["index"]}]: ').strip()
        selected = default if not answer else next((item for item in items if str(item['index']) == answer), None)
        if selected is None:
            print('Введите индекс из таблицы.')
            continue
        session.interface = selected['name']
        atomic_json(session.config, {'name': selected['name'], 'index': selected['index']})
        return session.interface


def check_environment(root=None):
    if sys.platform != 'darwin':
        raise RuntimeError('Эта версия предназначена только для macOS.')
    version = run(['/usr/bin/sw_vers', '-productVersion']).stdout.strip().split('.')
    if not version or not version[0].isdigit() or int(version[0]) < 26:
        raise RuntimeError('Требуется macOS 26 или новее.')
    if os.geteuid() != 0:
        raise RuntimeError('Для PF и BPF нужны права root. Запустите START.sh через sudo.')
    for path in ('/sbin/pfctl', '/sbin/ifconfig', '/usr/sbin/arp', '/bin/netstat'):
        if not os.access(path, os.X_OK):
            raise RuntimeError('Не найдена системная утилита: ' + path)
    try:
        fd = os.open('/dev/pf', os.O_RDWR)
        os.close(fd)
    except OSError as error:
        raise RuntimeError('Недоступен /dev/pf: ' + str(error))
    config = Path('/etc/pf.conf').read_text(encoding='utf-8')
    if not re.search(r'(?m)^\s*anchor\s+"com\.apple/\*"', config):
        raise RuntimeError('В /etc/pf.conf нет штатного anchor "com.apple/*". Автоматическое изменение системного файла запрещено.')
    if root is not None:
        atomic_json(Path(root) / 'engine-environment.json', {'platform': 'darwin', 'macos': '.'.join(version), 'pf': True, 'bpf': True})


class Session:
    def __init__(self, root):
        self.root = Path(root).resolve()
        manifest = json.loads((self.root / 'installation.json').read_text())
        if manifest.get('standard_uninstalled'):
            raise RuntimeError('Программа уже удалена. Для полного удаления используйте DELETE.sh --purge.')
        if not re.fullmatch(r'[0-9a-f]{32}', manifest['id']) or Path(manifest['prefix']) != self.root:
            raise RuntimeError('Неверный маркер установки. Запустите INSTALL.sh.')
        self.anchor = 'com.apple/igareck_' + manifest['id'][:12]
        self.journal = self.root / '_state/runtime.json'
        self.config = self.root / '_state/adapter.json'
        self.lock = None
        self.entries = []
        self.processes = {}
        self.pflogs = set()
        self.pf_token = None
        self.active_anchor = False
        self.interface = None
        self.scope = 'all'
        self.stamp = time.strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:8]
        self.logs = self.root / 'logs'
        self.logs.mkdir(exist_ok=True)
        self.networks = [line.strip() for line in (self.root / 'lists/ips-exclude.txt').read_text().splitlines()
                         if line.strip() and not line.startswith('#')]
        self.transport = None

    def __enter__(self):
        check_environment()
        descriptor = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self.lock = os.fdopen(descriptor, 'w')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            raise RuntimeError('Уже работает другая копия macOS-оболочки Igareck. Закройте её сначала.')
        try:
            self.recover()
        except BaseException:
            self.lock.close()
            self.lock = None
            raise
        return self

    def save(self):
        atomic_json(self.journal, {'anchor': self.anchor, 'pf_token': self.pf_token, 'pflogs': sorted(self.pflogs),
                    'engines': [{'pid': process.pid, 'stamp': process_stamp(process.pid)} for process, _ in self.processes.values()]})

    def pfctl(self, *args, input=None):
        return run(['/sbin/pfctl', *args], input=input)

    def flush_anchor(self):
        result = self.pfctl('-a', self.anchor, '-F', 'all')
        if result.returncode and 'No such file or directory' not in result.stderr:
            raise RuntimeError('Не удалось очистить собственный PF-anchor: ' + result.stderr.strip())
        self.active_anchor = False

    def release_pf(self, token=None):
        token = token or self.pf_token
        if token:
            result = self.pfctl('-X', token)
            if result.returncode:
                raise RuntimeError('Не удалось освободить PF-token: ' + result.stderr.strip())
        if token == self.pf_token:
            self.pf_token = None

    def recover(self):
        record = json.loads(self.journal.read_text()) if self.journal.exists() else {'anchor': self.anchor}
        if record['anchor'] != self.anchor:
            raise RuntimeError('Маркер восстановления не принадлежит этой установке.')
        failure = None
        try:
            self.flush_anchor()
        except Exception as error:
            failure = error
        for item in record.get('engines', []):
            pid = item['pid']
            if item.get('stamp') and process_stamp(pid) == item['stamp'] and process_matches(pid, self.root):
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for pflog in set(record.get('pflogs', [])) | self.pflogs:
            if re.fullmatch(r'pflog(?:[9]|[12][0-9]|3[01])', pflog):
                run(['/sbin/ifconfig', pflog, 'destroy'])
        self.pflogs.clear()
        try:
            self.release_pf(record.get('pf_token'))
        except Exception as error:
            failure = failure or error
        if failure:
            self.save()
            raise failure
        self.journal.unlink(missing_ok=True)

    def enable_pf(self):
        if self.pf_token:
            return
        result = self.pfctl('-E')
        match = re.search(r'(?m)^\s*Token\s*:\s*(\d+)\s*$', result.stdout + '\n' + result.stderr)
        if result.returncode or not match:
            raise RuntimeError('pfctl -E: ' + (result.stderr or result.stdout).strip())
        self.pf_token = match.group(1)
        self.save()

    def apply(self):
        if not self.entries:
            if self.active_anchor or self.journal.exists():
                self.flush_anchor()
            return
        self.enable_pf()
        rules = pf_rules(self.anchor, self.interface, self.entries, self.networks, self.scope)
        (getattr(self, 'scan_logs', self.logs) / ('pf_' + self.stamp + '.conf')).write_text(rules)
        self.save()
        checked = self.pfctl('-a', self.anchor, '-n', '-f', '-', input=rules)
        if checked.returncode:
            raise RuntimeError('PF: ' + (checked.stderr or checked.stdout).strip())
        result = self.pfctl('-a', self.anchor, '-f', '-', input=rules)
        if result.returncode:
            raise RuntimeError('PF: ' + (result.stderr or result.stdout).strip())
        self.active_anchor = True

    def create_pflog(self):
        for number in range(9, 32):
            name = 'pflog' + str(number)
            if name in self.pflogs:
                continue
            created = run(['/sbin/ifconfig', name, 'create'])
            if created.returncode:
                continue
            up = run(['/sbin/ifconfig', name, 'up'])
            if up.returncode:
                run(['/sbin/ifconfig', name, 'destroy'])
                raise RuntimeError('Не удалось активировать ' + name + ': ' + up.stderr.strip())
            self.pflogs.add(name)
            self.save()
            return name
        raise RuntimeError('Не найден свободный pflog-интерфейс в диапазоне 9–31.')

    def transport_environment(self, pflog):
        if not self.transport:
            item = next(item for item in interfaces() if item['name'] == self.interface)
            gateway = route_gateway(self.interface)
            self.transport = {'mtu': item['mtu'], 'source': item['mac'], 'gateway': arp_mac(gateway, self.interface)}
        return dict(os.environ, IGARECK_DARWIN_IFACE=self.interface, IGARECK_DARWIN_PFLOG=pflog,
                    IGARECK_DARWIN_SRC_MAC=self.transport['source'], IGARECK_DARWIN_DST_MAC=self.transport['gateway'],
                    IGARECK_DARWIN_MTU=str(self.transport['mtu']), IGARECK_DARWIN_ANCHOR=self.anchor,
                    IGARECK_DARWIN_PF_TOKEN=self.pf_token or '')

    def start(self, row, ports=None):
        from igareck import engine_arguments
        queue = next(number for number in range(24000, 25000) if number not in self.processes)
        log_path = getattr(self, 'scan_logs', self.logs) / f'macws2_{self.stamp}_p{row["Number"]}_{queue}.log'
        argv = engine_arguments(self.root, row, queue, self.scope)
        checked = run(argv + ['--dry-run'])
        if checked.returncode:
            log_path.write_text(checked.stdout + checked.stderr)
            raise RuntimeError(f'Проверка параметров/Lua стратегии {row["Number"]}: macws2 завершился с кодом {checked.returncode}. Лог: {log_path}')
        pflog = self.create_pflog()
        self.enable_pf()
        environment = self.transport_environment(pflog)
        stream = log_path.open('w')
        stream.write(shlex.join(argv) + '\n')
        stream.flush()
        process = subprocess.Popen([sys.executable, str(self.root / 'engine_guard.py'), str(os.getpid())] + argv,
                                   cwd=self.root / 'engine', env=environment, stdout=stream, stderr=subprocess.STDOUT)
        self.processes[queue] = (process, stream)
        self.save()
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f'macws2 завершился, код {process.returncode}. Лог: {log_path}')
                if log_path.exists() and 'PFLOG_READY ' + pflog in log_path.read_text(errors='replace'):
                    break
                time.sleep(.05)
            else:
                raise RuntimeError('pflog/BPF не открылся за 10 секунд. Лог: ' + str(log_path))
            self.entries.append({'queue': queue, 'ports': ports, 'number': row['Number'], 'pflog': pflog})
            self.apply()
            return queue
        except BaseException:
            self.stop(queue)
            raise

    def stop(self, queue):
        self.entries = [entry for entry in self.entries if entry['queue'] != queue]
        try:
            self.apply()
        finally:
            if queue in self.processes:
                process, stream = self.processes.pop(queue)
                stop_process(process)
                stream.close()
            owned = {entry['pflog'] for entry in self.entries}
            for pflog in list(self.pflogs - owned):
                run(['/sbin/ifconfig', pflog, 'destroy'])
                self.pflogs.remove(pflog)
            self.save()

    def close(self):
        failure = None
        for queue in list(self.processes):
            try:
                self.stop(queue)
            except Exception as error:
                failure = error
        try:
            self.recover()
        except Exception as error:
            failure = failure or error
        if self.lock:
            self.lock.close()
            self.lock = None
        if failure:
            print('Не завершена очистка; запустите START.sh recover. ' + str(failure), file=sys.stderr)

    def __exit__(self, *_):
        self.close()
