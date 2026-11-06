from __future__ import annotations
import os
from pathlib import Path
import platform
import shutil
import sys
import textwrap
import unicodedata
from app_paths import resource_path

VERSION = 'CLI Version 1.0'
SEPARATOR = '----------------------'


def color(text, code='93'):
    return '\033[' + code + 'm' + text + '\033[0m' if sys.stdout.isatty() and 'NO_COLOR' not in os.environ else text


def columns():
    try:
        return max(40, os.get_terminal_size(sys.stdout.fileno()).columns)
    except (OSError, AttributeError):
        return max(40, shutil.get_terminal_size((100, 24)).columns)


def cell_width(text):
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1 for c in str(text))


def wrap(text, width):
    parts = []
    for line in str(text).splitlines() or ['']:
        parts.extend(textwrap.wrap(line, width=max(1, width), break_long_words=True, break_on_hyphens=False) or [''])
    return parts


def table(headers, rows, widths):
    border = '+' + '+'.join('-' * (w + 2) for w in widths) + '+'
    print(border)

    def emit(values, heading=False):
        cells = [wrap(value, w) for value, w in zip(values, widths)]
        for i in range(max(map(len, cells))):
            line = '|'
            for parts, w in zip(cells, widths):
                item = parts[i] if i < len(parts) else ''
                line += ' ' + item + ' ' * (w - cell_width(item) + 1) + '|'
            print(color(line, '96') if heading else line)

    emit(headers, True)
    print(border)
    for row in rows:
        emit(row)
        print(border)


def paragraphs(lines, code=None):
    for line in lines:
        print(color(str(line), code) if code else str(line))


def show_header(root):
    architecture = 'ARM64' if platform.machine().lower() == 'arm64' else 'x64'
    rule = '=' * min(79, columns())
    paragraphs([
        rule,
        '  Igareck AntiDPI Strategies + Bol-Van Zapret2',
        '  ' + VERSION + ' | macOS 26+ ' + architecture,
        rule,
        '  ПРОГРАММА ГОТОВЫХ ANTI-DPI СТРАТЕГИЙ ОТ IGARECK НА БАЗЕ ZAPRET2 (BOL-VAN)',
        '  В УДОБНОЙ CLI ОБОЛОЧКЕ ДЛЯ РАБОТЫ ЧЕРНЫХ СПИСКОВ VPN/TOR + YOUTUBE',
        rule,
        '  https://github.com/igareck/anti-dpi-for-russia',
        '  https://github.com/bol-van/zapret2',
        '  Telegram: https://t.me/igareq',
        rule,
        '  macOS-транспорт: PF/pflog + BPF; исходный nfqws2 адаптируется при установке.',
        rule,
    ], '96')


def pause(message):
    if sys.stdin.isatty() and sys.stdout.isatty():
        input('\n' + SEPARATOR + '\n\n' + message + '\n')


def show_intro(root, prefix=None, installing=False):
    show_header(root)
    destination = 'папка, которую вы выберете далее' if installing else str(prefix or root)
    engine_path = '<выбранная папка>/engine/macws2' if installing else str((prefix or root) / 'engine/macws2')
    paragraphs([
        '', 'ВНИМАНИЕ!',
        '1. Программа использует root, PF и BPF. SIP отключать не требуется.',
        '2. Правила загружаются только в собственный anchor com.apple/igareck_*; /etc/pf.conf не изменяется.',
        '3. Папка программы: ' + destination,
        '   Движок: ' + engine_path,
        '4. Полный VPN-туннель может направлять трафик мимо физического адаптера. Для проверки YouTube отключите VPN/TUN.',
        '5. Не запускайте одновременно другие средства, изменяющие те же PF-правила.',
    ], '93')
    pause('Нажмите Enter, чтобы продолжить и прочитать ЗАМЕТКИ')
    paragraphs([
        '', 'ЗАМЕТКИ:',
        '1. Программа разработана для восстановления работоспособности VPN-конфигураций Черных Списков, Tor и YouTube.',
        '2. Пробуйте стратегии поочерёдно и проверяйте подписки/мосты в своём клиенте.',
        '3. Успех YouTube не гарантирует успех VPN, и наоборот: это разные проверки.',
        '4. Golden для VPN/Tor/YouTube могут работать лучше, чем Silver.',
        '5. Результат зависит от сети и ТСПУ; локальная проверка параметров не заменяет проверку в реальной сети.',
    ], '93')
    pause('Нажмите Enter, чтобы продолжить установку' if installing else 'Нажмите Enter, чтобы продолжить работу')


def catalogue(data):
    print('\n######################\n')
    paragraphs([
        'КАТАЛОГ: Golden+Silver; 484 уникальные AntiDPI стратегии.',
        'Golden: 1–45 (45). Silver: 46–484 (439).',
    ], '96')
    print('\n' + SEPARATOR + '\n\nВводите номер стратегии из колонки «Номера».')
    family_width = max(10, min(65, columns() - 40))
    rows = []
    for family in data['FamilyRows']:
        group, name = family['Name'].split(' / ', 1)
        numbers = str(family['First']) if family['First'] == family['Last'] else f'{family["First"]}–{family["Last"]}'
        rows.append([family['Number'], group, name, family['Count'], numbers])
    table(['#', 'Набор', 'Семейство', 'Кол.', 'Номера'], rows, [2, 6, family_width, 4, 7])


def selection_prompt():
    print('\n' + color('Выберите один из двух вариантов.', '96'))
    paragraphs([
        '1. Либо введите номер AntiDPI-стратегии из таблицы (0 — выход из программы)',
        '2. Либо введите "Youtube" для автоматической проверки стратегий',
    ])
    print(SEPARATOR)
    return input('Ваш выбор: ').strip()
