from pathlib import Path

FILE_LAYOUT = {
    'igareck.py': 'app/igareck.py',
    'darwin_session.py': 'app/darwin_session.py',
    'diagnostics.py': 'app/diagnostics.py',
    'dependencies.py': 'app/dependencies.py',
    'install.py': 'app/install.py',
    'remove_installation.py': 'app/remove_installation.py',
    'cli_ui.py': 'app/cli_ui.py',
    'desktop_integration.py': 'app/desktop_integration.py',
    'global_command.py': 'app/global_command.py',
    'engine_guard.py': 'app/engine_guard.py',
    'source_download.py': 'app/source_download.py',
    'youtube_probe.py': 'app/youtube_probe.py',
    'app_paths.py': 'app/app_paths.py',
    'INSTALL.sh': 'INSTALL.sh',
    'START.sh': 'START.sh',
    'DELETE.sh': 'DELETE.sh',
    'LICENSE.txt': 'LICENSE.txt',
    'README_Установка_macOS_v1.0.txt': 'README_Установка_macOS_v1.0.txt',
    'README_Стратегии_macOS_v1.0.txt': 'README_Стратегии_macOS_v1.0.txt',
    'catalogue.json': 'data/catalogue.json',
    'release.json': 'data/release.json',
    'upstream.json': 'data/upstream.json',
    'actual_tls_guard.lua': 'data/actual_tls_guard.lua',
    'lists/ips-exclude.txt': 'data/lists/ips-exclude.txt',
    'darwin.c': 'engine/darwin.c',
    'darwin.h': 'engine/darwin.h',
    'zapret2-darwin.patch': 'engine/zapret2-darwin.patch',
}


def resource_path(root, name):
    root = Path(root).resolve()
    if name not in FILE_LAYOUT:
        raise ValueError('Unknown application resource: ' + name)
    direct = root / name
    if direct.is_file():
        return direct
    if root.name == 'app' and (root.parent / 'INSTALL.sh').is_file():
        root = root.parent
    return root / FILE_LAYOUT[name]
