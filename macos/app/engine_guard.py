#!/usr/bin/env python3
import os
import signal
import subprocess
import sys
import time


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def orphan_cleanup():
    anchor = os.environ.get('IGARECK_DARWIN_ANCHOR', '')
    pflog = os.environ.get('IGARECK_DARWIN_PFLOG', '')
    token = os.environ.get('IGARECK_DARWIN_PF_TOKEN', '')
    if anchor.startswith('com.apple/igareck_'):
        subprocess.run(['/sbin/pfctl', '-a', anchor, '-F', 'all'], capture_output=True)
    if pflog.startswith('pflog'):
        subprocess.run(['/sbin/ifconfig', pflog, 'destroy'], capture_output=True)
    if token.isdigit():
        subprocess.run(['/sbin/pfctl', '-X', token], capture_output=True)


def main():
    parent = int(sys.argv[1])
    process = subprocess.Popen(sys.argv[2:])
    stopping = False

    def terminate(_signal, _frame):
        nonlocal stopping
        stopping = True
        stop(process)

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    signal.signal(signal.SIGHUP, terminate)
    while process.poll() is None:
        if os.getppid() != parent:
            stop(process)
            orphan_cleanup()
            return 1
        if stopping:
            break
        time.sleep(.1)
    return process.wait()


if __name__ == '__main__':
    raise SystemExit(main())
