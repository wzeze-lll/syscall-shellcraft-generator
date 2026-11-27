#!/usr/bin/env python3
"""Export a static ELF profile for PwnWorkbench; never starts the target."""
import argparse
import contextlib
import hashlib
import json
import sys
from pathlib import Path


def inspect(path):
    from pwnlib.context import context
    from pwnlib.elf.elf import ELF

    with path.open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            raise ValueError('输入不是 ELF 文件（PE / Mach-O 不适用）')
        stream.seek(0)
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    # Do not use ELF.libs / ELF.maps: those can execute the target.
    with context.local(log_level='error'), contextlib.redirect_stdout(sys.stderr):
        elf = ELF(str(path), checksec=False)
        try:
            if elf.arch not in ('amd64', 'i386') or elf.endian != 'little':
                raise ValueError('工作台目前只支持小端 amd64 / i386 ELF')
            return {
                'format': 'pwnworkbench.elf.v1',
                'binary': './' + path.name,
                'sha256': digest.hexdigest(),
                'arch': elf.arch,
                'security': {'pie': bool(elf.pie), 'canary': bool(elf.canary),
                             'nx': elf.nx, 'relro': elf.relro},
                'functions': sorted(elf.functions)[:512],
                'plt': sorted(elf.plt),
                'got': sorted(elf.got),
                'note': '静态符号和保护信息；不包含实测 offset、运行时基址或 gadget。'
            }
        finally:
            elf.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path, help='local amd64 / i386 ELF')
    args = parser.parse_args()
    try:
        profile = inspect(args.binary)
    except ImportError:
        parser.exit(2, '请先安装检查工具依赖：python3 -m pip install -r requirements.txt\n')
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(profile, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
