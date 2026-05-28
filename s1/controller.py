#!/usr/bin/env python3
"""
P4 DNS Monitor Controller
Reads BMv2 registers via simple_switch_CLI and displays live DNS telemetry.

Usage:
  python3 controller.py                          # live dashboard (5s refresh)
  python3 controller.py --once                   # one-shot stats print
  python3 controller.py --block-qtype 15         # block MX queries
  python3 controller.py --block-qtype 28         # block AAAA queries
  python3 controller.py --clear --block-qtype 1  # replace block rule
  python3 controller.py --clear                  # remove all block rules
  python3 controller.py --show-blocked           # show dropped packet counts by QTYPE
  python3 controller.py --list-rules             # list currently configured block rules
"""

import argparse
import re
import subprocess
import time

# DNS QTYPE number -> human-readable name mapping
QTYPE_NAMES = {
    1:   'A',
    2:   'NS',
    5:   'CNAME',
    6:   'SOA',
    12:  'PTR',
    15:  'MX',
    16:  'TXT',
    28:  'AAAA',
    33:  'SRV',
    255: 'ANY',
}

# QTYPEs we show in the dashboard (all fit in the 256-entry register)
DISPLAY_QTYPES = [1, 2, 5, 6, 12, 15, 16, 28, 33, 255]


def _cli(cmd: str, thrift_port: int) -> str:
    """Send one or more newline-separated commands to simple_switch_CLI."""
    result = subprocess.run(
        ['simple_switch_CLI', '--thrift-port', str(thrift_port)],
        input=cmd + '\n',
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout + result.stderr


def read_register(name: str, index: int, thrift_port: int) -> int:
    out = _cli(f'register_read {name} {index}', thrift_port)
    m = re.search(r'\[\s*\d+\s*\]=\s*(\d+)', out)
    return int(m.group(1)) if m else 0


def read_register_batch(name: str, indices: list, thrift_port: int) -> dict:
    """Read multiple register indices in one CLI call. Returns {index: value}."""
    cmd = '\n'.join(f'register_read {name} {i}' for i in indices)
    out = _cli(cmd, thrift_port)
    values = {}
    for m in re.finditer(r'\[\s*(\d+)\s*\]=\s*(\d+)', out):
        values[int(m.group(1))] = int(m.group(2))
    return values


def print_stats(thrift_port: int) -> None:
    separator = '=' * 52

    # QR counters
    qr = read_register_batch('qr_counter', [0, 1], thrift_port)
    queries   = qr.get(0, 0)
    responses = qr.get(1, 0)

    # QTYPE counters
    qt = read_register_batch('qtype_counter', DISPLAY_QTYPES, thrift_port)

    # Client counters (only non-zero entries, indices 1-254 for 10.0.0.X)
    client_indices = list(range(1, 255))
    cl = read_register_batch('client_counter', client_indices, thrift_port)
    active_clients = {i: v for i, v in cl.items() if v > 0}

    # --- Print dashboard ---
    print(f'\n{separator}')
    print(f'  DNS Monitor  [{time.strftime("%Y-%m-%d %H:%M:%S")}]')
    print(separator)
    print(f'  Total Queries  : {queries}')
    print(f'  Total Responses: {responses}')

    print(f'\n  {"QTYPE":<6} {"Name":<8} {"Count":>10}')
    print(f'  {"-" * 26}')
    for qt_num in DISPLAY_QTYPES:
        count = qt.get(qt_num, 0)
        name  = QTYPE_NAMES.get(qt_num, '?')
        marker = '  <-- TRACKED' if count > 0 else ''
        print(f'  {qt_num:<6} {name:<8} {count:>10}{marker}')

    if active_clients:
        print(f'\n  Per-client query counts:')
        print(f'  {"Source IP":<18} {"Count":>10}')
        print(f'  {"-" * 30}')
        for last_octet, count in sorted(active_clients.items()):
            ip = f'10.0.0.{last_octet}'
            print(f'  {ip:<18} {count:>10}')
    else:
        print('\n  No client traffic seen yet.')

    print()


def block_qtype(qtype: int, thrift_port: int) -> None:
    out = _cli(f'table_add dns_block dns_drop {qtype} =>', thrift_port)
    if 'success' in out.lower() or 'entry' in out.lower():
        print(f'[+] Block rule installed: QTYPE={qtype} ({QTYPE_NAMES.get(qtype, "?")})')
    else:
        print(f'[!] CLI response: {out.strip()}')


def clear_blocks(thrift_port: int) -> None:
    out = _cli('table_clear dns_block', thrift_port)
    if 'error' in out.lower():
        print(f'[!] CLI response: {out.strip()}')
    else:
        print('[+] dns_block table cleared.')


def show_blocked(thrift_port: int) -> None:
    bt = read_register_batch('blocked_counter', DISPLAY_QTYPES, thrift_port)
    total = sum(bt.values())
    print(f'\n  Blocked packets (total: {total})')
    print(f'  {"QTYPE":<6} {"Name":<8} {"Dropped":>10}')
    print(f'  {"-" * 26}')
    for qt_num in DISPLAY_QTYPES:
        count = bt.get(qt_num, 0)
        if count > 0:
            name = QTYPE_NAMES.get(qt_num, '?')
            print(f'  {qt_num:<6} {name:<8} {count:>10}  <-- BLOCKED')
    if total == 0:
        print('  (no blocked packets)')
    print()


def list_rules(thrift_port: int) -> None:
    """Print the DNS QTYPE block rules currently installed in the P4 dns_block table."""
    out = _cli('table_dump dns_block', thrift_port)
    # BMv2 table_dump separates entries with lines of '*****'.
    # Each entry block looks like:
    #   * hdr.dns_question.qtype : EXACT     001e
    #   Action entry: P4DNSMonitor.dns_drop -
    qtypes = []
    for block in re.split(r'\*{5,}', out):
        if 'dns_drop' in block:
            m = re.search(r'EXACT\s+([0-9a-fA-F]+)', block)
            if m:
                qtypes.append(int(m.group(1), 16))

    print('\nCurrently blocked DNS query types:')
    if not qtypes:
        print('  (none — all query types are currently allowed)')
    else:
        for qt_num in sorted(qtypes):
            name = QTYPE_NAMES.get(qt_num, 'UNKNOWN')
            print(f'  - QTYPE {qt_num:>3}  ({name})')
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description='P4 DNS Monitor Controller')
    parser.add_argument('--thrift-port', type=int, default=9090,
                        help='BMv2 Thrift port (default: 9090)')
    parser.add_argument('--block-qtype', type=int, default=None, metavar='N',
                        help='Install drop rule for DNS QTYPE N (e.g. 15=MX, 28=AAAA)')
    parser.add_argument('--clear', action='store_true',
                        help='Clear all entries from the dns_block table')
    parser.add_argument('--once', action='store_true',
                        help='Print stats once and exit (no live loop)')
    parser.add_argument('--interval', type=int, default=5, metavar='SEC',
                        help='Dashboard refresh interval in seconds (default: 5)')
    parser.add_argument('--show-blocked', action='store_true',
                        help='Show blocked packet counts by QTYPE and exit')
    parser.add_argument('--list-rules', action='store_true',
                        help='List DNS QTYPE block rules currently installed in the switch and exit')
    args = parser.parse_args()

    if args.list_rules:
        list_rules(args.thrift_port)
        return

    if args.show_blocked:
        show_blocked(args.thrift_port)
        return

    if args.clear:
        clear_blocks(args.thrift_port)

    if args.block_qtype is not None:
        block_qtype(args.block_qtype, args.thrift_port)

    if args.once or (not args.clear and args.block_qtype is None):
        print_stats(args.thrift_port)

    if args.once:
        return

    # Live dashboard loop
    if not args.clear and args.block_qtype is None:
        try:
            while True:
                time.sleep(args.interval)
                print_stats(args.thrift_port)
        except KeyboardInterrupt:
            print('\nExiting controller.')


if __name__ == '__main__':
    main()
