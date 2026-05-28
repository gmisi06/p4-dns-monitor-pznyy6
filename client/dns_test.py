#!/usr/bin/env python3
"""
DNS Test Traffic Generator for P4DNSMonitor verification.

Sends crafted DNS query packets using Scapy so the P4 data plane can parse
and count them.  Uses SINGLE-LABEL QNAME (e.g. "test") so the fixed-offset
P4 parser correctly locates the QTYPE field right after the label.

  Multi-label names like "example.com" would produce:
    0x07 'example' 0x03 'com' 0x00  <QTYPE>
  After extracting the first label, the parser reads 0x03 as null_term
  (not 0x00), so QTYPE is misread.  Stick to single-label names here.

Usage (run inside the 'client' Kathara node):
  python3 dns_test.py                          # default: 5 of each type
  python3 dns_test.py --target 10.0.0.2 --count 10
  python3 dns_test.py --target 10.0.0.2 --qtype 15 --count 3 --name mail
"""

import argparse
import sys

try:
    from scapy.all import sendp, RandShort
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.layers.dns import DNS, DNSQR
except ImportError:
    sys.exit('scapy not installed. Run: pip3 install scapy')


def send_query(
    dst_ip: str,
    qname: str,
    qtype: int,
    src_ip: str,
    iface: str,
    count: int,
    verbose: bool = False,
) -> None:
    """Send `count` DNS queries for `qname` of type `qtype` to `dst_ip`."""
    # Scapy encodes qname='test' -> b'\x04test\x00' (single-label wire format)
    pkt = (
        Ether(dst='00:00:0a:00:00:02')  # server MAC – P4 switch forwards by port, exact MAC match is not required
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=RandShort(), dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    )
    for _ in range(count):
        sendp(pkt, iface=iface, verbose=verbose)
    qtype_str = QTYPE_LABELS.get(qtype, str(qtype))
    print(f'  Sent {count:>3}x  QNAME={qname!r:<12} QTYPE={qtype_str} ({qtype})')


QTYPE_LABELS = {
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

DEFAULT_TESTS = [
    # (qname,  qtype)  -- all single-label names
    ('test',   1),    # A
    ('test',   28),   # AAAA
    ('mail',   15),   # MX
    ('ptr',    12),   # PTR
    ('ns',     2),    # NS
    ('alias',  5),    # CNAME
    ('svc',    33),   # SRV
    ('txt',    16),   # TXT
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Send crafted DNS queries through the P4 switch for telemetry testing.'
    )
    parser.add_argument('--target',  default='10.0.0.2',  help='Destination IP (DNS server)')
    parser.add_argument('--src',     default='10.0.0.1',  help='Source IP')
    parser.add_argument('--iface',   default='eth0',       help='Network interface')
    parser.add_argument('--count',   type=int, default=5,  help='Packets per query type')
    parser.add_argument('--qtype',   type=int, default=None,
                        help='Send only this QTYPE (omit to run all default tests)')
    parser.add_argument('--name',    default='test',       help='QNAME label to use with --qtype')
    parser.add_argument('--verbose', action='store_true',  help='Verbose Scapy output')
    args = parser.parse_args()

    print(f'[*] Sending DNS test traffic -> {args.target}  iface={args.iface}')
    print(f'    src={args.src}  count={args.count}\n')

    if args.qtype is not None:
        send_query(args.target, args.name, args.qtype,
                   args.src, args.iface, args.count, args.verbose)
    else:
        for qname, qtype in DEFAULT_TESTS:
            send_query(args.target, qname, qtype,
                       args.src, args.iface, args.count, args.verbose)

    print('\n[*] Done. Read counters on s1:')
    print('    python3 controller.py --thrift-port 9090 --once')


if __name__ == '__main__':
    main()
