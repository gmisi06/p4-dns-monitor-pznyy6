#!/usr/bin/env python3
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 53))
print('Listening on :53 ...')

while True:
    data, addr = s.recvfrom(512)
    print(f'DNS query from {addr[0]}: {len(data)} bytes')
    resp = bytearray(data)
    resp[2] = (resp[2] | 0x80) & 0xFF
    s.sendto(bytes(resp), addr)
