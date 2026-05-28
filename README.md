# P4 DNS Monitor

DNS traffic monitoring and filtering system built with P4, BMv2, and Kathara.

The P4 program runs on a software switch between a client and a DNS server. It inspects every DNS packet at the data plane, maintains counters per query type and per source IP, and enforces configurable drop rules — all without touching the host kernel.

---

## Architecture

```
client (10.0.0.1)
    eth0
      |
    [s1 — BMv2 simple_switch running P4DNSMonitor.p4]
      |
    eth1
server (10.0.0.2)
```

### P4 pipeline (`s1/P4DNSMonitor.p4`)

**Parser** — Ethernet → IPv4 → UDP → DNS header → QNAME (first label) → QTYPE/QCLASS

**Tables:**

| Table | Match key | Actions | Default |
|---|---|---|---|
| `port_forward` | ingress port (exact) | `do_forward(port)`, `drop` | drop |
| `dns_block` | DNS QTYPE (exact, 16-bit) | `dns_drop`, `NoAction` | NoAction (allow) |

**Registers (indexed counters, readable from user space):**

| Register | Size | Index | Counts |
|---|---|---|---|
| `qr_counter` | 2 | 0 = query, 1 = response | total queries / responses |
| `qtype_counter` | 256 | QTYPE value | packets per DNS record type |
| `client_counter` | 256 | last octet of source IP | queries per 10.0.0.X client |
| `blocked_counter` | 256 | QTYPE value | dropped packets per record type |

**Ingress logic (simplified):**
```
if DNS packet:
    increment qr_counter[QR flag]
    increment qtype_counter[QTYPE]
    increment client_counter[src_ip last octet]
    apply dns_block:
        hit  → increment blocked_counter[QTYPE], drop packet
        miss → apply port_forward, forward packet
else:
    apply port_forward, forward packet
```

---

## Quick Start

```bash
# 1. Start the Kathara lab (compiles P4, starts BMv2, loads forwarding rules,
#    and launches the controller dashboard automatically via s1.startup)
kathara lstart

# 2. Start the DNS listener on the server node (must be done manually)
kathara exec server -- python3 dns_listener.py

# 3. Send test DNS traffic from the client node
kathara exec client -- python3 dns_test.py
```

---

## Controller — `s1/controller.py`

Communicates with the BMv2 switch over the Thrift API (default port 9090).
Run from inside the `s1` container or via `kathara exec s1 --`.

### Dashboard / stats

```bash
python3 controller.py
```
Live-refreshing dashboard showing total queries, responses, per-QTYPE counts, and per-client counts. Refreshes every 5 seconds. Press Ctrl+C to exit.

```bash
python3 controller.py --once
```
Prints the dashboard once and exits immediately.

```bash
python3 controller.py --interval 10
```
Sets the dashboard refresh interval to 10 seconds (default: 5).

### Block rules

```bash
python3 controller.py --block-qtype 15
```
Installs a drop rule in the `dns_block` table for QTYPE 15 (MX). All incoming DNS queries of that type are silently dropped at the data plane from this point on. The rule persists until `--clear` is run or the switch is restarted.

```bash
python3 controller.py --block-qtype 28
```
Same, but for QTYPE 28 (AAAA — IPv6 address queries).

```bash
python3 controller.py --clear
```
Removes **all** entries from the `dns_block` table (`table_clear dns_block`). All query types are allowed again.

```bash
python3 controller.py --clear --block-qtype 1
```
Clears existing rules first, then installs a single new rule (here: block QTYPE 1 / A records). Use this pattern to replace the current blocklist rather than append to it.

### Inspecting the blocklist

```bash
python3 controller.py --list-rules
```
Reads the live contents of the `dns_block` P4 table and prints which QTYPE values currently have a drop rule installed. This reflects the current switch configuration, regardless of whether any traffic has been seen.

Example output:
```
Currently blocked DNS query types:
  - QTYPE  15  (MX)
  - QTYPE  28  (AAAA)
```

```bash
python3 controller.py --show-blocked
```
Reads the `blocked_counter` register and shows how many packets of each type have been dropped since the switch started. This is historical data — it accumulates across rule changes and is only reset on switch restart.

Example output:
```
  Blocked packets (total: 25)
  QTYPE  Name     Dropped
  --------------------------
  15     MX            10  <-- BLOCKED
  28     AAAA          15  <-- BLOCKED
```

> **`--list-rules` vs `--show-blocked`:**
> `--list-rules` shows what the switch is *configured* to block right now (table entries).
> `--show-blocked` shows what has *already been dropped* (register history).
> A rule with no matching traffic yet appears in `--list-rules` but not in `--show-blocked`.
> After `--clear`, `--list-rules` shows nothing but `--show-blocked` still shows past drops.

### Thrift port

```bash
python3 controller.py --thrift-port 9091
```
Connect to a BMv2 instance on a non-default Thrift port. Default is 9090.

---

## Test Traffic Generator — `client/dns_test.py`

Sends crafted DNS query packets using Scapy. Run from inside the `client` container.

> **Note:** The P4 parser extracts only the first QNAME label. Use single-label names (e.g. `test`, `mail`) — multi-label names like `example.com` cause QTYPE misalignment.

### Send the default test suite

```bash
python3 dns_test.py
```
Sends 5 packets each for: A, AAAA, MX, PTR, NS, CNAME, SRV, TXT. Target: 10.0.0.2, source interface: eth0.

### Options

```bash
python3 dns_test.py --count 20
```
Send 20 packets per query type instead of 5.

```bash
python3 dns_test.py --qtype 15 --name mail
```
Send only QTYPE 15 (MX) queries with the QNAME label `mail`.

```bash
python3 dns_test.py --target 10.0.0.2 --src 10.0.0.1 --iface eth0
```
Override destination IP, source IP, and network interface.

```bash
python3 dns_test.py --verbose
```
Enable Scapy's verbose packet output.

---

## DNS QTYPE Reference

| QTYPE | Name | Description |
|---|---|---|
| 1 | A | IPv4 address |
| 2 | NS | Name server |
| 5 | CNAME | Canonical name (alias) |
| 6 | SOA | Start of authority |
| 12 | PTR | Reverse lookup |
| 15 | MX | Mail exchange |
| 16 | TXT | Text record |
| 28 | AAAA | IPv6 address |
| 33 | SRV | Service locator |
| 255 | ANY | All records |

---

## File Layout

```
p4-dns-monitor/
├── lab.conf              Kathara topology (client, s1, server)
├── s1.startup            s1 init: compile P4, start BMv2, load rules, start controller
├── client.startup        client init: set MAC, IP, static ARP
├── server.startup        server init: set MAC, IP, static ARP (DNS listener manual)
├── build.sh              standalone P4 compilation helper
├── requirements.txt      Python dependencies (scapy)
│
├── s1/
│   ├── P4DNSMonitor.p4   P4 data-plane program
│   ├── controller.py     Python controller (dashboard + block rule management)
│   └── commands.txt      Initial port_forward table entries loaded at startup
│
├── client/
│   └── dns_test.py       Scapy-based DNS traffic generator
│
└── server/
    └── dns_listener.py   Minimal UDP/53 listener that echoes responses
```

---

## Dependencies

| Tool | Purpose |
|---|---|
| [Kathara](https://github.com/KatharaFramework/Kathara) | Network emulation (Docker-based containers) |
| [p4c](https://github.com/p4lang/p4c) | P4 compiler targeting BMv2 |
| [BMv2 simple_switch](https://github.com/p4lang/behavioral-model) | Software P4 switch |
| Python 3 + Scapy | DNS packet generation (`dns_test.py`) |
