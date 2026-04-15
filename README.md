# Project 14 – DNS Packet Filter / Monitor

**Implementation Plan · Gönye Mihály (PZNYY6)**

---

## 1. Overview

This project implements a DNS Packet Filter and Monitor using **P4** (Portable Switch Architecture) with the **Kathara** network emulation framework and the **BMv2** software switch. The system parses live UDP/53 DNS traffic at the data-plane level, collects per-query-type telemetry, and enforces a configurable blocking rule — all without touching the host's kernel.

---

## 2. Goals & Scope

- Detect DNS query and response packets (QR flag in DNS header)
- Count traffic per DNS query type (A, AAAA, MX, CNAME, PTR, …) using P4 registers
- Count per-client (source IP) query volume
- Block a single configurable domain pattern **or** resource-record type via a P4 match-action table
- Export collected stats to a user-space Python controller (dashboard / CLI)

> **Note:** Full DNS name decompression is not feasible in P4. Fixed-offset parsing (first QNAME label, QTYPE field) is sufficient for all required tasks.

---

## 3. System Architecture

### 3.1 Kathara Topology

Two end-hosts (`client`, `server`) connected through a P4-enabled BMv2 router node. DNS traffic flows from client → BMv2 → server (resolver).

```
client ── eth0 ── [BMv2 p4-router] ── eth1 ── server/resolver
```

### 3.2 P4 Pipeline

| Stage               | Description                                                                  |
| ------------------- | ---------------------------------------------------------------------------- |
| **Parser**          | Ethernet → IPv4 → UDP → DNS header extraction                                |
| **Ingress control** | QR-bit check, QTYPE extraction, register updates, drop logic                 |
| **Egress**          | Pass-through (no modification needed for monitoring)                         |
| **Control plane**   | `runtime_CLI` / Python Thrift API to insert table entries and read registers |

---

## 4. Implementation Phases

| Phase             | Task                                                                     |
| ----------------- | ------------------------------------------------------------------------ |
| **1 – Setup**     | Kathara topology (2 hosts + router) + BMv2 switch                        |
| **2 – Parsing**   | Parse Ethernet/IP/UDP headers; extract DNS payload at fixed offsets      |
| **3 – Telemetry** | QR-bit detection; per-type (A/AAAA/MX/…) counters via registers          |
| **4 – Blocking**  | Match-action table for configurable domain hash / RR type drop rule      |
| **5 – Userspace** | Python controller: reads registers, prints stats, configures block rules |
| **6 – Testing**   | Scapy-generated DNS traffic; verify counts + drops                       |

---

## 5. Key Technical Details

### 5.1 DNS Header Parsing (Fixed-Offset)

DNS sits at a fixed byte offset after the UDP payload. The P4 parser extracts:

- Transaction ID (2 bytes)
- Flags field: QR bit (bit 15), OPCODE, RD, RA
- `QDCOUNT` – number of questions
- `QTYPE` – 2 bytes at offset +4 after the QNAME label _(assumes single-label or known-length name)_

The QNAME is variable-length; parsing stops after the first label to extract QTYPE at a predictable offset. This is the standard P4 approach for partial DNS inspection.

### 5.2 Telemetry Registers

```p4
register<bit<32>>(16)  qtype_counter;   // indexed by QTYPE value (up to 15 types)
register<bit<32>>(256) client_counter;  // indexed by last octet of src IP
register<bit<32>>(2)   qr_counter;      // index 0 = queries, index 1 = responses
```

### 5.3 Blocking Table

A ternary match-action table keyed on QTYPE and/or a 4-byte QNAME prefix hash:

```p4
table dns_block {
    key = {
        hdr.dns.qtype : exact;
    }
    actions = { drop; NoAction; }
}
```

The controller inserts a single rule at runtime — e.g., block all `QTYPE=MX` (value 15) packets.

### 5.4 User-Space Controller

- Reads register arrays via the BMv2 `runtime_CLI` or Thrift API
- Displays a live CLI table of per-type counts every N seconds
- Accepts CLI arguments to set the blocked QTYPE and push the table entry
- Optional: simple HTTP endpoint for a stats dashboard

---

## 6. Dependencies

| Tool                                                             | Purpose                                      |
| ---------------------------------------------------------------- | -------------------------------------------- |
| [Kathara](https://github.com/KatharaFramework/Kathara)           | Network emulation (Docker-based)             |
| [p4c](https://github.com/p4lang/p4c)                             | P4 compiler (targeting BMv2 / simple_switch) |
| [BMv2 simple_switch](https://github.com/p4lang/behavioral-model) | Software P4 target                           |
| Python 3 + Scapy                                                 | Test traffic generation                      |
| Python 3 + thrift                                                | Runtime register access from controller      |

---
