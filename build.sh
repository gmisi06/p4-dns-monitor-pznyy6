#!/usr/bin/env bash
# Compile P4DNSMonitor.p4 for BMv2 simple_switch.
# Run this on a machine with p4c installed (or inside the kathara/p4 container).
set -euo pipefail

P4SRC="s1/P4DNSMonitor.p4"
OUTDIR="build"

mkdir -p "$OUTDIR"

echo "[*] Compiling $P4SRC ..."
p4c --target bmv2 --arch v1model \
    --p4runtime-files "$OUTDIR/P4DNSMonitor.p4info.txt" \
    -o "$OUTDIR" \
    "$P4SRC"

echo "[+] Output in $OUTDIR/:"
ls -lh "$OUTDIR/"

echo ""
echo "To start the switch manually:"
echo "  simple_switch -i 1@eth0 -i 2@eth1 --thrift-port 9090 \\"
echo "      --log-file /tmp/sw.log $OUTDIR/P4DNSMonitor.json &"
