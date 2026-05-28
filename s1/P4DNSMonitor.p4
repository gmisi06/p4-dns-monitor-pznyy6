/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  PROTO_UDP = 17;
const bit<16> DNS_PORT  = 53;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

/* Fixed 12-byte DNS header */
header dns_hdr_t {
    bit<16> txid;
    bit<1>  qr;       // 0 = query, 1 = response
    bit<4>  opcode;
    bit<1>  aa;
    bit<1>  tc;
    bit<1>  rd;
    bit<1>  ra;
    bit<3>  z;
    bit<4>  rcode;
    bit<16> qdcount;
    bit<16> ancount;
    bit<16> nscount;
    bit<16> arcount;
}

/* First QNAME label: 1-byte length + varbit label body (max 63 bytes).
   Parser assumes a single-label QNAME (e.g. "test" -> 0x04 't' 'e' 's' 't').
   Multi-label names (e.g. example.com) will misparse QTYPE – use single-label
   names in dns_test.py for correct telemetry. */
header dns_qname_t {
    bit<8>      label_len;
    varbit<504> label;      // up to 63 bytes (504 bits)
}

/* Immediately follows the QNAME: null terminator + QTYPE + QCLASS */
header dns_question_t {
    bit<8>  null_term;  // 0x00 end-of-QNAME
    bit<16> qtype;
    bit<16> qclass;
}

struct metadata {
    /* empty – all decisions use header fields directly */
}

struct headers {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
    udp_t         udp;
    dns_hdr_t     dns;
    dns_qname_t   dns_qname;
    dns_question_t dns_question;
}

/*************************************************************************
*********************** P A R S E R  *************************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_UDP: parse_udp;
            default:   accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        /* Capture both DNS queries (dstPort=53) and responses (srcPort=53) */
        transition select(hdr.udp.dstPort) {
            DNS_PORT: parse_dns;
            default:  check_udp_src;
        }
    }

    state check_udp_src {
        transition select(hdr.udp.srcPort) {
            DNS_PORT: parse_dns;
            default:  accept;
        }
    }

    state parse_dns {
        packet.extract(hdr.dns);
        transition select(hdr.dns.qr) {
            0: parse_dns_qname;   // query: has question section
            default: accept;       // response: only header guaranteed
        }
    }

    /* Peek at the first label-length byte, then extract that many bytes as
       the varbit label body. Works correctly for single-label QNAME. */
    state parse_dns_qname {
        bit<8> llen = packet.lookahead<bit<8>>();
        packet.extract(hdr.dns_qname, (bit<32>)(llen) * 8);
        transition parse_dns_question;
    }

    state parse_dns_question {
        packet.extract(hdr.dns_question);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* [0] = query count, [1] = response count */
    register<bit<32>>(2)   qr_counter;

    /* Indexed directly by QTYPE value (0-255 covers A,NS,CNAME,SOA,PTR,MX,TXT,AAAA,SRV,ANY) */
    register<bit<32>>(256) qtype_counter;

    /* Indexed by last octet of source IP (e.g. 10.0.0.X → index X) */
    register<bit<32>>(256) client_counter;

    /* Indexed by QTYPE: counts packets dropped by dns_block */
    register<bit<32>>(256) blocked_counter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action do_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    /* Simple port-based L2 forwarding: ingress port → egress port */
    table port_forward {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            do_forward;
            drop;
        }
        size = 4;
        default_action = drop();
    }

    action dns_drop() {
        mark_to_drop(standard_metadata);
    }

    /* Configurable blocking table: match on QTYPE to drop matching DNS packets.
       Populated at runtime via the controller (--block-qtype).
       Example: block all MX (15) queries with:
         table_add dns_block dns_drop 15 */
    table dns_block {
        key = {
            hdr.dns_question.qtype: exact;
        }
        actions = {
            dns_drop;
            NoAction;
        }
        size = 32;
        default_action = NoAction();
    }

    apply {
        if (hdr.dns.isValid()) {
            /* --- QR counter: index 0 = query, 1 = response --- */
            bit<32> qr_val;
            bit<32> qr_idx = (bit<32>)hdr.dns.qr;
            qr_counter.read(qr_val, qr_idx);
            qr_counter.write(qr_idx, qr_val + 1);

            if (hdr.dns_question.isValid() && hdr.ipv4.isValid()) {
                /* --- QTYPE counter (only QTYPE 0-255 fit the register) --- */
                bit<32> qt_idx = (bit<32>)hdr.dns_question.qtype;
                if (qt_idx < 256) {
                    bit<32> qt_val;
                    qtype_counter.read(qt_val, qt_idx);
                    qtype_counter.write(qt_idx, qt_val + 1);
                }

                /* --- Per-client counter (last octet of src IP) --- */
                bit<32> cl_idx = (bit<32>)hdr.ipv4.srcAddr[7:0];
                bit<32> cl_val;
                client_counter.read(cl_val, cl_idx);
                client_counter.write(cl_idx, cl_val + 1);

                /* --- Blocking check --- */
                if (dns_block.apply().hit) {
                    bit<32> bt_idx = (bit<32>)hdr.dns_question.qtype;
                    if (bt_idx < 256) {
                        bit<32> bt_val;
                        blocked_counter.read(bt_val, bt_idx);
                        blocked_counter.write(bt_idx, bt_val + 1);
                    }
                } else {
                    port_forward.apply();
                }
            } else {
                port_forward.apply();
            }
        } else {
            port_forward.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  ********************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.dns);
        packet.emit(hdr.dns_qname);
        packet.emit(hdr.dns_question);
    }
}

/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
