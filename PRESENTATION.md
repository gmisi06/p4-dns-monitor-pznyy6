# P4 DNS Monitor

> A projekt egy P4-alapú DNS monitor, amely a BMv2 szoftveres switch data plane-jén számolja és szűri az UDP/53 DNS forgalmat – kernel érintése nélkül.

## Kód

Ez a rész mutatja meg, hogyan küzdi le a switch a DNS protokoll változó hosszúságú mezőiből adódó nehézségeket.

```p4
// P4DNSMonitor.p4 (40-42. sor)
state parse_dns_qname {
    bit<8> llen = packet.lookahead<bit<8>>();          // Előretekintés a hosszra
    packet.extract(hdr.dns_qname, (bit<32>)(llen) * 8); // Dinamikus kiemelés
    transition parse_dns_question;
}
```

---

Itt látható, hogyan valósul meg a nagy sebességű mérés közvetlenül a hardver-közeli regiszterekben.

```p4
// P4DNSMonitor.p4 (56-61. sor)
// QR számláló: 0=Query, 1=Response
bit<32> qr_idx = (bit<32>)hdr.dns.qr;
qr_counter.write(qr_idx, qr_val + 1);

// QTYPE számláló (pl. 15 = MX)
bit<32> qt_idx = (bit<32>)hdr.dns_question.qtype;
qtype_counter.write(qt_idx, qt_val + 1);

// Kliens számláló az IP utolsó bájtja alapján
bit<32> cl_idx = (bit<32>)hdr.ipv4.srcAddr[7:0];
client_counter.write(cl_idx, cl_val + 1);
```

---

A biztonsági funkció, amely a switch "tűzfal" képességét bizonyítja.

```p4
// P4DNSMonitor.p4 (53-56. sor és 62. sor)
table dns_block {
    key = { hdr.dns_question.qtype: exact; }
    actions = { dns_drop; NoAction; }
}

// Alkalmazás: ha van találat, a port_forward meg sem hívódik!
if (!dns_block.apply().hit) {
    port_forward.apply();
}
```

## 0. Indítás

```bash
kathara lstart
```

---

## 1. Ellenőrzések (s1 terminál)

```bash
# simple_switch folyamat ellenőrzése
pgrep simple_switch

# tábla ami mutatja hova kell küldeni a csomagot
simple_switch_CLI --thrift-port 9090 <<< "table_dump port_forward"
```

---

## 2. Alap forgalom

### Server terminál

```bash
python3 dns_listener.py
```

### Client terminál

Ez a parancs egy egyedi tesztscriptet futtat, amely összesen 40 darab DNS lekérdezést generál és küld el a ```10.0.0.2``` IP-címre. A script sorban végigmegy nyolc különböző DNS típuson (```A```, ```AAAA```, ```MX```, ```PTR```, ```NS```, ```CNAME```, ```SRV```, ```TXT```), és mindegyikből pontosan 5-5 darab csomagot indít útnak a hálózaton.

```bash
python3 dns_test.py --target 10.0.0.2 --count 5
```

---

## 3. Számlálók olvasása (s1 terminál)

Ez a parancs egyszeri alkalommal kiolvassa a P4 switch regisztereit és tábláit a Thrift API-n keresztül, majd a terminálon strukturált formában (lekérdezési típusok, kliens statisztikák) jeleníti meg az aktuális DNS forgalmi adatokat.

```bash
python3 controller.py --thrift-port 9090 --once
```

---

## 4. Live dashboard (s1 terminál)

3 másodpercenként kiolvassa a P4 switch regisztereit és tábláit

```bash
python3 controller.py --thrift-port 9090 --interval 3
```

---

## 5. Blokkolás

| QTYPE | Név | Leírás |
| :--- | :--- | :--- |
| **1** | **A** | IPv4 cím lekérdezése |
| **2** | **NS** | Névszerver rekord |
| **5** | **CNAME** | Álnév (Alias) |
| **12** | **PTR** | Inverz DNS (IP -> Név) |
| **15** | **MX** | Levelezőszerver |
| **16** | **TXT** | Szöveges információ |
| **28** | **AAAA** | IPv6 cím lekérdezése |
| **33** | **SRV** | Szolgáltatás azonosító |


### MIELŐTT – MX átmegy (client terminál)

```bash
python3 dns_test.py --target 10.0.0.2 --qtype 15 --count 3 --name mail
```

> **server terminálon látható:**
> ```
> DNS query from 10.0.0.1: 43 bytes
> DNS query from 10.0.0.1: 43 bytes
> DNS query from 10.0.0.1: 43 bytes
> ```

### Blokk bekapcsolása (s1 terminál)

```bash
python3 controller.py --thrift-port 9090 --block-qtype 15
```

```bash
python3 controller.py --show-blocked
```

### MIUTÁN – MX nem megy át (client terminál)

```bash
python3 dns_test.py --target 10.0.0.2 --qtype 15 --count 3 --name mail
```

> **server terminálon: semmi nem jelenik meg** – a P4 switch a data plane-en dobta el a csomagokat

### Számláló ellenőrzés (s1 terminál)
```bash
python3 controller.py --thrift-port 9090 --once
```

### Blokk törlése (s1 terminál)
```bash
python3 controller.py --thrift-port 9090 --clear
```

---
