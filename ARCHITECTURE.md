# 🛡️ SENTINEL — Architecture Technique

## Vue d'ensemble

SENTINEL est un système de détection d'intrusion réseau (NIDS)
qui capture le trafic réseau en temps réel et utilise le ML
pour détecter les attaques (port scan, brute force, DDoS).

---

## Pipeline de traitement
```
Réseau (eth0)
     ↓
sniffer.py       → capture les bytes bruts (scapy + BPF)
     ↓
parser.py        → décode les entêtes réseau
     ↓
flow_builder.py  → agrège en flux statistiques
     ↓
features/        → vecteurs ML [à venir]
     ↓
ml/              → détection [à venir]
     ↓
alerts/          → notification [à venir]
```

---

## Couche 1 — Capture (sniffer.py)

Chaque paquet qui transite sur l'interface réseau est
une suite de bytes organisés en couches (modèle OSI) :
```
Couche 2 — Ethernet : adresses MAC
Couche 3 — IP       : adresses IP, TTL, protocole
Couche 4 — TCP/UDP  : ports, flags, fenêtre
Couche 7 — Payload  : données applicatives
```

Le sniffer utilise un filtre **BPF (Berkeley Packet Filter)**
— le même langage que Wireshark/tcpdump — pour ne capturer
que les paquets IP et ignorer le reste.

---

## Couche 2 — Parser (parser.py)

Les bytes bruts du paquet IP sont structurés selon la **RFC 791**
(spécification officielle, 1981, toujours valide) :
```
Octet 0    : Version (4 bits) + IHL (4 bits)
Octet 8    : TTL
Octet 9    : Protocol (6=TCP, 17=UDP, 1=ICMP)
Octets 12-15 : IP source
Octets 16-19 : IP destination
```

Sans librairie, le décodage s'écrirait :
```python
ttl      = raw_bytes[8]
protocol = raw_bytes[9]
ip_src   = socket.inet_ntoa(raw_bytes[12:16])
```

Scapy abstrait ce décodage : `packet[IP].ttl`, `packet[IP].src`

Le parser produit un `ParsedPacket` (dataclass) — structure
immuable et sérialisable qui représente un paquet décodé.

### Flags TCP — clés pour la détection
```
SYN (S) : début de connexion
          beaucoup de SYN sans ACK = port scan

ACK (A) : accusé de réception

RST (R) : connexion refusée
          RST en réponse à SYN = port fermé

FIN (F) : fin de connexion

PSH (P) : données à transmettre immédiatement
```

---

## Couche 3 — Flow Builder (flow_builder.py)

Un **flow** est l'agrégation de tous les paquets entre
deux hôtes sur une fenêtre temporelle (5 secondes).
```
Paquet 1 : 192.168.1.1:54231 → 8.8.8.8:80 TCP SYN
Paquet 2 : 192.168.1.1:54231 → 8.8.8.8:80 TCP ACK
Paquet 3 : 192.168.1.1:54231 → 8.8.8.8:80 TCP PSH
                 ↓
         1 FLOW avec statistiques :
         nb_packets=3, nb_syn=1, nb_ack=1...
```

### Pourquoi des flows et pas des paquets ?

Le ML ne détecte pas les attaques sur un paquet isolé
mais sur des **patterns temporels** :
```
Port scan   → 1 IP source contacte N ports différents
              en quelques secondes
              → N flows distincts de la même IP source

Brute force → des centaines de tentatives de connexion
              sur le même port (ex: SSH 22)
              → 1 flow avec nb_packets très élevé

DDoS        → N IP sources différentes vers 1 IP cible
              → N flows avec même ip_dst
```

### Fenêtre temporelle

`WINDOW_SIZE = 5 secondes` — compromis entre :
- Trop court → flows incomplets, patterns non détectés
- Trop long  → détection lente, mémoire consommée

---

## Tests

Les tests unitaires utilisent des **paquets synthétiques**
créés avec scapy sans accès au réseau réel :
```python
pkt = IP(src="192.168.1.1", dst="8.8.8.8") / TCP(dport=80, flags="S")
```

C'est la méthode utilisée par Snort et Suricata pour
tester leurs parsers sans infrastructure réseau.

---

*Document mis à jour à chaque étape du développement.*

---

## Couche 4 — Feature Engineering (extractor.py)

Le ML ne comprend pas un objet Python — il comprend
un vecteur de nombres. Le feature extractor fait
cette transformation.

### Les 27 features extraites
```
Catégorie        Features
─────────────────────────────────────────────────
Volume           nb_packets, nb_bytes, avg_packet_size,
                 bytes_per_second, packets_per_second

Durée            duration

TCP Flags        nb_syn, nb_ack, nb_rst, nb_fin, nb_psh
(absolus)

TCP Flags        syn_ratio, rst_ratio
(ratios)         → plus robustes que les valeurs absolues
                 car indépendants du volume de trafic

Diversité        unique_dst_ports → élevé = port scan
                 unique_src_ips   → élevé = DDoS

TTL              avg_ttl, min_ttl, max_ttl
                 → peut trahir l'OS source

Protocole        proto_tcp, proto_udp, proto_icmp
(one-hot)        → encodage catégoriel sans ordinalité

ICMP             nb_icmp_request, nb_icmp_reply

Ports connus     is_http (80), is_https (443),
                 is_ssh (22), is_dns (53), is_ftp (21)
```

### One-Hot Encoding

Le protocole (TCP/UDP/ICMP) est une variable catégorielle.
On ne peut pas écrire TCP=1, UDP=2, ICMP=3 car cela
introduit une fausse ordinalité (TCP n'est pas "plus petit" qu'UDP).

Solution : une colonne binaire par catégorie.
```
proto="TCP"  → proto_tcp=1, proto_udp=0, proto_icmp=0
proto="UDP"  → proto_tcp=0, proto_udp=1, proto_icmp=0
```

### Règle critique : ordre des features fixe

L'ordre de FEATURE_NAMES doit être identique entre
l'entraînement et l'inférence. Si on change l'ordre,
le modèle reçoit les mauvaises valeurs et prédit
n'importe quoi — sans lever d'erreur.

