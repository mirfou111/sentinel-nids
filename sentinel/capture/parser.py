# sentinel/capture/parser.py
"""
Parser de paquets réseau — transforme les paquets bruts scapy
en structures de données Python propres et exploitables.

Pourquoi un parser séparé du sniffer ?
→ Séparation des responsabilités :
  - sniffer.py  : CAPTURER les paquets (I/O réseau)
  - parser.py   : COMPRENDRE les paquets (logique)
  - flow_builder.py : AGRÉGER les paquets (statistiques)

C'est le principe Unix : chaque module fait UNE chose bien.
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, Raw
from loguru import logger


# ─────────────────────────────────────────────────────
# STRUCTURES DE DONNÉES
# ─────────────────────────────────────────────────────

@dataclass
class ParsedPacket:
    """
    Représentation structurée d'un paquet réseau.

    Un dataclass est parfait ici :
    - Immutable (on ne modifie pas un paquet après parsing)
    - Léger (pas de logique métier)
    - Sérialisable facilement en dict/JSON

    Couches représentées :
    timestamp   → quand le paquet a été capturé
    ip_*        → couche réseau (Layer 3)
    proto       → protocole transport (TCP/UDP/ICMP)
    tcp_*/udp_* → couche transport (Layer 4)
    payload_len → taille des données applicatives (Layer 7)
    """

    # Métadonnées
    timestamp: float = 0.0          # Unix timestamp (ex: 1710123456.789)

    # Couche IP (Layer 3)
    ip_src: str = ""                 # IP source      (ex: 192.168.1.1)
    ip_dst: str = ""                 # IP destination (ex: 8.8.8.8)
    ip_ttl: int = 0                  # Time To Live   (ex: 64)
    ip_len: int = 0                  # Taille totale du paquet IP en bytes
    ip_proto: int = 0                # Numéro protocole (6=TCP, 17=UDP, 1=ICMP)

    # Protocole transport
    proto: str = "OTHER"             # "TCP", "UDP", "ICMP", "OTHER"

    # Couche TCP (Layer 4) — rempli seulement si proto == "TCP"
    tcp_sport: int = 0               # Port source
    tcp_dport: int = 0               # Port destination
    tcp_flags: str = ""              # Flags : S=SYN, A=ACK, F=FIN, R=RST, P=PUSH
    tcp_seq: int = 0                 # Numéro de séquence
    tcp_ack: int = 0                 # Numéro d'acquittement
    tcp_window: int = 0              # Taille de fenêtre TCP

    # Couche UDP (Layer 4) — rempli seulement si proto == "UDP"
    udp_sport: int = 0
    udp_dport: int = 0
    udp_len: int = 0                 # Taille du datagramme UDP

    # Couche ICMP — rempli seulement si proto == "ICMP"
    icmp_type: int = -1              # 8=request, 0=reply, 3=unreachable...
    icmp_code: int = -1              # Sous-type ICMP

    # Payload
    payload_len: int = 0             # Taille des données applicatives

    def is_tcp(self) -> bool:
        return self.proto == "TCP"

    def is_udp(self) -> bool:
        return self.proto == "UDP"

    def is_icmp(self) -> bool:
        return self.proto == "ICMP"

    def has_flag(self, flag: str) -> bool:
        """
        Vérifie si un flag TCP est présent.
        Flags importants pour la détection :
        - S (SYN)  : début de connexion → beaucoup de SYN = port scan
        - A (ACK)  : accusé de réception
        - R (RST)  : reset connexion → RST en réponse = port fermé
        - F (FIN)  : fin de connexion
        - P (PSH)  : données à envoyer immédiatement
        """
        return flag in self.tcp_flags

    def to_dict(self) -> dict:
        """Convertit en dictionnaire pour logs JSON et ML."""
        from dataclasses import asdict
        return asdict(self)

    def __str__(self) -> str:
        """Affichage lisible pour les logs."""
        if self.is_tcp():
            return (f"TCP {self.ip_src}:{self.tcp_sport} → "
                   f"{self.ip_dst}:{self.tcp_dport} [{self.tcp_flags}] "
                   f"ttl={self.ip_ttl} len={self.ip_len}")
        elif self.is_udp():
            return (f"UDP {self.ip_src}:{self.udp_sport} → "
                   f"{self.ip_dst}:{self.udp_dport} "
                   f"len={self.udp_len}")
        elif self.is_icmp():
            return (f"ICMP {self.ip_src} → {self.ip_dst} "
                   f"type={self.icmp_type} code={self.icmp_code}")
        else:
            return f"OTHER {self.ip_src} → {self.ip_dst}"


# ─────────────────────────────────────────────────────
# PARSER PRINCIPAL
# ─────────────────────────────────────────────────────

class PacketParser:
    """
    Parse les paquets scapy en ParsedPacket.

    Pourquoi une classe et pas juste une fonction ?
    → La classe peut garder des statistiques de parsing
      (nb paquets parsés, nb erreurs, nb par protocole)
    → Facilite les tests unitaires
    """

    def __init__(self):
        # Statistiques de parsing
        self.stats = {
            "total":   0,
            "tcp":     0,
            "udp":     0,
            "icmp":    0,
            "other":   0,
            "errors":  0,
        }

    def parse(self, packet) -> Optional[ParsedPacket]:
        """
        Parse un paquet scapy brut en ParsedPacket structuré.
        Retourne None si le paquet n'est pas IP ou en cas d'erreur.
        """
        try:
            # On ignore les paquets non-IP
            if not packet.haslayer(IP):
                return None

            self.stats["total"] += 1

            # Extraire la couche IP (commune à tous)
            ip = packet[IP]
            parsed = ParsedPacket(
                timestamp = float(packet.time),
                ip_src    = ip.src,
                ip_dst    = ip.dst,
                ip_ttl    = ip.ttl,
                ip_len    = ip.len,
                ip_proto  = ip.proto,
            )

            # Parser selon le protocole de transport
            if packet.haslayer(TCP):
                parsed = self._parse_tcp(parsed, packet)
                self.stats["tcp"] += 1

            elif packet.haslayer(UDP):
                parsed = self._parse_udp(parsed, packet)
                self.stats["udp"] += 1

            elif packet.haslayer(ICMP):
                parsed = self._parse_icmp(parsed, packet)
                self.stats["icmp"] += 1

            else:
                parsed.proto = "OTHER"
                self.stats["other"] += 1

            # Taille du payload applicatif
            if packet.haslayer(Raw):
                parsed.payload_len = len(packet[Raw].load)

            return parsed

        except Exception as e:
            self.stats["errors"] += 1
            logger.warning(f"Erreur parsing paquet : {e}")
            return None

    def _parse_tcp(self, parsed: ParsedPacket, packet) -> ParsedPacket:
        """
        Extrait les champs TCP.

        Les flags TCP sont cruciaux pour la détection :
        Un port scan SYN envoie des milliers de paquets SYN
        vers des ports différents sans jamais compléter
        la poignée de main (SYN → SYN-ACK → ACK)
        """
        tcp = packet[TCP]
        parsed.proto      = "TCP"
        parsed.tcp_sport  = tcp.sport
        parsed.tcp_dport  = tcp.dport
        parsed.tcp_flags  = str(tcp.flags)  # ex: "S", "SA", "A", "FA"
        parsed.tcp_seq    = tcp.seq
        parsed.tcp_ack    = tcp.ack
        parsed.tcp_window = tcp.window
        return parsed

    def _parse_udp(self, parsed: ParsedPacket, packet) -> ParsedPacket:
        """Extrait les champs UDP."""
        udp = packet[UDP]
        parsed.proto     = "UDP"
        parsed.udp_sport = udp.sport
        parsed.udp_dport = udp.dport
        parsed.udp_len   = udp.len
        return parsed

    def _parse_icmp(self, parsed: ParsedPacket, packet) -> ParsedPacket:
        """
        Extrait les champs ICMP.
        ICMP flood = envoyer des milliers de ping → DDoS
        """
        icmp = packet[ICMP]
        parsed.proto     = "ICMP"
        parsed.icmp_type = icmp.type
        parsed.icmp_code = icmp.code
        return parsed

    def get_stats(self) -> dict:
        """Retourne les statistiques de parsing."""
        return self.stats.copy()

    def print_stats(self) -> None:
        """Affiche les statistiques en console."""
        logger.info(f"📊 Stats parsing : {self.stats}")