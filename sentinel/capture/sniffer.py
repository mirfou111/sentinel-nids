# sentinel/capture/sniffer.py
"""
Couche de capture réseau — le point d'entrée de SENTINEL.

C'est ici qu'on "écoute" l'interface réseau et qu'on
récupère les paquets bruts avant tout traitement.

Concepts clés :
- scapy.sniff() : capture les paquets en temps réel
- prn          : callback appelé pour chaque paquet capturé
- store=False  : ne garde pas les paquets en mémoire (économie RAM)
- filter       : filtre BPF (Berkeley Packet Filter) — langage
                 de filtrage réseau utilisé par Wireshark/tcpdump
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from loguru import logger
import psutil


def get_available_interfaces() -> list[str]:
    """
    Retourne la liste des interfaces réseau disponibles.
    psutil nous donne les stats de chaque interface.
    """
    interfaces = list(psutil.net_if_addrs().keys())
    logger.info(f"Interfaces disponibles : {interfaces}")
    return interfaces


def on_packet(packet) -> None:
    """
    Callback appelé par scapy pour CHAQUE paquet capturé.
    C'est le cœur de la capture — tout commence ici.

    Un paquet réseau c'est comme une enveloppe avec des enveloppes :
    Ethernet (couche 2)
      └── IP (couche 3)
            └── TCP/UDP/ICMP (couche 4)
                    └── Payload/Data (couche 7)
    """
    # On ne traite que les paquets qui ont une couche IP
    if not packet.haslayer(IP):
        return

    ip_src = packet[IP].src    # IP source
    ip_dst = packet[IP].dst    # IP destination
    protocol = packet[IP].proto  # Numéro de protocole (6=TCP, 17=UDP, 1=ICMP)

    # Identifier le protocole de transport
    if packet.haslayer(TCP):
        proto_name = "TCP"
        sport = packet[TCP].sport  # port source
        dport = packet[TCP].dport  # port destination
        flags = packet[TCP].flags  # SYN, ACK, FIN, RST...
        logger.info(f"{proto_name} {ip_src}:{sport} → {ip_dst}:{dport} [{flags}]")

    elif packet.haslayer(UDP):
        proto_name = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        logger.info(f"{proto_name} {ip_src}:{sport} → {ip_dst}:{dport}")

    elif packet.haslayer(ICMP):
        proto_name = "ICMP"
        icmp_type = packet[ICMP].type  # 8=ping request, 0=ping reply
        logger.info(f"{proto_name} {ip_src} → {ip_dst} type={icmp_type}")


def start_capture(interface: str = "eth0", packet_count: int = 0) -> None:
    """
    Lance la capture réseau sur l'interface donnée.

    interface    : nom de l'interface (eth0, wlan0...)
    packet_count : nombre de paquets à capturer (0 = infini)
    filter       : filtre BPF — "ip" = seulement les paquets IP
                   autres exemples :
                   "tcp port 80"     → seulement HTTP
                   "icmp"            → seulement ping
                   "not port 22"     → exclure SSH
    """
    logger.info(f"🛡️  SENTINEL démarré sur {interface}")
    logger.info("Appuyez sur Ctrl+C pour arrêter")

    sniff(
        iface=interface,
        prn=on_packet,
        store=False,          # Ne stocke pas en RAM
        filter="ip",          # Filtre BPF : seulement IP
        count=packet_count,   # 0 = capture infinie
    )


if __name__ == "__main__":
    # Test direct : sudo python -m sentinel.capture.sniffer
    interfaces = get_available_interfaces()
    start_capture(interface="eth0")