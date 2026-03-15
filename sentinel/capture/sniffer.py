# sentinel/capture/sniffer.py
from scapy.all import sniff, IP, TCP, UDP, ICMP
from loguru import logger
import psutil
from .parser import PacketParser

# Instance globale du parser
_parser = PacketParser()


def get_available_interfaces() -> list[str]:
    interfaces = list(psutil.net_if_addrs().keys())
    logger.info(f"Interfaces disponibles : {interfaces}")
    return interfaces


def on_packet(packet) -> None:
    """Callback scapy — parse et affiche chaque paquet."""
    parsed = _parser.parse(packet)
    if parsed:
        logger.info(str(parsed))


def start_capture(interface: str = "eth0", packet_count: int = 0) -> None:
    logger.info(f"🛡️  SENTINEL démarré sur {interface}")
    logger.info("Appuyez sur Ctrl+C pour arrêter")
    try:
        sniff(
            iface=interface,
            prn=on_packet,
            store=False,
            filter="ip",
            count=packet_count,
        )
    except KeyboardInterrupt:
        logger.info("⏹️  Capture arrêtée")
        _parser.print_stats()


if __name__ == "__main__":
    start_capture(interface="eth0")