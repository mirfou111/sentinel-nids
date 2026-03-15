# tests/test_parser.py
"""
Tester le parser SANS capturer de vrai trafic.
On crée des paquets scapy synthétiques.
C'est comme ça que les vrais IDS sont testés.
"""
from scapy.all import IP, TCP, UDP, ICMP, Raw
from sentinel.capture.parser import PacketParser, ParsedPacket


def make_tcp_packet(src="192.168.1.1", dst="8.8.8.8",
                    sport=12345, dport=80, flags="S"):
    """Crée un paquet TCP synthétique pour les tests."""
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)


def make_udp_packet(src="192.168.1.1", dst="8.8.8.8",
                    sport=12345, dport=53):
    """Crée un paquet UDP synthétique."""
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)


def make_icmp_packet(src="192.168.1.1", dst="8.8.8.8", icmp_type=8):
    """Crée un paquet ICMP synthétique."""
    return IP(src=src, dst=dst) / ICMP(type=icmp_type)


def test_parse_tcp():
    parser = PacketParser()
    pkt = make_tcp_packet(flags="S")
    result = parser.parse(pkt)

    assert result is not None
    assert result.proto == "TCP"
    assert result.ip_src == "192.168.1.1"
    assert result.ip_dst == "8.8.8.8"
    assert result.tcp_dport == 80
    assert result.has_flag("S")   # SYN présent
    assert not result.has_flag("A")  # ACK absent


def test_parse_udp():
    parser = PacketParser()
    pkt = make_udp_packet(dport=53)
    result = parser.parse(pkt)

    assert result is not None
    assert result.proto == "UDP"
    assert result.udp_dport == 53


def test_parse_icmp():
    parser = PacketParser()
    pkt = make_icmp_packet(icmp_type=8)
    result = parser.parse(pkt)

    assert result is not None
    assert result.proto == "ICMP"
    assert result.icmp_type == 8   # ping request


def test_stats():
    parser = PacketParser()
    parser.parse(make_tcp_packet())
    parser.parse(make_udp_packet())
    parser.parse(make_icmp_packet())

    stats = parser.get_stats()
    assert stats["total"] == 3
    assert stats["tcp"] == 1
    assert stats["udp"] == 1
    assert stats["icmp"] == 1
    assert stats["errors"] == 0