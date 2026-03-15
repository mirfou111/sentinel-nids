# tests/test_flow_builder.py
from scapy.all import IP, TCP, UDP, ICMP
from sentinel.capture.parser import PacketParser
from sentinel.capture.flow_builder import FlowBuilder
import time


def make_parsed(src="192.168.1.1", dst="8.8.8.8",
                sport=12345, dport=80, flags="S"):
    parser = PacketParser()
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    return parser.parse(pkt)


def test_flow_creation():
    """Un paquet crée un flow."""
    builder = FlowBuilder(window_size=60.0)
    pkt = make_parsed()
    builder.add_packet(pkt)

    stats = builder.get_stats()
    assert stats["flows_created"] == 1
    assert stats["packets_processed"] == 1


def test_same_flow_aggregation():
    """Plusieurs paquets du même flow sont agrégés."""
    builder = FlowBuilder(window_size=60.0)

    # 5 paquets du même flow
    for i in range(5):
        pkt = make_parsed(flags="A")
        builder.add_packet(pkt)

    stats = builder.get_stats()
    # Même src/dst/ports → 1 seul flow
    assert stats["flows_created"] == 1
    assert stats["packets_processed"] == 5


# tests/test_flow_builder.py
def test_port_scan_detection_features():
    """
    Un port scan = même IP source, ports destination différents.
    Chaque port contacté = un flow séparé.
    La détection se fait sur le NOMBRE de flows de la même IP.
    """
    builder = FlowBuilder(window_size=60.0)
    parser = PacketParser()

    # Simuler un scan de 10 ports différents
    for port in range(80, 90):
        pkt = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(
            sport=54321, dport=port, flags="S"
        )
        parsed = parser.parse(pkt)
        builder.add_packet(parsed)

    # Flush pour obtenir les flows finalisés
    flows = builder.force_flush()

    # 10 ports différents = 10 flows distincts
    assert len(flows) == 10

    # Chaque flow vient de la même IP source
    src_ips = set(f.ip_src for f in flows)
    assert src_ips == {"10.0.0.1"}

    # Chaque flow = 1 SYN sans ACK → suspect
    for flow in flows:
        assert flow.nb_syn == 1
        assert flow.nb_ack == 0
        assert flow.syn_ratio == 1.0

    # Les ports contactés sont tous différents
    dst_ports = set(f.dst_port for f in flows)
    assert len(dst_ports) == 10

def test_flow_finalization():
    """Les statistiques sont correctement calculées."""
    builder = FlowBuilder(window_size=60.0)
    parser = PacketParser()

    pkt = IP(src="1.1.1.1", dst="2.2.2.2", ttl=64, len=100) / TCP(
        sport=1234, dport=80, flags="S"
    )
    parsed = parser.parse(pkt)
    builder.add_packet(parsed)

    flows = builder.force_flush()
    assert len(flows) == 1

    flow = flows[0]
    assert flow.nb_packets == 1
    assert flow.avg_ttl == 64.0
    assert flow.nb_syn == 1
    assert flow.syn_ratio == 1.0