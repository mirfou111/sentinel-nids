# sentinel/capture/flow_builder.py
"""
Flow Builder — agrège les paquets individuels en flux réseau.

Un "flow" = ensemble de paquets partageant :
  - même IP source
  - même IP destination
  - même port source
  - même port destination
  - même protocole
  - dans une fenêtre de temps donnée (ex: 1 seconde)

C'est l'unité d'analyse du ML — pas le paquet individuel.

Analogie :
  Paquet = une lettre individuelle
  Flow   = toute la correspondance entre deux personnes
           sur une période donnée
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import defaultdict
import time
from loguru import logger

from .parser import ParsedPacket


# ─────────────────────────────────────────────────────
# STRUCTURE D'UN FLOW
# ─────────────────────────────────────────────────────

@dataclass
class Flow:
    """
    Représente un flux réseau agrégé.

    Contient les statistiques calculées sur un ensemble
    de paquets entre deux hôtes sur une période donnée.
    Ce sont ces statistiques qui alimentent le modèle ML.
    """

    # Identité du flow (clé unique)
    flow_id: str = ""           # "src_ip:sport→dst_ip:dport/proto"
    ip_src: str = ""
    ip_dst: str = ""
    proto: str = ""
    src_port: int = 0
    dst_port: int = 0

    # Fenêtre temporelle
    start_time: float = 0.0     # timestamp premier paquet
    end_time: float = 0.0       # timestamp dernier paquet
    duration: float = 0.0       # durée en secondes

    # Statistiques de volume
    nb_packets: int = 0         # nombre total de paquets
    nb_bytes: int = 0           # nombre total de bytes
    avg_packet_size: float = 0.0
    bytes_per_second: float = 0.0
    packets_per_second: float = 0.0

    # Statistiques TCP (détection port scan / brute force)
    nb_syn: int = 0             # nb paquets SYN
    nb_ack: int = 0             # nb paquets ACK
    nb_rst: int = 0             # nb paquets RST (port fermé !)
    nb_fin: int = 0             # nb paquets FIN
    nb_psh: int = 0             # nb paquets PSH
    syn_ratio: float = 0.0      # nb_syn / nb_packets → élevé = scan
    rst_ratio: float = 0.0      # nb_rst / nb_packets → élevé = ports fermés

    # Statistiques ICMP
    nb_icmp_request: int = 0    # type 8
    nb_icmp_reply: int = 0      # type 0

    # Diversité des ports contactés (port scan = beaucoup de ports différents)
    unique_dst_ports: int = 0
    unique_src_ips: int = 0

    # TTL (Time To Live) — peut trahir l'OS source
    avg_ttl: float = 0.0
    min_ttl: int = 255
    max_ttl: int = 0

    # Label ML (rempli après prédiction)
    label: str = "UNKNOWN"      # NORMAL, PORT_SCAN, BRUTE_FORCE, DDOS
    confidence: float = 0.0

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)

    def __str__(self) -> str:
        return (f"[{self.proto}] {self.ip_src}:{self.src_port} → "
                f"{self.ip_dst}:{self.dst_port} | "
                f"{self.nb_packets} pkts | "
                f"{self.nb_bytes} bytes | "
                f"SYN={self.nb_syn} RST={self.nb_rst} | "
                f"dur={self.duration:.2f}s")


# ─────────────────────────────────────────────────────
# FLOW BUILDER
# ─────────────────────────────────────────────────────

class FlowBuilder:
    """
    Agrège les paquets en flows en temps réel.

    Stratégie de fenêtrage :
    On utilise des fenêtres temporelles glissantes.
    Tous les N secondes, on "ferme" les flows actifs
    et on les envoie au moteur de détection ML.

    Pourquoi des fenêtres temporelles ?
    Un port scan dure quelques secondes.
    Un brute force dure plusieurs minutes.
    On doit choisir une fenêtre qui capture ces patterns.
    → On utilise WINDOW_SIZE = 5 secondes (bon compromis)
    """

    # Fenêtre temporelle en secondes
    WINDOW_SIZE: float = 5.0

    def __init__(self, window_size: float = 5.0):
        self.window_size = window_size

        # Flows actifs : clé = flow_id, valeur = (Flow, liste de paquets)
        self._active_flows: Dict[str, dict] = defaultdict(lambda: {
            "flow": None,
            "packets": [],
            "dst_ports": set(),   # ports de destination uniques
            "src_ips": set(),     # IPs sources uniques
            "ttls": [],           # liste des TTL pour calcul moyenne
        })

        # Flows complétés prêts pour le ML
        self._completed_flows: List[Flow] = []

        # Timestamp de la dernière purge
        self._last_purge: float = time.time()

        # Stats
        self.stats = {
            "packets_processed": 0,
            "flows_created": 0,
            "flows_completed": 0,
        }

    def _make_flow_id(self, packet: ParsedPacket) -> str:
        """
        Crée un identifiant unique pour un flow.

        Convention : on normalise src/dst pour regrouper
        les paquets aller ET retour dans le même flow.

        Ex: 192.168.1.1:80→8.8.8.8:54321 et
            8.8.8.8:54321→192.168.1.1:80
        → même flow_id
        """
        if packet.is_tcp():
            sport, dport = packet.tcp_sport, packet.tcp_dport
        elif packet.is_udp():
            sport, dport = packet.udp_sport, packet.udp_dport
        else:
            sport, dport = 0, 0

        # Normalisation : toujours mettre la plus petite IP en premier
        if packet.ip_src < packet.ip_dst:
            return f"{packet.ip_src}:{sport}↔{packet.ip_dst}:{dport}/{packet.proto}"
        else:
            return f"{packet.ip_dst}:{dport}↔{packet.ip_src}:{sport}/{packet.proto}"

    def add_packet(self, packet: ParsedPacket) -> Optional[List[Flow]]:
        """
        Ajoute un paquet au flow correspondant.

        Retourne les flows complétés si la fenêtre
        temporelle est écoulée, None sinon.
        """
        self.stats["packets_processed"] += 1
        flow_id = self._make_flow_id(packet)
        entry = self._active_flows[flow_id]

        # Initialiser le flow si nouveau
        if entry["flow"] is None:
            entry["flow"] = Flow(
                flow_id  = flow_id,
                ip_src   = packet.ip_src,
                ip_dst   = packet.ip_dst,
                proto    = packet.proto,
                src_port = packet.tcp_sport or packet.udp_sport,
                dst_port = packet.tcp_dport or packet.udp_dport,
                start_time = packet.timestamp,
            )
            self.stats["flows_created"] += 1

        # Accumuler les données du paquet dans le flow
        flow = entry["flow"]
        entry["packets"].append(packet)
        entry["ttls"].append(packet.ip_ttl)

        # Ports de destination uniques (clé pour détecter port scan)
        if packet.is_tcp():
            entry["dst_ports"].add(packet.tcp_dport)
        elif packet.is_udp():
            entry["dst_ports"].add(packet.udp_dport)

        # IPs sources uniques (clé pour détecter DDoS)
        entry["src_ips"].add(packet.ip_src)

        # Mise à jour du timestamp de fin
        flow.end_time = packet.timestamp
        flow.nb_packets += 1
        flow.nb_bytes += (packet.ip_len or 0)


        # Comptage des flags TCP
        if packet.is_tcp():
            if packet.has_flag("S"): flow.nb_syn += 1
            if packet.has_flag("A"): flow.nb_ack += 1
            if packet.has_flag("R"): flow.nb_rst += 1
            if packet.has_flag("F"): flow.nb_fin += 1
            if packet.has_flag("P"): flow.nb_psh += 1

        # Comptage ICMP
        if packet.is_icmp():
            if packet.icmp_type == 8: flow.nb_icmp_request += 1
            if packet.icmp_type == 0: flow.nb_icmp_reply += 1

        # Vérifier si la fenêtre temporelle est écoulée
        return self._maybe_purge()

    def _maybe_purge(self) -> Optional[List[Flow]]:
        """
        Vérifie si des flows doivent être fermés.
        Appelé après chaque paquet — efficient car
        on vérifie juste un timestamp.
        """
        now = time.time()
        if now - self._last_purge < self.window_size:
            return None

        self._last_purge = now
        return self._purge_old_flows(now)

    def _purge_old_flows(self, now: float) -> List[Flow]:
        """
        Ferme et finalise les flows dont la fenêtre est écoulée.
        Calcule toutes les statistiques finales.
        """
        completed = []
        to_delete = []

        for flow_id, entry in self._active_flows.items():
            flow = entry["flow"]
            if flow is None:
                continue

            # Flow inactif depuis plus d'une fenêtre → fermer
            if now - flow.end_time >= self.window_size:
                finalized = self._finalize_flow(flow, entry)
                completed.append(finalized)
                to_delete.append(flow_id)
                self.stats["flows_completed"] += 1

        # Supprimer les flows fermés
        for flow_id in to_delete:
            del self._active_flows[flow_id]

        if completed:
            logger.debug(f"🔄 {len(completed)} flows complétés")

        return completed

    def _finalize_flow(self, flow: Flow, entry: dict) -> Flow:
        """
        Calcule les statistiques finales d'un flow.
        C'est ici qu'on prépare les features pour le ML.
        """
        # Durée
        flow.duration = max(flow.end_time - flow.start_time, 0.001)

        # Taille moyenne des paquets
        flow.avg_packet_size = (flow.nb_bytes / flow.nb_packets
                                if flow.nb_packets > 0 else 0)

        # Débits
        flow.bytes_per_second   = flow.nb_bytes   / flow.duration
        flow.packets_per_second = flow.nb_packets / flow.duration

        # Ratios TCP (indicateurs clés d'attaque)
        if flow.nb_packets > 0:
            flow.syn_ratio = flow.nb_syn / flow.nb_packets
            flow.rst_ratio = flow.nb_rst / flow.nb_packets

        # Diversité des ports et IPs
        flow.unique_dst_ports = len(entry["dst_ports"])
        flow.unique_src_ips   = len(entry["src_ips"])

        # Statistiques TTL
        if entry["ttls"]:
            flow.avg_ttl = sum(entry["ttls"]) / len(entry["ttls"])
            flow.min_ttl = min(entry["ttls"])
            flow.max_ttl = max(entry["ttls"])

        return flow

    def force_flush(self) -> List[Flow]:
        """
        Force la fermeture de tous les flows actifs.
        Utile à l'arrêt du programme.
        """
        now = time.time()
        completed = []

        for flow_id, entry in list(self._active_flows.items()):
            if entry["flow"]:
                finalized = self._finalize_flow(entry["flow"], entry)
                completed.append(finalized)

        self._active_flows.clear()
        logger.info(f"🔄 Flush final : {len(completed)} flows")
        return completed

    def get_stats(self) -> dict:
        return {
            **self.stats,
            "active_flows": len(self._active_flows),
        }