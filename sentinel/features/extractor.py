# sentinel/features/extractor.py
"""
Feature Extractor — transforme les flows en vecteurs ML.

Deux usages :
1. Entraînement : extraire features de milliers de flows
   labellisés (dataset CICIDS2017) → DataFrame pandas
2. Inférence temps réel : extraire features d'un flow
   capturé → numpy array → prédiction ML en < 1ms

Règles du feature engineering réseau :
- Toujours normaliser les ratios (0.0 à 1.0)
- Encoder les catégories (protocole) en one-hot
- Gérer les divisions par zéro (flows vides)
- Garder les features interprétables (pas de black box)
"""

import numpy as np
import pandas as pd
from dataclasses import asdict
from typing import List
from loguru import logger

from ..capture.flow_builder import Flow


# ─────────────────────────────────────────────────────
# DÉFINITION DES FEATURES
# ─────────────────────────────────────────────────────

# Ordre fixe et immuable des features
# CRITIQUE : doit être identique entre entraînement et inférence
# Si vous changez cet ordre → le modèle prédit n'importe quoi

FEATURE_NAMES = [
    # Volume
    "nb_packets",
    "nb_bytes",
    "avg_packet_size",
    "bytes_per_second",
    "packets_per_second",

    # Durée
    "duration",

    # TCP Flags (absolus)
    "nb_syn",
    "nb_ack",
    "nb_rst",
    "nb_fin",
    "nb_psh",

    # TCP Flags (ratios) — plus robustes que les valeurs absolues
    "syn_ratio",
    "rst_ratio",

    # Diversité — clés pour port scan et DDoS
    "unique_dst_ports",
    "unique_src_ips",

    # TTL
    "avg_ttl",
    "min_ttl",
    "max_ttl",

    # Protocole (one-hot encoding)
    # Un seul sera à 1, les autres à 0
    "proto_tcp",
    "proto_udp",
    "proto_icmp",

    # ICMP
    "nb_icmp_request",
    "nb_icmp_reply",

    # Ports (indicateurs de services courants)
    "is_http",       # dst_port == 80
    "is_https",      # dst_port == 443
    "is_ssh",        # dst_port == 22
    "is_dns",        # dst_port == 53
    "is_ftp",        # dst_port == 21
]

# Nombre total de features — doit correspondre à len(FEATURE_NAMES)
N_FEATURES = len(FEATURE_NAMES)


# ─────────────────────────────────────────────────────
# EXTRACTEUR
# ─────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Transforme les flows en vecteurs de features numériques.

    Usage entraînement :
        extractor = FeatureExtractor()
        df = extractor.flows_to_dataframe(flows, labels)

    Usage inférence temps réel :
        extractor = FeatureExtractor()
        vector = extractor.flow_to_vector(flow)
        prediction = model.predict([vector])
    """

    def flow_to_vector(self, flow: Flow) -> np.ndarray:
        """
        Transforme UN flow en vecteur numpy 1D.
        Utilisé en inférence temps réel.

        Retourne un array de shape (N_FEATURES,)
        """
        features = self._extract_features(flow)
        vector = np.array([features[name] for name in FEATURE_NAMES],
                          dtype=np.float32)
        return vector

    def flow_to_dict(self, flow: Flow) -> dict:
        """
        Transforme UN flow en dictionnaire de features.
        Utile pour le debug et les logs.
        """
        return self._extract_features(flow)

    def flows_to_dataframe(self,
                           flows: List[Flow],
                           labels: List[str] = None) -> pd.DataFrame:
        """
        Transforme une liste de flows en DataFrame pandas.
        Utilisé pour l'entraînement du modèle ML.

        Si labels est fourni, ajoute une colonne 'label'.
        Labels possibles : NORMAL, PORT_SCAN, BRUTE_FORCE, DDOS
        """
        rows = []
        for flow in flows:
            row = self._extract_features(flow)
            rows.append(row)

        df = pd.DataFrame(rows, columns=FEATURE_NAMES)

        if labels:
            assert len(labels) == len(flows), \
                "Nombre de labels != nombre de flows"
            df["label"] = labels

        return df

    def _extract_features(self, flow: Flow) -> dict:
        """
        Extraction centrale — calcule toutes les features d'un flow.
        Appelé par flow_to_vector() et flows_to_dataframe().
        """
        # Sécurité : éviter les divisions par zéro
        nb_packets = max(flow.nb_packets, 1)
        duration   = max(flow.duration, 0.001)

        # One-hot encoding du protocole
        proto_tcp  = 1.0 if flow.proto == "TCP"  else 0.0
        proto_udp  = 1.0 if flow.proto == "UDP"  else 0.0
        proto_icmp = 1.0 if flow.proto == "ICMP" else 0.0

        # Indicateurs de ports connus
        dst_port = flow.dst_port
        is_http  = 1.0 if dst_port == 80  else 0.0
        is_https = 1.0 if dst_port == 443 else 0.0
        is_ssh   = 1.0 if dst_port == 22  else 0.0
        is_dns   = 1.0 if dst_port == 53  else 0.0
        is_ftp   = 1.0 if dst_port == 21  else 0.0

        return {
            # Volume
            "nb_packets":         float(flow.nb_packets),
            "nb_bytes":           float(flow.nb_bytes),
            "avg_packet_size":    float(flow.nb_bytes / nb_packets),
            "bytes_per_second":   float(flow.nb_bytes / duration),
            "packets_per_second": float(flow.nb_packets / duration),

            # Durée
            "duration":           float(duration),

            # TCP Flags absolus
            "nb_syn":             float(flow.nb_syn),
            "nb_ack":             float(flow.nb_ack),
            "nb_rst":             float(flow.nb_rst),
            "nb_fin":             float(flow.nb_fin),
            "nb_psh":             float(flow.nb_psh),

            # TCP Flags ratios
            "syn_ratio":          float(flow.nb_syn / nb_packets),
            "rst_ratio":          float(flow.nb_rst / nb_packets),

            # Diversité
            "unique_dst_ports":   float(flow.unique_dst_ports),
            "unique_src_ips":     float(flow.unique_src_ips),

            # TTL
            "avg_ttl":            float(flow.avg_ttl),
            "min_ttl":            float(flow.min_ttl),
            "max_ttl":            float(flow.max_ttl),

            # Protocole one-hot
            "proto_tcp":          proto_tcp,
            "proto_udp":          proto_udp,
            "proto_icmp":         proto_icmp,

            # ICMP
            "nb_icmp_request":    float(flow.nb_icmp_request),
            "nb_icmp_reply":      float(flow.nb_icmp_reply),

            # Ports connus
            "is_http":            is_http,
            "is_https":           is_https,
            "is_ssh":             is_ssh,
            "is_dns":             is_dns,
            "is_ftp":             is_ftp,
        }