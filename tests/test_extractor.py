# tests/test_extractor.py
import numpy as np
from sentinel.capture.flow_builder import Flow
from sentinel.features.extractor import FeatureExtractor, FEATURE_NAMES, N_FEATURES


def make_flow(proto="TCP", nb_packets=10, nb_syn=8,
              dst_port=80, duration=1.0) -> Flow:
    """Crée un flow de test."""
    flow = Flow(
        proto       = proto,
        nb_packets  = nb_packets,
        nb_bytes    = nb_packets * 100,
        nb_syn      = nb_syn,
        nb_ack      = nb_packets - nb_syn,
        dst_port    = dst_port,
        duration    = duration,
        avg_ttl     = 64.0,
        min_ttl     = 64,
        max_ttl     = 64,
        unique_dst_ports = 1,
        unique_src_ips   = 1,
    )
    return flow


def test_vector_shape():
    """Le vecteur doit avoir exactement N_FEATURES dimensions."""
    extractor = FeatureExtractor()
    flow = make_flow()
    vector = extractor.flow_to_vector(flow)

    assert vector.shape == (N_FEATURES,)
    assert vector.dtype == np.float32


def test_feature_names_count():
    """FEATURE_NAMES doit avoir exactement N_FEATURES éléments."""
    assert len(FEATURE_NAMES) == N_FEATURES


def test_proto_one_hot_tcp():
    """Un flow TCP → proto_tcp=1, proto_udp=0, proto_icmp=0."""
    extractor = FeatureExtractor()
    features = extractor.flow_to_dict(make_flow(proto="TCP"))

    assert features["proto_tcp"]  == 1.0
    assert features["proto_udp"]  == 0.0
    assert features["proto_icmp"] == 0.0


def test_proto_one_hot_udp():
    """Un flow UDP → proto_udp=1."""
    extractor = FeatureExtractor()
    features = extractor.flow_to_dict(make_flow(proto="UDP"))

    assert features["proto_udp"]  == 1.0
    assert features["proto_tcp"]  == 0.0


def test_syn_ratio():
    """syn_ratio = nb_syn / nb_packets."""
    extractor = FeatureExtractor()
    # 8 SYN sur 10 paquets = 0.8
    features = extractor.flow_to_dict(make_flow(nb_packets=10, nb_syn=8))
    assert abs(features["syn_ratio"] - 0.8) < 0.001


def test_port_indicators():
    """is_http=1 si dst_port==80."""
    extractor = FeatureExtractor()

    f_http = extractor.flow_to_dict(make_flow(dst_port=80))
    assert f_http["is_http"]  == 1.0
    assert f_http["is_https"] == 0.0
    assert f_http["is_ssh"]   == 0.0

    f_ssh = extractor.flow_to_dict(make_flow(dst_port=22))
    assert f_ssh["is_ssh"]   == 1.0
    assert f_ssh["is_http"]  == 0.0


def test_dataframe():
    """flows_to_dataframe produit un DataFrame avec les bonnes colonnes."""
    extractor = FeatureExtractor()
    flows  = [make_flow(proto="TCP"), make_flow(proto="UDP")]
    labels = ["NORMAL", "PORT_SCAN"]

    df = extractor.flows_to_dataframe(flows, labels)

    assert len(df) == 2
    assert "label" in df.columns
    assert list(df["label"]) == ["NORMAL", "PORT_SCAN"]
    assert all(col in df.columns for col in FEATURE_NAMES)


def test_no_division_by_zero():
    """Un flow avec nb_packets=0 ne doit pas planter."""
    extractor = FeatureExtractor()
    flow = Flow(proto="TCP", nb_packets=0, duration=0.0)
    vector = extractor.flow_to_vector(flow)

    assert not np.any(np.isnan(vector))
    assert not np.any(np.isinf(vector))