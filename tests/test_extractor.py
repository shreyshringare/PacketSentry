"""Tests for features.extractor — written BEFORE implementation (TDD).

Covers:
  - FlowFeatures dataclass and to_vector()
  - Basic TCP / UDP / ICMP flow extraction
  - Duration calculation (multi-packet vs single-packet)
  - Protocol type mapping (6→0, 17→1, 1→2, other→3)
  - TCP flag counting from flow packets
  - Traffic statistics (bytes/sec, packets/sec, avg packet size)
  - Connection behaviour features (count, srv_count, dst_host_*)
  - Error rates (serror_rate, rerror_rate)
  - Port extraction
"""

from __future__ import annotations

import numpy as np
import pytest

from packetsentry.features.extractor import FeatureExtractor, FlowFeatures
from packetsentry.features.flow_tracker import Flow, ParsedPacket


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pkt(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int = 80,
    protocol: int = 6,
    length: int = 100,
    flags: int = 0,
    timestamp: float = 1000.0,
    payload: bytes = b"",
) -> ParsedPacket:
    return ParsedPacket(
        timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port, protocol=protocol,
        length=length, flags=flags, payload=payload,
    )


def _tcp_flow(
    n_packets: int = 5,
    duration: float = 2.0,
    src_bytes: int = 500,
    dst_bytes: int = 300,
    flags_list: list[int] | None = None,
) -> Flow:
    """Build a synthetic TCP flow for testing."""
    if flags_list is None:
        # Typical TCP: SYN, SYN+ACK, ACK, PSH+ACK, FIN+ACK
        flags_list = [0x02, 0x12, 0x10, 0x18, 0x11][:n_packets]

    packets = []
    for i in range(n_packets):
        t = 1000.0 + (duration * i / max(n_packets - 1, 1))
        packets.append(_pkt(
            timestamp=t,
            flags=flags_list[i] if i < len(flags_list) else 0x10,
            length=100,
        ))

    return Flow(
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=12345, dst_port=80, protocol=6,
        start_time=packets[0].timestamp,
        end_time=packets[-1].timestamp,
        packets=packets,
        src_bytes=src_bytes, dst_bytes=dst_bytes,
        flags=[p.flags for p in packets],
    )


# ===================================================================
# FlowFeatures dataclass
# ===================================================================

class TestFlowFeatures:
    """FlowFeatures dataclass and vector conversion."""

    def test_to_vector_shape(self) -> None:
        ff = FlowFeatures(
            duration=1.0, protocol_type=0, src_bytes=100, dst_bytes=50,
            flag_syn=1, flag_ack=3, flag_fin=1, flag_rst=0, flag_psh=1,
            packet_count=5, avg_packet_size=30.0,
            bytes_per_second=150.0, packets_per_second=5.0,
            count=0, srv_count=0, dst_host_count=0, dst_host_srv_count=0,
            serror_rate=0.0, rerror_rate=0.0,
            same_srv_rate=0.0, diff_srv_rate=0.0,
            src_port=12345, dst_port=80,
        )
        vec = ff.to_vector()
        assert vec.shape == (23,)

    def test_to_vector_dtype(self) -> None:
        ff = FlowFeatures(
            duration=1.0, protocol_type=0, src_bytes=100, dst_bytes=50,
            flag_syn=1, flag_ack=3, flag_fin=1, flag_rst=0, flag_psh=1,
            packet_count=5, avg_packet_size=30.0,
            bytes_per_second=150.0, packets_per_second=5.0,
            count=0, srv_count=0, dst_host_count=0, dst_host_srv_count=0,
            serror_rate=0.0, rerror_rate=0.0,
            same_srv_rate=0.0, diff_srv_rate=0.0,
            src_port=12345, dst_port=80,
        )
        assert ff.to_vector().dtype == np.float32

    def test_to_vector_values_order(self) -> None:
        ff = FlowFeatures(
            duration=2.5, protocol_type=1, src_bytes=200, dst_bytes=100,
            flag_syn=0, flag_ack=0, flag_fin=0, flag_rst=0, flag_psh=0,
            packet_count=3, avg_packet_size=100.0,
            bytes_per_second=120.0, packets_per_second=1.2,
            count=5, srv_count=2, dst_host_count=10, dst_host_srv_count=4,
            serror_rate=0.1, rerror_rate=0.05,
            same_srv_rate=0.6, diff_srv_rate=0.4,
            src_port=5000, dst_port=53,
        )
        vec = ff.to_vector()
        assert vec[0] == pytest.approx(2.5)    # duration
        assert vec[1] == pytest.approx(1.0)    # protocol_type (UDP)
        assert vec[22] == pytest.approx(53.0)  # dst_port (last)


# ===================================================================
# FeatureExtractor — basic extraction
# ===================================================================

class TestBasicExtraction:
    """Basic feature extraction from flows."""

    def test_extract_returns_flow_features(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow()
        result = ext.extract(flow)
        assert isinstance(result, FlowFeatures)

    def test_extract_tcp_protocol_type(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow()
        ff = ext.extract(flow)
        assert ff.protocol_type == 0  # TCP → 0

    def test_extract_udp_protocol_type(self) -> None:
        ext = FeatureExtractor()
        flow = Flow(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=53, protocol=17,
            start_time=1000.0, end_time=1001.0,
            packets=[_pkt(protocol=17, timestamp=1000.0),
                     _pkt(protocol=17, timestamp=1001.0)],
            src_bytes=64, dst_bytes=128,
            flags=[0, 0],
        )
        ff = ext.extract(flow)
        assert ff.protocol_type == 1  # UDP → 1

    def test_extract_icmp_protocol_type(self) -> None:
        ext = FeatureExtractor()
        flow = Flow(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=0, dst_port=0, protocol=1,
            start_time=1000.0, end_time=1000.5,
            packets=[_pkt(protocol=1, src_port=0, dst_port=0)],
            src_bytes=64, dst_bytes=0, flags=[0],
        )
        ff = ext.extract(flow)
        assert ff.protocol_type == 2  # ICMP → 2


# ===================================================================
# FeatureExtractor — duration
# ===================================================================

class TestDuration:
    """Duration computation."""

    def test_multi_packet_duration(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow(n_packets=3, duration=5.0)
        ff = ext.extract(flow)
        assert ff.duration == pytest.approx(5.0, abs=0.01)

    def test_single_packet_minimum_duration(self) -> None:
        ext = FeatureExtractor()
        flow = Flow(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, protocol=6,
            start_time=1000.0, end_time=1000.0,
            packets=[_pkt()], src_bytes=100, dst_bytes=0, flags=[0x02],
        )
        ff = ext.extract(flow)
        assert ff.duration == pytest.approx(0.001)


# ===================================================================
# FeatureExtractor — flag counting
# ===================================================================

class TestFlagCounting:
    """TCP flag extraction from flow packets."""

    def test_syn_count(self) -> None:
        ext = FeatureExtractor()
        # SYN=0x02 appears in SYN (0x02) and SYN+ACK (0x12)
        flow = _tcp_flow(flags_list=[0x02, 0x12, 0x10, 0x18, 0x11])
        ff = ext.extract(flow)
        assert ff.flag_syn == 2  # 0x02 and 0x12 both have SYN bit

    def test_ack_count(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow(flags_list=[0x02, 0x12, 0x10, 0x18, 0x11])
        ff = ext.extract(flow)
        # ACK=0x10 in: SYN+ACK(0x12), ACK(0x10), PSH+ACK(0x18), FIN+ACK(0x11)
        assert ff.flag_ack == 4

    def test_fin_count(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow(flags_list=[0x02, 0x12, 0x10, 0x18, 0x11])
        ff = ext.extract(flow)
        assert ff.flag_fin == 1  # FIN=0x01 only in FIN+ACK(0x11)

    def test_rst_count(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow(flags_list=[0x02, 0x04])  # SYN then RST
        ff = ext.extract(flow)
        assert ff.flag_rst == 1

    def test_psh_count(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow(flags_list=[0x02, 0x12, 0x10, 0x18, 0x11])
        ff = ext.extract(flow)
        assert ff.flag_psh == 1  # PSH=0x08 only in PSH+ACK(0x18)


# ===================================================================
# FeatureExtractor — traffic statistics
# ===================================================================

class TestTrafficStats:
    """Bytes/sec, packets/sec, avg packet size."""

    def test_bytes_per_second(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow(n_packets=4, duration=2.0, src_bytes=300, dst_bytes=200)
        ff = ext.extract(flow)
        # total_bytes=500, duration=2.0s → 250.0 bytes/sec
        assert ff.bytes_per_second == pytest.approx(250.0, rel=0.01)

    def test_packets_per_second(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow(n_packets=10, duration=5.0)
        ff = ext.extract(flow)
        assert ff.packets_per_second == pytest.approx(2.0, rel=0.01)

    def test_avg_packet_size(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow(n_packets=4, src_bytes=400, dst_bytes=200)
        ff = ext.extract(flow)
        # total_bytes=600, 4 packets → avg=150.0
        assert ff.avg_packet_size == pytest.approx(150.0)

    def test_byte_counts(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow(src_bytes=1000, dst_bytes=500)
        ff = ext.extract(flow)
        assert ff.src_bytes == 1000
        assert ff.dst_bytes == 500


# ===================================================================
# FeatureExtractor — port extraction
# ===================================================================

class TestPortExtraction:
    """Source and destination ports."""

    def test_ports(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow()
        ff = ext.extract(flow)
        assert ff.src_port == 12345
        assert ff.dst_port == 80


# ===================================================================
# FeatureExtractor — connection behaviour (window features)
# ===================================================================

class TestConnectionBehaviour:
    """Window-based features: count, srv_count, dst_host_count, etc."""

    def test_count_same_host(self) -> None:
        """Multiple flows to same dst_ip within 2s increase count."""
        ext = FeatureExtractor()
        # First flow to 10.0.0.2:80
        flow1 = _tcp_flow()
        ext.extract(flow1)
        # Second flow to 10.0.0.2:443 (same host, different port)
        flow2 = Flow(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12346, dst_port=443, protocol=6,
            start_time=1001.0, end_time=1001.5,
            packets=[_pkt(dst_port=443, timestamp=1001.0)],
            src_bytes=100, dst_bytes=0, flags=[0x02],
        )
        ff2 = ext.extract(flow2)
        assert ff2.count >= 1  # At least 1 prior connection to same host

    def test_srv_count_same_service(self) -> None:
        """Multiple flows to same dst_port within 2s increase srv_count."""
        ext = FeatureExtractor()
        flow1 = _tcp_flow()
        ext.extract(flow1)
        flow2 = Flow(
            src_ip="10.0.0.3", dst_ip="10.0.0.4",
            src_port=23456, dst_port=80, protocol=6,
            start_time=1001.0, end_time=1001.5,
            packets=[_pkt(src_ip="10.0.0.3", dst_ip="10.0.0.4",
                          src_port=23456, dst_port=80, timestamp=1001.0)],
            src_bytes=100, dst_bytes=0, flags=[0x02],
        )
        ff2 = ext.extract(flow2)
        assert ff2.srv_count >= 1

    def test_fresh_extractor_has_zero_counts(self) -> None:
        """First flow extracted has count=0."""
        ext = FeatureExtractor()
        ff = ext.extract(_tcp_flow())
        assert ff.count == 0
        assert ff.srv_count == 0
        assert ff.dst_host_count == 0
        assert ff.dst_host_srv_count == 0


# ===================================================================
# FeatureExtractor — error rates
# ===================================================================

class TestErrorRates:
    """serror_rate and rerror_rate based on flag ratios."""

    def test_serror_rate_all_syn(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow(n_packets=4, flags_list=[0x02, 0x02, 0x02, 0x02])
        ff = ext.extract(flow)
        assert ff.serror_rate == pytest.approx(1.0)

    def test_rerror_rate_with_rst(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow(n_packets=4, flags_list=[0x02, 0x04, 0x04, 0x10])
        ff = ext.extract(flow)
        # 2 RSTs out of 4 packets
        assert ff.rerror_rate == pytest.approx(0.5)

    def test_no_errors(self) -> None:
        ext = FeatureExtractor()
        flow = _tcp_flow(n_packets=3, flags_list=[0x10, 0x10, 0x10])  # all ACK
        ff = ext.extract(flow)
        assert ff.serror_rate == pytest.approx(0.0)
        assert ff.rerror_rate == pytest.approx(0.0)
