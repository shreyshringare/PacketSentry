"""Tests for features.flow_tracker — written BEFORE implementation (TDD).

Covers:
  - ParsedPacket dataclass construction
  - Flow key normalisation (smaller IP first)
  - Flow creation and packet grouping
  - Bidirectional flow tracking (A→B and B→A)
  - Byte counting per direction
  - Timeout-based flow completion
  - expire_flows() for idle cleanup
  - flush() for shutdown collection
  - Edge cases: ICMP (no ports), concurrent flows
"""

from __future__ import annotations

import pytest

from packetsentry.features.flow_tracker import Flow, FlowTracker, ParsedPacket


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
    """Shorthand factory for test packets."""
    return ParsedPacket(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        flags=flags,
        payload=payload,
    )


# ===================================================================
# ParsedPacket
# ===================================================================

class TestParsedPacket:
    """ParsedPacket dataclass basics."""

    def test_creation(self) -> None:
        pkt = _pkt()
        assert pkt.src_ip == "10.0.0.1"
        assert pkt.dst_ip == "10.0.0.2"
        assert pkt.protocol == 6

    def test_defaults(self) -> None:
        pkt = _pkt()
        assert pkt.flags == 0
        assert pkt.payload == b""

    def test_tcp_flags(self) -> None:
        pkt = _pkt(flags=0x12)  # SYN+ACK
        assert pkt.flags == 0x12


# ===================================================================
# Flow dataclass
# ===================================================================

class TestFlow:
    """Flow properties and invariants."""

    def test_packet_count(self) -> None:
        flow = Flow(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, protocol=6,
        )
        assert flow.packet_count == 0

    def test_duration_single_packet(self) -> None:
        flow = Flow(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, protocol=6,
        )
        # Single-packet flow → minimum duration 0.001
        assert flow.duration == pytest.approx(0.001)

    def test_duration_multi_packet(self) -> None:
        flow = Flow(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, protocol=6,
            start_time=100.0, end_time=105.5,
            packets=[_pkt(timestamp=100.0), _pkt(timestamp=105.5)],
        )
        assert flow.duration == pytest.approx(5.5)


# ===================================================================
# FlowTracker — key normalisation
# ===================================================================

class TestFlowKey:
    """Flow key normalises direction so smaller IP is always first."""

    def test_forward_and_reverse_same_key(self) -> None:
        tracker = FlowTracker()
        fwd = _pkt(src_ip="10.0.0.1", dst_ip="10.0.0.2")
        rev = _pkt(src_ip="10.0.0.2", dst_ip="10.0.0.1",
                    src_port=80, dst_port=12345)
        assert tracker._flow_key(fwd) == tracker._flow_key(rev)

    def test_different_ports_different_key(self) -> None:
        tracker = FlowTracker()
        p1 = _pkt(dst_port=80)
        p2 = _pkt(dst_port=443)
        assert tracker._flow_key(p1) != tracker._flow_key(p2)

    def test_different_protocol_different_key(self) -> None:
        tracker = FlowTracker()
        tcp = _pkt(protocol=6)
        udp = _pkt(protocol=17)
        assert tracker._flow_key(tcp) != tracker._flow_key(udp)


# ===================================================================
# FlowTracker — basic tracking
# ===================================================================

class TestFlowTracking:
    """Adding packets creates and groups flows."""

    def test_first_packet_creates_flow(self) -> None:
        tracker = FlowTracker()
        tracker.add_packet(_pkt())
        assert tracker.active_count == 1

    def test_same_flow_packets_grouped(self) -> None:
        tracker = FlowTracker()
        tracker.add_packet(_pkt(timestamp=1000.0))
        tracker.add_packet(_pkt(timestamp=1001.0))
        assert tracker.active_count == 1

    def test_different_flows_separate(self) -> None:
        tracker = FlowTracker()
        tracker.add_packet(_pkt(dst_port=80))
        tracker.add_packet(_pkt(dst_port=443))
        assert tracker.active_count == 2

    def test_bidirectional_same_flow(self) -> None:
        """A→B and B→A should land in the same flow."""
        tracker = FlowTracker()
        tracker.add_packet(_pkt(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, timestamp=1000.0,
        ))
        tracker.add_packet(_pkt(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=12345, timestamp=1001.0,
        ))
        assert tracker.active_count == 1


# ===================================================================
# FlowTracker — byte counting
# ===================================================================

class TestByteTracking:
    """Byte counts are attributed to the correct direction."""

    def test_src_bytes(self) -> None:
        tracker = FlowTracker()
        tracker.add_packet(_pkt(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, length=200,
        ))
        key = list(tracker._active.keys())[0]
        flow = tracker._active[key]
        assert flow.src_bytes == 200

    def test_dst_bytes_reverse_direction(self) -> None:
        tracker = FlowTracker()
        # Forward packet (src is the normalised "source")
        tracker.add_packet(_pkt(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, length=100,
        ))
        # Reverse packet
        tracker.add_packet(_pkt(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=12345, length=300, timestamp=1001.0,
        ))
        key = list(tracker._active.keys())[0]
        flow = tracker._active[key]
        assert flow.src_bytes == 100
        assert flow.dst_bytes == 300


# ===================================================================
# FlowTracker — timeout
# ===================================================================

class TestTimeout:
    """Flows complete when the timeout window is exceeded."""

    def test_no_timeout_returns_none(self) -> None:
        tracker = FlowTracker(timeout=60.0)
        result = tracker.add_packet(_pkt(timestamp=1000.0))
        assert result is None

    def test_timeout_returns_completed_flow(self) -> None:
        tracker = FlowTracker(timeout=60.0)
        tracker.add_packet(_pkt(timestamp=1000.0))
        result = tracker.add_packet(_pkt(timestamp=1061.0))
        assert result is not None
        assert isinstance(result, Flow)
        assert result.packet_count == 2

    def test_completed_flow_removed_from_active(self) -> None:
        tracker = FlowTracker(timeout=60.0)
        tracker.add_packet(_pkt(timestamp=1000.0))
        tracker.add_packet(_pkt(timestamp=1061.0))
        assert tracker.active_count == 0

    def test_completed_flow_in_completed_list(self) -> None:
        tracker = FlowTracker(timeout=60.0)
        tracker.add_packet(_pkt(timestamp=1000.0))
        tracker.add_packet(_pkt(timestamp=1061.0))
        assert len(tracker.completed) == 1


# ===================================================================
# FlowTracker — expire_flows
# ===================================================================

class TestExpireFlows:
    """Periodic expiration of idle flows."""

    def test_expire_idle_flow(self) -> None:
        tracker = FlowTracker(timeout=60.0)
        tracker.add_packet(_pkt(timestamp=1000.0))
        expired = tracker.expire_flows(now=1061.0)
        assert len(expired) == 1
        assert tracker.active_count == 0

    def test_no_expire_active_flow(self) -> None:
        tracker = FlowTracker(timeout=60.0)
        tracker.add_packet(_pkt(timestamp=1000.0))
        expired = tracker.expire_flows(now=1030.0)
        assert len(expired) == 0
        assert tracker.active_count == 1

    def test_expire_selective(self) -> None:
        """Only idle flows expire; active ones remain."""
        tracker = FlowTracker(timeout=60.0)
        tracker.add_packet(_pkt(dst_port=80, timestamp=1000.0))
        tracker.add_packet(_pkt(dst_port=443, timestamp=1050.0))
        expired = tracker.expire_flows(now=1061.0)
        # Port 80 flow expired (idle 61s), port 443 still active (11s)
        assert len(expired) == 1
        assert tracker.active_count == 1


# ===================================================================
# FlowTracker — flush
# ===================================================================

class TestFlush:
    """flush() returns all active flows and clears tracker."""

    def test_flush_returns_all(self) -> None:
        tracker = FlowTracker()
        tracker.add_packet(_pkt(dst_port=80))
        tracker.add_packet(_pkt(dst_port=443))
        flushed = tracker.flush()
        assert len(flushed) == 2
        assert tracker.active_count == 0

    def test_flush_empty_tracker(self) -> None:
        tracker = FlowTracker()
        assert tracker.flush() == []


# ===================================================================
# FlowTracker — edge cases
# ===================================================================

class TestEdgeCases:
    """Protocol edge cases."""

    def test_icmp_no_ports(self) -> None:
        tracker = FlowTracker()
        tracker.add_packet(_pkt(protocol=1, src_port=0, dst_port=0))
        assert tracker.active_count == 1

    def test_udp_flow(self) -> None:
        tracker = FlowTracker()
        tracker.add_packet(_pkt(protocol=17, dst_port=53, timestamp=1000.0))
        tracker.add_packet(_pkt(protocol=17, dst_port=53, timestamp=1001.0))
        assert tracker.active_count == 1

    def test_flag_accumulation(self) -> None:
        tracker = FlowTracker()
        tracker.add_packet(_pkt(flags=0x02, timestamp=1000.0))  # SYN
        tracker.add_packet(_pkt(flags=0x12, timestamp=1001.0))  # SYN+ACK
        tracker.add_packet(_pkt(flags=0x10, timestamp=1002.0))  # ACK
        key = list(tracker._active.keys())[0]
        flow = tracker._active[key]
        assert flow.flags == [0x02, 0x12, 0x10]

    def test_many_concurrent_flows(self) -> None:
        tracker = FlowTracker()
        for port in range(1000, 1050):
            tracker.add_packet(_pkt(dst_port=port))
        assert tracker.active_count == 50
