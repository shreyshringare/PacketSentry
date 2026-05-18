"""Feature extractor: computes 23 NSL-KDD aligned features per flow.

The 23 features are designed to bridge raw Scapy packet captures and
the ML detection models.  They cover four categories:

  1. **Basic** — duration, protocol, byte counts
  2. **TCP flags** — SYN/ACK/FIN/RST/PSH counts
  3. **Traffic statistics** — rates, averages
  4. **Connection behaviour** — window-based counts (NSL-KDD style)

The extractor is **stateful**: it maintains a sliding window of recent
flows to compute connection behaviour features (count, srv_count,
dst_host_count, etc.) just like the NSL-KDD dataset computes them.

Usage::

    extractor = FeatureExtractor()
    for flow in completed_flows:
        features = extractor.extract(flow)
        vec = features.to_vector()  # shape (23,), dtype float32
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass

import numpy as np

from packetsentry.features.flow_tracker import Flow

logger = logging.getLogger(__name__)

# TCP flag bitmasks
_SYN = 0x02
_ACK = 0x10
_FIN = 0x01
_RST = 0x04
_PSH = 0x08


@dataclass
class FlowFeatures:
    """23 features aligned with the NSL-KDD dataset.

    Attributes:
        duration: Flow duration in seconds (min 0.001).
        protocol_type: 0=TCP, 1=UDP, 2=ICMP, 3=other.
        src_bytes: Bytes from source direction.
        dst_bytes: Bytes from destination direction.
        flag_syn: Number of packets with SYN flag set.
        flag_ack: Number of packets with ACK flag set.
        flag_fin: Number of packets with FIN flag set.
        flag_rst: Number of packets with RST flag set.
        flag_psh: Number of packets with PSH flag set.
        packet_count: Total number of packets in the flow.
        avg_packet_size: Mean bytes per packet.
        bytes_per_second: Total bytes / duration.
        packets_per_second: Total packets / duration.
        count: Connections to same host in last 2 seconds.
        srv_count: Connections to same service in last 2 seconds.
        dst_host_count: Connections to same dst in last 100 connections.
        dst_host_srv_count: Same dst + service in last 100 connections.
        serror_rate: Fraction of packets with SYN flag (SYN error proxy).
        rerror_rate: Fraction of packets with RST flag (REJ error proxy).
        same_srv_rate: Fraction of recent connections to same service.
        diff_srv_rate: Fraction of recent connections to different service.
        src_port: Source port number.
        dst_port: Destination port number.
    """

    # Basic
    duration: float
    protocol_type: int
    src_bytes: int
    dst_bytes: int

    # TCP flags
    flag_syn: int
    flag_ack: int
    flag_fin: int
    flag_rst: int
    flag_psh: int

    # Traffic statistics
    packet_count: int
    avg_packet_size: float
    bytes_per_second: float
    packets_per_second: float

    # Connection behaviour (sliding window)
    count: int
    srv_count: int
    dst_host_count: int
    dst_host_srv_count: int

    # Error rates
    serror_rate: float
    rerror_rate: float
    same_srv_rate: float
    diff_srv_rate: float

    # Port info
    src_port: int
    dst_port: int

    def to_vector(self) -> np.ndarray:
        """Convert to numpy array for ML models.

        Returns:
            Array of shape ``(23,)`` with dtype ``float32``.
        """
        return np.array([
            self.duration, self.protocol_type, self.src_bytes,
            self.dst_bytes, self.flag_syn, self.flag_ack, self.flag_fin,
            self.flag_rst, self.flag_psh, self.packet_count,
            self.avg_packet_size, self.bytes_per_second,
            self.packets_per_second, self.count, self.srv_count,
            self.dst_host_count, self.dst_host_srv_count,
            self.serror_rate, self.rerror_rate, self.same_srv_rate,
            self.diff_srv_rate, self.src_port, self.dst_port,
        ], dtype=np.float32)


class FeatureExtractor:
    """Computes FlowFeatures from a completed Flow.

    Maintains a sliding window of recent flows to compute NSL-KDD
    style connection behaviour features.

    Args:
        time_window: Seconds for time-based features (count, srv_count).
        conn_window: Number of recent connections for host-based features.
    """

    def __init__(
        self,
        time_window: float = 2.0,
        conn_window: int = 100,
    ) -> None:
        self._time_window = time_window
        self._conn_window = conn_window
        # (end_time, dst_ip, dst_port)
        self._recent_by_time: deque[tuple[float, str, int]] = deque()
        # (dst_ip, dst_port)
        self._recent_by_conn: deque[tuple[str, int]] = deque(
            maxlen=conn_window,
        )

    def extract(self, flow: Flow) -> FlowFeatures:
        """Extract 23 features from a completed flow.

        Args:
            flow: A completed Flow from FlowTracker.

        Returns:
            FlowFeatures with all 23 fields populated.
        """
        duration = flow.duration
        pkt_count = flow.packet_count
        total_bytes = flow.src_bytes + flow.dst_bytes
        flags = self._count_flags(flow)

        # Connection behaviour (before updating the window)
        count, srv_count = self._time_based_counts(
            flow.end_time, flow.dst_ip, flow.dst_port,
        )
        dst_host_count, dst_host_srv_count = self._conn_based_counts(
            flow.dst_ip, flow.dst_port,
        )
        same_srv, diff_srv = self._service_rates(flow.dst_port)

        # Update the window AFTER computing features for this flow
        self._recent_by_time.append(
            (flow.end_time, flow.dst_ip, flow.dst_port),
        )
        self._recent_by_conn.append((flow.dst_ip, flow.dst_port))

        return FlowFeatures(
            duration=duration,
            protocol_type=self._protocol_type(flow.protocol),
            src_bytes=flow.src_bytes,
            dst_bytes=flow.dst_bytes,
            flag_syn=flags["SYN"],
            flag_ack=flags["ACK"],
            flag_fin=flags["FIN"],
            flag_rst=flags["RST"],
            flag_psh=flags["PSH"],
            packet_count=pkt_count,
            avg_packet_size=total_bytes / max(pkt_count, 1),
            bytes_per_second=total_bytes / duration,
            packets_per_second=pkt_count / duration,
            count=count,
            srv_count=srv_count,
            dst_host_count=dst_host_count,
            dst_host_srv_count=dst_host_srv_count,
            serror_rate=flags["SYN"] / max(pkt_count, 1),
            rerror_rate=flags["RST"] / max(pkt_count, 1),
            same_srv_rate=same_srv,
            diff_srv_rate=diff_srv,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _protocol_type(proto: int) -> int:
        """Map IP protocol number to NSL-KDD encoding.

        Returns:
            0 for TCP, 1 for UDP, 2 for ICMP, 3 for anything else.
        """
        return {6: 0, 17: 1, 1: 2}.get(proto, 3)

    @staticmethod
    def _count_flags(flow: Flow) -> dict[str, int]:
        """Count TCP flag occurrences across all packets in the flow."""
        counts = {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0}
        for f in flow.flags:
            if f & _SYN:
                counts["SYN"] += 1
            if f & _ACK:
                counts["ACK"] += 1
            if f & _FIN:
                counts["FIN"] += 1
            if f & _RST:
                counts["RST"] += 1
            if f & _PSH:
                counts["PSH"] += 1
        return counts

    def _time_based_counts(
        self, now: float, dst_ip: str, dst_port: int,
    ) -> tuple[int, int]:
        """Compute count and srv_count from the time window.

        - count: connections to same dst_ip in last ``time_window`` seconds.
        - srv_count: connections to same dst_port in last ``time_window`` seconds.
        """
        # Evict old entries
        cutoff = now - self._time_window
        while self._recent_by_time and self._recent_by_time[0][0] < cutoff:
            self._recent_by_time.popleft()

        count = sum(1 for _, ip, _ in self._recent_by_time if ip == dst_ip)
        srv_count = sum(
            1 for _, _, port in self._recent_by_time if port == dst_port
        )
        return count, srv_count

    def _conn_based_counts(
        self, dst_ip: str, dst_port: int,
    ) -> tuple[int, int]:
        """Compute dst_host_count and dst_host_srv_count from last N connections."""
        dst_host_count = sum(
            1 for ip, _ in self._recent_by_conn if ip == dst_ip
        )
        dst_host_srv_count = sum(
            1 for ip, port in self._recent_by_conn
            if ip == dst_ip and port == dst_port
        )
        return dst_host_count, dst_host_srv_count

    def _service_rates(self, dst_port: int) -> tuple[float, float]:
        """Compute same_srv_rate and diff_srv_rate from recent connections."""
        if not self._recent_by_conn:
            return 0.0, 0.0

        total = len(self._recent_by_conn)
        same = sum(1 for _, port in self._recent_by_conn if port == dst_port)
        return same / total, (total - same) / total
