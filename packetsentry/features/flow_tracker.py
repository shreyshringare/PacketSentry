"""Flow tracker: groups packets into bidirectional flows.

A flow is defined as all packets sharing the same 5-tuple:
(src_ip, src_port, dst_ip, dst_port, protocol).

Direction is normalised so that the lexicographically smaller
(IP, port) pair is always the "source" in the flow key.  This ensures
A→B and B→A packets join the same flow.

Key design decisions:
  - ``ParsedPacket`` is a lightweight dataclass so callers (live capture,
    PCAP replay) don't need to pass raw Scapy objects into the feature
    pipeline.  This also makes the module testable without Scapy.
  - Flows complete when a new packet exceeds ``timeout`` seconds from
    the flow's start time.
  - ``expire_flows()`` checks idle flows and should be called
    periodically in the main loop.
  - ``flush()`` collects remaining active flows at shutdown.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ParsedPacket:
    """Lightweight, protocol-agnostic packet representation.

    Created by the capture/dissector layer from a raw Scapy packet.
    All fields needed for flow tracking and feature extraction are
    captured here so downstream modules never touch Scapy directly.

    Attributes:
        timestamp: Epoch timestamp of the packet.
        src_ip: Source IP address string.
        dst_ip: Destination IP address string.
        src_port: Source port (0 for ICMP).
        dst_port: Destination port (0 for ICMP).
        protocol: IP protocol number (6=TCP, 17=UDP, 1=ICMP).
        length: Total packet length in bytes.
        flags: TCP flags bitmask (SYN=0x02, ACK=0x10, etc.).
        payload: Raw payload bytes.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    length: int
    flags: int = 0
    payload: bytes = b""


@dataclass
class Flow:
    """Bidirectional network flow.

    Accumulates packets between two endpoints identified by the
    normalised 5-tuple (smaller IP first).

    Attributes:
        src_ip: Normalised source IP (lexicographically smaller).
        dst_ip: Normalised destination IP.
        src_port: Port associated with src_ip in the normalised key.
        dst_port: Port associated with dst_ip in the normalised key.
        protocol: IP protocol number.
        start_time: Timestamp of the first packet.
        end_time: Timestamp of the most recent packet.
        packets: All packets belonging to this flow.
        src_bytes: Total bytes from the normalised source direction.
        dst_bytes: Total bytes from the normalised destination direction.
        flags: TCP flags seen in each packet (ordered list).
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    start_time: float = 0.0
    end_time: float = 0.0
    packets: list[ParsedPacket] = field(default_factory=list)
    src_bytes: int = 0
    dst_bytes: int = 0
    flags: list[int] = field(default_factory=list)

    @property
    def packet_count(self) -> int:
        """Number of packets in this flow."""
        return len(self.packets)

    @property
    def duration(self) -> float:
        """Flow duration in seconds (minimum 0.001 to avoid division by zero)."""
        if self.packet_count < 2:
            return 0.001
        return max(self.end_time - self.start_time, 0.001)


class FlowTracker:
    """Groups raw packets into flows using a configurable timeout window.

    A flow = all packets between the same (src_ip, dst_ip, src_port,
    dst_port, protocol) 5-tuple, with direction normalised so the
    smaller (IP, port) pair is always first.

    Usage::

        tracker = FlowTracker(timeout=60.0)
        for packet in packets:
            completed = tracker.add_packet(packet)
            if completed:
                features = extractor.extract(completed)

    Args:
        timeout: Seconds after which a flow is considered complete,
                 measured from the first packet's timestamp.
    """

    def __init__(self, timeout: float = 60.0) -> None:
        self.timeout = timeout
        self._active: dict[tuple, Flow] = {}
        self._completed: list[Flow] = []

    @property
    def active_count(self) -> int:
        """Number of currently tracked flows."""
        return len(self._active)

    @property
    def completed(self) -> list[Flow]:
        """All flows that have completed so far (defensive copy)."""
        return list(self._completed)

    def add_packet(self, packet: ParsedPacket) -> Flow | None:
        """Add a packet to its flow.

        Creates a new flow if no matching flow exists.  Updates byte
        counts and timestamps.  Returns the completed flow if the
        timeout has been exceeded, otherwise returns None.

        Args:
            packet: Parsed packet to add.

        Returns:
            The completed Flow if timeout was exceeded, else None.
        """
        key = self._flow_key(packet)

        if key not in self._active:
            self._active[key] = Flow(
                src_ip=key[0],
                dst_ip=key[2],
                src_port=key[1],
                dst_port=key[3],
                protocol=key[4],
                start_time=packet.timestamp,
            )

        flow = self._active[key]
        flow.packets.append(packet)
        flow.end_time = packet.timestamp
        flow.flags.append(packet.flags)
        self._update_bytes(flow, packet, key)

        return self._check_timeout(key, flow, packet.timestamp)

    def expire_flows(self, now: float | None = None) -> list[Flow]:
        """Check all active flows and return any that have timed out.

        Should be called periodically in the main capture loop to
        clean up idle flows that received no new packets.

        Args:
            now: Current timestamp.  Defaults to ``time.time()``.

        Returns:
            List of expired flows.
        """
        if now is None:
            now = time.time()

        expired: list[Flow] = []
        expired_keys: list[tuple] = []

        for key, flow in self._active.items():
            if now - flow.end_time > self.timeout:
                expired_keys.append(key)
                expired.append(flow)

        for key in expired_keys:
            del self._active[key]

        self._completed.extend(expired)
        return expired

    def flush(self) -> list[Flow]:
        """Return all active flows and clear the tracker.

        Used at shutdown or end of PCAP replay to collect remaining
        flows that haven't timed out yet.

        Returns:
            List of all active flows.
        """
        flows = list(self._active.values())
        self._completed.extend(flows)
        self._active.clear()
        return flows

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _flow_key(self, packet: ParsedPacket) -> tuple:
        """Compute normalised flow key.

        Direction is normalised so the lexicographically smaller
        (IP, port) pair is always first.  This ensures A→B and B→A
        packets belong to the same flow.
        """
        src = (packet.src_ip, packet.src_port)
        dst = (packet.dst_ip, packet.dst_port)
        proto = packet.protocol

        if src > dst:
            src, dst = dst, src

        return (src[0], src[1], dst[0], dst[1], proto)

    def _update_bytes(
        self, flow: Flow, packet: ParsedPacket, key: tuple
    ) -> None:
        """Update byte counters based on packet direction."""
        if packet.src_ip == key[0] and packet.src_port == key[1]:
            flow.src_bytes += packet.length
        else:
            flow.dst_bytes += packet.length

    def _check_timeout(
        self, key: tuple, flow: Flow, now: float
    ) -> Flow | None:
        """Check if flow has exceeded the timeout window."""
        if flow.packet_count > 1 and (now - flow.start_time) > self.timeout:
            completed = self._active.pop(key)
            self._completed.append(completed)
            logger.debug(
                "Flow completed: %s:%d → %s:%d proto=%d (%d pkts, %.1fs)",
                completed.src_ip,
                completed.src_port,
                completed.dst_ip,
                completed.dst_port,
                completed.protocol,
                completed.packet_count,
                completed.duration,
            )
            return completed
        return None
