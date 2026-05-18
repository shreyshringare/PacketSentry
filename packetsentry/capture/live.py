"""Live packet capture via Scapy.

Uses ``scapy.sniff()`` in a background thread to capture packets off a
network interface, convert them to ``ParsedPacket``s, and feed them
into the ``DetectionPipeline``.

Requirements:
  - Windows: Npcap must be installed (https://npcap.com)
  - Linux:   root or CAP_NET_RAW capability

Usage::

    from packetsentry.capture.pipeline import DetectionPipeline
    from packetsentry.capture.live import start_live_capture

    pipeline = DetectionPipeline()
    start_live_capture("Wi-Fi", pipeline)
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

from scapy.all import IP, TCP, UDP, Ether, sniff  # type: ignore

from packetsentry.capture.pipeline import DetectionPipeline
from packetsentry.detection.ensemble import DecisionResult
from packetsentry.features.flow_tracker import ParsedPacket

logger = logging.getLogger(__name__)


def scapy_to_parsed(pkt) -> ParsedPacket | None:
    """Convert a raw Scapy packet to our ParsedPacket dataclass.

    Returns None for packets without an IP layer (ARP, etc).
    """
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    proto = ip.proto
    src_port = 0
    dst_port = 0
    flags = 0
    payload = b""

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = int(tcp.flags)
        if tcp.payload:
            payload = bytes(tcp.payload)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        if udp.payload:
            payload = bytes(udp.payload)

    return ParsedPacket(
        timestamp=float(pkt.time),
        src_ip=ip.src,
        dst_ip=ip.dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        length=len(pkt),
        flags=flags,
        payload=payload,
    )


def start_live_capture(
    interface: str,
    pipeline: DetectionPipeline,
    alert_callback: Callable[[DecisionResult], None] | None = None,
    stop_event: threading.Event | None = None,
    packet_count: int = 0,
) -> None:
    """Start capturing packets on the given interface.

    This function blocks until ``stop_event`` is set or ``packet_count``
    packets have been captured (0 = infinite).

    Args:
        interface: Network interface name (e.g. "Wi-Fi", "eth0").
        pipeline: The detection pipeline to feed packets into.
        alert_callback: Called with each DecisionResult that is an alert.
        stop_event: Threading event to signal graceful shutdown.
        packet_count: Max packets to capture (0 = unlimited).
    """
    _stop = stop_event or threading.Event()

    def _on_packet(pkt):
        if _stop.is_set():
            return

        parsed = scapy_to_parsed(pkt)
        if parsed is None:
            return

        result = pipeline.ingest(parsed)
        if result and result.is_alert and alert_callback:
            alert_callback(result)

    logger.info("Starting live capture on interface '%s'", interface)
    try:
        sniff(
            iface=interface,
            prn=_on_packet,
            store=False,
            count=packet_count,
            stop_filter=lambda _: _stop.is_set(),
        )
    except PermissionError:
        logger.error(
            "Permission denied — live capture requires admin/root. "
            "On Windows, install Npcap (https://npcap.com)."
        )
        raise
    except OSError as e:
        logger.error("Capture error on '%s': %s", interface, e)
        raise
    finally:
        # Flush remaining flows at shutdown
        pipeline.flush()
        logger.info("Live capture stopped. %s", pipeline.stats())
