"""UDP (Layer 4) dissector."""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class UDPDatagram:
    """Parsed UDP datagram fields."""

    sport: int
    dport: int
    length: int


def parse(packet) -> UDPDatagram | None:
    """
    Parse a Scapy packet into a UDPDatagram.

    Args:
        packet: Scapy packet object.

    Returns:
        UDPDatagram if the packet has a UDP layer, else None.
    """
    if packet is None:
        logger.warning("udp.parse: received None packet")
        return None

    try:
        layer = packet["UDP"]
    except (KeyError, Exception):
        logger.warning("udp.parse: no UDP layer in packet")
        return None

    return UDPDatagram(
        sport=layer.sport,
        dport=layer.dport,
        length=layer.len,
    )
