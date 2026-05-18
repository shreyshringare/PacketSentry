"""IP (Layer 3) dissector."""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class IPPacket:
    """Parsed IPv4 packet fields."""

    src: str
    dst: str
    proto: int
    ttl: int
    length: int


def parse(packet) -> IPPacket | None:
    """
    Parse a Scapy packet into an IPPacket.

    Args:
        packet: Scapy packet object.

    Returns:
        IPPacket if the packet has an IP layer, else None.
    """
    if packet is None:
        logger.warning("ip.parse: received None packet")
        return None

    try:
        layer = packet["IP"]
    except (KeyError, Exception):
        logger.warning("ip.parse: no IP layer in packet")
        return None

    # layer.len may be None on unbuilt packets — fall back to actual byte length
    length = layer.len if layer.len is not None else len(bytes(layer))

    return IPPacket(
        src=layer.src,
        dst=layer.dst,
        proto=layer.proto,
        ttl=layer.ttl,
        length=length,
    )
