"""Ethernet (Layer 2) dissector."""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class EthernetFrame:
    """Parsed Ethernet frame fields."""

    src: str
    dst: str
    ethertype: int


def parse(packet) -> EthernetFrame | None:
    """
    Parse a Scapy packet into an EthernetFrame.

    Args:
        packet: Scapy packet object.

    Returns:
        EthernetFrame if the packet has an Ethernet layer, else None.
    """
    if packet is None:
        logger.warning("ethernet.parse: received None packet")
        return None

    try:
        layer = packet["Ether"]
    except (KeyError, Exception):
        logger.warning("ethernet.parse: no Ethernet layer in packet")
        return None

    return EthernetFrame(
        src=layer.src,
        dst=layer.dst,
        ethertype=layer.type,
    )
