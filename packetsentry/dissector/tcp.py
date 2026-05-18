"""TCP (Layer 4) dissector."""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Scapy TCP flag bitmasks
_SYN = 0x02
_ACK = 0x10
_FIN = 0x01
_RST = 0x04
_PSH = 0x08


@dataclass
class TCPSegment:
    """Parsed TCP segment fields."""

    sport: int
    dport: int
    seq: int
    ack: int
    window: int
    flags_syn: bool
    flags_ack: bool
    flags_fin: bool
    flags_rst: bool
    flags_psh: bool


def parse(packet) -> TCPSegment | None:
    """
    Parse a Scapy packet into a TCPSegment.

    Args:
        packet: Scapy packet object.

    Returns:
        TCPSegment if the packet has a TCP layer, else None.
    """
    if packet is None:
        logger.warning("tcp.parse: received None packet")
        return None

    try:
        layer = packet["TCP"]
    except (KeyError, Exception):
        logger.warning("tcp.parse: no TCP layer in packet")
        return None

    flags = int(layer.flags)
    return TCPSegment(
        sport=layer.sport,
        dport=layer.dport,
        seq=layer.seq,
        ack=layer.ack,
        window=layer.window,
        flags_syn=bool(flags & _SYN),
        flags_ack=bool(flags & _ACK),
        flags_fin=bool(flags & _FIN),
        flags_rst=bool(flags & _RST),
        flags_psh=bool(flags & _PSH),
    )
