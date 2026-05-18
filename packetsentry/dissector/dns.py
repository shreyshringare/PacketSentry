"""DNS (application layer) dissector."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class DNSMessage:
    """Parsed DNS message fields."""

    qname: str
    qtype: int
    is_response: bool
    answers: list[str] = field(default_factory=list)


def parse(packet) -> DNSMessage | None:
    """
    Parse a Scapy packet into a DNSMessage.

    Args:
        packet: Scapy packet object.

    Returns:
        DNSMessage if the packet has a DNS layer, else None.
    """
    if packet is None:
        logger.warning("dns.parse: received None packet")
        return None

    try:
        layer = packet["DNS"]
    except (KeyError, Exception):
        logger.warning("dns.parse: no DNS layer in packet")
        return None

    # Extract query name — Scapy returns bytes with trailing dot
    qname = ""
    qtype = 0
    if layer.qd is not None:
        raw = layer.qd.qname
        qname = raw.decode() if isinstance(raw, bytes) else str(raw)
        qname = qname.rstrip(".")
        qtype = int(layer.qd.qtype)

    # Extract answer RRs — layer.an is a PacketListField in Scapy ≥ 2.5
    answers: list[str] = []
    if layer.qr == 1:
        try:
            an_list = layer.an  # PacketListField — iterable
            for rr in an_list:
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    answers.append(rdata.decode(errors="replace"))
                else:
                    answers.append(str(rdata))
        except Exception:
            pass

    return DNSMessage(
        qname=qname,
        qtype=qtype,
        is_response=bool(layer.qr),
        answers=answers,
    )
