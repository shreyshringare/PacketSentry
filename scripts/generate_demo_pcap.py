#!/usr/bin/env python3
"""Generate a synthetic attack.pcap for PacketSentry demo/testing.

Creates a PCAP containing:
  - SQL injection payload in HTTP request body
  - XSS payload in HTTP GET parameter
  - Port scan (SYN packets to 20 ports)
  - Path traversal attempt
  - Normal HTTP background traffic

Usage:
    python scripts/generate_demo_pcap.py          # writes attack.pcap
    python scripts/generate_demo_pcap.py --out /tmp/demo.pcap
"""

from __future__ import annotations

from pathlib import Path

import typer

app = typer.Typer(help="Generate synthetic attack PCAP for PacketSentry demo.")


@app.command()
def generate(
    out: Path = typer.Option(Path("attack.pcap"), "--out", "-o", help="Output PCAP path."),
) -> None:
    """Write a synthetic attack PCAP to disk."""
    try:
        from scapy.all import (
            IP, TCP, Raw, wrpcap, Ether,
        )
    except ImportError:
        typer.echo("ERROR: scapy is required. Run: pip install scapy", err=True)
        raise typer.Exit(1)

    packets = []
    attacker = "192.168.1.100"
    victim = "10.0.0.1"
    base_sport = 50000

    def _tcp_pkt(sport: int, dport: int, payload: bytes, flags: str = "PA") -> object:
        return (
            Ether()
            / IP(src=attacker, dst=victim)
            / TCP(sport=sport, dport=dport, flags=flags, seq=1000)
            / Raw(load=payload)
        )

    # Normal HTTP traffic (background)
    for i in range(10):
        packets.append(_tcp_pkt(
            sport=base_sport + i, dport=80,
            payload=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ))

    # SQL injection
    packets.append(_tcp_pkt(
        sport=base_sport + 100, dport=80,
        payload=b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin' OR '1'='1&pass=x"
    ))

    # XSS
    packets.append(_tcp_pkt(
        sport=base_sport + 101, dport=80,
        payload=b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: example.com\r\n\r\n"
    ))

    # Path traversal
    packets.append(_tcp_pkt(
        sport=base_sport + 102, dport=80,
        payload=b"GET /../../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n"
    ))

    # Port scan (SYN packets to 20 ports)
    for port in range(20, 40):
        packets.append(
            Ether()
            / IP(src=attacker, dst=victim)
            / TCP(sport=base_sport + 200 + port, dport=port, flags="S")
        )

    # Command injection
    packets.append(_tcp_pkt(
        sport=base_sport + 103, dport=80,
        payload=b"POST /exec HTTP/1.1\r\n\r\ncmd=ls; /bin/sh -i"
    ))

    wrpcap(str(out), packets)
    typer.echo(f"[OK] Wrote {len(packets)} packets to {out}")
    typer.echo("     Run: packetsentry replay attack.pcap --speed 0.0")


if __name__ == "__main__":
    app()
