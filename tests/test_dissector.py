"""
Tests for protocol dissector stack.

Written BEFORE implementation (TDD — RED phase).
Each test will fail until the corresponding dissector is implemented.

Dissector contract:
  - parse(packet) → dataclass | None
  - Unknown/missing layer → log via logging module, return None
  - Never raise on malformed input
  - All fields typed, all classes are dataclasses

Packet construction uses real Scapy objects (no mocks).
"""

import logging

import pytest

# Scapy imports — real packets, no mocks
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from packetsentry.dissector.ethernet import EthernetFrame, parse as parse_ethernet
from packetsentry.dissector.ip import IPPacket, parse as parse_ip
from packetsentry.dissector.tcp import TCPSegment, parse as parse_tcp
from packetsentry.dissector.udp import UDPDatagram, parse as parse_udp
from packetsentry.dissector.dns import DNSMessage, parse as parse_dns


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def eth_pkt():
    return Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66", type=0x0800)


@pytest.fixture()
def ip_pkt():
    return Ether() / IP(src="192.168.1.1", dst="10.0.0.1", proto=6, ttl=64)


@pytest.fixture()
def tcp_pkt():
    return Ether() / IP() / TCP(sport=12345, dport=80, flags="S", seq=100, ack=0, window=65535)


@pytest.fixture()
def udp_pkt():
    return Ether() / IP() / UDP(sport=54321, dport=53, len=20)


@pytest.fixture()
def dns_query_pkt():
    return (
        Ether() / IP() / UDP(dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )


@pytest.fixture()
def dns_response_pkt():
    return (
        Ether() / IP() / UDP(sport=53)
        / DNS(
            qr=1, rd=1, ra=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34"),
        )
    )


# ---------------------------------------------------------------------------
# EthernetFrame
# ---------------------------------------------------------------------------

class TestEthernetParse:
    def test_src_mac(self, eth_pkt):
        frame = parse_ethernet(eth_pkt)
        assert frame is not None
        assert frame.src == "aa:bb:cc:dd:ee:ff"

    def test_dst_mac(self, eth_pkt):
        frame = parse_ethernet(eth_pkt)
        assert frame is not None
        assert frame.dst == "11:22:33:44:55:66"

    def test_ethertype_ipv4(self, eth_pkt):
        frame = parse_ethernet(eth_pkt)
        assert frame is not None
        assert frame.ethertype == 0x0800

    def test_returns_ethernet_frame_dataclass(self, eth_pkt):
        frame = parse_ethernet(eth_pkt)
        assert isinstance(frame, EthernetFrame)

    def test_no_ethernet_layer_returns_none(self, caplog):
        """Packet without Ethernet layer → None, no crash."""
        raw_ip = IP(src="1.2.3.4", dst="5.6.7.8")
        with caplog.at_level(logging.WARNING):
            result = parse_ethernet(raw_ip)
        assert result is None

    def test_none_input_returns_none(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = parse_ethernet(None)
        assert result is None


# ---------------------------------------------------------------------------
# IPPacket
# ---------------------------------------------------------------------------

class TestIPParse:
    def test_src_ip(self, ip_pkt):
        pkt = parse_ip(ip_pkt)
        assert pkt is not None
        assert pkt.src == "192.168.1.1"

    def test_dst_ip(self, ip_pkt):
        pkt = parse_ip(ip_pkt)
        assert pkt is not None
        assert pkt.dst == "10.0.0.1"

    def test_protocol(self, ip_pkt):
        pkt = parse_ip(ip_pkt)
        assert pkt is not None
        assert pkt.proto == 6  # TCP

    def test_ttl(self, ip_pkt):
        pkt = parse_ip(ip_pkt)
        assert pkt is not None
        assert pkt.ttl == 64

    def test_length_is_int(self, ip_pkt):
        pkt = parse_ip(ip_pkt)
        assert pkt is not None
        assert isinstance(pkt.length, int)

    def test_returns_ip_packet_dataclass(self, ip_pkt):
        pkt = parse_ip(ip_pkt)
        assert isinstance(pkt, IPPacket)

    def test_no_ip_layer_returns_none(self, caplog):
        eth_only = Ether()
        with caplog.at_level(logging.WARNING):
            result = parse_ip(eth_only)
        assert result is None

    def test_udp_protocol(self):
        pkt = Ether() / IP(proto=17)
        result = parse_ip(pkt)
        assert result is not None
        assert result.proto == 17

    def test_icmp_protocol(self):
        pkt = Ether() / IP(proto=1)
        result = parse_ip(pkt)
        assert result is not None
        assert result.proto == 1


# ---------------------------------------------------------------------------
# TCPSegment
# ---------------------------------------------------------------------------

class TestTCPParse:
    def test_sport(self, tcp_pkt):
        seg = parse_tcp(tcp_pkt)
        assert seg is not None
        assert seg.sport == 12345

    def test_dport(self, tcp_pkt):
        seg = parse_tcp(tcp_pkt)
        assert seg is not None
        assert seg.dport == 80

    def test_syn_flag(self, tcp_pkt):
        seg = parse_tcp(tcp_pkt)
        assert seg is not None
        assert seg.flags_syn is True
        assert seg.flags_ack is False

    def test_ack_flag(self):
        pkt = Ether() / IP() / TCP(flags="A")
        seg = parse_tcp(pkt)
        assert seg is not None
        assert seg.flags_ack is True
        assert seg.flags_syn is False

    def test_fin_flag(self):
        pkt = Ether() / IP() / TCP(flags="F")
        seg = parse_tcp(pkt)
        assert seg is not None
        assert seg.flags_fin is True

    def test_rst_flag(self):
        pkt = Ether() / IP() / TCP(flags="R")
        seg = parse_tcp(pkt)
        assert seg is not None
        assert seg.flags_rst is True

    def test_psh_flag(self):
        pkt = Ether() / IP() / TCP(flags="P")
        seg = parse_tcp(pkt)
        assert seg is not None
        assert seg.flags_psh is True

    def test_seq(self, tcp_pkt):
        seg = parse_tcp(tcp_pkt)
        assert seg is not None
        assert seg.seq == 100

    def test_window(self, tcp_pkt):
        seg = parse_tcp(tcp_pkt)
        assert seg is not None
        assert seg.window == 65535

    def test_returns_tcp_segment_dataclass(self, tcp_pkt):
        seg = parse_tcp(tcp_pkt)
        assert isinstance(seg, TCPSegment)

    def test_no_tcp_layer_returns_none(self, caplog):
        pkt = Ether() / IP() / UDP()
        with caplog.at_level(logging.WARNING):
            result = parse_tcp(pkt)
        assert result is None

    def test_synack_flags(self):
        pkt = Ether() / IP() / TCP(flags="SA")
        seg = parse_tcp(pkt)
        assert seg is not None
        assert seg.flags_syn is True
        assert seg.flags_ack is True


# ---------------------------------------------------------------------------
# UDPDatagram
# ---------------------------------------------------------------------------

class TestUDPParse:
    def test_sport(self, udp_pkt):
        dgram = parse_udp(udp_pkt)
        assert dgram is not None
        assert dgram.sport == 54321

    def test_dport(self, udp_pkt):
        dgram = parse_udp(udp_pkt)
        assert dgram is not None
        assert dgram.dport == 53

    def test_length_is_int(self, udp_pkt):
        dgram = parse_udp(udp_pkt)
        assert dgram is not None
        assert isinstance(dgram.length, int)

    def test_returns_udp_datagram_dataclass(self, udp_pkt):
        dgram = parse_udp(udp_pkt)
        assert isinstance(dgram, UDPDatagram)

    def test_no_udp_layer_returns_none(self, caplog):
        pkt = Ether() / IP() / TCP()
        with caplog.at_level(logging.WARNING):
            result = parse_udp(pkt)
        assert result is None


# ---------------------------------------------------------------------------
# DNSMessage
# ---------------------------------------------------------------------------

class TestDNSParse:
    def test_query_name(self, dns_query_pkt):
        msg = parse_dns(dns_query_pkt)
        assert msg is not None
        # Scapy appends trailing dot; strip it
        assert "example.com" in msg.qname

    def test_query_is_not_response(self, dns_query_pkt):
        msg = parse_dns(dns_query_pkt)
        assert msg is not None
        assert msg.is_response is False

    def test_response_flag(self, dns_response_pkt):
        msg = parse_dns(dns_response_pkt)
        assert msg is not None
        assert msg.is_response is True

    def test_response_has_answer(self, dns_response_pkt):
        msg = parse_dns(dns_response_pkt)
        assert msg is not None
        assert len(msg.answers) >= 1
        assert "93.184.216.34" in msg.answers

    def test_query_type_a(self, dns_query_pkt):
        msg = parse_dns(dns_query_pkt)
        assert msg is not None
        assert msg.qtype == 1  # A record

    def test_returns_dns_message_dataclass(self, dns_query_pkt):
        msg = parse_dns(dns_query_pkt)
        assert isinstance(msg, DNSMessage)

    def test_no_dns_layer_returns_none(self, caplog):
        pkt = Ether() / IP() / TCP()
        with caplog.at_level(logging.WARNING):
            result = parse_dns(pkt)
        assert result is None

    def test_long_subdomain_query(self):
        """DNS tunneling often uses long subdomains — must not crash."""
        long = "a" * 60 + ".evil.com"
        pkt = Ether() / IP() / UDP(dport=53) / DNS(qd=DNSQR(qname=long))
        msg = parse_dns(pkt)
        assert msg is not None
        assert "evil.com" in msg.qname
