"""Pruebas del analizador de paquetes: extracción de campos y descarte del tráfico no IPv4."""

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from sniffer.parser import build_bpf_filter, parse_packet, protocol_name


def test_tcp_fields():
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=443) / Raw(b"a" * 10)
    pkt.time = 1_700_000_000.0
    rec = parse_packet(pkt, default_iface="enp1s0")
    assert rec is not None
    assert rec.src_ip == "10.0.0.1"
    assert rec.dst_ip == "10.0.0.2"
    assert rec.protocol == "TCP"
    assert rec.protocol_number == 6
    assert (rec.src_port, rec.dst_port) == (1234, 443)
    assert rec.length == len(pkt) == 14 + 20 + 20 + 10   # Ethernet + IP + TCP + datos (bytes)
    assert rec.interface == "enp1s0"
    assert rec.captured_at.year == 2023


def test_udp_and_icmp():
    udp = parse_packet(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=53, dport=5353))
    icmp = parse_packet(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP())
    assert udp.protocol == "UDP" and udp.dst_port == 5353
    assert icmp.protocol == "ICMP" and icmp.src_port is None and icmp.dst_port is None


def test_unknown_protocol_is_other():
    rec = parse_packet(Ether() / IP(src="1.1.1.1", dst="2.2.2.2", proto=253))
    assert rec.protocol == "OTHER"
    assert rec.protocol_number == 253


def test_ipv6_is_discarded():
    assert parse_packet(Ether() / IPv6(src="fe80::1", dst="ff02::1") / UDP()) is None


def test_arp_is_discarded():
    assert parse_packet(Ether() / ARP()) is None


def test_fragment_has_no_ports():
    frag = Ether() / IP(src="1.1.1.1", dst="2.2.2.2", proto=17, frag=100) / Raw(b"z" * 20)
    rec = parse_packet(frag)
    assert rec.protocol == "UDP"
    assert rec.src_port is None and rec.dst_port is None


def test_bpf_filter_always_forces_ipv4():
    assert build_bpf_filter("") == "ip"
    assert build_bpf_filter("   ") == "ip"
    assert build_bpf_filter("tcp port 443") == "ip and (tcp port 443)"


def test_protocol_name():
    assert protocol_name(6) == "TCP"
    assert protocol_name(17) == "UDP"
    assert protocol_name(999) == "OTHER"
