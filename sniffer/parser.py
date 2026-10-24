"""Extracción de campos de un paquete IPv4.

Convierte un paquete de Scapy en un registro (`PacketRecord`) con los
campos que se almacenan en la base de datos. Todo paquete que no sea
IPv4 devuelve `None` y se descarta.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

# Correspondencia entre el número de protocolo IPv4 (campo "proto" de la cabecera) y su nombre.
# Fuente: IANA "Assigned Internet Protocol Numbers".
PROTOCOL_NAMES: dict[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
}


def protocol_name(number: int) -> str:
    """Devuelve el nombre del protocolo, o 'OTHER' si no figura en la tabla."""
    return PROTOCOL_NAMES.get(number, "OTHER")


@dataclass(frozen=True, slots=True)
class PacketRecord:
    captured_at: datetime
    interface: str
    src_ip: str
    dst_ip: str
    protocol: str
    protocol_number: int
    length: int
    src_port: int | None
    dst_port: int | None


def parse_packet(pkt: Packet, default_iface: str = "desconocida") -> PacketRecord | None:
    """Extrae los campos de interés. Devuelve None si el paquete no es IPv4.

    - Tamaño: `len(pkt)` corresponde a la longitud de la trama completa tal
      como se capturó (cabecera Ethernet, IP y datos). Es el mismo valor que
      tcpdump y Wireshark muestran como "length".
    - Puertos: solo se registran para TCP y UDP, y únicamente si el paquete no
      es un fragmento posterior (los fragmentos no contienen cabecera de transporte).
    """
    # Segundo nivel de control: el filtro BPF "ip" ya descarta IPv6 y ARP en el
    # kernel, pero la verificación se repite aquí (p. ej. al procesar un .pcap).
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto_num = int(ip.proto)

    src_port = dst_port = None
    is_first_fragment = int(ip.frag) == 0
    if is_first_fragment:
        if TCP in ip:
            src_port, dst_port = int(ip[TCP].sport), int(ip[TCP].dport)
        elif UDP in ip:
            src_port, dst_port = int(ip[UDP].sport), int(ip[UDP].dport)

    return PacketRecord(
        captured_at=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc),
        interface=getattr(pkt, "sniffed_on", None) or default_iface,
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        protocol=protocol_name(proto_num),
        protocol_number=proto_num,
        length=len(pkt),
        src_port=src_port,
        dst_port=dst_port,
    )


def build_bpf_filter(user_filter: str = "") -> str:
    """Construye el filtro BPF aplicado, que siempre incluye "ip" (solo IPv4).

    Si el usuario indica un filtro adicional, este se combina con AND, de modo
    que en ningún caso se admita tráfico IPv6 u otro tráfico distinto de IPv4.

        build_bpf_filter("")              -> "ip"
        build_bpf_filter("tcp port 443")  -> "ip and (tcp port 443)"
    """
    user_filter = user_filter.strip()
    return f"ip and ({user_filter})" if user_filter else "ip"
