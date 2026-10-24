"""Genera el archivo samples/ejemplo.pcap con tráfico sintético de contenido conocido.

Permite probar la aplicación sin tráfico real ni permisos especiales.
Incluye de forma intencional paquetes IPv6 y ARP para verificar su descarte.

Contenido (resultado esperado del procesamiento):
    IPv4 total ......... 60 paquetes
      TCP .............. 30  (192.168.1.10 -> 93.184.216.34:443)
      UDP .............. 20  (192.168.1.20 -> 8.8.8.8:53)
      ICMP ............. 10  (192.168.1.30 -> 1.1.1.1)
    Descartados ........ 8   (5 IPv6 + 3 ARP)

Uso:  python scripts/generar_pcap_ejemplo.py [ruta_salida]
"""

import sys
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap


def build_packets():
    pkts = []
    base = 1_760_000_000.0
    for i in range(30):
        pkts.append(Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=50000 + i, dport=443) / Raw(b"x" * 100))
    for i in range(20):
        pkts.append(Ether() / IP(src="192.168.1.20", dst="8.8.8.8") / UDP(sport=40000 + i, dport=53) / Raw(b"q" * 40))
    for _ in range(10):
        pkts.append(Ether() / IP(src="192.168.1.30", dst="1.1.1.1") / ICMP() / Raw(b"p" * 56))
    for _ in range(5):
        pkts.append(Ether() / IPv6(src="fe80::1", dst="ff02::1") / UDP(sport=546, dport=547))
    for _ in range(3):
        pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(psrc="192.168.1.1", pdst="192.168.1.99"))
    for i, p in enumerate(pkts):
        p.time = base + i * 0.01
    return pkts


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "samples" / "ejemplo.pcap")
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), build_packets())
    print(f"Generado {out}")
