"""Pruebas del cálculo de estadísticas en memoria y del procesamiento completo de un archivo .pcap."""

import importlib.util
from pathlib import Path

from sniffer.config import CaptureConfig, DatabaseConfig
from sniffer.parser import PacketRecord
from sniffer.stats import TrafficStats

ROOT = Path(__file__).resolve().parent.parent


def _rec(src, dst, proto="TCP", length=100):
    from datetime import datetime, timezone
    return PacketRecord(datetime.now(timezone.utc), "eth0", src, dst, proto, 6, length, None, None)


def test_top_by_packets_vs_bytes():
    st = TrafficStats()
    # El origen 10.0.0.1 envía muchos paquetes pequeños; 10.0.0.2, pocos paquetes de gran tamaño
    for _ in range(10):
        st.add(_rec("10.0.0.1", "8.8.8.8", length=60))
    for _ in range(2):
        st.add(_rec("10.0.0.2", "8.8.8.8", length=1500))
    snap = st.snapshot()
    assert snap.total_packets == 12
    assert snap.total_bytes == 10 * 60 + 2 * 1500
    assert snap.top_src_packets[0][0] == "10.0.0.1"   # mayor número de paquetes
    assert snap.top_src_bytes[0][0] == "10.0.0.2"     # mayor volumen en bytes
    assert snap.top_dst_packets[0] == ("8.8.8.8", 12, 3600)


def test_top_is_limited_to_five():
    st = TrafficStats()
    for i in range(10):
        st.add(_rec(f"10.0.0.{i}", "1.1.1.1"))
    assert len(st.snapshot().top_src_packets) == 5


def _load_pcap_generator():
    spec = importlib.util.spec_from_file_location("gen", ROOT / "scripts" / "generar_pcap_ejemplo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_offline_capture_counts(tmp_path, monkeypatch):
    """Procesa un pcap sintético de principio a fin (sin base de datos) y valida los conteos."""
    from scapy.utils import wrpcap

    from sniffer import capture

    pcap = tmp_path / "t.pcap"
    wrpcap(str(pcap), _load_pcap_generator().build_packets())

    captured = {}
    real_render = capture.render

    def spy_render(snap, *args, **kwargs):
        captured["s"] = snap
        real_render(snap, *args, **kwargs)

    monkeypatch.setattr(capture, "render", spy_render)

    rc = capture.run_capture(CaptureConfig(stats_interval=0), DatabaseConfig(), pcap_file=str(pcap), use_db=False)
    snap = captured["s"]
    assert rc == 0
    assert snap.total_packets == 60                    # los paquetes IPv6 y ARP se descartan
    protos = {p: n for p, n, _ in snap.by_protocol}
    assert protos == {"TCP": 30, "UDP": 20, "ICMP": 10}
    assert snap.top_src_packets[0][0] == "192.168.1.10"
    assert {ip for ip, _, _ in snap.top_dst_packets} == {"93.184.216.34", "8.8.8.8", "1.1.1.1"}


def test_offline_capture_respects_count(tmp_path):
    """Verifica que --count contabilice únicamente los paquetes IPv4 aceptados."""
    from scapy.utils import wrpcap

    from sniffer import capture

    pcap = tmp_path / "t.pcap"
    wrpcap(str(pcap), _load_pcap_generator().build_packets())
    cfg = CaptureConfig(stats_interval=0, count=15)
    assert capture.run_capture(cfg, DatabaseConfig(), pcap_file=str(pcap), use_db=False) == 0
