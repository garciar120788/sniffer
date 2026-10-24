"""Cálculo de estadísticas de tráfico en memoria y su presentación en la terminal."""

from __future__ import annotations

import threading
import time
from collections import Counter
from dataclasses import dataclass, field

from rich.console import Console
from rich.table import Table

from .parser import PacketRecord

TOP_N = 5


@dataclass
class StatsSnapshot:
    """Instantánea inmutable de las estadísticas (calculadas en memoria o en la base de datos)."""

    total_packets: int = 0
    total_bytes: int = 0
    by_protocol: list[tuple[str, int, int]] = field(default_factory=list)      # (protocolo, paquetes, bytes)
    by_interface: list[tuple[str, int, int]] = field(default_factory=list)     # (interfaz, paquetes, bytes)
    top_src_packets: list[tuple[str, int, int]] = field(default_factory=list)  # (ip, paquetes, bytes)
    top_src_bytes: list[tuple[str, int, int]] = field(default_factory=list)
    top_dst_packets: list[tuple[str, int, int]] = field(default_factory=list)
    top_dst_bytes: list[tuple[str, int, int]] = field(default_factory=list)


def _top(packets: Counter, bytes_: Counter, by: Counter, n: int) -> list[tuple[str, int, int]]:
    return [(key, packets[key], bytes_[key]) for key, _ in by.most_common(n)]


class TrafficStats:
    """Contadores acumulados durante la captura. Seguros para el acceso concurrente entre hilos."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started = time.monotonic()
        self.total_packets = 0
        self.total_bytes = 0
        self.proto_pkts: Counter[str] = Counter()
        self.proto_bytes: Counter[str] = Counter()
        self.iface_pkts: Counter[str] = Counter()
        self.iface_bytes: Counter[str] = Counter()
        self.src_pkts: Counter[str] = Counter()
        self.src_bytes: Counter[str] = Counter()
        self.dst_pkts: Counter[str] = Counter()
        self.dst_bytes: Counter[str] = Counter()

    def add(self, rec: PacketRecord) -> None:
        with self._lock:
            self.total_packets += 1
            self.total_bytes += rec.length
            self.proto_pkts[rec.protocol] += 1
            self.proto_bytes[rec.protocol] += rec.length
            self.iface_pkts[rec.interface] += 1
            self.iface_bytes[rec.interface] += rec.length
            self.src_pkts[rec.src_ip] += 1
            self.src_bytes[rec.src_ip] += rec.length
            self.dst_pkts[rec.dst_ip] += 1
            self.dst_bytes[rec.dst_ip] += rec.length

    def snapshot(self, n: int = TOP_N) -> StatsSnapshot:
        with self._lock:
            return StatsSnapshot(
                total_packets=self.total_packets,
                total_bytes=self.total_bytes,
                by_protocol=_top(self.proto_pkts, self.proto_bytes, self.proto_pkts, len(self.proto_pkts)),
                by_interface=_top(self.iface_pkts, self.iface_bytes, self.iface_pkts, len(self.iface_pkts)),
                top_src_packets=_top(self.src_pkts, self.src_bytes, self.src_pkts, n),
                top_src_bytes=_top(self.src_pkts, self.src_bytes, self.src_bytes, n),
                top_dst_packets=_top(self.dst_pkts, self.dst_bytes, self.dst_pkts, n),
                top_dst_bytes=_top(self.dst_pkts, self.dst_bytes, self.dst_bytes, n),
            )

    def live_line(self) -> str:
        """Genera la línea resumida de progreso que se muestra durante la captura."""
        with self._lock:
            elapsed = max(time.monotonic() - self.started, 1e-6)
            protos = "  ".join(f"{p}={c}" for p, c in self.proto_pkts.most_common())
            return (
                f"[{elapsed:6.0f}s] paquetes={self.total_packets}  "
                f"bytes={human_bytes(self.total_bytes)}  "
                f"({self.total_packets / elapsed:.1f} paq/s)  {protos}"
            )


# ---------------------------------------------------------------------------
# Presentación
# ---------------------------------------------------------------------------

def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024
    return f"{n} B"


def _pct(part: int, total: int) -> str:
    return f"{(part / total * 100):.1f} %" if total else "0.0 %"


def _table(title: str, first_col: str, rows: list[tuple[str, int, int]], total_pkts: int, total_bytes: int) -> Table:
    t = Table(title=title, title_justify="left", header_style="bold cyan")
    t.add_column("#", justify="right", style="dim")
    t.add_column(first_col)
    t.add_column("Paquetes", justify="right")
    t.add_column("% paq.", justify="right")
    t.add_column("Bytes", justify="right")
    t.add_column("% bytes", justify="right")
    if not rows:
        t.add_row("-", "(sin datos)", "0", "-", "0", "-")
    for i, (key, pkts, byts) in enumerate(rows, start=1):
        t.add_row(str(i), key, f"{pkts:,}", _pct(pkts, total_pkts), human_bytes(byts), _pct(byts, total_bytes))
    return t


def render(snapshot: StatsSnapshot, console: Console | None = None, heading: str = "Estadísticas de tráfico") -> None:
    console = console or Console()
    s = snapshot
    console.rule(f"[bold]{heading}")
    console.print(
        f"[bold]Número total de paquetes capturados:[/bold] {s.total_packets:,}    "
        f"[bold]Volumen total:[/bold] {human_bytes(s.total_bytes)}"
    )
    console.print(_table("Paquetes por protocolo", "Protocolo", s.by_protocol, s.total_packets, s.total_bytes))
    if len(s.by_interface) > 1:
        console.print(_table("Paquetes por interfaz", "Interfaz", s.by_interface, s.total_packets, s.total_bytes))
    console.print(_table(f"Top {TOP_N} IP de ORIGEN (por número de paquetes)", "IP origen", s.top_src_packets, s.total_packets, s.total_bytes))
    console.print(_table(f"Top {TOP_N} IP de ORIGEN (por bytes)", "IP origen", s.top_src_bytes, s.total_packets, s.total_bytes))
    console.print(_table(f"Top {TOP_N} IP de DESTINO (por número de paquetes)", "IP destino", s.top_dst_packets, s.total_packets, s.total_bytes))
    console.print(_table(f"Top {TOP_N} IP de DESTINO (por bytes)", "IP destino", s.top_dst_bytes, s.total_packets, s.total_bytes))
