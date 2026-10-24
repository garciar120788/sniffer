"""Control de la captura: integración de Scapy, cálculo de estadísticas y escritura en la base de datos."""

from __future__ import annotations

import logging
import signal
import threading
import time
from pathlib import Path

from rich.console import Console
from scapy.config import conf
from scapy.interfaces import get_if_list
from scapy.arch import get_if_addr
from scapy.sendrecv import AsyncSniffer

from . import db
from .config import CaptureConfig, DatabaseConfig
from .parser import build_bpf_filter, parse_packet
from .stats import TrafficStats, render
from .writer import DBWriter

log = logging.getLogger(__name__)
console = Console()


def validate_interfaces(interfaces: list[str]) -> None:
    """Verifica la existencia de las interfaces y emite un aviso si alguna carece de dirección IPv4."""
    if not interfaces:
        raise SystemExit(
            "ERROR: no se indicó ninguna interfaz.\n"
            "Define CAPTURE_IFACE en el archivo .env o usa --iface <nombre>.\n"
            "Lista de interfaces disponibles: docker compose run --rm sniffer interfaces"
        )
    available = get_if_list()
    missing = [i for i in interfaces if i not in available]
    if missing:
        raise SystemExit(
            f"ERROR: la(s) interfaz(es) {', '.join(missing)} no existe(n) en este equipo.\n"
            f"Interfaces disponibles: {', '.join(sorted(available))}\n"
            "Revisa CAPTURE_IFACE en el archivo .env."
        )
    for iface in interfaces:
        addr = get_if_addr(iface)
        if addr in ("0.0.0.0", ""):
            console.print(
                f"[yellow]AVISO: la interfaz {iface} no tiene dirección IPv4 asignada "
                "(¿cable desconectado o Wi-Fi sin asociar?). Puede que no se capture nada.[/yellow]"
            )


def run_capture(cap: CaptureConfig, dbc: DatabaseConfig, pcap_file: str | None = None, use_db: bool = True) -> int:
    conf.verb = 0
    bpf = build_bpf_filter(cap.bpf_filter)

    if pcap_file:
        if not Path(pcap_file).is_file():
            raise SystemExit(f"ERROR: no existe el archivo pcap {pcap_file}")
        source_label = [f"pcap:{Path(pcap_file).name}"]
        # En modo .pcap, Scapy aplicaría el filtro BPF mediante `tcpdump -r`,
        # que intenta cambiar de usuario (setuid) y falla en un contenedor sin
        # CAP_SETUID. Por ese motivo, al procesar un archivo, el filtrado IPv4
        # lo realiza parse_packet() y no se aplican filtros BPF adicionales.
        if cap.bpf_filter:
            console.print("[yellow]AVISO: --filter/CAPTURE_FILTER no se aplica al leer un .pcap "
                          "(solo en captura en vivo). Se procesará todo el tráfico IPv4 del archivo.[/yellow]")
        bpf = "ip (aplicado por el parser, modo pcap)"
    else:
        validate_interfaces(cap.interfaces)
        source_label = cap.interfaces

    # --- Base de datos -------------------------------------------------------
    writer: DBWriter | None = None
    session_id: int | None = None
    if use_db:
        conn = db.connect(dbc)
        db.init_schema(conn)
        session_id = db.create_session(conn, source_label, bpf)
        conn.close()
        writer = DBWriter(dbc, cap, session_id)
        writer.start()

    stats = TrafficStats()
    default_iface = source_label[0]

    def on_packet(pkt) -> None:
        rec = parse_packet(pkt, default_iface=default_iface)
        if rec is None:  # paquete no IPv4
            return
        stats.add(rec)
        if writer is not None:
            writer.submit(rec)

    # --- Señales: Ctrl+C (SIGINT) y `docker stop` (SIGTERM) ------------------
    stop_event = threading.Event()

    def _handle_signal(signum, _frame) -> None:
        if not stop_event.is_set():
            console.print(f"\n[yellow]Señal {signal.Signals(signum).name} recibida: deteniendo la captura...[/yellow]")
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # --- Captura ---------------------------------------------------------------
    # El límite --count se evalúa sobre los paquetes IPv4 aceptados (stop_filter se
    # invoca después de prn), por lo que tiene el mismo significado en vivo y con un .pcap.
    def reached_count(_pkt) -> bool:
        return bool(cap.count) and stats.total_packets >= cap.count

    sniffer_kwargs = dict(prn=on_packet, store=False, stop_filter=reached_count)
    if pcap_file:
        sniffer_kwargs["offline"] = pcap_file
    else:
        sniffer_kwargs["filter"] = bpf   # filtro BPF aplicado en el kernel: solo IPv4
        sniffer_kwargs["iface"] = cap.interfaces if len(cap.interfaces) > 1 else cap.interfaces[0]

    console.rule("[bold]Capturador de paquetes IPv4")
    console.print(f"Fuente:      [bold]{', '.join(source_label)}[/bold]")
    console.print(f"Filtro BPF:  [bold]{bpf}[/bold]")
    console.print(f"Límites:     paquetes={cap.count or 'sin límite'}  tiempo={str(cap.timeout) + ' s' if cap.timeout else 'sin límite'}")
    console.print(f"Base datos:  {'sesión #' + str(session_id) if use_db else 'desactivada (--no-db)'}")
    if not pcap_file:
        console.print("[dim]Pulsa Ctrl+C para detener la captura y ver las estadísticas.[/dim]")

    sniffer = AsyncSniffer(**sniffer_kwargs)
    sniffer.start()

    deadline = time.monotonic() + cap.timeout if cap.timeout else None
    next_live = time.monotonic() + cap.stats_interval if cap.stats_interval else None
    capture_error: Exception | None = None
    try:
        time.sleep(0.3)  # margen para el arranque del hilo de Scapy
        while not stop_event.is_set():
            if not sniffer.running:          # se alcanzó --count, finalizó el pcap o se produjo un error
                break
            if deadline and time.monotonic() >= deadline:
                break
            if next_live and time.monotonic() >= next_live:
                console.print(stats.live_line())
                next_live = time.monotonic() + cap.stats_interval
            time.sleep(0.2)
    finally:
        try:
            if sniffer.running and not pcap_file:
                sniffer.stop(join=True)
            else:
                sniffer.join()
        except Exception as exc:  # noqa: BLE001
            # Si el hilo de Scapy no pudo abrir el socket (p. ej. por falta de permisos),
            # el error original se encuentra en sniffer.exception; `exc` es secundario.
            if sniffer.thread:
                sniffer.thread.join(5)
            capture_error = sniffer.exception or exc

    # --- Cierre ordenado -------------------------------------------------------
    if writer is not None:
        console.print("[dim]Guardando paquetes pendientes en la base de datos...[/dim]")
        writer.close()
        conn = db.connect(dbc)
        db.finish_session(conn, session_id, writer.written, writer.dropped + writer.failed)
        conn.close()

    render(stats.snapshot(), console, heading="Estadísticas de la captura")

    if writer is not None:
        console.print(
            f"Guardados en BD: [bold]{writer.written:,}[/bold] paquetes (sesión #{session_id}). "
            f"Descartados por cola llena: {writer.dropped:,}. Fallidos al insertar: {writer.failed:,}."
        )
        if writer.error:
            console.print(f"[red]Error en el hilo escritor: {writer.error}[/red]")

    if capture_error is not None:
        if isinstance(capture_error, PermissionError):
            console.print(
                "[red]ERROR: permiso denegado para capturar. El contenedor necesita "
                "la capacidad NET_RAW (cap_add: [NET_RAW] en docker-compose.yml).[/red]"
            )
        else:
            console.print(f"[red]ERROR durante la captura: {capture_error}[/red]")
        return 1
    return 0
