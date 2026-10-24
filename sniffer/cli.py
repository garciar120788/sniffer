"""Interfaz de línea de comandos.

Uso (dentro del contenedor o mediante `docker compose run --rm sniffer ...`):

    python -m sniffer capture [--iface IFACE ...] [--filter BPF] [--count N] [--timeout S]
                              [--pcap ARCHIVO] [--no-db]
    python -m sniffer stats   [--session ID | --all]
    python -m sniffer sessions
    python -m sniffer interfaces
"""

from __future__ import annotations

import argparse
import logging
import sys

from rich.console import Console
from rich.table import Table

from .config import CaptureConfig, DatabaseConfig

console = Console()


def _split_ifaces(values: list[str] | None) -> list[str]:
    """Admite tanto '--iface a --iface b' como '--iface a,b'."""
    out: list[str] = []
    for v in values or []:
        out.extend(x.strip() for x in v.split(",") if x.strip())
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sniffer",
        description="Captura paquetes IPv4 de una interfaz de red, los guarda en PostgreSQL y muestra estadísticas.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("capture", help="Capturar paquetes (comando por defecto en Docker)")
    c.add_argument(
        "-i", "--iface", action="append", metavar="IFACE",
        help="Interfaz a escuchar. Repetible o separada por comas. "
             "Si se omite se usa CAPTURE_IFACE del archivo .env",
    )
    c.add_argument("-f", "--filter", metavar="BPF", help='Filtro BPF adicional, ej. "tcp port 443". Siempre se combina con "ip".')
    c.add_argument("-c", "--count", type=int, metavar="N", help="Detener tras N paquetes (0 = sin límite)")
    c.add_argument("-t", "--timeout", type=int, metavar="SEG", help="Detener tras SEG segundos (0 = sin límite)")
    c.add_argument("--stats-interval", type=int, metavar="SEG", help="Cada cuántos segundos mostrar progreso (0 = nunca)")
    c.add_argument("--pcap", metavar="ARCHIVO", help="Leer paquetes de un archivo .pcap en lugar de una interfaz")
    c.add_argument("--no-db", action="store_true", help="No guardar en la base de datos (solo estadísticas)")

    s = sub.add_parser("stats", help="Mostrar estadísticas guardadas en la base de datos")
    g = s.add_mutually_exclusive_group()
    g.add_argument("-s", "--session", type=int, metavar="ID", help="ID de sesión (por defecto: la última)")
    g.add_argument("-a", "--all", action="store_true", help="Todas las sesiones juntas")

    sub.add_parser("sessions", help="Listar las sesiones de captura guardadas")
    sub.add_parser("interfaces", help="Listar las interfaces de red disponibles")

    p.add_argument("-v", "--verbose", action="store_true", help="Mensajes de depuración")
    return p


def cmd_capture(args: argparse.Namespace) -> int:
    from .capture import run_capture

    cap = CaptureConfig()
    # Los argumentos de la línea de comandos tienen prioridad sobre el archivo .env
    if args.iface:
        cap.interfaces = _split_ifaces(args.iface)
    if args.filter is not None:
        cap.bpf_filter = args.filter
    if args.count is not None:
        cap.count = args.count
    if args.timeout is not None:
        cap.timeout = args.timeout
    if args.stats_interval is not None:
        cap.stats_interval = args.stats_interval
    return run_capture(cap, DatabaseConfig(), pcap_file=args.pcap, use_db=not args.no_db)


def cmd_stats(args: argparse.Namespace) -> int:
    from . import db
    from .stats import render

    conn = db.connect(DatabaseConfig(), retries=3)
    db.init_schema(conn)
    if args.all:
        session_id, heading = None, "Estadísticas de TODAS las sesiones"
    else:
        session_id = args.session or db.last_session_id(conn)
        if session_id is None:
            console.print("No hay sesiones guardadas todavía. Ejecuta primero una captura.")
            return 1
        heading = f"Estadísticas de la sesión #{session_id}"
    snapshot = db.query_stats(conn, session_id)
    conn.close()
    render(snapshot, console, heading=heading)
    return 0


def cmd_sessions(_args: argparse.Namespace) -> int:
    from . import db

    conn = db.connect(DatabaseConfig(), retries=3)
    db.init_schema(conn)
    rows = db.list_sessions(conn)
    conn.close()
    t = Table(title="Sesiones de captura", header_style="bold cyan")
    for col in ("ID", "Interfaces", "Filtro BPF", "Inicio (UTC)", "Fin (UTC)", "Paquetes"):
        t.add_column(col)
    for sid, ifaces, bpf, start, end, stored in rows:
        t.add_row(
            str(sid), ifaces, bpf,
            start.strftime("%Y-%m-%d %H:%M:%S") if start else "-",
            end.strftime("%Y-%m-%d %H:%M:%S") if end else "(en curso / interrumpida)",
            f"{stored:,}",
        )
    console.print(t)
    return 0


def cmd_interfaces(_args: argparse.Namespace) -> int:
    from scapy.arch import get_if_addr, get_if_hwaddr
    from scapy.interfaces import get_if_list

    t = Table(title="Interfaces de red visibles", header_style="bold cyan")
    t.add_column("Interfaz")
    t.add_column("Tipo probable")
    t.add_column("IPv4")
    t.add_column("MAC")
    for name in sorted(get_if_list()):
        if name.startswith(("en", "eth")):
            kind = "Ethernet (cable)"
        elif name.startswith("wl"):
            kind = "Wi-Fi"
        elif name == "lo":
            kind = "Loopback"
        elif name.startswith(("docker", "br-", "veth")):
            kind = "Virtual (Docker)"
        else:
            kind = "Otra / virtual"
        try:
            mac = get_if_hwaddr(name)
        except Exception:  # noqa: BLE001
            mac = "-"
        addr = get_if_addr(name)
        t.add_row(name, kind, addr if addr != "0.0.0.0" else "(sin IPv4)", mac)
    console.print(t)
    console.print("Copia el nombre de la interfaz en CAPTURE_IFACE dentro del archivo [bold].env[/bold].")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    handlers = {
        "capture": cmd_capture,
        "stats": cmd_stats,
        "sessions": cmd_sessions,
        "interfaces": cmd_interfaces,
    }
    try:
        return handlers[args.command](args)
    except RuntimeError as exc:
        console.print(f"[red]ERROR: {exc}[/red]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
