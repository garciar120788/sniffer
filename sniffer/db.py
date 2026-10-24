"""Acceso a PostgreSQL: creación del esquema, gestión de sesiones, inserción y consultas."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterable
from pathlib import Path

import psycopg

from .config import DatabaseConfig
from .parser import PacketRecord
from .stats import TOP_N, StatsSnapshot

log = logging.getLogger(__name__)

SCHEMA_PATH = Path(os.getenv("SCHEMA_PATH", Path(__file__).resolve().parent.parent / "sql" / "schema.sql"))

COPY_SQL = (
    "COPY packets (session_id, captured_at, interface, src_ip, dst_ip, "
    "protocol, protocol_number, length, src_port, dst_port) FROM STDIN"
)


def connect(cfg: DatabaseConfig, retries: int = 10, delay: float = 2.0) -> psycopg.Connection:
    """Establece la conexión con reintentos (la base de datos puede tardar unos segundos en estar disponible)."""
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            return psycopg.connect(cfg.conninfo, autocommit=False)
        except psycopg.OperationalError as exc:
            last_exc = exc
            log.warning("No se pudo conectar a PostgreSQL (%s:%s), intento %d/%d...", cfg.host, cfg.port, attempt, retries)
            time.sleep(delay)
    raise RuntimeError(f"No fue posible conectar a PostgreSQL en {cfg.host}:{cfg.port}: {last_exc}")


def init_schema(conn: psycopg.Connection) -> None:
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with conn.cursor() as cur:
        cur.execute(sql)
    conn.commit()


def create_session(conn: psycopg.Connection, interfaces: list[str], bpf_filter: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO capture_sessions (interfaces, bpf_filter) VALUES (%s, %s) RETURNING id",
            (interfaces, bpf_filter),
        )
        session_id = cur.fetchone()[0]
    conn.commit()
    return session_id


def finish_session(conn: psycopg.Connection, session_id: int, total: int, dropped: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE capture_sessions SET ended_at = now(), total_packets = %s, dropped_packets = %s WHERE id = %s",
            (total, dropped, session_id),
        )
    conn.commit()


def insert_packets(conn: psycopg.Connection, session_id: int, records: Iterable[PacketRecord]) -> int:
    """Inserta un lote mediante COPY (considerablemente más rápido que un INSERT por fila)."""
    n = 0
    with conn.cursor() as cur:
        with cur.copy(COPY_SQL) as copy:
            for r in records:
                copy.write_row((
                    session_id, r.captured_at, r.interface, r.src_ip, r.dst_ip,
                    r.protocol, r.protocol_number, r.length, r.src_port, r.dst_port,
                ))
                n += 1
    conn.commit()
    return n


# ---------------------------------------------------------------------------
# Consultas de estadísticas (subcomando `stats`)
# ---------------------------------------------------------------------------

def last_session_id(conn: psycopg.Connection) -> int | None:
    with conn.cursor() as cur:
        cur.execute("SELECT max(id) FROM capture_sessions")
        return cur.fetchone()[0]


def list_sessions(conn: psycopg.Connection, limit: int = 20) -> list[tuple]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT s.id, array_to_string(s.interfaces, ','), s.bpf_filter, s.started_at, s.ended_at,
                   (SELECT count(*) FROM packets p WHERE p.session_id = s.id) AS stored
            FROM capture_sessions s
            ORDER BY s.id DESC
            LIMIT %s
            """,
            (limit,),
        )
        return cur.fetchall()


def query_stats(conn: psycopg.Connection, session_id: int | None, n: int = TOP_N) -> StatsSnapshot:
    """Calcula las estadísticas mediante SQL. Con session_id=None se consideran todas las sesiones."""
    where = "WHERE session_id = %(sid)s" if session_id is not None else ""
    params = {"sid": session_id, "n": n}

    def rows(sql: str) -> list[tuple]:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return [(str(k), int(p), int(b)) for k, p, b in cur.fetchall()]

    def group(col: str, order: str, limit: bool) -> list[tuple]:
        lim = "LIMIT %(n)s" if limit else ""
        return rows(
            f"SELECT {col}, count(*) AS pkts, sum(length) AS bytes FROM packets {where} "
            f"GROUP BY {col} ORDER BY {order} DESC, {col} {lim}"
        )

    with conn.cursor() as cur:
        cur.execute(f"SELECT count(*), coalesce(sum(length), 0) FROM packets {where}", params)
        total_pkts, total_bytes = cur.fetchone()

    return StatsSnapshot(
        total_packets=int(total_pkts),
        total_bytes=int(total_bytes),
        by_protocol=group("protocol", "pkts", limit=False),
        by_interface=group("interface", "pkts", limit=False),
        top_src_packets=[(ip.split("/")[0], p, b) for ip, p, b in group("host(src_ip)", "pkts", True)],
        top_src_bytes=[(ip.split("/")[0], p, b) for ip, p, b in group("host(src_ip)", "bytes", True)],
        top_dst_packets=[(ip.split("/")[0], p, b) for ip, p, b in group("host(dst_ip)", "pkts", True)],
        top_dst_bytes=[(ip.split("/")[0], p, b) for ip, p, b in group("host(dst_ip)", "bytes", True)],
    )
