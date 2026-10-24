"""Configuración de la aplicación.

Todos los parámetros se obtienen de variables de entorno. En Docker, dichas
variables provienen del archivo `.env` (consulte docker-compose.yml).

    >>> IMPORTANTE: la interfaz de red no se configura en este archivo. <<<
    La interfaz se define en el archivo `.env` (variable CAPTURE_IFACE, línea 25)
    o en la línea de comandos mediante `--iface`. Consulte el manual de
    usuario, sección 4.2 "Selección de la interfaz de red".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"La variable de entorno {name} debe ser un número entero (valor: {value!r})") from exc


def _env_list(name: str) -> list[str]:
    """Convierte una lista separada por comas ('enp1s0, enp2s0') en ['enp1s0', 'enp2s0']."""
    raw = os.getenv(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass
class DatabaseConfig:
    host: str = field(default_factory=lambda: os.getenv("DB_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("DB_PORT", 5432))
    name: str = field(default_factory=lambda: os.getenv("DB_NAME", "sniffer"))
    user: str = field(default_factory=lambda: os.getenv("DB_USER", "sniffer"))
    password: str = field(default_factory=lambda: os.getenv("DB_PASSWORD", "sniffer"))

    @property
    def conninfo(self) -> str:
        return (
            f"host={self.host} port={self.port} dbname={self.name} "
            f"user={self.user} password={self.password} connect_timeout=5"
        )


@dataclass
class CaptureConfig:
    # Interfaz o interfaces a capturar. Valor por defecto: CAPTURE_IFACE del archivo .env
    interfaces: list[str] = field(default_factory=lambda: _env_list("CAPTURE_IFACE"))
    # Filtro BPF adicional (opcional). Siempre se combina con "ip" para restringir la captura a IPv4.
    bpf_filter: str = field(default_factory=lambda: os.getenv("CAPTURE_FILTER", "").strip())
    # Límite de paquetes (0 = sin límite)
    count: int = field(default_factory=lambda: _env_int("CAPTURE_COUNT", 0))
    # Límite de tiempo en segundos (0 = sin límite)
    timeout: int = field(default_factory=lambda: _env_int("CAPTURE_TIMEOUT", 0))
    # Intervalo en segundos entre los mensajes de progreso (0 = desactivado)
    stats_interval: int = field(default_factory=lambda: _env_int("STATS_INTERVAL", 5))
    # Parámetros de escritura por lotes en la base de datos
    batch_size: int = field(default_factory=lambda: _env_int("BATCH_SIZE", 500))
    flush_interval: float = field(default_factory=lambda: float(_env_int("FLUSH_INTERVAL", 1)))
    queue_size: int = field(default_factory=lambda: _env_int("QUEUE_SIZE", 100_000))
