"""Hilo de escritura: extrae paquetes de una cola y los almacena por lotes en la base de datos.

La separación entre captura y escritura evita que la latencia de la base de
datos provoque pérdida de paquetes: el hilo de captura solo deposita los
paquetes en la cola (una operación muy rápida) y este hilo ejecuta las
operaciones COPY en segundo plano.
"""

from __future__ import annotations

import logging
import queue
import threading
import time

from .config import CaptureConfig, DatabaseConfig
from .db import connect, insert_packets
from .parser import PacketRecord

log = logging.getLogger(__name__)

_SENTINEL = object()


class DBWriter(threading.Thread):
    def __init__(self, db_cfg: DatabaseConfig, cap_cfg: CaptureConfig, session_id: int) -> None:
        super().__init__(name="db-writer", daemon=True)
        self.db_cfg = db_cfg
        self.session_id = session_id
        self.batch_size = max(1, cap_cfg.batch_size)
        self.flush_interval = max(0.1, cap_cfg.flush_interval)
        self.queue: queue.Queue = queue.Queue(maxsize=cap_cfg.queue_size)
        self.written = 0
        self.dropped = 0          # paquetes descartados por cola llena
        self.failed = 0           # paquetes de lotes cuya inserción falló
        self.error: Exception | None = None

    # Métodos invocados desde el hilo de captura ---------------------------
    def submit(self, rec: PacketRecord) -> None:
        try:
            self.queue.put_nowait(rec)
        except queue.Full:
            self.dropped += 1

    def close(self, timeout: float = 30.0) -> None:
        """Solicita al hilo que vacíe la cola, guarde los paquetes pendientes y finalice."""
        self.queue.put(_SENTINEL)
        self.join(timeout)

    # Ejecución del hilo de escritura ----------------------------------------
    def run(self) -> None:
        conn = connect(self.db_cfg)
        batch: list[PacketRecord] = []
        last_flush = time.monotonic()
        try:
            while True:
                try:
                    item = self.queue.get(timeout=self.flush_interval)
                except queue.Empty:
                    item = None

                if item is _SENTINEL:
                    break
                if item is not None:
                    batch.append(item)

                due = time.monotonic() - last_flush >= self.flush_interval
                if batch and (len(batch) >= self.batch_size or due):
                    self._flush(conn, batch)
                    batch = []
                    last_flush = time.monotonic()

            # Procesa los elementos restantes tras el centinela (en condiciones normales, ninguno)
            while not self.queue.empty():
                item = self.queue.get_nowait()
                if item is not _SENTINEL:
                    batch.append(item)
            if batch:
                self._flush(conn, batch)
        except Exception as exc:  # noqa: BLE001 - el error se registra y se expone
            self.error = exc
            log.exception("El hilo escritor terminó con error")
        finally:
            conn.close()

    def _flush(self, conn, batch: list[PacketRecord]) -> None:
        try:
            self.written += insert_packets(conn, self.session_id, batch)
        except Exception:  # noqa: BLE001
            conn.rollback()
            self.failed += len(batch)
            log.exception("Error guardando un lote de %d paquetes", len(batch))
