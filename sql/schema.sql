-- =====================================================================
-- Esquema de la base de datos del capturador de paquetes (solo IPv4)
-- Motor: PostgreSQL 16
--
-- La aplicación ejecuta este archivo automáticamente en cada inicio.
-- Todas las sentencias son idempotentes (IF NOT EXISTS), por lo que
-- su ejecución repetida no produce efectos secundarios.
-- =====================================================================

-- ---------------------------------------------------------------------
-- Tabla: capture_sessions
-- Un registro por cada ejecución del capturador. Permite separar y
-- comparar capturas (por ejemplo, una por cada interfaz de red).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS capture_sessions (
    id              BIGSERIAL    PRIMARY KEY,
    interfaces      TEXT[]       NOT NULL,              -- interfaces capturadas, p. ej. {enp1s0,wlp3s0}
    bpf_filter      TEXT         NOT NULL,              -- filtro BPF aplicado, p. ej. "ip and (tcp)"
    started_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,                        -- NULL mientras la captura permanece activa
    total_packets   BIGINT,                             -- paquetes almacenados (se registra al finalizar)
    dropped_packets BIGINT                              -- paquetes descartados por saturación de la cola
);

-- ---------------------------------------------------------------------
-- Tabla: packets
-- Un registro por cada paquete IPv4 capturado.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS packets (
    id              BIGSERIAL    PRIMARY KEY,
    session_id      BIGINT       NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
    captured_at     TIMESTAMPTZ  NOT NULL,              -- marca de tiempo asignada por el kernel en la captura
    interface       TEXT         NOT NULL,              -- interfaz por la que se recibió el paquete

    -- Campos exigidos en los requerimientos
    src_ip          INET         NOT NULL,              -- dirección IP de origen
    dst_ip          INET         NOT NULL,              -- dirección IP de destino
    protocol        VARCHAR(10)  NOT NULL,              -- TCP, UDP, ICMP, IGMP, GRE, ESP, etc., u OTHER
    length          INTEGER      NOT NULL,              -- tamaño de la trama en bytes

    -- Campos complementarios para el análisis posterior
    protocol_number SMALLINT     NOT NULL,              -- número de protocolo IPv4 (campo "proto")
    src_port        INTEGER,                            -- solo TCP/UDP; NULL en los demás casos
    dst_port        INTEGER,                            -- solo TCP/UDP; NULL en los demás casos

    -- Restricciones de integridad: la base de datos solo admite direcciones IPv4
    CONSTRAINT packets_src_ipv4   CHECK (family(src_ip) = 4),
    CONSTRAINT packets_dst_ipv4   CHECK (family(dst_ip) = 4),
    CONSTRAINT packets_proto_num  CHECK (protocol_number BETWEEN 0 AND 255),
    CONSTRAINT packets_length_pos CHECK (length > 0),
    CONSTRAINT packets_src_port   CHECK (src_port IS NULL OR src_port BETWEEN 0 AND 65535),
    CONSTRAINT packets_dst_port   CHECK (dst_port IS NULL OR dst_port BETWEEN 0 AND 65535)
);

-- ---------------------------------------------------------------------
-- Índices: diseñados para las consultas de estadísticas, que filtran por
-- sesión y agrupan por IP de origen, IP de destino o protocolo.
-- ---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_packets_session_src   ON packets (session_id, src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_session_dst   ON packets (session_id, dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_session_proto ON packets (session_id, protocol);
CREATE INDEX IF NOT EXISTS idx_packets_captured_at   ON packets (captured_at);
