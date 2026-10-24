#!/usr/bin/env bash
# ---------------------------------------------------------------------
# Genera tráfico IPv4 de prueba a través de una interfaz específica.
# Debe ejecutarse en el equipo anfitrión (no dentro del contenedor), en una
# terminal independiente, mientras el capturador se encuentra activo.
#
# Uso:       ./scripts/generar_trafico.sh <interfaz>
# Ejemplo:   ./scripts/generar_trafico.sh wlp3s0
# ---------------------------------------------------------------------
set -euo pipefail

IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then
  echo "Uso: $0 <interfaz>   (ver nombres con: ip -br addr)" >&2
  exit 1
fi

if ! ip -4 addr show dev "$IFACE" | grep -q "inet "; then
  echo "AVISO: $IFACE no tiene dirección IPv4. ¿Cable conectado / Wi-Fi asociada?" >&2
fi

echo ">> ICMP: 10 pings a 8.8.8.8 por $IFACE"
ping -4 -c 10 -i 0.2 -I "$IFACE" 8.8.8.8 || true

echo ">> TCP: 3 peticiones HTTPS por $IFACE"
for url in https://example.com https://www.google.com https://github.com; do
  curl -4 -s -o /dev/null --interface "$IFACE" -w "   %{http_code} $url\n" "$url" || true
done

echo ">> UDP: consultas DNS a 1.1.1.1 por $IFACE"
SRC_IP="$(ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -1)"
if command -v dig >/dev/null && [[ -n "$SRC_IP" ]]; then
  for host in example.com google.com github.com; do
    # La opción -b fija la IP de origen, de modo que la consulta se envía por esa interfaz
    dig -4 +short -b "$SRC_IP" @1.1.1.1 "$host" >/dev/null || true
  done
else
  echo "   (omitido: instala 'dig' con  sudo apt install bind9-dnsutils)"
fi

echo "Listo."
