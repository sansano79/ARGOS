#!/usr/bin/env bash
set -euo pipefail

# Exporta un dump comprimido de MySQL desde el stack docker-compose de producción.
# Uso:
#   ./scripts/db-export-prod.sh
#   ./scripts/db-export-prod.sh /ruta/salida.sql.gz

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env.prod}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "No existe $ENV_FILE"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker no está instalado o no está en PATH"
  exit 1
fi

if ! docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps mysql >/dev/null 2>&1; then
  echo "No se puede acceder al servicio mysql con compose file: $COMPOSE_FILE"
  echo "Asegúrate de tener el stack levantado: docker compose -f $COMPOSE_FILE --env-file $ENV_FILE up -d mysql"
  exit 1
fi

timestamp="$(date +%Y%m%d_%H%M%S)"
default_out="$ROOT_DIR/storage/backups/occ_vulns_${timestamp}.sql.gz"
out_file="${1:-$default_out}"

mkdir -p "$(dirname "$out_file")"

echo "Exportando DB a: $out_file"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" exec -T mysql sh -lc '
  mysqldump \
    -u"$MYSQL_USER" \
    -p"$MYSQL_PASSWORD" \
    "$MYSQL_DATABASE" \
    --single-transaction \
    --quick \
    --routines \
    --events \
    --triggers \
    --set-gtid-purged=OFF \
    --default-character-set=utf8mb4
' | gzip -9 > "$out_file"

echo "Dump generado correctamente."
ls -lh "$out_file"
