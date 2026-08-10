#!/usr/bin/env bash
set -euo pipefail

# Restaura un dump SQL(.gz) en MySQL dentro del stack docker-compose.
# Uso:
#   ./scripts/db-restore-prod.sh /ruta/backup.sql.gz
#   ./scripts/db-restore-prod.sh /ruta/backup.sql
#
# Variables opcionales:
#   COMPOSE_FILE=/ruta/docker-compose.yml
#   ENV_FILE=/ruta/.env.prod
#   FORCE_RESTORE=true   # omite confirmación interactiva

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env.prod}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "No existe $ENV_FILE"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker no está instalado o no está en PATH"
  exit 1
fi

if [[ $# -lt 1 ]]; then
  echo "Uso: $0 /ruta/backup.sql.gz|/ruta/backup.sql"
  exit 1
fi

DUMP_FILE="$1"

if [[ ! -f "$DUMP_FILE" ]]; then
  echo "No existe el dump: $DUMP_FILE"
  exit 1
fi

if ! docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps mysql >/dev/null 2>&1; then
  echo "No se puede acceder al servicio mysql con compose file: $COMPOSE_FILE"
  echo "Levanta el servicio: docker compose -f $COMPOSE_FILE --env-file $ENV_FILE up -d mysql"
  exit 1
fi

echo "ATENCION: este proceso reemplazará datos de la BD actual."
echo "Archivo: $DUMP_FILE"
echo "Compose: $COMPOSE_FILE"
echo "Env: $ENV_FILE"

if [[ "${FORCE_RESTORE:-false}" != "true" ]]; then
  read -r -p "Escribe RESTORE para continuar: " confirm
  if [[ "$confirm" != "RESTORE" ]]; then
    echo "Operación cancelada."
    exit 1
  fi
fi

echo "Restaurando base de datos..."
if [[ "$DUMP_FILE" == *.gz ]]; then
  gzip -cd "$DUMP_FILE" | docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" exec -T mysql sh -lc '
    mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"
  '
else
  cat "$DUMP_FILE" | docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" exec -T mysql sh -lc '
    mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"
  '
fi

echo "Restore completado correctamente."
