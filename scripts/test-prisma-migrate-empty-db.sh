#!/usr/bin/env bash
# Prueba prisma migrate deploy sobre MySQL efímero completamente vacío.
# Limpia contenedor, red y volumen siempre, incluso si falla.
set -euo pipefail

CONTAINER="occ_vuls_migrate_test"
NETWORK="occ_vuls_migrate_net"
VOLUME="occ_vuls_migrate_vol"
DB_NAME="occ_vuls_test"
DB_PASS="testpass123"
DB_PORT="3399"
MYSQL_IMAGE="mysql:8.0"
TIMEOUT_SECS=60

cleanup() {
  echo ""
  echo "── Limpieza ──────────────────────────────────"
  docker rm -f "$CONTAINER"  2>/dev/null || true
  docker network rm "$NETWORK" 2>/dev/null || true
  docker volume rm "$VOLUME"  2>/dev/null || true
  echo "Limpieza completada."
}
trap cleanup EXIT

# ── Asegurar limpieza previa ────────────────────────────────
cleanup

echo "── Creando red y volumen ──────────────────────"
docker network create "$NETWORK"
docker volume create "$VOLUME"

echo "── Iniciando MySQL 8.0 efímero ────────────────"
docker run -d \
  --name "$CONTAINER" \
  --network "$NETWORK" \
  -v "${VOLUME}:/var/lib/mysql" \
  -e MYSQL_ROOT_PASSWORD="$DB_PASS" \
  -e MYSQL_DATABASE="$DB_NAME" \
  -p "${DB_PORT}:3306" \
  "$MYSQL_IMAGE" \
  --character-set-server=utf8mb4 \
  --collation-server=utf8mb4_unicode_ci

echo "── Esperando que MySQL esté listo ─────────────"
elapsed=0
until docker exec "$CONTAINER" mysqladmin ping -uroot -p"$DB_PASS" --silent 2>/dev/null; do
  if [ $elapsed -ge $TIMEOUT_SECS ]; then
    echo "ERROR: MySQL no respondió en ${TIMEOUT_SECS}s" >&2
    exit 1
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done
echo "MySQL listo (${elapsed}s)."

# Extra: esperar a que la DB esté completamente inicializada
sleep 2

DATABASE_URL="mysql://root:${DB_PASS}@127.0.0.1:${DB_PORT}/${DB_NAME}"
export DATABASE_URL

echo ""
echo "── prisma migrate deploy ──────────────────────"
npx prisma migrate deploy

echo ""
echo "── prisma migrate status ──────────────────────"
npx prisma migrate status

echo ""
echo "── Verificación: contar tablas creadas ────────"
TABLE_COUNT=$(docker exec "$CONTAINER" mysql -uroot -p"$DB_PASS" "$DB_NAME" \
  -e "SELECT COUNT(*) AS tables FROM information_schema.tables WHERE table_schema='${DB_NAME}';" \
  --skip-column-names 2>/dev/null)
echo "Tablas en DB: ${TABLE_COUNT}"

echo ""
echo "── Lista de tablas ────────────────────────────"
docker exec "$CONTAINER" mysql -uroot -p"$DB_PASS" "$DB_NAME" \
  -e "SELECT table_name FROM information_schema.tables WHERE table_schema='${DB_NAME}' ORDER BY table_name;" \
  2>/dev/null

echo ""
echo "── Validación tablas de equipos (Fase 1A) ─────"
TEAM_TABLES=("subscriber_teams" "team_members" "notification_recipients" "team_subscriptions" "team_systems")
ALL_OK=true
for TABLE in "${TEAM_TABLES[@]}"; do
  EXISTS=$(docker exec "$CONTAINER" mysql -uroot -p"$DB_PASS" "$DB_NAME" \
    -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}' AND table_name='${TABLE}';" \
    --skip-column-names 2>/dev/null)
  if [ "$EXISTS" -eq 1 ]; then
    echo "  ✓ ${TABLE}"
  else
    echo "  ✗ ${TABLE} — NO ENCONTRADA" >&2
    ALL_OK=false
  fi
done

echo ""
if [ "$ALL_OK" = true ]; then
  echo "==================================================="
  echo "RESULTADO: migrate deploy completado correctamente."
  echo "           Tablas de equipos presentes (5/5)."
  echo "==================================================="
else
  echo "==================================================="
  echo "ERROR: faltan tablas de equipos. Ver salida arriba."
  echo "==================================================="
  exit 1
fi
