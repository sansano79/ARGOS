#!/usr/bin/env bash
# Prueba prisma migrate deploy sobre una base con las 11 migraciones previas ya aplicadas.
# Simula el escenario de una DB de producción donde solo la migración nueva debe aplicarse.
#
# Estrategia:
#   1. Arrancar MySQL efímero.
#   2. Mover la nueva migración a /tmp para que Prisma no la vea.
#   3. Aplicar las 11 migraciones previas + insertar fila de prueba en users.
#   4. Restaurar la nueva migración.
#   5. Aplicar solo la 12ª migración.
#   6. Verificar que: fila legacy intacta, 5 tablas nuevas presentes.
set -euo pipefail

CONTAINER="argos_existing_test"
NETWORK="argos_existing_net"
VOLUME="argos_existing_vol"
DB_NAME="argos_test"
DB_PASS="testpass123"
DB_PORT="3400"
MYSQL_IMAGE="mysql:8.0"
TIMEOUT_SECS=60

NEW_MIGRATION="20260623000000_add_subscriber_teams"
MIGRATION_SRC="prisma/migrations/${NEW_MIGRATION}"
MIGRATION_TMP="/tmp/${NEW_MIGRATION}_$$"

restored=false

restore_migration() {
  if [ "$restored" = false ] && [ -d "$MIGRATION_TMP" ]; then
    mv "$MIGRATION_TMP" "$MIGRATION_SRC"
    restored=true
  fi
}

cleanup() {
  restore_migration
  echo ""
  echo "── Limpieza ──────────────────────────────────"
  docker rm -f "$CONTAINER"  2>/dev/null || true
  docker network rm "$NETWORK" 2>/dev/null || true
  docker volume rm "$VOLUME"  2>/dev/null || true
  echo "Limpieza completada."
}
trap cleanup EXIT

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
sleep 5

DATABASE_URL="mysql://root:${DB_PASS}@127.0.0.1:${DB_PORT}/${DB_NAME}"
export DATABASE_URL

# ── Paso 1: ocultar la nueva migración y aplicar las 11 previas ──────────
echo ""
echo "── Paso 1: aplicando las 11 migraciones previas ──"
mv "$MIGRATION_SRC" "$MIGRATION_TMP"

node_modules/.bin/prisma migrate deploy

echo ""
echo "── Verificación intermedia: 11 migraciones aplicadas ──"
node_modules/.bin/prisma migrate status 2>&1 | grep -E "migrations found|up to date|pending" || true

# Insertar fila legacy de prueba para confirmar preservación de datos
echo ""
echo "── Insertando fila legacy de prueba en users ──"
docker exec "$CONTAINER" mysql -uroot -p"$DB_PASS" "$DB_NAME" 2>/dev/null \
  -e "INSERT INTO users (email, name, role, auth_provider, can_login, is_subscriber, can_receive_notifications, notifications_paused, is_active, mfa_enabled, created_at, updated_at) VALUES ('test-legacy@example.com', 'Legacy Test', 'SUBSCRIBER', 'LOCAL', 1, 1, 1, 0, 1, 0, NOW(), NOW());"
LEGACY_ID=$(docker exec "$CONTAINER" mysql -uroot -p"$DB_PASS" "$DB_NAME" \
  -e "SELECT id FROM users WHERE email='test-legacy@example.com';" \
  --skip-column-names 2>/dev/null)
echo "Fila legacy insertada con id=${LEGACY_ID}"

# ── Paso 2: restaurar la nueva migración y aplicarla ─────────────────────
echo ""
echo "── Paso 2: restaurando y aplicando la migración de equipos ──"
restore_migration

node_modules/.bin/prisma migrate deploy

echo ""
echo "── prisma migrate status ──────────────────────"
node_modules/.bin/prisma migrate status

# ── Verificaciones ────────────────────────────────────────────────────────
echo ""
echo "── Verificación: fila legacy intacta ───────────"
FOUND=$(docker exec "$CONTAINER" mysql -uroot -p"$DB_PASS" "$DB_NAME" \
  -e "SELECT COUNT(*) FROM users WHERE email='test-legacy@example.com' AND is_subscriber=1;" \
  --skip-column-names 2>/dev/null)
if [ "$FOUND" -eq 1 ]; then
  echo "  ✓ fila legacy intacta en users"
else
  echo "  ✗ fila legacy PERDIDA en users" >&2
  exit 1
fi

echo ""
echo "── Verificación: tablas de equipos (Fase 1A) ──"
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
echo "── Verificación: tablas legacy intactas ────────"
LEGACY_TABLES=("users" "user_subscriptions" "subscriber_owned_systems" "notification_policies" "vulnerability_notifications" "pending_digest_notifications" "subscriber_patched_cves")
for TABLE in "${LEGACY_TABLES[@]}"; do
  EXISTS=$(docker exec "$CONTAINER" mysql -uroot -p"$DB_PASS" "$DB_NAME" \
    -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}' AND table_name='${TABLE}';" \
    --skip-column-names 2>/dev/null)
  if [ "$EXISTS" -eq 1 ]; then
    echo "  ✓ ${TABLE} (legacy intacta)"
  else
    echo "  ✗ ${TABLE} — FALTA TABLA LEGACY" >&2
    ALL_OK=false
  fi
done

echo ""
if [ "$ALL_OK" = true ]; then
  echo "==================================================="
  echo "RESULTADO: migración incremental correcta."
  echo "           Fila legacy intacta, tablas nuevas (5/5)"
  echo "           y tablas legacy (7/7) presentes."
  echo "==================================================="
else
  echo "==================================================="
  echo "ERROR: alguna verificación falló. Ver salida arriba."
  echo "==================================================="
  exit 1
fi
