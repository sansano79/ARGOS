#!/bin/sh
set -e

echo "🚀 Servicios OCC — Starting..."

PRISMA="./node_modules/.bin/prisma"

# Apply migrations (recommended for production)
echo "📦 Applying database migrations..."
if [ "${PRISMA_MIGRATE_ON_START:-true}" = "true" ]; then
  if ! $PRISMA migrate deploy; then
    echo "❌ migrate deploy failed. Aborting startup."
    exit 1
  fi
else
  echo "⏭️ PRISMA_MIGRATE_ON_START=false -> skipping migrate deploy"
fi

# Optional: db push (development/edge cases)
if [ "${PRISMA_DB_PUSH_ON_START:-false}" = "true" ]; then
  echo "📦 Applying database schema (db push)..."
  if ! $PRISMA db push --skip-generate --accept-data-loss; then
    echo "❌ db push failed. Aborting startup."
    exit 1
  fi
fi

# Seed on first boot: only if users table is empty
echo "🌱 Checking if seed is needed..."
USERS_COUNT=$(node -e "
const { PrismaClient } = require('@prisma/client');
const p = new PrismaClient();
p.user.count()
  .then(c => { console.log(c); return p.\$disconnect(); })
  .catch(() => { console.log('0'); return p.\$disconnect(); });
" 2>/dev/null || echo "0")

if [ "$USERS_COUNT" = "0" ]; then
  echo "🌱 No users found — running seed..."
  node prisma/seed.js || echo "⚠️ Seed had errors (non-fatal), continuing..."
else
  echo "✅ Database already seeded ($USERS_COUNT users)"
fi

echo "🚀 Starting NestJS..."
exec node dist/src/main.js
