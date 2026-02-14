#!/bin/sh
set -e

echo "🚀 Servicios OCC — Starting..."

PRISMA="./node_modules/.bin/prisma"

# Apply schema to database (works without migration files)
echo "📦 Applying database schema..."
$PRISMA db push --skip-generate --accept-data-loss 2>&1 || echo "⚠️ db push warning (non-fatal)"

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
