#!/bin/sh
set -e

echo "🚀 Servicios OCC — Starting..."

# Use the project's prisma
PRISMA="./node_modules/.bin/prisma"

# Wait for DB (though depends_on healthy should handle it, double check)
# In production with MySQL, we use 'migrate deploy' instead of 'db push'
echo "📦 Running database migrations..."
$PRISMA migrate deploy

# Seed if needed (optional, distinct step usually, but for convenience on first run)
# Ideally check if users table is empty
# echo "🌱 Seeding database..."
# $PRISMA db seed

echo "🚀 Starting NestJS..."
exec node dist/src/main.js
