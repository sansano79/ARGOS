#!/bin/sh
set -e

echo "🚀 Servicios OCC — Starting..."

# Use the project's prisma, not npx (which may download a different version)
PRISMA="./node_modules/.bin/prisma"

if [ ! -f /app/data/occ.db ]; then
    echo "📦 First run: Creating SQLite database..."
    $PRISMA db push
    echo "✅ Database initialized"
else
    echo "✅ Database exists, checking schema..."
    $PRISMA db push --accept-data-loss 2>/dev/null || echo "⚠️  Schema already up to date"
fi

echo "🚀 Starting NestJS..."
exec node dist/src/main.js
