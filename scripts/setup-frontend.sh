#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Servicios OCC — Frontend Setup
# ═══════════════════════════════════════════════════════════════
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FRONTEND_DIR="$PROJECT_ROOT/frontend"

echo "╔══════════════════════════════════════════════╗"
echo "║  Servicios OCC — Frontend Setup              ║"
echo "╚══════════════════════════════════════════════╝"

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js no encontrado. Instalar Node.js >= 18"
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js >= 18 requerido. Versión actual: $(node -v)"
    exit 1
fi

echo "✓ Node.js $(node -v)"

# Install dependencies
echo ""
echo "▸ Instalando dependencias frontend..."
cd "$FRONTEND_DIR"
npm install

echo ""
echo "══════════════════════════════════════════════════"
echo "✅ Frontend instalado correctamente"
echo ""
echo "Comandos disponibles:"
echo ""
echo "  Desarrollo (con proxy a API):"
echo "    cd frontend && npm run dev"
echo "    → http://localhost:5173"
echo ""
echo "  Build para producción:"
echo "    cd frontend && npm run build"
echo "    → Output en public/frontend/"
echo ""
echo "  Docker Compose (todo junto):"
echo "    docker compose up -d"
echo "    → API:      http://localhost:3000"
echo "    → Frontend: http://localhost:5173"
echo "    → Swagger:  http://localhost:3000/api/docs"
echo ""
echo "══════════════════════════════════════════════════"
