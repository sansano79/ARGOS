#!/bin/bash

# Script de despliegue para el stack OCC-TVM
# Uso: ./deploy.sh

set -euo pipefail

echo "🚀 Iniciando despliegue de OCC-TVM..."

COMPOSE="docker compose --env-file .env.prod -f docker-compose.yml"

# 1. (Opcional) Traer últimos cambios de git
# echo "📥 Actualizando repositorio..."
# git pull

# 2. Reconstruir y levantar. No se ejecuta `down`: evita una caída evitable y
# preserva los volúmenes de datos durante la actualización.
echo "🏗️ Reconstruyendo y levantando servicios con .env.prod..."
$COMPOSE build api frontend
$COMPOSE up -d --remove-orphans

# 4. Esperar a que el API arranque
echo "⏳ Esperando a que el API arranque..."
sleep 15

# 5. Verificar estado
echo "✅ Despliegue completado. Verificando logs..."
$COMPOSE logs --tail=80 api
$COMPOSE logs --tail=80 frontend

echo "🌍 Estado de los contenedores:"
$COMPOSE ps
