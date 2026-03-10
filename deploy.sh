#!/bin/bash

# Script de despliegue para producción
# Uso: ./deploy.sh

set -euo pipefail

echo "🚀 Iniciando despliegue de Servicios OCC..."

COMPOSE="docker compose"

# 1. Detener contenedores antiguos (y limpiar huérfanos)
echo "🛑 Deteniendo servicios (prod) y limpiando huérfanos..."
$COMPOSE --env-file .env.prod -f docker-compose.prod.yml down --remove-orphans || true

# 2. (Opcional) Traer últimos cambios de git
# echo "📥 Actualizando repositorio..."
# git pull

# 3. Reconstruir y levantar (build API + frontend para evitar imágenes desfasadas)
echo "🏗️ Reconstruyendo y levantando servicios con .env.prod..."
$COMPOSE --env-file .env.prod -f docker-compose.prod.yml build --no-cache api
$COMPOSE --env-file .env.prod -f docker-compose.prod.yml build frontend
$COMPOSE --env-file .env.prod -f docker-compose.prod.yml up -d --remove-orphans --force-recreate

# 4. Esperar a que el API arranque
echo "⏳ Esperando a que el API arranque..."
sleep 15

# 5. Verificar estado
echo "✅ Despliegue completado. Verificando logs..."
$COMPOSE -f docker-compose.prod.yml logs --tail=80 api
$COMPOSE -f docker-compose.prod.yml logs --tail=80 nginx
$COMPOSE -f docker-compose.prod.yml logs --tail=80 frontend

echo "🌍 Estado de los contenedores:"
$COMPOSE -f docker-compose.prod.yml ps
