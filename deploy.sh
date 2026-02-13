#!/bin/bash

# Script de despliegue para producción
# Uso: ./deploy.sh

echo "🚀 Iniciando despliegue de Servicios OCC..."

# 1. Detener contenedores antiguos
echo "🛑 Deteniendo servicios..."
docker compose -f docker-compose.prod.yml down

# 2. (Opcional) Traer últimos cambios de git
# echo "📥 Actualizando repositorio..."
# git pull

# 3. Reconstruir y levantar con variables de entorno correctas
echo "🏗️ Reconstruyendo y levantando servicios con .env.prod..."
docker compose --env-file .env.prod -f docker-compose.prod.yml up -d --build

# 4. Verificar estado
echo "✅ Despliegue completado. Verificando logs..."
sleep 5
docker compose -f docker-compose.prod.yml logs --tail=50 api

echo "🌍 Estado de los contenedores:"
docker compose -f docker-compose.prod.yml ps
