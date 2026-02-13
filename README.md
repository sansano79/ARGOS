# Servicios OCC — Vulnerability Collector

Sistema automatizado de recolección, análisis y reporte de vulnerabilidades para la Oficina de Ciberseguridad.

## Stack Tecnológico

| Componente | Tecnología |
|-----------|------------|
| Backend | NestJS + TypeScript |
| Base de datos | **MySQL 8.0** |
| ORM | Prisma |
| Cache | Redis 7 |
| PDF | Puppeteer + Handlebars |
| Notificaciones | Nodemailer (SMTP) |
| IA | OpenAI / Ollama |
| Contenedores | Docker Compose |
| Scheduler | @nestjs/schedule (Cron) |

## Fuentes de Datos

- **NVD (NIST)**: CVEs, CVSS scores, CPE (software afectado)
- **CISA KEV**: Vulnerabilidades con explotación activa confirmada
- **FIRST EPSS**: Probabilidad de explotación en 30 días
- **GitHub / nomi-sec**: Exploits públicos (PoC)

## Inicio Rápido (Desarrollo)

```bash
# 1. Configurar entorno
cp .env.example .env
# Editar .env con tus claves

# 2. Levantar servicios básicos (MySQL + Redis)
docker compose up -d mysql redis

# 3. Instalar y migrar
npm install
npx prisma migrate dev --name init
npx prisma db seed

# 4. Arrancar API
npm run start:dev
```

## Despliegue en Producción

Para desplegar la aplicación completa (API + Frontend + Nginx + SSL + MySQL + Redis):

1. **Configurar entorno de producción**:
   ```bash
   cp .env.prod.example .env.prod
   nano .env.prod
   # Ajustar contraseñas, claves API y dominios
   ```

2. **Generar certificados SSL (si usas HTTPS autofirmado)**:
   ```bash
   ./scripts/generate-ssl.sh
   ```

3. **Arrancar Stack de Producción**:
   ```bash
   docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
   ```

Esto levantará:
- **Nginx** en puertos 80/443 (Reverse Proxy & SSL offloading)
- **API NestJS** (Optimizada para producción)
- **Frontend React** (Build estático servido por Nginx interno)
- **MySQL 8.0** (Database)
- **Redis 7** (Cache)

## Configuración

Variables clave en `.env` (dev) o `.env.prod` (prod):

- `DATABASE_URL`: Connection string MySQL
- `NVD_API_KEY`: Key de NVD (Vital para performance)
- `GITHUB_TOKEN`: Token de GitHub (Para búsqueda de exploits)
- `JWT_SECRET`: Secreto para tokens de sesión
- `OLLAMA_BASE_URL`: URL de IA local (opcional)

## Nuevas Funcionalidades

### 📧 Sistema de Notificaciones
- Configuración dinámica de SMTP desde la UI / API.
- Soporte para plantillas HTML (`src/templates`).

### 🤖 Integración IA
- Módulo agnóstico (**OpenAI** o **Ollama**).
- Endpoint `POST /api/ai/chat` para consultas.
- Configurable desde la base de datos.
