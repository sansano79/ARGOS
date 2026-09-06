# ARGOS — Threat & Vulnerability Management

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

## Despliegue en Producción de ARGOS

### 1) Requisitos recomendados

- Ubuntu/Debian LTS
- Docker + Docker Compose plugin
- Proxy corporativo/ingress externo para publicar HTTPS en producción
- Puerto HTTP interno publicado por este stack: `80/tcp`

### 2) Preparar variables de producción

```bash
cp .env.example .env.prod
nano .env.prod
```

Valores clave de seguridad:

- `NODE_ENV=production`
- `JWT_SECRET=<random-largo>`
- `CORS_ORIGIN=https://app.tu-dominio.com`
- `ENABLE_SWAGGER=false`
- `TRUST_PROXY=1` si el stack queda detrás de un proxy/ingress externo
- `PRISMA_MIGRATE_ON_START=false` y `PRISMA_DB_PUSH_ON_START=false`: las migraciones no se ejecutan al arrancar.
- `OLLAMA_BASE_URL` y `OLLAMA_MODEL` según tu servidor IA

### 3) Publicación HTTP/HTTPS

Este repositorio no gestiona el reverse proxy TLS ni los certificados de producción. El stack publica la aplicación por HTTP en el puerto configurado con `OCC_HTTP_PORT` (`80` por defecto), y el proxy corporativo/ingress externo debe encargarse de HTTPS, certificados, HSTS, WAF y políticas de borde.

Para desarrollo o entornos internos sin TLS local:

```bash
http://<host>/health
http://<host>/api/health
http://<host>/api/v1/vulnerabilities?limit=5
```

### 4) Primer despliegue

```bash
docker compose -f docker-compose.yml --env-file .env.prod up -d --build
```

Verifica:

```bash
docker compose -f docker-compose.yml --env-file .env.prod ps
docker compose -f docker-compose.yml --env-file .env.prod logs -f api
docker compose -f docker-compose.yml --env-file .env.prod logs -f frontend
```

### 5) Migraciones / esquema (modo seguro)

Con `PRISMA_DB_PUSH_ON_START=false`, aplica migraciones de forma controlada y trazable:

```bash
# Aplicar migraciones pendientes (produce historial auditable)
docker compose -f docker-compose.yml --env-file .env.prod run --rm api npx prisma migrate deploy
docker compose -f docker-compose.yml --env-file .env.prod up -d api
```

> **Importante:** usa `prisma migrate deploy`, no `prisma db push`.
> `db push` no registra historial, no es idempotente en producción y puede
> silenciar pérdidas de datos. Reserva `db push` exclusivamente para
> entornos de prototipado local.

Luego reinicia API:

```bash
docker compose -f docker-compose.yml --env-file .env.prod up -d --build api
```

### 6) Publicación y validaciones

1. Health:
   - Interno/desarrollo: `http://<host>/health`
   - Producción: `https://app.tu-dominio.com/health` a través del proxy/ingress externo
2. Login y navegación UI
3. Envío SMTP de prueba
4. Asistente IA (si Ollama está configurado)

### 7) Endurecimiento adicional recomendado

- Restringir en firewall del servidor el acceso directo al origen si sólo debe recibir tráfico del proxy corporativo.
- Rotar periódicamente:
  - `JWT_SECRET`
  - contraseñas DB/Redis
  - API keys (NVD/GitHub/SMTP)
- Backups automáticos de MySQL y pruebas de restore.
- Monitorizar logs de `frontend`, `api` y del proxy externo con alertas.

## Migrar Estado Actual de la Base de Datos (recolecciones)

Si quieres subir al servidor todo el estado actual (CVE recolectadas, tags, plantillas, etc.), usa dump + restore.

Importante para despliegue vía GitHub:
- Sube al repo solo código y scripts.
- No subas `.env.prod`, claves SSL ni dumps `.sql/.sql.gz`.
- El dump se transfiere fuera de GitHub (por `scp`/`rsync`) directo al servidor.

### 1) Exportar en origen

```bash
./scripts/db-export-prod.sh
```

Genera un archivo `.sql.gz` en `storage/backups/`.

### 2) Copiar dump al servidor

```bash
scp ./storage/backups/occ_vulns_YYYYMMDD_HHMMSS.sql.gz usuario@tu-servidor:/opt/occ-vuls-git/storage/backups/
```

### 3) Restaurar en servidor destino

```bash
cd /opt/occ-vuls-git
docker compose -f docker-compose.yml --env-file .env.prod up -d mysql
./scripts/db-restore-prod.sh ./storage/backups/occ_vulns_YYYYMMDD_HHMMSS.sql.gz
```

Notas:
- El script pide confirmación (`RESTORE`) para evitar borrados accidentales.
- Puedes omitir confirmación solo si sabes lo que haces: `FORCE_RESTORE=true ./scripts/db-restore-prod.sh ...`

### 4) Levantar aplicación y validar

```bash
docker compose -f docker-compose.yml --env-file .env.prod up -d --build
docker compose -f docker-compose.yml --env-file .env.prod logs -f api
```

Validaciones mínimas:
- Login correcto.
- Conteo de CVE en panel.
- Contactos, configuraciones y plantillas visibles.

## Configuración

Variables clave en `.env` (dev) o `.env.prod` (prod):

- `DATABASE_URL`: Connection string MySQL
- `NVD_API_KEY`: Key de NVD (Vital para performance)
- `GITHUB_TOKEN`: Token de GitHub (Para búsqueda de exploits)
- `JWT_SECRET`: Secreto para tokens de sesión
- `OLLAMA_BASE_URL`: URL de IA local (opcional)
- `CORS_ORIGIN`: Origen permitido del frontend en producción
- `ENABLE_SWAGGER`: `false` recomendado en producción
- `TRUST_PROXY`: `1` detrás de proxy/ingress externo

## Nuevas Funcionalidades

### 📧 Sistema de Notificaciones
- Configuración dinámica de SMTP desde la UI / API.
- Soporte para plantillas HTML (`src/templates`).

### 🤖 Integración IA
- Módulo agnóstico (**OpenAI** o **Ollama**).
- Endpoint `POST /api/ai/chat` para consultas.
- Configurable desde la base de datos.
