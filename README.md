# OCC-TVM — Threat & Vulnerability Management

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

## Despliegue en Producción de OCC-TVM

### 1) Requisitos recomendados

- Ubuntu/Debian LTS
- Docker + Docker Compose plugin
- Dominio en Cloudflare (proxy naranja activo)
- Puertos abiertos: `80/tcp`, `443/tcp`

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
- `TRUST_PROXY=1`
- `PRISMA_MIGRATE_ON_START=false` y `PRISMA_DB_PUSH_ON_START=false`: las migraciones no se ejecutan al arrancar.
- `OLLAMA_BASE_URL` y `OLLAMA_MODEL` según tu servidor IA

### 3) Cloudflare (recomendado)

En Cloudflare Dashboard:

1. `DNS`:
   - `A app.tu-dominio.com -> IP_ORIGEN` (Proxy: ON)
2. `SSL/TLS`:
   - Mode: **Full (strict)**
3. `Edge Certificates`:
   - Always Use HTTPS: **ON**
   - TLS 1.3: **ON**
4. `Firewall`:
   - WAF Managed Rules: **ON**
   - Bot Fight Mode/Super Bot Fight: **ON** (si aplica)

### 4) Certificado en origen

Opciones:

- Certificado de Cloudflare Origin (recomendado para Full strict)
- O certificado válido de Let’s Encrypt

Coloca los ficheros en:

- `docker/ssl/server.crt`
- `docker/ssl/server.key`

### 5) Primer despliegue

```bash
docker compose -f docker-compose.yml --env-file .env.prod up -d --build
```

Verifica:

```bash
docker compose -f docker-compose.yml --env-file .env.prod ps
docker compose -f docker-compose.yml --env-file .env.prod logs -f nginx
docker compose -f docker-compose.yml --env-file .env.prod logs -f api
```

### 6) Migraciones / esquema (modo seguro)

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

### 7) Publicación y validaciones

1. Health:
   - `https://app.tu-dominio.com/health`
2. Login y navegación UI
3. Envío SMTP de prueba
4. Asistente IA (si Ollama está configurado)

### 8) Endurecimiento adicional recomendado

- Restringir en firewall del servidor el acceso directo al origen (permitir solo IPs de Cloudflare).
- Rotar periódicamente:
  - `JWT_SECRET`
  - contraseñas DB/Redis
  - API keys (NVD/GitHub/SMTP)
- Backups automáticos de MySQL y pruebas de restore.
- Monitorizar logs de `nginx` y `api` con alertas.

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
- `TRUST_PROXY`: `1` detrás de proxy (Cloudflare/Nginx)

## Nuevas Funcionalidades

### 📧 Sistema de Notificaciones
- Configuración dinámica de SMTP desde la UI / API.
- Soporte para plantillas HTML (`src/templates`).

### 🤖 Integración IA
- Módulo agnóstico (**OpenAI** o **Ollama**).
- Endpoint `POST /api/ai/chat` para consultas.
- Configurable desde la base de datos.
