# Servicios OCC — Vulnerability Collector

Sistema automatizado de recolección, análisis y reporte de vulnerabilidades para la Oficina de Ciberseguridad.

## Stack Tecnológico

| Componente | Tecnología |
|-----------|------------|
| Backend | NestJS + TypeScript |
| Base de datos | PostgreSQL 16 |
| ORM | Prisma |
| Cache | Redis 7 |
| PDF | Puppeteer + Handlebars |
| Contenedores | Docker Compose |
| Scheduler | @nestjs/schedule (Cron) |

## Fuentes de Datos

- **NVD (NIST)**: CVEs, CVSS scores, CPE (software afectado)
- **CISA KEV**: Vulnerabilidades con explotación activa confirmada
- **FIRST EPSS**: Probabilidad de explotación en 30 días
- **GitHub / nomi-sec**: Exploits públicos (PoC)

## Inicio Rápido

```bash
# 1. Levantar infraestructura
docker compose up -d postgres redis

# 2. Instalar dependencias
npm install

# 3. Generar cliente Prisma + migrar BD
npx prisma generate
npx prisma migrate dev --name init

# 4. Seed (usuarios y config iniciales)
npx prisma db seed

# 5. Arrancar API
npm run start:dev
```

O con Docker completo:
```bash
docker compose up -d
```

## Configuración

Copiar `.env.example` → `.env` y configurar:

- `NVD_API_KEY`: Obtener en https://nvd.nist.gov/developers/request-an-api-key
- `GITHUB_TOKEN`: Token personal de GitHub (mejora rate limit)
- `JWT_SECRET`: Cambiar obligatoriamente en producción
- `POSTGRES_PASSWORD`: Cambiar en producción

## API Endpoints

| Método | Endpoint | Descripción |
|--------|---------|-------------|
| POST | `/api/auth/login` | Login (email + password) |
| GET | `/api/auth/profile` | Perfil usuario autenticado |
| GET | `/api/vulnerabilities` | Listar vulnerabilidades (filtros: severity, exploited, hours) |
| POST | `/api/vulnerabilities/collect` | Disparo manual de recolección (admin) |
| POST | `/api/vulnerabilities/report` | Generar informe PDF |
| GET | `/api/vulnerabilities/dashboard` | Datos para dashboard |
| GET | `/api/vulnerabilities/reports` | Historial de informes |
| GET | `/api/vulnerabilities/runs` | Historial de ejecuciones del collector |
| GET | `/api/docs` | Swagger UI |

## Usuarios por Defecto

| Email | Password | Rol |
|-------|----------|-----|
| admin@servicios-occ.local | Admin.OCC.2026! | ADMIN |
| viewer@servicios-occ.local | Viewer.OCC.2026! | VIEWER |

⚠️ **Cambiar passwords en producción**

## Funcionamiento del Collector

Cada 30 minutos (configurable):

1. **NVD API** → Descarga CVEs publicados en la última hora
2. **Parse CPE** → Extrae vendor, producto, versiones afectadas
3. **CISA KEV** → Flag si la vulnerabilidad tiene explotación activa
4. **EPSS** → Probabilidad de explotación en 30 días
5. **Exploit Check** → Busca PoCs en GitHub (solo HIGH/CRITICAL)
6. **Persist** → Upsert en PostgreSQL con todos los datos enriquecidos

## Generación de Informes

```bash
# Via API
curl -X POST "http://localhost:3000/api/vulnerabilities/report?hours=24&minSeverity=HIGH" \
  -H "Authorization: Bearer <token>"

# Via CLI
npx ts-node scripts/manual-collect.ts
```

El PDF incluye:
- Portada con branding SEIDOR/OCC
- Resumen ejecutivo con métricas
- Sección de acción inmediata (CVEs con explotación activa)
- Tabla completa con CVSS, EPSS, exploit status, productos y remediación
- Clasificación CONFIDENCIAL

## Estructura del Proyecto

```
src/
├── auth/                          # Autenticación JWT
├── prisma/                        # Prisma service
├── modules/
│   ├── vulnerability-collector/
│   │   ├── collectors/            # NVD, CISA KEV, EPSS, Exploit Check
│   │   ├── report/                # Generador PDF + plantilla Handlebars
│   │   ├── vulnerability-collector.service.ts   # Orquestador + Cron
│   │   └── vulnerability-collector.controller.ts # API REST
│   └── dashboard/                 # Health check
├── app.module.ts
└── main.ts
```
