# Manual de Configuración y Uso — API Externa ARGOS-Vuls

## Tabla de Contenidos

1. [Introducción](#1-introducción)
2. [Configuración Inicial](#2-configuración-inicial)
3. [Autenticación por API Key](#3-autenticación-por-api-key)
4. [Gestión de API Keys (Admin)](#4-gestión-de-api-keys-admin)
5. [Rate Limiting](#5-rate-limiting)
6. [Endpoints Disponibles](#6-endpoints-disponibles)
   - [6.1 Vulnerabilidades](#61-vulnerabilidades)
   - [6.2 Evidencias y Fuentes](#62-evidencias-y-fuentes)
   - [6.3 Cobertura y Salud de Inteligencia](#63-cobertura-y-salud-de-inteligencia)
   - [6.4 Products & Assets](#64-products--assets)
   - [6.5 Catálogo](#65-catálogo)
   - [6.6 Collector & Reports](#66-collector--reports)
7. [Contrato de Datos y Estados de Inteligencia](#7-contrato-de-datos-y-estados-de-inteligencia)
   - [7.1 Compatibilidad hacia atrás](#71-compatibilidad-hacia-atrás)
   - [7.2 Atributos enriquecidos](#72-atributos-enriquecidos)
   - [7.3 Bloques normalizados de inteligencia](#73-bloques-normalizados-de-inteligencia)
   - [7.4 Política de Privacidad y Raw Data](#74-política-de-privacidad-y-raw-data)
8. [Sincronización Incremental](#8-sincronización-incremental)
   - [8.1 Uso de updatedSince](#81-uso-de-updatedsince)
   - [8.2 Paginación por cursor y watermark](#82-paginación-por-cursor-y-watermark)
9. [Formato de Respuesta](#9-formato-de-respuesta)
10. [Ejemplos Reales de Uso](#10-ejemplos-reales-de-uso)
    - [10.1 Listado con metadatos y bloques de inteligencia](#101-listado-con-metadatos-y-bloques-de-inteligencia)
    - [10.2 Detalle de vulnerabilidad (con y sin include=raw)](#102-detalle-de-vulnerabilidad-con-y-sin-includeraw)
    - [10.3 Evidencias de un CVE (/evidence)](#103-evidencias-de-un-cve-evidence)
    - [10.4 Resumen de cobertura (/coverage)](#104-resumen-de-cobertura-coverage)
    - [10.5 Ejemplos de estados unknown y source_unavailable](#105-ejemplos-de-estados-unknown-y-source_unavailable)
    - [10.6 Scripts en Python y Node.js para sincronización continua](#106-scripts-en-python-y-nodejs-para-sincronización-continua)
11. [Códigos de Error](#11-códigos-de-error)
12. [Integración con Aplicaciones Externas (ASTREA, SIEM, SOAR)](#12-integración-con-aplicaciones-externas-astrea-siem-soar)

---

## 1. Introducción

La API externa de ARGOS-Vuls permite que sistemas consumidores como **ASTREA**, SIEMs, dashboards analíticos, scripts de automatización y orquestadores SOAR consuman datos de vulnerabilidades de forma programática con alta riqueza contextual, trazabilidad de fuentes y sincronización incremental eficiente.

**Características principales:**

- Autenticación por API Key (`X-API-Key` header).
- Endpoints read-only bajo `/api/v1/`.
- **Compatibilidad absoluta hacia atrás:** se conservan todos los campos planos actuales mientras se añaden atributos de trazabilidad y bloques de inteligencia normalizados.
- **Sincronización incremental:** soporte de `updatedSince`, `cursor`, `watermark` y `hasMore`.
- **Endpoint de evidencias (`/evidence`):** auditoría de fuentes primarias por CVE sin datos fabricados.
- **Endpoint de cobertura (`/coverage`):** visibilidad del dataset global distinguiendo cero real, datos desconocidos y fuentes no disponibles.
- **Privacidad estricta:** omisión de datos personales (correos, destinatarios de notificación) y control granular de payloads crudos (`?include=raw`).
- Rate limiting configurable (100 req/min por defecto).
- Documentación Swagger interactiva en `/api/docs`.

**Base URL:**

```
http://<tu-servidor>/api/v1
```

---

## 2. Configuración Inicial

### 2.1 Variables de Entorno

Agregar las siguientes variables al archivo `.env`:

```bash
# Rate limiting para la API externa
API_RATE_LIMIT_TTL=60000    # Ventana de tiempo en milisegundos (default: 60 segundos)
API_RATE_LIMIT_MAX=100      # Máximo de requests por ventana (default: 100)
```

### 2.2 Migración de Base de Datos

Verificar que las migraciones de Prisma estén aplicadas:

```bash
npx prisma migrate deploy
```

---

## 3. Autenticación por API Key

### 3.1 Cómo autenticarse

Todas las llamadas a `/api/v1/*` requieren el header `X-API-Key`:

```bash
curl -H "X-API-Key: occ_a3f8b2c1e4d567890abcdef1234567890abcdef12" \
     http://<tu-servidor>/api/v1/vulnerabilities
```

### 3.2 Scopes disponibles

Cada API key cuenta con un conjunto de scopes que restringen los endpoints accesibles:

| Scope | Endpoints permitidos |
|-------|---------------------|
| `vulnerabilities:read` | `/v1/vulnerabilities`, `/v1/vulnerabilities/stats`, `/v1/vulnerabilities/:cveId`, `/v1/vulnerabilities/:cveId/evidence`, `/v1/vulnerabilities/:cveId/changes`, `/v1/coverage` |
| `products:read` | `/v1/product-assets`, `/v1/product-assets/:id/dependencies`, `/v1/product-assets/:id/vulnerabilities`, `/v1/products` |
| `catalog:read` | `/v1/manufacturers`, `/v1/tags`, `/v1/kev`, `/v1/exploits` |
| `collector:read` | `/v1/collector/runs`, `/v1/collector/sources-health`, `/v1/coverage` |
| `reports:read` | `/v1/reports` |

---

## 4. Gestión de API Keys (Admin)

Los endpoints de gestión de API keys requieren autenticación JWT con rol `ADMIN`:

- `POST /api/api-keys`: Crear API Key.
- `GET /api/api-keys`: Listar API Keys.
- `GET /api/api-keys/scopes`: Consultar scopes disponibles.
- `PATCH /api/api-keys/:id`: Modificar nombre, scopes o estado activo.
- `DELETE /api/api-keys/:id`: Desactivar una API Key.

---

## 5. Rate Limiting

| Parámetro | Default | Variable de Entorno |
|-----------|---------|-------------------|
| Ventana de tiempo | 60 segundos | `API_RATE_LIMIT_TTL` (en ms) |
| Máximo de requests | 100 por ventana | `API_RATE_LIMIT_MAX` |

Headers retornados en cada respuesta:
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

---

## 6. Endpoints Disponibles

### 6.1 Vulnerabilidades

#### `GET /api/v1/vulnerabilities`

Lista vulnerabilidades con filtrado avanzado, paginación y sincronización incremental.

**Parámetros de query:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `page` | int | Página solicitada (default: 1, base 1). |
| `limit` | int | Registros por página (default: 50, máx: 200). |
| `updatedSince` | string (ISO-8601) | **Sincronización incremental.** Filtra registros modificados desde esa fecha (`lastChangeDetectedAt >= fecha` o `updatedAt >= fecha`). |
| `cursor` | string | Cursor opaco (base64 o numérico) devuelto en `meta.nextCursor` para continuar la lectura de forma secuencial. |
| `severity` | string | Filtrar por severidad CVSS v3.1: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. |
| `exploited` | string | Si es `true`, filtra únicamente vulnerabilidades en catálogos de explotación activa (CISA KEV). |
| `hasPublicExploit` | string | `true` o `false` para filtrar por existencia de exploit público. |
| `exploitStatus` | string | Filtrar por estado de explotación (ej. `active_exploitation`, `public_poc`, `none`). |
| `exploitType` | string | Filtro semántico directo: `kev`, `public_exploit` o `confirmed`. |
| `patchAvailable` | string | `true` o `false` según la existencia de parches confirmados. |
| `minCvss` | number | Puntuación CVSS v3.1 mínima (0 - 10). |
| `maxCvss` | number | Puntuación CVSS v3.1 máxima (0 - 10). |
| `minEpss` | number | Puntuación EPSS mínima (0.0 - 1.0). |
| `vendor` | string | Filtrar por fabricante primario normalizado. |
| `product` | string | Filtrar por producto primario normalizado. |
| `source` | string | Filtrar por fuente asociada (ej. `nvd`, `cisa_kev`, `exploitdb`, `epss`). |
| `recordStatus` | string | Filtrar por estado del registro: `enriched`, `needs_enrichment`, `catalogued`. |
| `publishedFrom` | string (ISO-8601) | Fecha de publicación inicial. |
| `publishedTo` | string (ISO-8601) | Fecha de publicación final. |
| `search` | string | Búsqueda por texto en CVE ID, descripción, fabricante o producto. |
| `tag` | string | Filtrar por tag (nombre o ID). |
| `riskTier` | string | Nivel de riesgo operacional: `critical`, `high`, `medium`, `low`. |
| `weaknessCategory`| string | Categoría de debilidad CWE (ej. `sql_injection`, `path_traversal`). |

---

#### `GET /api/v1/vulnerabilities/:cveId`

Obtiene el detalle completo de una vulnerabilidad identificada por su identificador CVE oficial.

**Parámetros:**
- `cveId` (path): Identificador CVE (ej. `CVE-2024-3094`, insensible a mayúsculas/minúsculas).
- `include` (query, opcional): Lista separada por comas de campos adicionales. Para incluir el payload original sin transformar, especifique `?include=raw`.

---

#### `GET /api/v1/vulnerabilities/stats`

Estadísticas agregadas del inventario de vulnerabilidades:
- Conteo total y por severidad CVSS.
- Totales explotados y con exploit público.
- Totales con parche disponible.
- Nuevas vulnerabilidades detectadas en las últimas 24 horas y 7 días.

---

#### `GET /api/v1/vulnerabilities/:cveId/changes`

Auditoría cronológica de cambios detectados para un CVE. Devuelve una lista paginada de eventos con tipo de cambio, campo modificado, valor anterior y nuevo valor.

---

### 6.2 Evidencias y Fuentes

#### `GET /api/v1/vulnerabilities/:cveId/evidence`

Lista paginada de registros de fuentes y evidencias primarias recopiladas para una vulnerabilidad concreta.

**Parámetros:**
- `cveId` (path): CVE a consultar.
- `page`, `limit` (query): Paginación estándar.

**Campos devueltos por evidencia:**
- `source`: Identificador de la fuente (`cisa_kev`, `nvd`, `exploitdb`, `epss`, `cveorg`, `osv`).
- `sourceUrl`: URL oficial del registro o aviso en la fuente.
- `evidenceType`: Tipo de evidencia (`kev_catalog`, `exploit_poc`, `nvd_cve_advisory`, `epss_metric`, `package_advisory`, `cve_record`, `advisory`).
- `summary`: Resumen descriptivo de la evidencia.
- `observedAt`: Fecha de primera detección o publicación en la fuente.
- `lastValidatedAt`: Fecha de última comprobación o sincronización válida.
- `confidence`: Nivel de confianza numérico (0.0 - 1.0).
- `isCanonical`: `true` si es la fuente canónica del identificador.
- `status`: Estado de validación (`verified`, `active`).

> **Regla de integridad:** Si un CVE no cuenta con registros para una fuente determinada en ARGOS, el endpoint devuelve únicamente las evidencias reales existentes. **Nunca se fabrican evidencias artificiales.**

---

### 6.3 Cobertura y Salud de Inteligencia

#### `GET /api/v1/coverage`

Ofrece un resumen integral del dataset de vulnerabilidades, el grado de enriquecimiento del catálogo, la cobertura por cada fuente de inteligencia y el estado de frescura operativo.

**Información devuelta:**
- `totalVulnerabilities`: Total absoluto de vulnerabilidades en base de datos.
- `totalEnriched`: Total con catálogo normalizado y enriquecimiento completado.
- `totalPending`: Total pendiente de enriquecimiento (`needs_enrichment=true`).
- `totalKev`: Total de vulnerabilidades presentes en CISA KEV.
- `totalWithPublicExploit`: Total con prueba de concepto pública (ExploitDB, etc.).
- `totalConfirmedExploited`: Total confirmado con explotación activa.
- `coverageBySource`: Desglose por fuente (`nvd`, `cisa_kev`, `exploitdb`, `epss`, `cveorg`, `osv`):
  - `total`: Número de registros asociados a la fuente (o `null` si no está configurada).
  - `percentage`: Porcentaje de cobertura sobre el total de CVEs.
  - `status`: Estado de la fuente (`active`, `not_configured`, `source_unavailable`).
  - `isAvailable`: Indicador booleano de disponibilidad.
  - `distinction`: Diferenciación explícita entre `recorded` (registros presentes), `real_zero` (fuente ejecutada con 0 elementos) y `unknown` (sin datos o no configurada).
- `lastExecutionBySource`: Última ejecución del collector por fuente (fecha, estado, duración en ms, elementos procesados, errores).
- `recentErrors`: Lista de errores recientes en collectors.
- `calculatedAt`: Fecha y hora de cálculo (ISO-8601).
- `freshnessStatus`: Estado de frescura global (`fresh`, `stale`, `outdated`, `degraded`).

---

### 6.4 Products & Assets

- `GET /api/v1/product-assets`: Lista de activos de producto monitorizados.
- `GET /api/v1/product-assets/:id/dependencies`: Inventario de dependencias de un activo (SBOM/PURL/CPE).
- `GET /api/v1/product-assets/:id/vulnerabilities`: Vulnerabilidades asociadas al inventario de un activo.
- `GET /api/v1/products`: Catálogo de pares fabricante/producto registrados.

### 6.5 Catálogo

- `GET /api/v1/manufacturers`: Catálogo de fabricantes normalizados.
- `GET /api/v1/tags`: Etiquetas y categorías asignadas a vulnerabilidades.
- `GET /api/v1/kev`: Listado directo de vulnerabilidades CISA KEV.
- `GET /api/v1/exploits`: Listado directo de vulnerabilidades con exploits públicos.

### 6.6 Collector & Reports

- `GET /api/v1/collector/runs`: Auditoría de ejecuciones históricas del colector.
- `GET /api/v1/collector/sources-health`: Métricas operativas de salud por fuente.
- `GET /api/v1/reports`: Informes periódicos ejecutivos generados.

---

## 7. Contrato de Datos y Estados de Inteligencia

### 7.1 Compatibilidad hacia atrás

La respuesta de vulnerabilidad conserva todos los campos planos anteriores:
- Identificadores y métricas: `id`, `cveId`, `description`, `publishedAt`, `lastModifiedAt`, `firstSeenAt`.
- CVSS: `cvssV31Score`, `cvssV31Severity`, `cvssV31Vector`, `cvssV40Score`, `cvssV40Severity`, `cvssV40Vector`.
- Explotación plana: `epssScore`, `epssPercentile`, `isKnownExploited`, `kevDateAdded`, `kevDueDate`, `hasPublicExploit`, `exploitStatus`, `exploitConfidence`.
- Inventario plano: `primaryVendor`, `primaryProduct`, `affectedProducts`, `affectedProductsDetailed`, `patchAvailable`.
- Riesgo plano: `operationalRiskScore`, `operationalRiskTier`, `weaknessCategory`.
- Notificaciones agregadas: `notificable`, `notificada`, `fechaNotificacion`, `notificacionesCount`.

### 7.2 Atributos enriquecidos

Se incorporan al primer nivel de cada vulnerabilidad cuando están disponibles:

| Campo | Tipo | Significado |
|-------|------|-------------|
| `dataConfidence` | float \| null | Nivel de confianza ponderado del registro global (0.0 - 1.0). |
| `recordStatus` | string | Estado del registro (`enriched`, `needs_enrichment`, `catalogued`, etc.). |
| `canonicalSource` | string | Fuente de autoridad principal (`nvd`, `cveorg`). |
| `sourceCount` | int | Cantidad de fuentes distintas que corroboran la vulnerabilidad. |
| `enrichedAt` | string (ISO) \| null | Fecha en la que se completó el enriquecimiento semántico. |
| `lastChangeDetectedAt` | string (ISO) \| null | Fecha de detección del último cambio relevante en upstream. |
| `exploitFirstSeenAt` | string (ISO) \| null | Primera fecha en la que se observó el exploit. |
| `exploitLastCheckedAt`| string (ISO) \| null | Última fecha en la que se verificó la disponibilidad de exploits. |
| `patchPriority` | string \| null | Prioridad recomendada de aplicación de parche (`CRITICAL`, `HIGH`, etc.). |
| `workarounds` | array/object \| null | Medidas de mitigación temporal alternativas al parche. |
| `detectionOpportunities` | array/object \| null | Reglas de detección, firmas Snort/Suricata o indicadores de detección. |
| `riskSignals` | array \| null | Señales operacionales observadas (ej. `remote_code_execution`, `wormable`). |
| `affectedCpes` | string[] | Lista de identificadores CPE 2.3 normalizados. |
| `evidenceTypes` | string[] | Tipos de evidencias disponibles (`advisory`, `kev_catalog`, `exploit_poc`, `epss_metric`). |
| `isConfirmedExploited` | boolean | `true` si la vulnerabilidad tiene explotación confirmada en el mundo real. |

### 7.3 Bloques normalizados de inteligencia

Para facilitar el consumo analítico en ASTREA, cada vulnerabilidad incluye estructuras semánticas tipadas:

#### Bloque `exploitation`
```json
{
  "exploitation": {
    "status": "confirmed|not_found|unknown|not_checked|source_unavailable",
    "isKnownExploited": true,
    "hasPublicExploit": false,
    "exploitStatus": "active_exploitation",
    "sources": ["cisa_kev"],
    "lastCheckedAt": "2026-10-11T10:33:11.000Z"
  }
}
```

Estados posibles de `status`:
- `confirmed`: Explotación o prueba de concepto comprobada y confirmada en fuentes oficiales.
- `not_found`: Verificado contra fuentes de explotación pero no se hallaron registros activos.
- `not_checked`: Pendiente de verificación o registro en cola de enriquecimiento.
- `unknown`: No es posible determinar el estado con los datos actuales.
- `source_unavailable`: La fuente de explotación experimentó un fallo o no está disponible.

#### Bloque `epss`
```json
{
  "epss": {
    "status": "confirmed|not_found|unknown|not_checked|source_unavailable",
    "score": 0.01062,
    "percentile": 0.63623,
    "lastCheckedAt": "2026-10-11T10:30:00.000Z"
  }
}
```

#### Bloque `patch`
```json
{
  "patch": {
    "status": "available|unavailable|workaround_only|unknown",
    "isAvailable": true,
    "priority": "CRITICAL",
    "fixedVersions": ["2.4.50"],
    "hasWorkarounds": true,
    "workaroundsCount": 1
  }
}
```

#### Bloques `primaryEntity` y `affectedProduct`
```json
{
  "primaryEntity": {
    "status": "identified|unresolved|unknown|multiple",
    "vendor": "apache",
    "product": "http_server",
    "affectedCpes": ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
    "detailedCount": 1
  }
}
```

#### Bloque `operationalRisk`
```json
{
  "operationalRisk": {
    "status": "assessed|pending|unknown",
    "score": 95.0,
    "tier": "critical",
    "signals": ["remote_code_execution", "in_the_wild"]
  }
}
```

### 7.4 Política de Privacidad y Raw Data

1. **Privacidad garantizada:** Los serializadores externos **no exponen correos electrónicos de suscriptores, nombres de personas ni historiales personales de notificación**. Solo se entregan contadores e indicadores de estado agregados (`notificada`, `fechaNotificacion`, `notificacionesCount`).
2. **Protección de Raw Data:** En los listados generales `/v1/vulnerabilities`, el campo `rawData` **nunca se incluye**, evitando sobrecarga de transferencia y fugas no deseadas. En el detalle `/v1/vulnerabilities/:cveId`, el payload original se omite por defecto y solo se retorna cuando el cliente lo solicita expresamente mediante `?include=raw`.

---

## 8. Sincronización Incremental

### 8.1 Uso de updatedSince

Para sincronizaciones continuas de deltas:

```
GET /api/v1/vulnerabilities?updatedSince=2026-10-11T00:00:00.000Z
```

**Regla de filtrado:** El backend evalúa tanto la fecha de cambio en fuentes externas (`lastChangeDetectedAt`) como la fecha de modificación interna en ARGOS (`updatedAt`). De esta forma, ASTREA recibe:
- Modificaciones upstream en descripciones, severidades, CVSS o KEV.
- Enriquecimientos completados por tareas en segundo plano.

### 8.2 Paginación por cursor y watermark

En la sección `meta` de la respuesta:

```json
{
  "meta": {
    "total": 26583,
    "page": 1,
    "limit": 50,
    "pages": 532,
    "hasMore": true,
    "nextCursor": "eyJpZCI6NTU2OTM5LCJ1cGRhdGVkQXQiOiIyMDI2LTEwLTExVDEwOjQ0OjE2LjAwMFoifQ==",
    "watermark": "2026-10-11T10:44:16.000Z"
  }
}
```

- `watermark`: Marca de agua que contiene la fecha máxima procesada en el lote. Almacénela localmente para usarla en el siguiente ciclo como `updatedSince=<watermark>`.
- `hasMore`: Booleano que indica si existen registros pendientes en la consulta actual.
- `nextCursor`: Token opaco para solicitar la siguiente página sin drift de inserción:
  ```
  GET /api/v1/vulnerabilities?cursor=eyJpZCI6NTU2OTM5...&limit=50
  ```

---

## 9. Formato de Respuesta

### Formato Paginado Estándar

```json
{
  "data": [ ... ],
  "meta": {
    "total": 404202,
    "page": 1,
    "limit": 50,
    "pages": 8085,
    "hasMore": true,
    "nextCursor": "eyJpZCI6MTAxfQ==",
    "watermark": "2026-10-11T12:00:00.000Z"
  }
}
```

---

## 10. Ejemplos Reales de Uso

### 10.1 Listado con metadatos y bloques de inteligencia

**Petición:**

```bash
curl -s -H "X-API-Key: occ_..." \
     "http://localhost:3000/api/v1/vulnerabilities?limit=1"
```

**Respuesta:**

```json
{
  "data": [
    {
      "id": 546681,
      "cveId": "CVE-2026-93952",
      "description": "VeloCloud Orchestrator (VCO) on-prem has a security issue...",
      "cvssV31Score": 10.0,
      "cvssV31Severity": "CRITICAL",
      "cvssV31Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "cvssV40Score": null,
      "cvssV40Severity": null,
      "cvssV40Vector": null,
      "cvssVersion": null,
      "epssScore": 0.01062,
      "epssPercentile": 0.63623,
      "isKnownExploited": true,
      "kevDateAdded": "2026-09-22T02:00:00.000Z",
      "kevDueDate": "2026-09-25T02:00:00.000Z",
      "hasPublicExploit": false,
      "exploitStatus": "active_exploitation",
      "exploitConfidence": null,
      "exploitFirstSeenAt": null,
      "exploitLastCheckedAt": null,
      "primaryVendor": "arista",
      "primaryProduct": "velocloud_orchestrator",
      "affectedProducts": [
        { "vendor": "arista", "product": "velocloud_orchestrator" }
      ],
      "affectedProductsDetailed": [],
      "affectedCpes": [],
      "patchAvailable": null,
      "patchPriority": null,
      "fixedVersions": null,
      "workarounds": null,
      "detectionOpportunities": null,
      "operationalRiskScore": null,
      "operationalRiskTier": null,
      "riskSignals": null,
      "dataConfidence": null,
      "canonicalSource": "nvd",
      "sourceCount": 1,
      "sourcesPresent": ["cisa_kev"],
      "recordStatus": "needs_enrichment",
      "cweIds": null,
      "cweNames": null,
      "weaknessCategory": null,
      "source": "nvd",
      "processingStatus": "new",
      "needsEnrichment": true,
      "firstSeenAt": "2026-10-10T20:46:19.000Z",
      "publishedAt": "2026-09-22T08:16:43.047Z",
      "lastModifiedAt": "2026-09-23T14:32:12.417Z",
      "lastChangeDetectedAt": "2026-10-11T10:44:15.000Z",
      "enrichedAt": null,
      "isNotificable": false,
      "createdAt": "2026-10-10T20:46:19.000Z",
      "updatedAt": "2026-10-11T10:44:15.000Z",
      "tags": [],
      "evidenceTypes": ["advisory", "kev_catalog", "epss_metric"],
      "isConfirmedExploited": true,
      "exploitation": {
        "status": "confirmed",
        "isKnownExploited": true,
        "hasPublicExploit": false,
        "exploitStatus": "active_exploitation",
        "sources": ["cisa_kev"],
        "lastCheckedAt": null
      },
      "epss": {
        "status": "confirmed",
        "score": 0.01062,
        "percentile": 0.63623,
        "lastCheckedAt": null
      },
      "patch": {
        "status": "unknown",
        "isAvailable": null,
        "priority": null,
        "fixedVersions": [],
        "hasWorkarounds": false,
        "workaroundsCount": 0
      },
      "primaryEntity": {
        "status": "identified",
        "vendor": "arista",
        "product": "velocloud_orchestrator",
        "affectedCpes": [],
        "detailedCount": 0
      },
      "affectedProduct": {
        "status": "identified",
        "vendor": "arista",
        "product": "velocloud_orchestrator",
        "affectedCpes": [],
        "detailedCount": 0
      },
      "operationalRisk": {
        "status": "pending",
        "score": null,
        "tier": null,
        "signals": []
      },
      "notificable": false,
      "notificada": false,
      "fechaNotificacion": null,
      "notificacionesCount": 0
    }
  ],
  "meta": {
    "total": 404202,
    "page": 1,
    "limit": 1,
    "pages": 404202,
    "hasMore": true,
    "nextCursor": "eyJpZCI6NTQ2NjgxLCJ1cGRhdGVkQXQiOiIyMDI2LTEwLTExVDEwOjQ0OjE1LjAwMFoifQ==",
    "watermark": "2026-10-11T10:44:15.000Z"
  }
}
```

---

### 10.2 Detalle de vulnerabilidad (con y sin include=raw)

**Sin `include=raw`:**

```bash
curl -s -H "X-API-Key: occ_..." \
     "http://localhost:3000/api/v1/vulnerabilities/CVE-2026-93952"
```

El campo `rawData` **no figura** en el JSON retornado.

**Con `include=raw`:**

```bash
curl -s -H "X-API-Key: occ_..." \
     "http://localhost:3000/api/v1/vulnerabilities/CVE-2026-93952?include=raw"
```

Se adjunta `rawData`:

```json
{
  "id": 546681,
  "cveId": "CVE-2026-93952",
  "rawData": {
    "cve": {
      "id": "CVE-2026-93952",
      "sourceIdentifier": "security@vmware.com"
    }
  }
}
```

---

### 10.3 Evidencias de un CVE (/evidence)

**Petición:**

```bash
curl -s -H "X-API-Key: occ_..." \
     "http://localhost:3000/api/v1/vulnerabilities/CVE-2026-93952/evidence"
```

**Respuesta:**

```json
{
  "data": [
    {
      "id": 97622,
      "source": "cisa_kev",
      "sourceUrl": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2026-93952",
      "evidenceType": "kev_catalog",
      "summary": "Registro en el catálogo CISA KEV (Known Exploited Vulnerabilities) para CVE-2026-93952",
      "observedAt": "2026-10-11T10:33:11.000Z",
      "lastValidatedAt": "2026-10-11T10:33:11.000Z",
      "confidence": 1.0,
      "isCanonical": false,
      "status": "verified"
    }
  ],
  "meta": {
    "total": 1,
    "page": 1,
    "limit": 50,
    "pages": 1,
    "hasMore": false,
    "nextCursor": null,
    "watermark": null
  }
}
```

---

### 10.4 Resumen de cobertura (/coverage)

**Petición:**

```bash
curl -s -H "X-API-Key: occ_..." \
     "http://localhost:3000/api/v1/coverage"
```

**Respuesta:**

```json
{
  "totalVulnerabilities": 404202,
  "totalEnriched": 79581,
  "totalPending": 307057,
  "totalKev": 1739,
  "totalWithPublicExploit": 25052,
  "totalConfirmedExploited": 1739,
  "coverageBySource": {
    "nvd": {
      "total": 97145,
      "percentage": 24.03,
      "status": "active",
      "isAvailable": true,
      "distinction": "recorded"
    },
    "cisa_kev": {
      "total": 1739,
      "percentage": 0.43,
      "status": "active",
      "isAvailable": true,
      "distinction": "recorded"
    },
    "exploitdb": {
      "total": 25052,
      "percentage": 6.2,
      "status": "active",
      "isAvailable": true,
      "distinction": "recorded"
    },
    "epss": {
      "total": 1,
      "percentage": 0,
      "status": "active",
      "isAvailable": true,
      "distinction": "recorded"
    },
    "cveorg": {
      "total": null,
      "percentage": null,
      "status": "not_configured",
      "isAvailable": false,
      "distinction": "unknown"
    },
    "osv": {
      "total": null,
      "percentage": null,
      "status": "not_configured",
      "isAvailable": false,
      "distinction": "unknown"
    }
  },
  "lastExecutionBySource": {
    "cisa_kev": {
      "runDate": "2026-10-11T11:00:01.335Z",
      "status": "success",
      "durationMs": 398,
      "itemsProcessed": 1739,
      "itemsErrored": 0,
      "errorMessage": null
    },
    "exploitdb": {
      "runDate": "2026-10-11T11:00:02.983Z",
      "status": "success",
      "durationMs": 1642,
      "itemsProcessed": 25052,
      "itemsErrored": 0,
      "errorMessage": null
    }
  },
  "recentErrors": [],
  "calculatedAt": "2026-10-11T11:20:04.602Z",
  "freshnessStatus": "fresh"
}
```

---

### 10.5 Ejemplos de estados unknown y source_unavailable

#### Estado de explotación `unknown` / `not_checked`
En vulnerabilidades históricas o importadas recientemente que no han completado el ciclo de colectores:
```json
{
  "exploitation": {
    "status": "not_checked",
    "isKnownExploited": false,
    "hasPublicExploit": false,
    "exploitStatus": "none",
    "sources": [],
    "lastCheckedAt": null
  }
}
```

#### Cobertura con `source_unavailable`
Si el colector de EPSS o CISA falla en sus peticiones por caída del servicio remoto o rate limit upstream:
```json
{
  "coverageBySource": {
    "epss": {
      "total": 0,
      "percentage": null,
      "status": "source_unavailable",
      "isAvailable": false,
      "distinction": "unknown"
    }
  },
  "lastExecutionBySource": {
    "epss": {
      "runDate": "2026-10-11T10:30:02.477Z",
      "status": "failed",
      "errorMessage": "HTTP 429 Too Many Requests from upstream FIRST EPSS API"
    }
  }
}
```

---

### 10.6 Scripts en Python y Node.js para sincronización continua

#### Consumo Incremental en Python (ASTREA Worker)

```python
import time
import requests

API_URL = "http://localhost:3000/api/v1"
API_KEY = "occ_6669fff108e72e81dc430f64735618de5d3686ef"
HEADERS = {"X-API-Key": API_KEY}

last_watermark = "2026-10-11T00:00:00.000Z"

while True:
    print(f"Sincronizando cambios desde {last_watermark}...")
    cursor = None
    has_more = True

    while has_more:
        params = {"limit": 100}
        if cursor:
            params["cursor"] = cursor
        else:
            params["updatedSince"] = last_watermark

        resp = requests.get(f"{API_URL}/vulnerabilities", headers=HEADERS, params=params)
        if resp.status_code != 200:
            print(f"Error {resp.status_code}: {resp.text}")
            break

        body = resp.json()
        data = body.get("data", [])
        meta = body.get("meta", {})

        for vuln in data:
            cve_id = vuln["cveId"]
            exploit_status = vuln["exploitation"]["status"]
            print(f"  Procesando {cve_id} (Explotación: {exploit_status}, CVSS: {vuln.get('cvssV31Score')})")

        has_more = meta.get("hasMore", False)
        cursor = meta.get("nextCursor")
        if meta.get("watermark"):
            last_watermark = meta["watermark"]

    print("Ciclo completado. Esperando 5 minutos...")
    time.sleep(300)
```

---

## 11. Códigos de Error

| Código | Significado | Causa común |
|--------|-------------|-------------|
| `200` | OK | Petición ejecutada exitosamente. |
| `400` | Bad Request | Formato de parámetros inválido (ej. fecha mal formada en `updatedSince`). |
| `401` | Unauthorized | Falta la cabecera `X-API-Key` o la clave no existe o está expirada. |
| `403` | Forbidden | La clave carece del scope requerido (ej. `vulnerabilities:read`). |
| `404` | Not Found | El CVE especificado en la ruta no existe en el catálogo. |
| `429` | Too Many Requests | Se superó el límite de peticiones por minuto. Esperar antes de reintentar. |
| `500` | Internal Server Error | Error inesperado en el servidor. |

---

## 12. Integración con Aplicaciones Externas (ASTREA, SIEM, SOAR)

1. **Principio de mínimo privilegio:** Otorgue únicamente el scope `vulnerabilities:read` a sistemas que solo requieran consultar CVEs, evidencias o cobertura.
2. **Uso de Watermarks:** Persista siempre `meta.watermark` en la base de datos de ASTREA para reiniciar la sincronización desde el último estado conocido tras cualquier reinicio.
3. **Auditoría de Evidencias:** Utilice `/api/v1/vulnerabilities/:cveId/evidence` para justificar decisiones automatizadas de parcheo basándose únicamente en fuentes corroboradas.
4. **Respeto a la Privacidad:** La API externa garantiza la ausencia de información de destinatarios de correo electrónico por defecto.
