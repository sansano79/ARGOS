# Manual de Configuración y Uso — API Externa OCC-Vuls

## Tabla de Contenidos

1. [Introducción](#1-introducción)
2. [Configuración Inicial](#2-configuración-inicial)
3. [Autenticación por API Key](#3-autenticación-por-api-key)
4. [Gestión de API Keys (Admin)](#4-gestión-de-api-keys-admin)
5. [Rate Limiting](#5-rate-limiting)
6. [Endpoints Disponibles](#6-endpoints-disponibles)
7. [Formato de Respuesta](#7-formato-de-respuesta)
8. [Ejemplos de Uso](#8-ejemplos-de-uso)
9. [Códigos de Error](#9-códigos-de-error)
10. [Integración con Aplicaciones Externas](#10-integración-con-aplicaciones-externas)

---

## 1. Introducción

La API externa de OCC-Vuls permite que aplicaciones de terceros (SIEMs, dashboards, scripts de automatización, sistemas de ticketing) consuman datos de vulnerabilidades de forma programática.

**Características principales:**

- Autenticación por API Key (`X-API-Key` header)
- Endpoints read-only bajo `/api/v1/`
- Rate limiting configurable (100 req/min por defecto)
- Respuestas paginadas con formato consistente
- Control de acceso granular mediante scopes
- Documentación Swagger interactiva en `/api/docs`

**Base URL:**

```
http://<tu-servidor>/api/v1
```

En producción, si la plataforma se publica por HTTPS, TLS y certificados los gestiona el proxy/ingress externo. Este stack expone HTTP y mantiene la API bajo `/api/v1`.

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

Al desplegar la nueva versión, ejecutar la migración de Prisma para crear la tabla `api_keys`:

```bash
npx prisma migrate deploy
```

Esto creará la tabla `api_keys` en MySQL con los campos necesarios para almacenar las API keys de forma segura (hash bcrypt).

### 2.3 Verificar Swagger

Si Swagger está habilitado (`ENABLE_SWAGGER=true` o entorno no productivo), la documentación interactiva estará disponible en:

```
http://<tu-servidor>/api/docs
```

Los endpoints de la API externa aparecen bajo las secciones:
- **External API — Vulnerabilities**
- **External API — Products & Assets**
- **External API — Catalog**
- **External API — Collector & Reports**
- **API Key Management**

---

## 3. Autenticación por API Key

### 3.1 Cómo autenticarse

Todas las llamadas a `/api/v1/*` requieren el header `X-API-Key`:

```bash
curl -H "X-API-Key: occ_a3f8b2c1e4d567890abcdef1234567890abcdef12" \
     http://<tu-servidor>/api/v1/vulnerabilities
```

### 3.2 Scopes disponibles

Cada API key tiene un conjunto de scopes que determinan a qué endpoints puede acceder:

| Scope | Endpoints permitidos |
|-------|---------------------|
| `vulnerabilities:read` | `/v1/vulnerabilities`, `/v1/vulnerabilities/stats`, `/v1/vulnerabilities/:cveId`, `/v1/vulnerabilities/:cveId/changes` |
| `products:read` | `/v1/product-assets`, `/v1/product-assets/:id/dependencies`, `/v1/product-assets/:id/vulnerabilities`, `/v1/products` |
| `catalog:read` | `/v1/manufacturers`, `/v1/tags`, `/v1/kev`, `/v1/exploits` |
| `collector:read` | `/v1/collector/runs`, `/v1/collector/sources-health` |
| `reports:read` | `/v1/reports` |

Si no se especifican scopes al crear la key, se otorgan **todos los scopes** por defecto.

### 3.3 Seguridad

- Las API keys se almacenan como hash bcrypt (nunca en texto plano)
- El prefijo de la key (primeros 12 caracteres) se usa para identificación rápida en la UI
- La key completa se muestra **una sola vez** al momento de crearla
- Cada key está asociada a un usuario del sistema
- Las keys pueden tener fecha de expiración opcional
- Se registra la última fecha de uso (`lastUsedAt`) de cada key

---

## 4. Gestión de API Keys (Admin)

Los endpoints de gestión de API keys requieren autenticación JWT con rol `ADMIN`.

### 4.1 Crear una API Key

```bash
curl -X POST http://<tu-servidor>/api/api-keys \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Dashboard SIEM",
    "scopes": ["vulnerabilities:read", "catalog:read"],
    "expiresAt": "2027-01-01T00:00:00Z"
  }'
```

**Respuesta:**

```json
{
  "id": 1,
  "name": "Dashboard SIEM",
  "key": "occ_a3f8b2c1e4d567890abcdef1234567890abcdef12",
  "keyPrefix": "occ_a3f8b2c1",
  "scopes": ["vulnerabilities:read", "catalog:read"],
  "expiresAt": "2027-01-01T00:00:00.000Z",
  "createdAt": "2026-03-28T20:00:00.000Z",
  "message": "Store this key securely — it will not be shown again."
}
```

> **IMPORTANTE:** Copia y guarda la key inmediatamente. No se puede recuperar después.

### 4.2 Listar API Keys

```bash
curl http://<tu-servidor>/api/api-keys \
  -H "Authorization: Bearer <jwt-token>"
```

**Respuesta:**

```json
[
  {
    "id": 1,
    "name": "Dashboard SIEM",
    "keyPrefix": "occ_a3f8b2c1",
    "scopes": ["vulnerabilities:read", "catalog:read"],
    "isActive": true,
    "expiresAt": "2027-01-01T00:00:00.000Z",
    "lastUsedAt": "2026-03-28T21:30:00.000Z",
    "createdAt": "2026-03-28T20:00:00.000Z",
    "user": { "id": 1, "name": "Admin", "email": "admin@example.com" }
  }
]
```

### 4.3 Consultar scopes disponibles

```bash
curl http://<tu-servidor>/api/api-keys/scopes \
  -H "Authorization: Bearer <jwt-token>"
```

**Respuesta:**

```json
["vulnerabilities:read", "products:read", "catalog:read", "collector:read", "reports:read"]
```

### 4.4 Actualizar una API Key

```bash
curl -X PATCH http://<tu-servidor>/api/api-keys/1 \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Dashboard SIEM v2",
    "scopes": ["vulnerabilities:read", "catalog:read", "products:read"],
    "isActive": true
  }'
```

### 4.5 Revocar una API Key

```bash
curl -X DELETE http://<tu-servidor>/api/api-keys/1 \
  -H "Authorization: Bearer <jwt-token>"
```

**Respuesta:**

```json
{ "message": "API key revoked" }
```

La key se desactiva (`isActive = false`), no se elimina de la base de datos.

---

## 5. Rate Limiting

La API externa tiene rate limiting por API key para proteger el servicio.

| Parámetro | Default | Variable de Entorno |
|-----------|---------|-------------------|
| Ventana de tiempo | 60 segundos | `API_RATE_LIMIT_TTL` (en ms) |
| Máximo de requests | 100 por ventana | `API_RATE_LIMIT_MAX` |

Cuando se excede el límite, la API responde con:

```
HTTP 429 Too Many Requests
```

**Headers de rate limit en cada respuesta:**

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1711656120
```

### Ajustar límites

Para un entorno con alto volumen de consultas:

```bash
API_RATE_LIMIT_TTL=60000    # 1 minuto
API_RATE_LIMIT_MAX=500      # 500 requests por minuto
```

Para un entorno restrictivo:

```bash
API_RATE_LIMIT_TTL=60000
API_RATE_LIMIT_MAX=30       # 30 requests por minuto
```

---

## 6. Endpoints Disponibles

### 6.1 Vulnerabilidades

#### `GET /api/v1/vulnerabilities`

Lista vulnerabilidades con filtros y paginación.

**Parámetros de query:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `page` | int | Página (default: 1) |
| `limit` | int | Resultados por página (default: 50, max: 200) |
| `severity` | string | Filtrar por severidad: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `exploited` | string | Solo explotadas conocidas: `true` |
| `minCvss` | number | Puntuación CVSS v3.1 mínima (0-10) |
| `maxCvss` | number | Puntuación CVSS v3.1 máxima (0-10) |
| `minEpss` | number | Puntuación EPSS mínima (0-1) |
| `vendor` | string | Filtrar por fabricante |
| `product` | string | Filtrar por producto |
| `publishedFrom` | string | Fecha publicación desde (ISO 8601) |
| `publishedTo` | string | Fecha publicación hasta (ISO 8601) |
| `search` | string | Búsqueda en CVE ID, descripción, vendor, producto |
| `tag` | string | Filtrar por tag (nombre o ID) |
| `riskTier` | string | Filtrar por nivel de riesgo operacional |
| `exploitStatus` | string | Filtrar por estado de exploit |
| `hasPublicExploit` | string | Con exploit público: `true` |
| `patchAvailable` | string | Con parche disponible: `true`/`false` |
| `weaknessCategory` | string | Filtrar por categoría de debilidad |

**Ejemplo:**

```bash
curl -H "X-API-Key: occ_..." \
  "http://server/api/v1/vulnerabilities?severity=CRITICAL&exploited=true&limit=10"
```

---

#### `GET /api/v1/vulnerabilities/stats`

Estadísticas agregadas de vulnerabilidades.

**Respuesta:**

```json
{
  "total": 25430,
  "bySeverity": {
    "critical": 1250,
    "high": 5600,
    "medium": 12300,
    "low": 6280
  },
  "exploited": 340,
  "withPublicExploits": 890,
  "patchAvailable": 18500,
  "newLast24h": 45,
  "newLast7d": 312
}
```

---

#### `GET /api/v1/vulnerabilities/:cveId`

Detalle completo de una vulnerabilidad por CVE ID.

**Ejemplo:**

```bash
curl -H "X-API-Key: occ_..." \
  "http://server/api/v1/vulnerabilities/CVE-2024-3094"
```

**Respuesta:** Objeto completo con todos los campos de la vulnerabilidad, tags, y registros de fuentes.

---

#### `GET /api/v1/vulnerabilities/:cveId/changes`

Historial de cambios detectados para una vulnerabilidad.

**Parámetros:** `page`, `limit`

**Respuesta:** Lista paginada de eventos de cambio con `changeType`, `fieldName`, `oldValue`, `newValue`, `isSignificant`, `summary`, `detectedAt`.

---

### 6.2 Products & Assets

#### `GET /api/v1/product-assets`

Lista de activos de producto registrados.

**Parámetros:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `page`, `limit` | int | Paginación |
| `environment` | string | Filtrar: `prod`, `staging`, `dev` |
| `criticality` | string | Filtrar: `critical`, `high`, `medium`, `low` |
| `productType` | string | Tipo de producto |
| `isActive` | string | Estado activo: `true`/`false` |
| `search` | string | Buscar por nombre |

---

#### `GET /api/v1/product-assets/:id/dependencies`

Lista de dependencias (librerías, frameworks) de un activo.

Incluye: `componentName`, `componentVendor`, `componentVersion`, `ecosystem`, `purl`, `cpe`, `directDependency`, `confidence`.

---

#### `GET /api/v1/product-assets/:id/vulnerabilities`

Vulnerabilidades que afectan a un activo específico.

Incluye: `cveId`, `impactStatus`, `confidence`, `matchedComponentName`, `fixedVersion`, y datos de la vulnerabilidad asociada (CVSS, EPSS, KEV).

---

#### `GET /api/v1/products`

Catálogo de software (pares vendor/producto).

**Parámetros:** `page`, `limit`, `vendor`, `product`

---

### 6.3 Catálogo

#### `GET /api/v1/manufacturers`

Lista de fabricantes de software.

**Parámetros:** `page`, `limit`

---

#### `GET /api/v1/tags`

Lista de tags de vulnerabilidades con conteo.

**Respuesta:**

```json
[
  {
    "id": 1,
    "name": "zero-day",
    "color": "#FF0000",
    "isAutoGenerated": false,
    "vulnerabilityCount": 42
  }
]
```

---

#### `GET /api/v1/kev`

Vulnerabilidades conocidas explotadas (CISA KEV).

**Parámetros:** `page`, `limit`

Incluye: `cveId`, `cvssV31Score`, `kevDateAdded`, `kevDueDate`, `primaryVendor`, `primaryProduct`, `patchAvailable`.

---

#### `GET /api/v1/exploits`

Vulnerabilidades con exploits públicos disponibles.

**Parámetros:** `page`, `limit`

Incluye: `exploitStatus`, `exploitConfidence`, `exploitReferences`, `exploitFirstSeenAt`.

---

### 6.4 Collector & Reports

#### `GET /api/v1/collector/runs`

Historial de ejecuciones del collector.

**Parámetros:** `page`, `limit`, `source`, `status`

---

#### `GET /api/v1/collector/sources-health`

Estado de salud de cada fuente de datos (NVD, CISA, EPSS, GitHub, etc.).

**Respuesta:** Lista con `source`, `fetchStatus`, `itemsFetched`, `itemsProcessed`, `itemsErrored`, `durationMs`.

---

#### `GET /api/v1/reports`

Lista de reportes de vulnerabilidades generados.

**Parámetros:** `page`, `limit`

---

## 7. Formato de Respuesta

### 7.1 Respuestas paginadas

Todos los endpoints que retornan listas usan el siguiente formato:

```json
{
  "data": [
    { ... },
    { ... }
  ],
  "meta": {
    "total": 1234,
    "page": 1,
    "limit": 50,
    "pages": 25
  }
}
```

| Campo | Descripción |
|-------|-------------|
| `data` | Array de resultados |
| `meta.total` | Total de registros que coinciden con los filtros |
| `meta.page` | Página actual |
| `meta.limit` | Registros por página |
| `meta.pages` | Total de páginas |

### 7.2 Respuestas individuales

Los endpoints que retornan un solo recurso (ej: `/v1/vulnerabilities/:cveId`) retornan el objeto directamente sin envelope.

---

## 8. Ejemplos de Uso

### 8.1 Python

```python
import requests

API_URL = "http://server/api/v1"
API_KEY = "occ_a3f8b2c1e4d567890abcdef1234567890abcdef12"
HEADERS = {"X-API-Key": API_KEY}

# Listar vulnerabilidades críticas explotadas
response = requests.get(
    f"{API_URL}/vulnerabilities",
    headers=HEADERS,
    params={
        "severity": "CRITICAL",
        "exploited": "true",
        "limit": 20,
    },
)
data = response.json()

for vuln in data["data"]:
    print(f"{vuln['cveId']} - CVSS: {vuln['cvssV31Score']} - {vuln['primaryVendor']}/{vuln['primaryProduct']}")

print(f"\nTotal: {data['meta']['total']} vulnerabilidades")
```

### 8.2 JavaScript / Node.js

```javascript
const API_URL = "http://server/api/v1";
const API_KEY = "occ_a3f8b2c1e4d567890abcdef1234567890abcdef12";

async function getVulnerabilities() {
  const res = await fetch(`${API_URL}/vulnerabilities?severity=CRITICAL&limit=10`, {
    headers: { "X-API-Key": API_KEY },
  });
  const { data, meta } = await res.json();

  console.log(`Mostrando ${data.length} de ${meta.total} resultados`);
  data.forEach((v) => console.log(`${v.cveId} - ${v.cvssV31Severity}`));
}

getVulnerabilities();
```

### 8.3 PowerShell

```powershell
$ApiUrl = "http://server/api/v1"
$Headers = @{ "X-API-Key" = "occ_a3f8b2c1e4d567890abcdef1234567890abcdef12" }

# Obtener estadísticas
$stats = Invoke-RestMethod -Uri "$ApiUrl/vulnerabilities/stats" -Headers $Headers
Write-Host "Total: $($stats.total) | Críticas: $($stats.bySeverity.critical) | Explotadas: $($stats.exploited)"

# Listar KEV
$kev = Invoke-RestMethod -Uri "$ApiUrl/kev?limit=5" -Headers $Headers
$kev.data | ForEach-Object { Write-Host "$($_.cveId) - Due: $($_.kevDueDate)" }
```

### 8.4 cURL — Recorrer todas las páginas

```bash
API_KEY="occ_a3f8b2c1e4d567890abcdef1234567890abcdef12"
PAGE=1
TOTAL_PAGES=1

while [ $PAGE -le $TOTAL_PAGES ]; do
  RESPONSE=$(curl -s -H "X-API-Key: $API_KEY" \
    "http://server/api/v1/vulnerabilities?severity=CRITICAL&page=$PAGE&limit=100")

  TOTAL_PAGES=$(echo $RESPONSE | jq '.meta.pages')
  COUNT=$(echo $RESPONSE | jq '.data | length')
  echo "Página $PAGE/$TOTAL_PAGES — $COUNT resultados"

  # Procesar datos...
  echo $RESPONSE | jq '.data[].cveId'

  PAGE=$((PAGE + 1))
done
```

### 8.5 Integración con SIEM (Splunk HEC)

```python
import requests

OCC_API = "http://server/api/v1"
OCC_KEY = "occ_..."
SPLUNK_HEC = "https://splunk:8088/services/collector/event"
SPLUNK_TOKEN = "..."

# Obtener vulnerabilidades nuevas (últimas 24h)
vulns = requests.get(
    f"{OCC_API}/vulnerabilities",
    headers={"X-API-Key": OCC_KEY},
    params={"publishedFrom": "2026-03-27T00:00:00Z", "severity": "CRITICAL"},
).json()

# Enviar a Splunk
for v in vulns["data"]:
    requests.post(
        SPLUNK_HEC,
        headers={"Authorization": f"Splunk {SPLUNK_TOKEN}"},
        json={
            "event": {
                "cveId": v["cveId"],
                "severity": v["cvssV31Severity"],
                "cvss": v["cvssV31Score"],
                "vendor": v["primaryVendor"],
                "product": v["primaryProduct"],
                "exploited": v["isKnownExploited"],
            },
            "sourcetype": "occ:vulnerability",
        },
    )
```

---

## 9. Códigos de Error

| Código | Descripción | Causa |
|--------|-------------|-------|
| `200` | OK | Solicitud exitosa |
| `401` | Unauthorized | API key faltante, inválida, expirada o usuario deshabilitado |
| `403` | Forbidden | API key no tiene el scope requerido para este endpoint |
| `404` | Not Found | Recurso no encontrado (CVE, product asset, etc.) |
| `429` | Too Many Requests | Rate limit excedido — esperar antes de reintentar |

### Formato de error

```json
{
  "statusCode": 401,
  "message": "Invalid API key",
  "error": "Unauthorized"
}
```

### Manejo de errores recomendado

```python
response = requests.get(url, headers=headers)

if response.status_code == 429:
    retry_after = int(response.headers.get("Retry-After", 60))
    time.sleep(retry_after)
    # reintentar...
elif response.status_code == 401:
    print("API key inválida o expirada")
elif response.status_code == 403:
    print("Sin permisos para este endpoint — verificar scopes de la key")
elif response.status_code == 200:
    data = response.json()
```

---

## 10. Integración con Aplicaciones Externas

### 10.1 Flujo recomendado

1. Un administrador crea una API key desde la UI o via `POST /api/api-keys`
2. Se asignan solo los scopes necesarios (principio de mínimo privilegio)
3. Se configura una fecha de expiración si es apropiado
4. La aplicación externa almacena la key de forma segura (vault, variable de entorno)
5. Cada request incluye el header `X-API-Key`

### 10.2 Buenas prácticas

- **Una key por aplicación:** Crear una API key dedicada para cada integración. Esto permite revocar acceso de forma granular.
- **Scopes mínimos:** Otorgar solo los scopes que la aplicación necesita.
- **Rotación:** Establecer fechas de expiración y rotar keys periódicamente.
- **Monitoreo:** Revisar `lastUsedAt` en la lista de keys para detectar keys sin uso.
- **Almacenamiento seguro:** Nunca incluir API keys en código fuente o repositorios. Usar variables de entorno o gestores de secretos.
- **Paginación:** Usar paginación en lugar de solicitar todos los registros. El máximo es 200 por página.
- **Caché:** Implementar caché local para datos que no cambian frecuentemente (tags, manufacturers, software catalog).
- **Rate limiting:** Diseñar la aplicación para respetar los límites de rate. Implementar exponential backoff en caso de HTTP 429.

### 10.3 Casos de uso comunes

| Caso de uso | Endpoints sugeridos | Frecuencia |
|-------------|-------------------|------------|
| Dashboard de seguridad | `/vulnerabilities/stats`, `/kev`, `/exploits` | Cada 5-15 min |
| Alertas de nuevas CVEs | `/vulnerabilities?publishedFrom=...` | Cada 1 hora |
| Inventario de activos | `/product-assets`, `/product-assets/:id/dependencies` | Diario |
| Feed a SIEM | `/vulnerabilities?severity=CRITICAL`, `/kev` | Cada 1 hora |
| Auditoría de parches | `/product-assets/:id/vulnerabilities` | Diario |
| Estado del collector | `/collector/runs`, `/collector/sources-health` | Cada 30 min |
| Reporte ejecutivo | `/vulnerabilities/stats`, `/reports` | Semanal |
