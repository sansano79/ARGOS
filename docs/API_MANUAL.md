# 📚 Manual API - Plataforma OCC

**Versión 1.0 - Marzo 2026**

---

## 📖 Tabla de Contenidos

1. [Introducción](#introducción)
2. [Gestión de API Keys](#gestión-de-api-keys)
3. [Scopes y Permisos](#scopes-y-permisos)
4. [Uso de la API](#uso-de-la-api)
5. [Endpoints Disponibles](#endpoints-disponibles)
6. [Ejemplos Prácticos](#ejemplos-prácticos)
7. [Rate Limiting](#rate-limiting)
8. [Seguridad](#seguridad)
9. [Solución de Problemas](#solución-de-problemas)

---

## Introducción

La API externa de OCC permite a aplicaciones terceras acceder a toda la información de la plataforma de forma segura y controlada. A través de API Keys, puedes integrar nuestros datos de vulnerabilidades, productos, fabricantes y catálogos en tus propias aplicaciones.

### ✨ Características principales

- ✅ Autenticación basada en API Keys
- ✅ Control granular de permisos (scopes)
- ✅ Rate limiting para proteger la plataforma
- ✅ Endpoints RESTful documentados
- ✅ Responses en JSON
- ✅ Soporte para filtrado y paginación

---

## Gestión de API Keys

### 🔑 Acceso al Panel de Control

Las API Keys se gestionan desde el panel administrativo de la plataforma:

1. **Inicia sesión** como administrador
2. Accede a **Configuración → API Keys**

### ➕ Crear una API Key

Sigue estos pasos para crear una nueva API Key:

1. Haz clic en el botón **+ Nueva API Key**
2. Asigna un nombre descriptivo:
   - ✓ Ejemplo: `"Mi Aplicación - Integración Vulnerabilidades"`
3. Selecciona los **scopes** (permisos) que tu aplicación necesita
4. Haz clic en **Crear API Key**

⚠️ **IMPORTANTE**: Copia la clave inmediatamente. **No podrás verla nuevamente**.

### 🔧 Administrar API Keys

Desde el panel de API Keys puedes:

- Ver todas tus API Keys activas
- Editar nombre y scopes
- **Rotar** (regenerar) claves
- Eliminar claves no utilizadas
- Ver último acceso y uso

---

## Scopes y Permisos

Los scopes definen qué endpoints puede acceder tu API Key. **Siempre utiliza el scope más restrictivo necesario**.

| Scope | Descripción | Endpoints |
|-------|-------------|-----------|
| `vulnerabilities:read` | Lectura de vulnerabilidades | `GET /api/v1/vulnerabilities*` |
| `products:read` | Lectura de productos y activos | `GET /api/v1/product-assets*` |
| `manufacturers:read` | Lectura de fabricantes y catálogos | `GET /api/v1/manufacturers`, `GET /api/v1/tags` |
| `reports:read` | Lectura de reportes y análisis | `GET /api/v1/reports`, `GET /api/v1/collector/*` |

---

## Uso de la API

### 🌐 URL Base

```
https://tu-dominio/api/v1
```

### 🔐 Autenticación

Incluye la API Key en el header de cada solicitud:

```
Authorization: Bearer YOUR_API_KEY
```

### 📝 Ejemplo con cURL

```bash
curl -H "Authorization: Bearer sk_live_abc123xyz..." \
  https://tu-dominio/api/v1/vulnerabilities
```

### 📝 Ejemplo con JavaScript

```javascript
const response = await fetch('https://tu-dominio/api/v1/vulnerabilities', {
  headers: {
    'Authorization': 'Bearer sk_live_abc123xyz...'
  }
});

const data = await response.json();
console.log(data);
```

### 📝 Ejemplo con Python

```python
import requests

headers = {
    'Authorization': 'Bearer sk_live_abc123xyz...'
}

response = requests.get(
    'https://tu-dominio/api/v1/vulnerabilities',
    headers=headers
)

data = response.json()
print(data)
```

### 📝 Ejemplo con Node.js (Axios)

```javascript
const axios = require('axios');

const API_KEY = 'sk_live_abc123xyz...';

const response = await axios.get(
  'https://tu-dominio/api/v1/vulnerabilities',
  {
    headers: {
      'Authorization': `Bearer ${API_KEY}`
    }
  }
);

console.log(response.data);
```

---

## Endpoints Disponibles

### 🔴 Vulnerabilidades

#### Listar vulnerabilidades

```
GET /api/v1/vulnerabilities
```

**Parámetros opcionales:**

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `limit` | number | Número de resultados (defecto: 50, máximo: 1000) |
| `offset` | number | Número de resultados a saltar (para paginación) |
| `severity` | string | Filtrar por severidad: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `kev` | boolean | Solo vulnerabilidades conocidas (KEV) |
| `published_after` | date | Filtrar por fecha de publicación (ISO 8601) |

**Ejemplo:**
```bash
GET /api/v1/vulnerabilities?limit=100&severity=CRITICAL&kev=true
```

**Respuesta exitosa (200):**
```json
{
  "success": true,
  "total": 42,
  "limit": 50,
  "offset": 0,
  "items": [
    {
      "id": 1,
      "cveId": "CVE-2024-1234",
      "description": "Descripción de la vulnerabilidad",
      "severity": "CRITICAL",
      "cvssScore": 9.8,
      "published": "2024-01-15T10:00:00Z",
      "modified": "2024-03-28T20:00:00Z",
      "kev": true,
      "exploits": 5
    }
  ]
}
```

---

#### Obtener CVE específico

```
GET /api/v1/vulnerabilities/:cveId
```

**Ejemplo:**
```bash
GET /api/v1/vulnerabilities/CVE-2024-1234
```

**Respuesta:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "cveId": "CVE-2024-1234",
    "description": "Descripción detallada",
    "severity": "CRITICAL",
    "cvssScore": 9.8,
    "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "published": "2024-01-15T10:00:00Z",
    "modified": "2024-03-28T20:00:00Z",
    "kev": true,
    "cwe": ["CWE-79"],
    "references": ["https://..."],
    "exploits": 5
  }
}
```

---

#### Cambios en vulnerabilidades

```
GET /api/v1/vulnerabilities/:cveId/changes
```

Retorna el histórico de cambios en una vulnerabilidad.

---

#### Estadísticas globales

```
GET /api/v1/vulnerabilities/stats
```

**Respuesta:**
```json
{
  "success": true,
  "stats": {
    "total": 50000,
    "byCriticality": {
      "CRITICAL": 1250,
      "HIGH": 3500,
      "MEDIUM": 20000,
      "LOW": 25250
    },
    "kev": 2500,
    "exploits": 8000,
    "lastUpdated": "2026-03-28T20:00:00Z"
  }
}
```

---

### 📦 Productos y Activos

#### Listar todos los productos/activos

```
GET /api/v1/product-assets
```

**Parámetros:**
- `limit`: Número de resultados
- `offset`: Para paginación
- `manufacturer`: Filtrar por fabricante

---

#### Vulnerabilidades de un producto

```
GET /api/v1/product-assets/:id/vulnerabilities
```

Retorna todas las vulnerabilidades que afectan a un producto específico.

---

#### Dependencias de un producto

```
GET /api/v1/product-assets/:id/dependencies
```

---

### 🏭 Fabricantes y Catálogos

```
GET /api/v1/manufacturers     # Listar fabricantes
GET /api/v1/tags              # Listar etiquetas
GET /api/v1/kev               # CISA KEV (Exploited Vulnerabilities)
GET /api/v1/exploits          # Exploits disponibles
```

---

### 📊 Reportes

```
GET /api/v1/reports                    # Listar reportes disponibles
GET /api/v1/collector/runs             # Histórico de colecciones
GET /api/v1/collector/sources-health   # Salud de las fuentes
```

---

## Ejemplos Prácticos

### Obtener todas las vulnerabilidades críticas

```bash
curl -H "Authorization: Bearer sk_live_abc123xyz..." \
  "https://tu-dominio/api/v1/vulnerabilities?severity=CRITICAL&limit=100"
```

---

### Buscar vulnerabilidad específica

```bash
curl -H "Authorization: Bearer sk_live_abc123xyz..." \
  "https://tu-dominio/api/v1/vulnerabilities/CVE-2024-1234"
```

---

### Integración en JavaScript - Monitoreo de vulnerabilidades

```javascript
async function monitorVulnerabilities() {
  const API_KEY = process.env.OCC_API_KEY; // Usar variable de entorno

  try {
    const response = await fetch(
      'https://tu-dominio/api/v1/vulnerabilities?severity=CRITICAL&kev=true',
      {
        headers: {
          'Authorization': `Bearer ${API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();

    console.log(`✅ Vulnerabilidades encontradas: ${data.total}`);
    console.log(`📍 Mostrando: ${data.items.length} de ${data.total}`);

    data.items.forEach(vuln => {
      console.log(`
        CVE: ${vuln.cveId}
        Severidad: ${vuln.severity}
        CVSS: ${vuln.cvssScore}
        Exploits conocidos: ${vuln.exploits}
        Descripción: ${vuln.description}
      `);
    });

  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

// Ejecutar cada hora
setInterval(monitorVulnerabilities, 3600000);
```

---

### Integración en Python - Dashboard de estadísticas

```python
import requests
import json
from datetime import datetime

def get_vulnerability_stats():
    API_KEY = os.getenv('OCC_API_KEY')
    headers = {
        'Authorization': f'Bearer {API_KEY}'
    }

    try:
        response = requests.get(
            'https://tu-dominio/api/v1/vulnerabilities/stats',
            headers=headers
        )
        response.raise_for_status()

        data = response.json()
        stats = data.get('stats', {})

        print("=" * 50)
        print("🔒 ESTADÍSTICAS DE VULNERABILIDADES")
        print("=" * 50)
        print(f"Total: {stats.get('total', 0):,}")
        print(f"Críticas: {stats.get('byCriticality', {}).get('CRITICAL', 0):,}")
        print(f"Altas: {stats.get('byCriticality', {}).get('HIGH', 0):,}")
        print(f"Con exploits: {stats.get('exploits', 0):,}")
        print(f"Última actualización: {stats.get('lastUpdated')}")
        print("=" * 50)

        return stats

    except requests.exceptions.RequestException as e:
        print(f"❌ Error: {e}")
        return None
```

---

## Rate Limiting

La API implementa límites de tasa para proteger la infraestructura:

- ⏱️ **100 solicitudes por minuto** por API Key
- ⏱️ **1000 solicitudes por hora** por API Key
- 🔄 Los límites se resetean automáticamente

### Headers de Rate Limit

Cada respuesta incluye información sobre el estado:

```
X-RateLimit-Limit: 100              # Límite por minuto
X-RateLimit-Remaining: 45           # Solicitudes restantes
X-RateLimit-Reset: 1711731660       # Timestamp UNIX del reset
Retry-After: 60                     # Segundos a esperar (si 429)
```

### Manejo de error 429

```javascript
async function makeApiRequest(url, apiKey) {
  const response = await fetch(url, {
    headers: { 'Authorization': `Bearer ${apiKey}` }
  });

  if (response.status === 429) {
    const retryAfter = response.headers.get('Retry-After');
    console.log(`⏳ Límite alcanzado. Esperando ${retryAfter} segundos...`);
    await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
    return makeApiRequest(url, apiKey); // Reintentar
  }

  return response.json();
}
```

---

## Seguridad

### 🔒 Mejores Prácticas

1. **NUNCA compartas tu API Key** públicamente o en repositorios de código
   ```bash
   # ❌ NUNCA hagas esto
   git add api_key.txt
   echo "sk_live_abc123xyz..." > config.js

   # ✅ SIEMPRE usa variables de entorno
   export OCC_API_KEY="sk_live_abc123xyz..."
   ```

2. **Usa variables de entorno** para almacenar las API Keys
   ```bash
   # .env file
   OCC_API_KEY=sk_live_abc123xyz...
   OCC_API_URL=https://tu-dominio/api/v1
   ```

3. **Rota las claves regularmente** desde el panel de administración
   - Regenera cada 90 días
   - Inmediatamente si la clave se expone

4. **Usa HTTPS siempre** para todas las solicitudes
   - Nunca HTTP sin cifrar
   - Verifica certificados SSL válidos

5. **Limita los scopes** solo a los necesarios
   - Si solo necesitas vulnerabilidades, no solicites `products:read`
   - Reduce el impacto en caso de compromiso

6. **Monitorea el uso** desde el panel de API Keys
   - Revisa último acceso
   - Vigila patrones de uso anómalos

---

## Solución de Problemas

### ❌ Error 401 - Unauthorized

**Causas posibles:**
- API Key incorrecta o mal copiada
- Clave expirada o rotada
- Formato incorrecto del header

**Solución:**
```bash
# ✅ Formato correcto
curl -H "Authorization: Bearer sk_live_abc123xyz..." https://...

# ❌ Formatos incorrectos
curl -H "Authorization: sk_live_abc123xyz..." https://...      # Falta "Bearer"
curl -H "Api-Key: sk_live_abc123xyz..." https://...             # Header incorrecto
```

---

### ❌ Error 403 - Forbidden

**Causa:**
La API Key no tiene permisos para acceder a este endpoint.

**Solución:**
1. Abre el panel de administración
2. Verifica los scopes asignados a la API Key
3. Añade el scope necesario si falta

---

### ❌ Error 429 - Too Many Requests

**Causa:**
Has excedido el límite de solicitudes.

**Solución:**
```javascript
// Esperar y reintentar
const retryAfter = parseInt(response.headers.get('Retry-After') || '60');
setTimeout(() => {
  // Reintentar solicitud
}, retryAfter * 1000);
```

---

### ❌ Respuesta vacía

**Causas posibles:**
- Parámetros de filtrado muy restrictivos
- Datos no disponibles
- Página sin resultados

**Solución:**
```bash
# Verificar con parámetros más amplios
GET /api/v1/vulnerabilities?limit=10&offset=0

# Omitir filtros
GET /api/v1/vulnerabilities?limit=100
```

---

### ❌ Errores de conexión

Si tienes problemas para conectar:

1. Verifica la URL del dominio
2. Comprueba tu conexión a internet
3. Intenta con `curl` primero para descartar problemas de código
4. Revisa los logs del servidor

```bash
# Diagnosticar conexión
curl -v -H "Authorization: Bearer sk_live_abc123xyz..." \
  https://tu-dominio/api/v1/vulnerabilities
```

---

## 📞 Soporte

Para preguntas, problemas o solicitudes de características:

- 📧 Email: soporte@occ-platform.com
- 💬 Chat: Panel de administración → Soporte
- 📚 Documentación: https://docs.occ-platform.com

---

**© 2026 OCC Platform. Todos los derechos reservados.**

*Última actualización: 2026-03-28*
