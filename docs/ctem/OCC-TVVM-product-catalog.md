# OCC-TVM — Catálogo de Producto

**Threat & Vulnerability Management para la Oficina de Ciberseguridad**

> Documento de catálogo funcional. Describe las capacidades y características de la plataforma OCC-TVM tal como están implementadas en el repositorio. Cada capacidad está respaldada por componentes reales del sistema.

---

## Visión general

OCC-TVM es una plataforma de **gestión de amenazas y vulnerabilidades** que automatiza el ciclo completo: descubre vulnerabilidades desde las principales fuentes públicas de inteligencia, las correlaciona con el inventario tecnológico de la organización, prioriza según explotabilidad real, y notifica a los equipos responsables con informes accionables.

Está diseñada como base evolutiva hacia una plataforma **CTEM** (Continuous Threat Exposure Management) completa, y hoy cubre con solidez las fases de **descubrimiento** y **priorización** de exposición.

**Para quién es:** oficinas de ciberseguridad, equipos SOC, responsables de sistemas y suscriptores que necesitan estar al día de las vulnerabilidades que afectan a sus activos concretos.

---

## Capacidades principales

### 1. 🔎 Recolección automática multi-fuente de vulnerabilidades

Ingesta continua y desatendida desde las fuentes de referencia del sector, sin intervención manual.

| Fuente | Qué aporta |
|--------|-----------|
| **NVD (NIST)** | Catálogo oficial de CVEs, puntuaciones CVSS, software afectado (CPE) |
| **CVE.org** | Registro primario de CVEs |
| **OSV** | Vulnerabilidades de código abierto y dependencias |
| **CISA KEV** | Vulnerabilidades con **explotación activa confirmada** |
| **FIRST EPSS** | Probabilidad de explotación en los próximos 30 días |
| **ExploitDB / verificación de exploits** | Existencia de exploits públicos y pruebas de concepto |

- Recolección programada automática (incremental cada 30 min, consolidaciones periódicas y trabajo diario nocturno).
- Soporte para **CVSS v3.1 y CVSS v4.0**, además de clasificación **CWE**.
- Configuración por fuente: activar/desactivar, umbrales de severidad, claves de API (NVD, GitHub).

### 2. 🧬 Trazabilidad y evidencia auditable

Cada vulnerabilidad conserva su **linaje completo** desde el origen.

- Registro por fuente de cada CVE: URL de origen, identificador, fechas de publicación/modificación y nivel de confianza.
- Conservación del **payload original en crudo** de cada fuente para auditoría.
- **Historial de cambios** de cada vulnerabilidad a lo largo del tiempo.
- Marca de registro canónico cuando varias fuentes reportan el mismo CVE.

### 3. 🎯 Priorización por exposición real

No todas las vulnerabilidades importan igual. OCC-TVM prioriza según riesgo efectivo.

- **Señal EPSS**: probabilidad real de explotación.
- **Señal KEV**: explotación confirmada en el mundo real.
- **Enriquecimiento de explotabilidad**: presencia de exploits/PoC públicos.
- Puntuaciones CVSS v3/v4 y clasificación de severidad.
- **Reclasificación semántica** asistida para contextualizar y afinar la criticidad.

### 4. 🗂️ Inventario de activos y dependencias

Conocer qué se tiene es el primer paso para saber qué está expuesto.

- Catálogo de **activos de producto** con propietario, entorno, criticidad y tipo.
- **Inventario de dependencias** por producto.
- **Importación de SBOM en formato CycloneDX** para descubrir la superficie de dependencias.
- Registro de **evidencias de dependencias** importadas.

### 5. 🔗 Correlación vulnerabilidad ↔ activo

El puente entre la inteligencia externa y la realidad de la organización.

- Correlación automática entre vulnerabilidades e inventario de productos/dependencias.
- Cálculo de **impactos concretos**: qué CVE afecta a qué activo.
- Base para responder "¿esto me afecta a mí?" de forma precisa.

### 6. 📧 Notificaciones inteligentes

Alertas dirigidas a la persona correcta, sin ruido.

- Configuración **dinámica de SMTP** desde la interfaz o la API.
- **Notificaciones inteligentes** con emparejamiento por suscriptor: cada destinatario recibe solo lo que le concierne.
- **Políticas de notificación de 3 niveles** para controlar el volumen y la relevancia.
- Plantillas HTML personalizables (alertas de CVE, informes semanales, digests).
- Control de pausa de notificaciones, idioma de comunicación y email de notificación por usuario.
- Modo de prueba para validar notificaciones antes de enviarlas.

### 7. 📄 Generación de informes

Entregables profesionales listos para compartir.

- Informes de vulnerabilidades en **PDF y HTML** (motor Puppeteer + plantillas Handlebars).
- Plantillas personalizables, con imagen de cabecera propia.
- Digest semanal e informes de resumen.

### 8. 🤖 Asistente de IA integrado

Contexto y análisis asistido sobre las vulnerabilidades.

- Módulo de IA **agnóstico** (OpenAI u Ollama local).
- Endpoint conversacional (`POST /api/ai/chat`) para consultas sobre el estado de vulnerabilidades.
- Configurable desde la base de datos (modelo, proveedor, contexto).
- Reclasificación y enriquecimiento semántico de vulnerabilidades.

### 9. 👥 Portal de suscriptores y equipos

Cada cliente/equipo gestiona su propia exposición.

- **Portal de suscriptor**: perfil, catálogo de suscripciones, sus vulnerabilidades y notificaciones.
- Marcado de vulnerabilidades como **parcheadas** (`POST /vulnerabilities/:cveId/patched`).
- **Equipos de suscriptor** con miembros, roles, suscripciones, sistemas y destinatarios de notificación.
- Gestión de **peticiones de acción al defensor** y seguimiento de parcheo.
- Control de acceso por rol y por pertenencia a equipo.

### 10. 🔌 API externa para integración

OCC-TVM se conecta con tu ecosistema de seguridad.

- **API REST versionada** (`/api/v1`) para vulnerabilidades, productos, catálogo y colector.
- Autenticación por **API keys con scopes** (permisos granulares por clave).
- Documentación **Swagger/OpenAPI** integrada (`/api/docs`).
- Consultas de estadísticas, cambios y detalle de CVEs.

### 11. 📊 Panel de control (Dashboard)

Visión de conjunto en tiempo real.

- Métricas agregadas del estado de vulnerabilidades.
- Endpoint de **salud del sistema**.
- Interfaz web React para navegación, administración y consulta.

---

## Seguridad y administración

| Característica | Detalle |
|---------------|---------|
| **Autenticación local** | Usuario/contraseña con hash bcrypt |
| **MFA obligatorio** | Segundo factor TOTP para cuentas locales, con secreto cifrado (AES-GCM) |
| **SSO empresarial (opcional)** | Azure AD vía SAML y OIDC |
| **Sesiones JWT** | Tokens con validación de usuario activo en cada petición |
| **Protección de fuerza bruta** | Límite de intentos de login con registro de intentos |
| **Roles y permisos** | Control de acceso por rol global y por equipo |
| **Gestión de usuarios** | Alta, aprobación de auto-registro, roles, estado |
| **Recuperación de contraseña** | Flujo de reset por email con plantillas |
| **Validación de entradas** | Saneamiento global de peticiones (whitelist estricta) |
| **Hardening HTTP** | Cabeceras de seguridad (Helmet), CSP/HSTS en producción, CORS configurable |

---

## Arquitectura y despliegue

| Componente | Tecnología |
|-----------|------------|
| **Backend** | NestJS 10 + TypeScript |
| **Frontend** | React + Vite |
| **Base de datos** | MySQL 8.0 |
| **ORM** | Prisma 6 |
| **Generación de PDF** | Puppeteer + Handlebars |
| **Notificaciones** | Nodemailer (SMTP) |
| **IA** | OpenAI / Ollama |
| **Planificador** | @nestjs/schedule (Cron) |
| **Contenedores** | Docker Compose |
| **Proxy / TLS** | Nginx (compatible con Cloudflare Full strict) |

**Operación:**
- Despliegue contenedorizado con migraciones controladas y trazables (`prisma migrate deploy`).
- Scripts de **backup y restore** de base de datos con confirmación de seguridad.
- Seed automático en el primer arranque.
- Healthchecks de infraestructura.
- Suite de pruebas automatizadas (unitarias backend, frontend y regresión de notificaciones).

---

## Fuentes de inteligencia soportadas

- **NVD (NIST)** — CVEs, CVSS, CPE
- **CVE.org** — registro primario
- **OSV** — vulnerabilidades de código abierto
- **CISA KEV** — explotación activa confirmada
- **FIRST EPSS** — probabilidad de explotación
- **ExploitDB / GitHub** — exploits públicos y PoC

---

## Posicionamiento CTEM

OCC-TVM ya cubre de forma nativa el corazón del ciclo de gestión de exposición:

| Fase CTEM | Cobertura actual |
|-----------|------------------|
| **Scoping** (alcance) | Inventario de activos, dependencias y equipos |
| **Discovery** (descubrimiento) | ✅ **Fuerte** — ingesta multi-fuente, SBOM, trazabilidad |
| **Prioritization** (priorización) | ✅ **Fuerte** — EPSS, KEV, explotabilidad, IA |
| **Validation** (validación) | Enriquecimiento de explotabilidad (base) |
| **Mobilization** (movilización) | Notificaciones dirigidas, informes, seguimiento de parcheo |

---

*OCC-TVM — Threat & Vulnerability Management. Descubre. Prioriza. Notifica. Remedia.*
