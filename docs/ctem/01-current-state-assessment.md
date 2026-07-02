# 01 — Evaluación del estado actual (Current State Assessment)

> **Consulta 1 — Auditoría técnica integral de OCC-TVM**
> Repositorio: `occ-vuls` (producto OCC-TVM). Rama: `feature/mejoras-v1.1-sin-keycloak`. HEAD de referencia: `64bb678`.
> Alcance: arquitectura, modelo de datos, backend, frontend, operación. **No** se ha modificado código de aplicación. **No** se diseña aquí la arquitectura CTEM objetivo ni el roadmap.
>
> **Convención de evidencia** en todos los documentos de esta consulta:
> - `[HECHO]` — verificado leyendo el repositorio, con referencia a archivo/símbolo.
> - `[INFERENCIA]` — deducción razonada a partir de hechos, no confirmada por ejecución.
> - `[RIESGO]` — riesgo potencial, no un fallo confirmado.
> - `[N/D]` — información no disponible en el repositorio; requiere confirmación externa.

---

## 1. Verificaciones expresas solicitadas

### 1.1 ¿Usa Redis de forma real (directa o indirecta)?

`[HECHO]` **No hay uso de Redis en el código de aplicación.** No existe ningún cliente Redis en `package.json` (dependencias: no aparecen `ioredis`, `redis`, `@nestjs/cache-manager`, `bull`/`bullmq`). Una búsqueda de `redis|Redis|REDIS` sobre `src/`, `config/`, `deploy.sh` y `docker/entrypoint.sh` no devuelve coincidencias en código.

`[HECHO]` Redis **sí está declarado en infraestructura**: `docker-compose.yml:24-42` define el servicio `occ-redis` (`redis:7-alpine`, `appendonly yes`, `requirepass`, healthcheck, volumen `redis_data`, red `cache_net`) y exige `REDIS_PASSWORD` (`:?REDIS_PASSWORD is required`).

`[INFERENCIA]` Redis es **infraestructura aprovisionada pero no consumida por la aplicación**. Es un punto único de fallo declarado en el arranque de compose (la variable es obligatoria) sin aportar función. Los jobs programados usan `@nestjs/schedule` en memoria del proceso, no una cola Redis (ver §1.8).

`[N/D]` Si algún despliegue externo (fuera de este repo) usa Redis para sesiones o caché a nivel de proxy. No hay evidencia en el repositorio.

**Decisión sugerida:** *retirar* de compose o *conservar* como reserva documentada; hoy es coste sin uso.

### 1.2 Pruebas reales existentes (unit / integración / BD / frontend / e2e)

`[HECHO]` **29 archivos de test.** Inventario completo:

| Tipo | Ubicación (ejemplos) | Nº aprox. |
|---|---|---|
| Unit backend | `src/auth/auth.service.spec.ts`, `src/auth/guards/roles.guard.spec.ts`, `src/common/occ-env.util.spec.ts`, `src/modules/users/users.service.spec.ts`, `src/modules/smart-notifications/intelligent-notification.logic.spec.ts`, `intelligent-email-render.spec.ts` | ~15 |
| Integración backend | `src/modules/external-api/api-keys.controller.int.spec.ts` (único `.int.spec.ts`), `src/modules/subscriber-teams/*.controller.spec.ts` (usan mocks de servicio) | ~4 |
| Unit frontend | `frontend/src/utils/{notificationCenter,appNavigation,userManagement,vulnerabilityReferences}.test.js`, `frontend/src/features/subscriber-teams/**` (utils, api, components), `frontend/src/features/users/components/UserFormModal.test.js` | ~9 |
| Regresión de notificaciones | `tests/intelligent-template-regression.test.js`, `tests/intelligent-notification-timeout-hardening.test.js`, `tests/notification-policy-schema-drift.test.js` | 3 |

`[HECHO]` Jest backend está configurado con `rootDir: src` y `testRegex: .*\.spec\.ts$` (`package.json:99-115`). Los tests de `tests/*.test.js` y `frontend/**` **no** los ejecuta ese runner (extensión y rootDir distintos); requieren otro corredor.

`[HECHO]` **No existe suite e2e real.** `package.json:19` define `test:e2e` apuntando a `./test/jest-e2e.json`, pero **el directorio `test/` no existe** (solo `tests/` con 3 `.test.js`). El script e2e fallaría por config ausente.

`[HECHO]` **No hay test contra base de datos real.** Los `.spec.ts` mockean `PrismaService`; el único que toca esquema de datos de forma "de integración" (`api-keys.controller.int.spec.ts`) debe revisarse para confirmar si usa BD o mocks. Los scripts `scripts/test-prisma-migrate-empty-db.sh` y `test-prisma-migrate-existing-db.sh` sí prueban migraciones sobre MySQL efímero, pero son scripts manuales, no parte de `npm test`.

**Zonas críticas sin test** (detalle en `02-technical-debt-register.md`): collectors de ingesta, `nvd-ingestion-processor.service.ts` (46,9 KB), `vulnerability-collector.service.ts` (64 KB), `notification.service.ts` (112 KB), `smart-notifications.service.ts` (192 KB), `report-generator.service.ts`, correlación de impactos.

### 1.3 ¿Subscriber, SubscriberTeam y User son ámbitos aislados o agrupaciones funcionales?

`[HECHO]` **No son ámbitos aislados (tenants); son agrupaciones funcionales sobre una única tabla `User`.** Evidencia:
- No existe entidad `Subscriber` ni `Organization` en `prisma/schema.prisma`. Un "subscriber" es un `User` con `isSubscriber = true` (`schema.prisma:24`, campo `is_subscriber`).
- `SubscriberTeam` (`schema.prisma:968`) agrupa `TeamMember` (referencia a `User`), `TeamSubscription`, `TeamSystem`, `NotificationRecipient` — es una agrupación, no una frontera de datos.
- El catálogo de vulnerabilidades (`Vulnerability`), fuentes, impactos y colectores son **globales/compartidos**: no tienen columna de propietario/tenant.

`[INFERENCIA]` El modelo es **single-tenant con segmentación funcional** de destinatarios de notificación. "Subscriber" designa a quién se notifica, no una partición de datos.

### 1.4 ¿Existe aislamiento obligatorio de datos por suscriptor / equipo / organización / rol?

`[HECHO]` **No hay aislamiento obligatorio a nivel de datos.** No hay row-level security, ni filtros de tenant sistemáticos, ni columna de scope en las entidades de dominio. La autorización es **por rol y por pertenencia a equipo, aplicada en la capa de servicio**, no en la de datos:
- `RolesGuard` (`src/auth/guards/roles.guard.ts`) sólo comprueba `requiredRoles.includes(user.role)` — control de acceso plano por rol global.
- `TeamAccessService` (`src/modules/subscriber-teams/team-access.service.ts`) aplica comprobaciones explícitas: `assertTeamReadable` / `assertTeamWritable` consultan `teamMember` con `isActive` y rol; `ADMIN` global bypassa todo (`if (user.role === 'ADMIN') return;`).

`[RIESGO]` El aislamiento por equipo depende de que **cada endpoint invoque manualmente** `TeamAccessService`. No es un mecanismo transversal obligatorio; un endpoint nuevo que olvide la comprobación expone datos cruzados. Esto es el patrón "authorization by convention", frágil para CTEM multi-cliente.

`[HECHO]` La API externa v1 **no aplica scope por suscriptor**: `ext-vulnerabilities.controller.ts` expone `GET /` (listado global), `GET /:cveId`, `stats`, `changes` protegidos sólo por `ApiKeyGuard` + scopes, sin filtrar por propietario. Coherente con un catálogo global de CVEs, pero relevante si CTEM introduce datos por cliente.

### 1.5 Coexistencia real: login local + MFA + Azure SAML + Azure OIDC

`[HECHO]` Los cuatro mecanismos **coexisten y están cableados** en `AuthModule` (`src/auth/auth.module.ts`): `LocalStrategy`, `JwtStrategy`, `SamlStrategy`, `AzureOidcService`. Keycloak **no** aparece (retirada confirmada).

- **Login local + MFA (por defecto):** `AuthService.loginLocal` (`auth.service.ts:116`) exige `authProvider === 'LOCAL'`; si `mfaEnabled` devuelve `mfaRequired` + `mfaToken` de propósito acotado (`purpose:'mfa'`, `signMfaToken` línea 52); si no está habilitado, fuerza `mfaEnrollRequired`. El secreto TOTP se cifra con AES-GCM (`encryptMfaSecret`, clave de 32 bytes obligatoria, `getMfaKey` línea 19-27). `[HECHO]` **MFA es efectivamente obligatorio para cuentas locales.**
- **Bypass MFA de test:** `shouldBypassMfaForUser` (`test-mfa-bypass.util.ts:62`) sólo actúa si `MFA_TEST_BYPASS_ENABLED=true`, con allowlist explícita, emails que empiezan por `test.`, y **bloqueado en producción** vía `assertOccEnvAllowsTestCapabilities(occEnv)` (línea 45, lanza si el entorno no lo permite). Uso registrado con `logger.warn('TEST_MFA_BYPASS_USED ...')`. `[HECHO]` Bien contenido.
- **Azure SAML / OIDC:** desactivados por defecto (`AZURE_SAML_ENABLED=false`, `AZURE_OIDC_ENABLED=false`, `.env.example:103,113`). Documentados en `docs/azure-saml.md`, `docs/azure-oidc.md`.

`[RIESGO]` `[INFERENCIA]` Usuarios SAML/OIDC tendrían `authProvider != 'LOCAL'` y por tanto **no pasan por MFA propio** (la rama MFA sólo aplica a LOCAL). Se asume que el IdP externo aporta el segundo factor. No verificado el flujo completo de callback SAML/OIDC en esta consulta.

### 1.6 ¿Qué ejecuta `bootstrap.sh` y su impacto en despliegue, secretos y datos?

`[HECHO]` `bootstrap.sh` (2.543 líneas, 85 KB) es un **generador/scaffolder de proyecto**, no un script operativo de despliegue. Su cabecera declara "Genera el proyecto completo: NestJS + **PostgreSQL** + Prisma + Docker" (`bootstrap.sh:5`). Emite mediante here-docs el `package.json`, docker-compose, código, etc.

`[HECHO]` **Deriva del estado real del repo:** menciona PostgreSQL, mientras el stack actual usa **MySQL 8** (`docker-compose.yml:4`, `mysql2` en `package.json:59`, `@db.LongText`/`@db.Text` en el schema). El script está **desactualizado** respecto al proyecto vivo.

`[RIESGO]` `[INFERENCIA]` Ejecutar `bootstrap.sh` sobre el repo actual podría **sobrescribir archivos generados** con versiones obsoletas (regenera `package.json`, código, compose). Debe tratarse como artefacto histórico, no ejecutable.

`[N/D]` No se ha auditado línea a línea si genera secretos o toca datos; no ejecutado (prohibido y no necesario). Recomendación: marcar como deprecado o mover a `scripts/legacy/`.

### 1.7 Aplicación de migraciones Prisma por entorno

`[HECHO]` **Producción/contenedor:** `docker/entrypoint.sh:9-17` ejecuta `prisma migrate deploy` en el arranque si `PRISMA_MIGRATE_ON_START` != false (por defecto true); aborta el arranque si falla. Opcionalmente `PRISMA_DB_PUSH_ON_START=true` ejecuta `prisma db push --skip-generate --accept-data-loss` (`entrypoint.sh:20-24`).
`[RIESGO]` **`--accept-data-loss` disponible por bandera de entorno** es peligroso si se activa por error en producción. Ver `03-security-assessment.md`.

`[HECHO]` **Seed condicional en primer arranque:** `entrypoint.sh:27-45` cuenta usuarios y ejecuta `prisma/seed.js` sólo si la tabla está vacía; errores de seed son no fatales.

`[HECHO]` **Desarrollo:** `npm run prisma:migrate` → `prisma migrate dev` (`package.json:22`). `[HECHO]` **Validación de migraciones:** existen `scripts/test-prisma-migrate-empty-db.sh` y `test-prisma-migrate-existing-db.sh` (prueban `migrate deploy` + `migrate status` sobre MySQL efímero, base vacía y con las 11 migraciones previas). `[HECHO]` 12 migraciones en `prisma/migrations/` con baseline `20260320000000_initial_schema_baseline`, documentado en `docs/prisma-migration-baseline.md`.

### 1.8 Datos y procesos que dependen de jobs programados

`[HECHO]` **5 jobs `@Cron` en memoria del proceso** (`@nestjs/schedule`, `ScheduleModule.forRoot()` en `app.module.ts:29`):

| Cron | Archivo:línea | Función (inferida por ubicación) |
|---|---|---|
| `0 */30 * * * *` (cada 30 min) | `vulnerability-collector.service.ts:98` | Recolección incremental de vulnerabilidades |
| `0 0 3 * * *` (03:00 diario) | `vulnerability-collector.service.ts:155` | Job diario (backfill/consolidación) |
| `0 0 */2 * * *` (cada 2 h) | `vulnerability-collector.service.ts:215` | Recolección/refresh periódico |
| `0 0 */2 * * *` (cada 2 h) | `notification.service.ts:1100` | Procesamiento de notificaciones |
| `0 0 * * * *` (cada hora) | `smart-notifications.service.ts:585` | Notificaciones inteligentes |

`[RIESGO]` Los jobs corren **dentro del proceso API**. `[INFERENCIA]` Con múltiples réplicas de `api`, cada instancia ejecutaría los crons en paralelo → **doble ingesta / doble notificación** salvo que exista un lock. No se ha encontrado mecanismo de liderazgo/lock distribuido (Redis no se usa; ver §1.1). **Punto único de fallo y anti-patrón de escalado horizontal.**

`[HECHO]` Trazabilidad de ejecuciones: `CollectorRun` (`schema.prisma:458`) y `CollectorSourceHealth` (`schema.prisma:277`, con `fetchStatus`, `itemsFetched/Processed/Errored`, `durationMs`, `anomalyFlags`) y `NotificationJobRun` (`schema.prisma:562`).

### 1.9 Trazabilidad de fuente → vulnerabilidad → impacto → notificación → informe

`[HECHO]` La cadena de trazabilidad **existe y es sólida en la mitad de ingesta**:
1. **Fuente → vulnerabilidad:** `VulnerabilitySourceRecord` (`schema.prisma:253`) guarda por cada `(cveId, sourceName)` único: `sourceUrl`, `sourceRecordId`, `sourcePublishedAt/ModifiedAt`, `confidence`, `rawPayload` (LongText), `normalizedData`, `firstSeenAt/lastSeenAt`, `isCanonical`. Relación `onDelete: Cascade` a `Vulnerability`. `Vulnerability.rawData` (`schema.prisma:193`) conserva el payload.
2. **Historial de cambios:** `VulnerabilityChangeEvent` (`schema.prisma:231`) registra la evolución.
3. **Salud de ingesta:** `CollectorSourceHealth` + `CollectorRun`.
4. **Vulnerabilidad → impacto:** `VulnerabilityProductImpact` (`schema.prisma:389`) enlaza `Vulnerability` con `ProductAsset`/`ProductDependencyInventory`.
5. **Notificación:** `NotificationLog` (`schema.prisma:539`), `VulnerabilityNotification` (`schema.prisma:606`), `NotificationJobRun`, más la rama inteligente (`IntelligentNotificationFinding`, `...SubscriberMatch`, `...TestRun`).
6. **Informe:** `VulnerabilityReport` (`schema.prisma:436`) + `report-generator.service.ts`.

`[RIESGO]` La trazabilidad **transversal end-to-end** (poder responder "esta notificación/este informe derivó de esta fuente concreta en esta fecha") no está garantizada por FKs continuas: `NotificationLog` e `VulnerabilityReport` no necesariamente referencian el `VulnerabilitySourceRecord` originario. Es trazabilidad por tramos, no un linaje único. `[N/D]` Confirmar leyendo las FKs completas de `NotificationLog`/`VulnerabilityReport`.

### 1.10 Componentes reutilizables para CTEM sin refactor previo

Resumen aquí; detalle en `04-reusable-capabilities.md`. `[HECHO]` Reutilizables tal cual: pipeline de collectors (NVD, CVE.org, OSV, KEV, EPSS, ExploitDB), modelo de trazabilidad de fuentes, `ProductAsset`/`ProductDependencyInventory`, import CycloneDX, `VulnerabilityProductImpact`, API externa v1 con API keys+scopes, autenticación local+MFA. Requieren refactor: motor de notificaciones (monolitos de 112/192 KB), `App.jsx`, ejecución de crons in-process.

---

## 2. Arquitectura

`[HECHO]` **Estilo:** monolito modular NestJS 10 (`package.json:39-71`) + frontend React/Vite servido por nginx + MySQL 8 + nginx reverse proxy, orquestado por docker-compose (5 servicios: mysql, redis, api, frontend, nginx — `docker-compose.yml`).

**Límites de dominio** `[HECHO]`: 16 módulos NestJS registrados en `app.module.ts:23-47`. Dominios: ingesta/vulnerabilidades, dashboard, notificaciones (clásicas + inteligentes), IA, usuarios, tags, fabricantes, reset de contraseña, portal de suscriptor, equipos de suscriptor, activos de producto, evidencias de dependencias, impactos, API externa.

**Acoplamiento y responsabilidades mezcladas** `[HECHO]`:
- `vulnerability-collector.service.ts` (64 KB) mezcla orquestación de crons, colección e I/O de repositorio.
- `notification.service.ts` (**112 KB**) y `smart-notifications.service.ts` (**192 KB**) concentran lógica de negocio, plantillas, matching y envío en un solo archivo cada uno — **componentes monolíticos críticos**.
- `AuthModule` importa `NotificationModule` y `PasswordResetModule` (`auth.module.ts:15-16`) → acoplamiento auth↔notificación.

**Componentes monolíticos** `[HECHO]`: `frontend/src/App.jsx` (**431 KB**), `smart-notifications.service.ts` (192 KB), `notification.service.ts` (112 KB), `vulnerability-collector.service.ts` (64 KB), `nvd-ingestion-processor.service.ts` (47 KB), `external-api.service.ts` (21 KB), `mysql.repository.ts` (21 KB).

**Mantenibilidad** `[INFERENCIA]`: buena en módulos recientes (subscriber-teams, external-api: bien segmentados, con tests); baja en el núcleo de notificaciones/ingesta y en el frontend por tamaño de archivo.

**Escalabilidad** `[RIESGO]`: crons in-process impiden escalado horizontal seguro de `api` (§1.8). MySQL es único (sin réplica declarada). Puppeteer para PDF es intensivo en memoria dentro del mismo proceso API (`report-generator.service.ts:159`).

**Puntos únicos de fallo** `[HECHO]/[INFERENCIA]`: MySQL único; proceso API único con crons; nginx proxy; Redis obligatorio en compose pero inútil (fallo de arranque si falta password, sin beneficio).

---

## 3. Modelo de datos

`[HECHO]` 38 modelos, 1.068 líneas, `prisma/schema.prisma`; **sin enums Prisma** (estados y roles se guardan como `String` con defaults, p. ej. `User.role String @default("USER")`, `authProvider String @default("LOCAL")`).

**Entidades núcleo:** `Vulnerability` (con CVSS v4.0 y CWE desde migración `20260323000000`), `VulnerabilitySourceRecord`, `VulnerabilityChangeEvent`, `VulnerabilityProductImpact`, `ProductAsset`, `ProductDependencyInventory`, `DependencyEvidenceImport`, `VulnerabilityReport`.

**Auditoría/historial** `[HECHO]`: cobertura desigual. Fuerte en ingesta (`VulnerabilitySourceRecord`, `VulnerabilityChangeEvent`, `CollectorRun`, `CollectorSourceHealth`, `LoginAttempt`, `UserSession`). Débil/ausente en entidades administrativas: no hay tabla genérica de audit-log de acciones de usuario (quién cambió qué en `User`, `SubscriberTeam`, `NotificationPolicy`).

**Estados y ciclos de vida** `[RIESGO]`: al no usar enums, los estados (roles, `authProvider`, `fetchStatus`, `productType`) son strings libres validados sólo en código → riesgo de deriva de valores. `tests/notification-policy-schema-drift.test.js` sugiere que la deriva ya ha sido un problema.

**Ownership / aislamiento** `[HECHO]`: ver §1.3–1.4. Sin columna de tenant en dominio; ownership funcional vía `TeamMember`/`TeamSubscription`/`TeamSystem`.

**Integridad** `[HECHO]`: FKs con `onDelete: Cascade` en trazabilidad de fuentes; índices únicos coherentes (`@@unique([cveId, sourceName])`, `User.email @unique`, `User.externalId @unique`). `[N/D]` No auditadas todas las FKs de notificaciones/informes.

**Duplicidad** `[HECHO]`: dos generaciones de notificaciones coexisten (`notification` clásico con `NotificationLog`/`NotificationPolicy` vs `smart-notifications` con modelos `IntelligentNotification*`). Solapamiento funcional → deuda. Campos `rawData` LongText repetidos en `Vulnerability`, `SubscriberOwnedSystem` (825), y modelo en 1059.

**Compatibilidad con evolución CTEM** `[INFERENCIA]`: la base de vulnerabilidad/producto/impacto es un buen sustrato para las fases CTEM de *scoping/discovery/prioritization*. Faltan entidades para *validación* (exposición confirmada, pentest) y *movilización* formal (workflows/SLA de remediación con estados y responsables auditables).

---

## 4. Backend (resumen; detalle en documentos 02 y 03)

`[HECHO]` **Controladores** (18): rutas en `/api` (prefijo global `main.ts:90`), Swagger en `/api/docs` condicionado por `ENABLE_SWAGGER`/`NODE_ENV` (`main.ts:72`). **Validación:** `ValidationPipe` global con `whitelist`, `forbidNonWhitelisted`, `transform` (`main.ts:62-68`) → buena higiene de DTO. **Guards:** `JwtAuthGuard`, `RolesGuard`, `SamlAuthGuard`, `ApiKeyGuard` (external-api, con scopes y hash bcrypt de la key, `api-key.guard.ts`). **Manejo de errores:** excepciones Nest estándar; `[N/D]` sin filtro de excepciones global visible ni logging estructurado centralizado. **Transacciones/idempotencia:** `[N/D]` requiere lectura profunda de los servicios de ingesta (siguiente consulta) para confirmar uso de `prisma.$transaction` y claves de idempotencia en upserts.

---

## 5. Frontend (resumen; detalle en 02 y 04)

`[HECHO]` `App.jsx` de **431 KB** es el componente monolítico dominante. Ya hay **estrategia de extracción iniciada**: `frontend/src/features/{subscriber-teams,users}` con subcarpetas `api/`, `components/`, `utils/`, `pages/` y **tests propios** (`teamForms`, `teamViewModel`, `teamPermissions`, `TeamUi`, `subscriberTeamsApi`, `UserFormModal`). Utilidades desacopladas en `frontend/src/utils/` con tests (`appNavigation`, `notificationCenter`, `userManagement`, `vulnerabilityReferences`). `[HECHO]` `occ-visual-kit/` sugiere un kit visual compartido. `[N/D]` Gestión de estado global (Redux/Context) y guardas de autorización de vistas no auditadas en esta pasada (App.jsx no leído íntegro por tamaño).

---

## 6. Operación (resumen; detalle en 02)

`[HECHO]` Healthchecks definidos para mysql y redis en compose. `[N/D]` Healthcheck HTTP de la API no confirmado. `[HECHO]` Backup/restore: `scripts/db-export-prod.sh`, `scripts/db-restore-prod.sh`. `[HECHO]` SSL: `scripts/generate-ssl.sh` + `docker/ssl/`. `[HECHO]` Migraciones en arranque con validación previa por scripts. `[N/D]` Observabilidad (métricas, tracing) y agregación de logs: no hay evidencia de Prometheus/OpenTelemetry.

---

## 7. Separación de afirmaciones

- **Hechos verificados:** estructura de módulos, ausencia de cliente Redis, inventario de 29 tests y ausencia de e2e, modelo single-tenant, coexistencia auth, crons in-process, migraciones vía entrypoint, trazabilidad de fuentes.
- **Inferencias principales:** doble ejecución de crons al escalar; SAML/OIDC omiten MFA propio; `bootstrap.sh` obsoleto y peligroso de re-ejecutar.
- **Riesgos potenciales:** autorización por convención (no transversal), `db push --accept-data-loss` por bandera, deriva de strings de estado, Redis como SPOF inútil.
- **No disponible:** volumen de datos en producción, uso de transacciones/idempotencia en ingesta, flujo completo SAML/OIDC, FKs completas de notificación/informe, observabilidad.

**Siguiente lectura recomendada:** `02-technical-debt-register.md`.
