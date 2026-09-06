# 02 — Registro de deuda técnica (Technical Debt Register)

> **Consulta 1 — ARGOS.** Rama `feature/mejoras-v1.1-sin-keycloak`, HEAD `64bb678`.
> Cada hallazgo se clasifica con: **ID · Categoría · Severidad · Evidencia · Archivo/símbolo · Impacto · Causa raíz · Recomendación · Esfuerzo · Dependencia · Decisión** (conservar / corregir / refactorizar / desacoplar / retirar).
> Severidad: **Crítica / Alta / Media / Baja**. Esfuerzo: **S / M / L / XL**.
> Los hallazgos de seguridad viven en `03-security-assessment.md`; aquí van arquitectura, datos, mantenibilidad y operación. Marcas de evidencia según convención del doc 01 (`[HECHO]`/`[INFERENCIA]`/`[RIESGO]`/`[N/D]`).

---

## Tabla resumen

| ID | Categoría | Severidad | Símbolo | Decisión |
|----|-----------|-----------|---------|----------|
| TD-01 | Escalabilidad | **Alta** | Crons `@Cron` in-process | Refactorizar |
| TD-02 | Mantenibilidad | **Alta** | `smart-notifications.service.ts` (192 KB) | Refactorizar |
| TD-03 | Mantenibilidad | **Alta** | `notification.service.ts` (112 KB) | Refactorizar |
| TD-04 | Mantenibilidad | **Alta** | `frontend/src/App.jsx` (431 KB) | Refactorizar (extracción gradual) |
| TD-05 | Calidad/Test | **Alta** | Ingesta/collectors sin test; e2e ausente | Corregir |
| TD-06 | Datos | Media | Duplicidad notificaciones clásicas vs inteligentes | Desacoplar/consolidar |
| TD-07 | Datos | Media | Estados como `String` sin enums | Corregir |
| TD-08 | Arquitectura | Media | Redis aprovisionado sin uso | Retirar/decidir |
| TD-09 | Operación | **Alta** | `bootstrap.sh` obsoleto (PostgreSQL) | Retirar/aislar |
| TD-10 | Seguridad-datos | **Alta** | Autorización por convención (no transversal) | Refactorizar |
| TD-11 | Datos | Media | Trazabilidad end-to-end por tramos, sin linaje continuo | Corregir |
| TD-12 | Acoplamiento | Media | `AuthModule` → Notification/PasswordReset | Desacoplar |
| TD-13 | Operación | Media | `PRISMA_DB_PUSH_ON_START` + `--accept-data-loss` | Corregir |
| TD-14 | Observabilidad | Media | Sin métricas/tracing ni logging estructurado | Corregir |
| TD-15 | Arquitectura | Media | Puppeteer PDF dentro del proceso API | Desacoplar |
| TD-16 | Backend | Media | Idempotencia/transacciones de ingesta no verificadas | Corregir (investigar) |
| TD-17 | Calidad | Baja | Runners de test fragmentados (jest src vs tests/ vs frontend) | Corregir |

---

## Detalle

### TD-01 — Jobs `@Cron` ejecutados dentro del proceso API
- **Categoría:** Escalabilidad / Arquitectura · **Severidad:** Alta
- **Evidencia `[HECHO]`:** 5 crons en `vulnerability-collector.service.ts:98,155,215`, `notification.service.ts:1100`, `smart-notifications.service.ts:585`, activados por `ScheduleModule.forRoot()` (`app.module.ts:29`).
- **Impacto `[INFERENCIA]`:** con >1 réplica de `api`, cada instancia dispara los mismos crons → doble ingesta, doble notificación, doble consumo de rate-limits de fuentes externas. Impide escalado horizontal y hace del proceso un SPOF.
- **Causa raíz:** scheduler en memoria sin coordinación distribuida (no hay lock; Redis no se usa, ver TD-08).
- **Recomendación:** externalizar la planificación (worker dedicado single-instance, o lock distribuido / cola). No introducir dependencia nueva sin decisión; documentar como bloqueo previo a CTEM.
- **Esfuerzo:** L · **Dependencia:** decisión sobre cola/lock (relac. TD-08) · **Decisión:** Refactorizar.

### TD-02 — `smart-notifications.service.ts` monolítico (192 KB)
- **Categoría:** Mantenibilidad · **Severidad:** Alta
- **Evidencia `[HECHO]`:** archivo único de 192,7 KB; contiene cron horario (`:585`) y toda la lógica de matching/render/envío inteligente.
- **Impacto:** superficie de cambio enorme, difícil de testear y razonar; alto riesgo de regresión (ya hay 3 tests de regresión dedicados en `tests/`).
- **Causa raíz:** crecimiento acumulado sin extracción de subdominios (reglas, plantillas, matching, entrega).
- **Recomendación:** descomponer en submódulos (rule engine, subscriber matching, render, delivery) preservando comportamiento; cubrir con tests antes de mover.
- **Esfuerzo:** XL · **Dependencia:** TD-05 (tests previos) · **Decisión:** Refactorizar.

### TD-03 — `notification.service.ts` monolítico (112 KB)
- **Categoría:** Mantenibilidad · **Severidad:** Alta
- **Evidencia `[HECHO]`:** 112 KB; cron cada 2 h (`:1100`). Coexiste con TD-02.
- **Impacto/Causa/Recom.:** análogos a TD-02; además solapa función con smart-notifications (ver TD-06).
- **Esfuerzo:** L · **Dependencia:** TD-06 · **Decisión:** Refactorizar (y consolidar con TD-06).

### TD-04 — `frontend/src/App.jsx` monolítico (431 KB)
- **Categoría:** Mantenibilidad / Frontend · **Severidad:** Alta
- **Evidencia `[HECHO]`:** 431,5 KB en un solo componente; extracción ya iniciada en `frontend/src/features/{subscriber-teams,users}` con tests.
- **Impacto:** build pesado, difícil navegación/onboarding, riesgo de regresión en cada cambio de UI.
- **Causa raíz:** UI construida como archivo único; refactor gradual en curso pero incipiente.
- **Recomendación:** continuar el patrón `features/*` ya establecido (api/components/utils/pages + tests) extrayendo un dominio por iteración; no reescritura.
- **Esfuerzo:** XL (incremental) · **Dependencia:** ninguna dura · **Decisión:** Refactorizar (extracción gradual).

### TD-05 — Núcleo de ingesta sin pruebas; e2e inexistente
- **Categoría:** Calidad/Test · **Severidad:** Alta
- **Evidencia `[HECHO]`:** no hay `.spec.ts` para collectors (`nvd`, `osv`, `cveorg`, `cisa-kev`, `epss`, `exploitdb`, `exploit-check`), ni para `nvd-ingestion-processor.service.ts` (47 KB), `vulnerability-collector.service.ts` (64 KB), `report-generator.service.ts`. `package.json:19` referencia `./test/jest-e2e.json` pero el directorio `test/` no existe → e2e no ejecutable.
- **Impacto:** cambios en el corazón del producto (ingesta y correlación) sin red de seguridad; refactors TD-01/02/03 arriesgados.
- **Causa raíz:** foco de testing en módulos nuevos (subscriber-teams) y en render de notificaciones; ingesta quedó fuera.
- **Recomendación:** añadir tests de contrato para collectors (fixtures de payload real) y tests de idempotencia del processor antes de refactorizar; crear el `test/` e2e o eliminar el script muerto.
- **Esfuerzo:** L · **Dependencia:** prerequisito de TD-01/02/03 · **Decisión:** Corregir.

### TD-06 — Duplicidad de modelos y lógica de notificación
- **Categoría:** Datos / Mantenibilidad · **Severidad:** Media
- **Evidencia `[HECHO]`:** dos generaciones: clásica (`NotificationLog` `schema.prisma:539`, `NotificationPolicy` `:875`, `VulnerabilityNotification` `:606`) e inteligente (`IntelligentNotificationFinding` `:708`, `...SubscriberMatch` `:744`, `...TestRun` `:773`, `SmartNotificationReport` `:683`).
- **Impacto:** dos caminos que hacen lo mismo → confusión, riesgo de notificaciones inconsistentes, doble mantenimiento.
- **Causa raíz:** evolución de un sistema al otro sin retirar el anterior.
- **Recomendación:** decidir sistema canónico y plan de migración/retirada del legado; no borrar datos, marcar deprecación.
- **Esfuerzo:** L · **Dependencia:** TD-03 · **Decisión:** Desacoplar/consolidar.

### TD-07 — Estados y roles como `String` sin enums
- **Categoría:** Datos · **Severidad:** Media
- **Evidencia `[HECHO]`:** `prisma/schema.prisma` sin `enum`; p. ej. `User.role String @default("USER")` (`:19`), `authProvider String` (`:20`), `productType String @default("unknown")` (`ProductAsset`), `fetchStatus String` (`CollectorSourceHealth`). `tests/notification-policy-schema-drift.test.js` evidencia deriva previa.
- **Impacto:** valores inválidos posibles, validación dispersa en código, deriva de vocabulario entre módulos.
- **Causa raíz:** decisión de flexibilidad early-stage.
- **Recomendación:** introducir enums Prisma o tablas de catálogo para estados de dominio críticos (roles, estados de colección, tipos de producto), con migración no destructiva.
- **Esfuerzo:** M · **Dependencia:** revisión de valores en producción `[N/D]` · **Decisión:** Corregir.

### TD-08 — Redis obligatorio en compose, no consumido
- **Categoría:** Arquitectura / Operación · **Severidad:** Media
- **Evidencia `[HECHO]`:** `docker-compose.yml:24-42` con `REDIS_PASSWORD` obligatoria; sin cliente Redis en `package.json` ni referencias en `src/`.
- **Impacto:** coste y complejidad sin beneficio; el arranque de compose falla si falta `REDIS_PASSWORD`, dando falsa sensación de dependencia crítica.
- **Causa raíz:** infraestructura preparada para un uso (caché/cola) nunca implementado.
- **Recomendación:** o **retirar** el servicio, o **conservarlo** documentando que se reservará para el lock distribuido de TD-01. Decidir explícitamente.
- **Esfuerzo:** S · **Dependencia:** TD-01 · **Decisión:** Retirar o reservar (decisión pendiente).

### TD-09 — `bootstrap.sh` obsoleto y potencialmente destructivo
- **Categoría:** Operación · **Severidad:** Alta
- **Evidencia `[HECHO]`:** 2.543 líneas; cabecera declara **PostgreSQL** (`bootstrap.sh:5`) mientras el stack real es MySQL; regenera `package.json`/código vía here-docs.
- **Impacto `[INFERENCIA]`:** re-ejecutarlo sobreescribiría archivos vivos con versiones obsoletas; confunde a cualquier nuevo operador.
- **Causa raíz:** script generador congelado en una fase temprana del proyecto.
- **Recomendación:** mover a `scripts/legacy/` o marcar deprecado en cabecera; no eliminar sin confirmar que no forma parte de ningún pipeline `[N/D]`.
- **Esfuerzo:** S · **Dependencia:** confirmar que ningún CI lo invoca · **Decisión:** Retirar/aislar.

### TD-10 — Autorización aplicada por convención, no transversal
- **Categoría:** Seguridad-datos / Arquitectura · **Severidad:** Alta
- **Evidencia `[HECHO]`:** `RolesGuard` sólo compara rol global; el aislamiento por equipo depende de llamadas manuales a `TeamAccessService.assertTeamReadable/Writable` (`team-access.service.ts`). No hay interceptor/policy transversal.
- **Impacto `[RIESGO]`:** un endpoint nuevo que olvide la comprobación expone datos cruzados entre equipos/suscriptores. Bloqueante para CTEM multi-cliente.
- **Causa raíz:** ausencia de capa de autorización basada en políticas centralizada.
- **Recomendación:** introducir política de acceso declarativa (guard/decorator por recurso) y tests de autorización sistemáticos.
- **Esfuerzo:** L · **Dependencia:** modelo de tenancy CTEM (consulta futura) · **Decisión:** Refactorizar. *(También en `03-security-assessment.md` como SEC.)*

### TD-11 — Trazabilidad end-to-end fragmentada
- **Categoría:** Datos · **Severidad:** Media
- **Evidencia `[HECHO]`:** trazabilidad fuerte fuente→vuln→impacto (`VulnerabilitySourceRecord`, `VulnerabilityChangeEvent`, `VulnerabilityProductImpact`), pero `NotificationLog`/`VulnerabilityReport` no encadenan FK al `VulnerabilitySourceRecord` originario `[N/D]`.
- **Impacto:** difícil responder auditorías de linaje completo (evidencia → acción notificada → informe), requisito típico CTEM.
- **Recomendación:** añadir referencias de linaje (o tabla de eventos de linaje) sin romper el modelo actual.
- **Esfuerzo:** M · **Dependencia:** verificación de FKs (siguiente consulta) · **Decisión:** Corregir.

### TD-12 — Acoplamiento `AuthModule` → Notification/PasswordReset
- **Categoría:** Acoplamiento · **Severidad:** Media
- **Evidencia `[HECHO]`:** `auth.module.ts:15-16` importa `NotificationModule` y `PasswordResetModule`.
- **Impacto:** ciclo conceptual auth↔notificación; dificulta extraer auth como servicio y testear aislado.
- **Recomendación:** invertir dependencia mediante eventos/puerto de notificación.
- **Esfuerzo:** M · **Decisión:** Desacoplar.

### TD-13 — `db push --accept-data-loss` habilitable por variable
- **Categoría:** Operación / Datos · **Severidad:** Media (potencialmente Alta si mal configurado)
- **Evidencia `[HECHO]`:** `docker/entrypoint.sh:20-24`, `PRISMA_DB_PUSH_ON_START=true` → `prisma db push --skip-generate --accept-data-loss`.
- **Impacto `[RIESGO]`:** una variable de entorno mal puesta en producción puede provocar pérdida de datos en el arranque.
- **Recomendación:** eliminar la rama `db push` de producción o protegerla con guard de entorno (`OCC_ENV != prod`).
- **Esfuerzo:** S · **Decisión:** Corregir.

### TD-14 — Sin observabilidad (métricas/tracing/log estructurado)
- **Categoría:** Observabilidad · **Severidad:** Media
- **Evidencia `[HECHO]/[N/D]`:** logging vía `Logger` de Nest; no hay Prometheus/OpenTelemetry ni filtro de excepciones global visible; agregación de logs no evidente.
- **Impacto:** diagnóstico y SLA de CTEM (que exige medir exposición/tiempo de remediación) sin telemetría base.
- **Recomendación:** añadir métricas de jobs (éxito/latencia por collector, ya hay datos en `CollectorSourceHealth`) y healthcheck HTTP.
- **Esfuerzo:** M · **Decisión:** Corregir.

### TD-15 — Generación de PDF con Puppeteer dentro del proceso API
- **Categoría:** Arquitectura / Escalabilidad · **Severidad:** Media
- **Evidencia `[HECHO]`:** `report-generator.service.ts:149-166` (`require('puppeteer')`, `launch`, `setContent`, `networkidle0`).
- **Impacto:** picos de memoria/CPU en el proceso API; contención con la API en tiempo de informe. (Seguridad SSRF tratada en doc 03.)
- **Recomendación:** aislar la generación de informes en worker/servicio dedicado.
- **Esfuerzo:** M · **Dependencia:** TD-01 (worker) · **Decisión:** Desacoplar.

### TD-16 — Idempotencia/transacciones de ingesta sin verificar
- **Categoría:** Backend / Datos · **Severidad:** Media
- **Evidencia `[N/D]`:** no auditado en esta consulta el uso de `prisma.$transaction` ni de claves de idempotencia en el upsert de vulnerabilidades (`nvd-ingestion-processor.service.ts`, `mysql.repository.ts`). El `@@unique([cveId, sourceName])` de `VulnerabilitySourceRecord` sugiere idempotencia a nivel de registro de fuente `[INFERENCIA]`.
- **Impacto:** relevante dado TD-01 (posible doble ejecución) — sin idempotencia sólida, la doble ejecución corrompería contadores/estado.
- **Recomendación:** auditar y garantizar upserts idempotentes + transacciones en el processor (objeto de la siguiente consulta).
- **Esfuerzo:** M · **Dependencia:** lectura profunda de ingesta · **Decisión:** Corregir (investigar primero).

### TD-17 — Runners de test fragmentados
- **Categoría:** Calidad · **Severidad:** Baja
- **Evidencia `[HECHO]`:** Jest backend con `rootDir: src` y `testRegex .*\.spec\.ts$` (`package.json:99-115`) no cubre `tests/*.test.js` ni `frontend/**`. Tres corredores efectivos sin orquestación única.
- **Impacto:** `npm test` no ejecuta toda la batería; riesgo de tests que nadie corre en CI.
- **Recomendación:** unificar en un pipeline (backend spec + tests/ + frontend) y reportar cobertura agregada.
- **Esfuerzo:** S · **Decisión:** Corregir.

---

## Priorización sugerida (sin diseñar roadmap CTEM)

**Bloqueos duros antes de tocar CTEM:** TD-01, TD-05, TD-10, TD-16 (habilitan refactor seguro del núcleo y aislamiento multi-cliente).
**Higiene de riesgo inmediato:** TD-09, TD-13 (peligro operativo/datos con bajo esfuerzo).
**Deuda estructural de fondo:** TD-02, TD-03, TD-04, TD-06.
