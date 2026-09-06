# 04 — Capacidades reutilizables para CTEM (Reusable Capabilities)

> **Consulta 1 — ARGOS.** Rama `feature/mejoras-v1.1-sin-keycloak`, HEAD `64bb678`.
> Objetivo: inventariar qué capacidades actuales sirven de sustrato para una evolución CTEM **sin reescritura**, clasificando su grado de reutilización. **No** se diseña aquí la arquitectura CTEM ni el roadmap.
> Marcas de evidencia según convención del doc 01.
>
> **Marco de referencia (sólo para clasificar, no para diseñar):** las cinco fases CTEM de Gartner — *Scoping · Discovery · Prioritization · Validation · Mobilization*. Se indica a qué fase alimenta cada capacidad.
>
> **Grado de reutilización:**
> - **A — Reutilizable tal cual** (sin refactor previo).
> - **B — Reutilizable con adaptación menor.**
> - **C — Reutilizable sólo tras refactor** (ver doc 02).

---

## Tabla resumen

| Cap. | Capacidad | Fase CTEM | Grado | Símbolo principal |
|------|-----------|-----------|-------|-------------------|
| CAP-01 | Pipeline multi-fuente de ingesta CVE | Discovery | **A** | `modules/vulnerability-collector/collectors/*` |
| CAP-02 | Trazabilidad y linaje de fuentes | Discovery/Validation | **A** | `VulnerabilitySourceRecord`, `VulnerabilityChangeEvent` |
| CAP-03 | Priorización por EPSS + KEV | Prioritization | **A** | `epss.collector.ts`, `cisa-kev.collector.ts` |
| CAP-04 | Enriquecimiento por explotabilidad | Prioritization/Validation | **B** | `exploit-check.collector.ts`, `exploitdb.collector.ts` |
| CAP-05 | Inventario de activos y dependencias | Scoping/Discovery | **A/B** | `ProductAsset`, `ProductDependencyInventory` |
| CAP-06 | Import CycloneDX (SBOM) | Discovery | **A** | `scripts/import-cyclonedx.ts`, `DependencyEvidenceImport` |
| CAP-07 | Correlación vulnerabilidad↔producto | Prioritization | **B** | `VulnerabilityProductImpact`, `correlate-vulnerability-impacts.ts` |
| CAP-08 | Salud/observabilidad de colección | Operación transversal | **A** | `CollectorSourceHealth`, `CollectorRun` |
| CAP-09 | API externa v1 con API keys+scopes | Integración/Mobilization | **A** | `modules/external-api/**` |
| CAP-10 | Autenticación local + MFA | Transversal | **A** | `auth/*`, MFA TOTP |
| CAP-11 | Modelo de equipos/suscriptores/recipients | Scoping/Mobilization | **B** | `subscriber-teams/**`, `SubscriberTeam` |
| CAP-12 | Motor de notificaciones | Mobilization | **C** | `notification.service.ts`, `smart-notifications.service.ts` |
| CAP-13 | Generación de informes (PDF/HTML) | Mobilization | **B/C** | `report-generator.service.ts` |
| CAP-14 | Enriquecimiento por IA (semántico) | Prioritization/Validation | **B** | `modules/ai/ai.service.ts`, scripts reclasificación |
| CAP-15 | Reclasificación semántica de vulnerabilidades | Prioritization | **B** | `scripts/*semantic-reclassification.ts` |
| CAP-16 | Frontend features desacoplados | UI transversal | **B** | `frontend/src/features/*`, `occ-visual-kit/` |
| CAP-17 | Gestión de acciones del defensor | Mobilization | **B** | `DefenderActionRequest`, `SubscriberPatchedCve` |

---

## Detalle por capacidad

### CAP-01 — Pipeline multi-fuente de ingesta de vulnerabilidades — Grado A
- **Fase:** Discovery. **Evidencia `[HECHO]`:** collectors en `src/modules/vulnerability-collector/collectors/`: `nvd.collector.ts`, `cveorg.collector.ts`, `osv.collector.ts`, `cisa-kev.collector.ts`, `epss.collector.ts`, `exploitdb.collector.ts`, `exploit-check.collector.ts`. Procesado en `nvd-ingestion-processor.service.ts`.
- **Por qué reutilizable:** arquitectura de colectores por fuente ya establecida; añadir fuentes CTEM (ASM/scanners) sigue el mismo patrón.
- **Condición:** para escalar necesita resolver TD-01 (crons in-process) y TD-16 (idempotencia). El *patrón* es A; su ejecución operativa es C.

### CAP-02 — Trazabilidad y linaje de fuentes — Grado A
- **Fase:** Discovery/Validation. **Evidencia `[HECHO]`:** `VulnerabilitySourceRecord` (`schema.prisma:253`, `@@unique([cveId,sourceName])`, `rawPayload`, `confidence`, `isCanonical`), `VulnerabilityChangeEvent` (`:231`), `Vulnerability.rawData` (`:193`).
- **Por qué reutilizable:** CTEM exige evidencia auditable del origen de cada hallazgo; el modelo ya la conserva por fuente y en crudo.
- **Condición:** extender linaje hasta notificación/informe (TD-11) para trazabilidad end-to-end.

### CAP-03 — Priorización por EPSS + CISA KEV — Grado A
- **Fase:** Prioritization. **Evidencia `[HECHO]`:** `epss.collector.ts` (probabilidad de explotación), `cisa-kev.collector.ts` (explotación conocida). Campos CVSS v3/v4 en `Vulnerability` (migración `20260323000000`).
- **Por qué reutilizable:** son exactamente las señales que CTEM usa para priorizar exposición real, ya ingeridas.

### CAP-04 — Enriquecimiento por explotabilidad — Grado B
- **Fase:** Prioritization/Validation. **Evidencia `[HECHO]`:** `exploit-check.collector.ts` (16,8 KB), `exploitdb.collector.ts`; `.env.example:44-59` (`VULN_COLLECTOR_EXPLOIT_CHECK_ENABLED`, umbral de severidad).
- **Condición:** adaptación menor para alinear la señal con el motor de priorización CTEM.

### CAP-05 — Inventario de activos y dependencias — Grado A/B
- **Fase:** Scoping/Discovery. **Evidencia `[HECHO]`:** `ProductAsset` (`:293`, con `owner`, `environment`, `criticality`, `productType`), `ProductDependencyInventory` (`:348`), `SubscriberOwnedSystem` (`:809`), `TeamSystem` (`:1043`).
- **Por qué reutilizable:** el *scoping* CTEM parte del inventario de activos; ya existe con criticidad y entorno.
- **Condición:** `criticality`/`environment`/`productType` son strings libres (TD-07); conviene normalizar para scoring de exposición → grado B en ese aspecto.

### CAP-06 — Import CycloneDX (SBOM) — Grado A
- **Fase:** Discovery. **Evidencia `[HECHO]`:** `scripts/import-cyclonedx.ts`, `DependencyEvidenceImport` (`:323`), módulo `dependency-evidence-imports`.
- **Por qué reutilizable:** ingesta de SBOM es un pilar de descubrimiento de superficie de dependencias; ya funcional.

### CAP-07 — Correlación vulnerabilidad↔producto — Grado B
- **Fase:** Prioritization. **Evidencia `[HECHO]`:** `VulnerabilityProductImpact` (`:389`), `scripts/correlate-vulnerability-impacts.ts`.
- **Condición:** verificar idempotencia y automatización (hoy hay script manual además del flujo); adaptación menor.

### CAP-08 — Salud y observabilidad de colección — Grado A
- **Fase:** Operación transversal. **Evidencia `[HECHO]`:** `CollectorSourceHealth` (`:277`: `fetchStatus`, `itemsFetched/Processed/Errored`, `durationMs`, `anomalyFlags`), `CollectorRun` (`:458`), `NotificationJobRun` (`:562`).
- **Por qué reutilizable:** base directa para métricas de CTEM (cobertura de descubrimiento, frescura de datos) — ya se recolectan, sólo falta exponerlas (TD-14).

### CAP-09 — API externa v1 con API keys + scopes — Grado A
- **Fase:** Integración/Mobilization. **Evidencia `[HECHO]`:** `modules/external-api/` con `ApiKeyGuard` (bcrypt+scopes) y controladores `v1/{vulnerabilities,products,catalog,collector}`. Documentada en `docs/EXTERNAL_API_MANUAL.md`.
- **Por qué reutilizable:** punto de integración maduro para conectar herramientas CTEM externas (SOAR, ticketing, EDR).
- **Condición:** añadir scope por cliente cuando exista tenancy (relac. SEC-01), rate-limit (SEC-08).

### CAP-10 — Autenticación local + MFA — Grado A
- **Fase:** Transversal. **Evidencia `[HECHO]`:** `auth/*`, MFA TOTP cifrado (`auth.service.ts`), JWT con validación de usuario vivo (`jwt.strategy.ts`), SAML/OIDC opcionales.
- **Por qué reutilizable:** cumple el mandato de no tocar autenticación; base sólida y segura para CTEM. Conservar tal cual.

### CAP-11 — Modelo de equipos / suscriptores / destinatarios — Grado B
- **Fase:** Scoping/Mobilization. **Evidencia `[HECHO]`:** `SubscriberTeam`, `TeamMember`, `TeamSubscription`, `TeamSystem`, `NotificationRecipient` (`:968-1043`), con `TeamAccessService` y tests. Es el trabajo más reciente y mejor cubierto por tests.
- **Por qué reutilizable:** aporta la agrupación funcional que CTEM necesita para asignar responsabilidad de remediación.
- **Condición:** hoy es agrupación, no aislamiento (SEC-01/TD-10); para multi-cliente CTEM requiere elevar a frontera de datos → grado B.

### CAP-12 — Motor de notificaciones — Grado C
- **Fase:** Mobilization. **Evidencia `[HECHO]`:** `notification.service.ts` (112 KB) + `smart-notifications.service.ts` (192 KB), plantillas `src/templates/*.html`, políticas `NotificationPolicy`, hallazgos inteligentes.
- **Por qué reutilizable (a futuro):** la *movilización* CTEM se apoya en alertar al responsable correcto; la funcionalidad existe y es rica (matching por suscriptor, políticas de 3 niveles).
- **Condición:** **refactor obligatorio** (TD-02/03/06: monolitos + duplicidad) antes de construir encima. Grado C.

### CAP-13 — Generación de informes PDF/HTML — Grado B/C
- **Fase:** Mobilization. **Evidencia `[HECHO]`:** `report-generator.service.ts` (Handlebars + Puppeteer), `VulnerabilityReport` (`:436`).
- **Por qué reutilizable:** informes de exposición son entregable CTEM habitual.
- **Condición:** resolver SSRF/sandbox (SEC-02/04) y aislar del proceso API (TD-15). Grado B en función, C en operación segura.

### CAP-14 — Enriquecimiento por IA — Grado B
- **Fase:** Prioritization/Validation. **Evidencia `[HECHO]`:** `modules/ai/ai.service.ts` (18 KB) con Ollama local (`.env.example:89-90`), controlador `ai.controller.ts`.
- **Por qué reutilizable:** clasificación/resumen semántico de vulnerabilidades ayuda a priorizar y contextualizar.
- **Condición:** modelo local (Ollama) — verificar coste/latencia para uso a escala; adaptación menor.

### CAP-15 — Reclasificación semántica de vulnerabilidades — Grado B
- **Fase:** Prioritization. **Evidencia `[HECHO]`:** `scripts/reclassify-vulnerability-semantics.ts`, `scripts/backfill-vulnerability-semantic-reclassification.ts` (17,3 KB).
- **Condición:** hoy son scripts batch; integrar en flujo continuo → adaptación.

### CAP-16 — Frontend por features desacoplados — Grado B
- **Fase:** UI transversal. **Evidencia `[HECHO]`:** `frontend/src/features/{subscriber-teams,users}` (api/components/utils/pages + tests), `frontend/src/utils/*` con tests, `occ-visual-kit/`.
- **Por qué reutilizable:** patrón de extracción ya probado sobre el que construir vistas CTEM sin tocar `App.jsx` monolítico.
- **Condición:** `App.jsx` (431 KB) sigue siendo el grueso (TD-04); nuevas vistas deben nacer en `features/`. Grado B.

### CAP-17 — Gestión de acciones del defensor — Grado B
- **Fase:** Mobilization. **Evidencia `[HECHO]`:** `DefenderActionRequest` (`:836`), `SubscriberPatchedCve` (`:854`), portales `subscriber-portal`/`team-portal`.
- **Por qué reutilizable:** primitivas de *movilización* (registrar parcheo, solicitar acción) ya modeladas.
- **Condición:** falta workflow formal de estados/SLA (no hay máquina de estados ni enums, TD-07); ampliar para remediación con seguimiento auditable.

---

## Síntesis de reutilización por fase CTEM

- **Scoping:** `[HECHO]` sustrato parcial (CAP-05, CAP-11) — inventario existe, falta normalización y frontera de datos.
- **Discovery:** `[HECHO]` **fuerte** (CAP-01, CAP-02, CAP-06, CAP-08) — el punto más maduro del producto.
- **Prioritization:** `[HECHO]` **fuerte** (CAP-03, CAP-04, CAP-07, CAP-14, CAP-15) — señales EPSS/KEV/exploit/IA presentes.
- **Validation:** `[INFERENCIA]` **débil** — sólo enriquecimiento de explotabilidad; no hay validación activa (pentest/simulación/exposición confirmada).
- **Mobilization:** `[INFERENCIA]` **parcial pero con deuda** (CAP-09, CAP-12, CAP-13, CAP-17) — notificación e informes existen pero requieren refactor (grado C) y falta workflow de remediación con SLA.

**Conclusión de reutilización `[INFERENCIA]`:** ARGOS es una base sólida para las fases de *Discovery* y *Prioritization* de CTEM, aprovechable con poco o ningún refactor. Las fases de *Validation* y *Mobilization* requieren nuevas capacidades y refactor del motor de notificaciones. *Scoping* necesita elevar el modelo de equipos a frontera de datos real. Nada de esto exige reescritura total.
