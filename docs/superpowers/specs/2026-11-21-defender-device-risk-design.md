# ARGOS — riesgo real por servidor a partir de Microsoft Defender

## Propósito y alcance

Defender for Endpoint lista decenas o cientos de CVEs por equipo, todas con su severidad nominal. Esa lista no responde a la pregunta que importa al responsable del servidor: **¿puede un atacante comprometer realmente este equipo, y por dónde?**

Esta entrega añade a ARGOS:

1. Un conector de **solo lectura** a la API de Defender for Endpoint que sincroniza los servidores (filtrados por tag) y las vulnerabilidades detectadas en cada uno.
2. Una **capa de estudio determinista** que enriquece cada hallazgo con la inteligencia de ARGOS, clasifica qué capacidad otorga cada CVE al atacante, relaciona las CVEs entre sí y construye caminos de ataque candidatos.
3. Una **capa de IA** que valida o descarta esos caminos y explica por qué.
4. Una **criticidad real por equipo**, comparada con la nominal.
5. Un **informe exportable** (PDF/JSON) que se envía al responsable del equipo tras confirmación humana.

Fuera del alcance: acciones sobre Defender (aislar, escanear, etiquetar), análisis de puestos de trabajo, ingesta de alertas/incidentes, Exposure Management y cualquier envío automático sin confirmación.

## Principios de decisión

- **Solo lectura en Defender.** La app de Entra ID solo recibe permisos `*.Read.All`. El catálogo de acciones existente (`DefenderActionRequest`) sigue siendo un registro de planificación; esta entrega no lo ejecuta.
- **Determinista primero, IA después.** El grafo de caminos lo construye código verificable. La IA razona sobre caminos candidatos ya estructurados, nunca sobre la lista bruta de CVEs, y no puede introducir CVEs que no estén en la entrada.
- **La IA no decide sola la criticidad.** Ajusta el score determinista dentro de un margen acotado y siempre deja justificación. Si la IA no está disponible, el análisis se completa con el score determinista y el informe lo indica.
- **Ausencia de datos ≠ ausencia de riesgo.** Una CVE de Defender sin registro en ARGOS, sin vector CVSS o sin EPSS se marca como `unknown`; nunca puntúa como riesgo bajo.
- **Trazabilidad.** Cada análisis guarda la entrada exacta (hash), la versión de reglas, la versión del prompt y el modelo usado, para poder reproducir y auditar el resultado.
- **Privacidad.** Hostnames, IPs, usuarios y rutas se seudonimizan antes de enviarse a un LLM que no sea local.
- **Sin colapsar.** La ingesta se limita a servidores, respeta los límites de la API y corre en jobs de fondo; el análisis se lanza bajo demanda o en lotes acotados.

## Arquitectura

```
Defender API ──► DefenderConnector ──► TeamSystem + DeviceVulnerabilityFinding
                                                │
                    Vulnerability (ARGOS) ──────┤ enriquecimiento
                                                ▼
                                   AttackPathEngine (determinista)
                                                │ caminos candidatos + score
                                                ▼
                                   AttackPathAiReviewer (AiService)
                                                │ veredicto validado
                                                ▼
                                   DeviceRiskAssessment ──► DeviceRiskReportService ──► PDF/JSON ──► email al owner
```

Módulo nuevo: `src/modules/defender/` con `DefenderClient`, `DefenderSyncService`, `AttackPathEngine`, `AttackPathAiReviewer`, `DeviceRiskAssessmentService`, `DeviceRiskReportService` y su controlador. Reutiliza `PrismaService`, `AiService.chatStructuredJson`, el patrón Handlebars + Puppeteer de `ReportGeneratorService` y el transporte SMTP de `NotificationService`.

### 1. Conector de Defender

**Autenticación.** App de Entra ID con *client credentials*. API `WindowsDefenderATP` (se busca en "APIs my organization uses"). Permisos de aplicación:

| Permiso | Uso |
|---|---|
| `Machine.Read.All` | Inventario de equipos y filtro por tag |
| `Vulnerability.Read.All` | Vulnerabilidades por equipo y deltas |
| `Software.Read.All` | Inventario de software (contexto) |
| `SecurityRecommendation.Read.All` | KB/actualización recomendada |
| `AdvancedQuery.Read.All` | Contexto de exposición (fase 1b, opcional) |

Token: `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` con scope `https://api.securitycenter.microsoft.com/.default`. Microsoft documenta que algunas APIs devuelven 403 si la audiencia del token no es la legacy, así que se usa esta y no `api.security.microsoft.com`. El token (vida 1 h) se cachea en memoria y se renueva 5 minutos antes de caducar.

Base URL configurable, por defecto el endpoint regional `https://eu.api.security.microsoft.com`.

**Configuración.** `ApiConfiguration` con slug `defender`:

```json
{
  "tenantId": "…",
  "clientId": "…",
  "baseUrl": "https://eu.api.security.microsoft.com",
  "serverTags": ["server"],
  "serverOsPlatforms": [],
  "teamId": null,
  "autoSyncEnabled": false,
  "fullSyncIntervalHours": 168,
  "deltaSyncIntervalHours": 6,
  "requestsPerMinute": 40,
  "maxDevicesPerRun": 500,
  "staleDeviceDays": 30
}
```

El *client secret* va en `apiKeyEncrypted` **cifrado** con AES-256-GCM (utilidad común `src/common/secret-crypto.util.ts`, con su propia clave `DEFENDER_SECRET_KEY`), o por `DEFENDER_CLIENT_SECRET` en el entorno, que tiene prioridad. Nunca se devuelve por API ni aparece en logs. Hoy `apiKeyEncrypted` guarda en claro otros secretos (SMTP, IA); eso queda fuera de esta entrega pero se registra como deuda.

**Selección de equipos (servidores).**

```http
GET /api/machines?$filter=machineTags/any(t: t eq '{tag}')
```

Una llamada por tag configurado; los resultados se unen por `id`. Si `serverOsPlatforms` no está vacío, se añade un filtro por `osPlatform` (por ejemplo `WindowsServer2019`) como alternativa cuando los tags no están al día. Se descartan equipos con `onboardingStatus` distinto de `Onboarded` y con `lastSeen` de más de 30 días. No se usa `/api/machines/findbytag` porque exige `Machine.ReadWrite.All`.

Campos que se guardan: `id`, `computerDnsName`, `osPlatform`, `osVersion`, `machineTags`, `rbacGroupName`, `exposureLevel`, `riskScore`, `deviceValue`, `lastIpAddress`, `lastExternalIpAddress`, `healthStatus`, `onboardingStatus`, `lastSeen`.

**Vulnerabilidades por servidor.**

```http
GET /api/vulnerabilities/machinesVulnerabilities?$filter=machineId eq '{id}'
```

Paginado con `$skip`/`$top` (máx. 10.000). Devuelve CVE, producto, versión, fabricante, severidad y KB que lo corrige. El export masivo `SoftwareVulnerabilitiesByMachine` no se usa en la sincronización completa porque no admite filtro por equipo y traería todo el parque.

**Deltas.** `GET /api/machines/SoftwareVulnerabilityChangesByMachine?sinceTime=…` (máx. 14 días atrás). No se puede filtrar por equipo: se descarga y se descartan los `DeviceId` que no pertenecen a servidores sincronizados. Si el último delta correcto es de hace más de 13 días, se fuerza una sincronización completa. Los registros duplicados por cambio de grupo RBAC se deduplican por `Id` quedándose con el evento más reciente.

**Límites.** Limitador de tasa por endpoint (token bucket) configurado por debajo de los límites publicados: listado de equipos 100/min, vulnerabilidades por equipo 50/min, export/delta 30/min. Ante `429` se respeta `Retry-After`; ante `5xx`, hasta 3 reintentos con backoff exponencial. Con 40 llamadas/min, 200 servidores tardan unos 5 minutos.

**Persistencia del sync.**
- Cada servidor se guarda como `TeamSystem` con `source = 'defender'` y `externalId = machineId`, en el equipo de ARGOS configurado en `teamId` (o en el que ya lo tenga asignado). `rawData` guarda el objeto de Defender.
- Los servidores que dejan de aparecer pasan a `isActive = false`; no se borran.
- Las ejecuciones se registran en `DefenderSyncRun` (contadores propios: servidores, hallazgos, corregidos, fallidos, CVEs no catalogadas) y la salud en `CollectorSourceHealth` (`source = 'defender'`). `CollectorRun` no se reutiliza porque sus contadores son de CVEs.
- Un listado de equipos vacío no desactiva servidores (casi siempre es un filtro mal configurado).
- Este flujo sustituye al stub `syncSubscriberSystemsFromDefender` de `smart-notifications.service.ts`, que queda deprecado.

**Contexto de exposición (fase 1b, opcional).** Mediante Advanced Hunting (`POST /api/advancedqueries/run`), una consulta por lote de servidores:
- `DeviceInfo`: `IsInternetFacing`.
- `DeviceNetworkInfo`: interfaces e IPs.
- `DeviceTvmSecureConfigurationAssessment`: configuraciones inseguras relevantes (SMB v1, RDP sin NLA, LSA protection, Credential Guard, firewall).

Si no hay licencia o permiso, el contexto queda `unknown` y el análisis lo trata con supuestos explícitos (ver 3.4).

### 2. Modelo de datos

**`DeviceVulnerabilityFinding`** (una fila por equipo + CVE + software + versión):

| Campo | Uso |
|---|---|
| `teamSystemId` | FK a `TeamSystem` |
| `deviceExternalId` | `machineId` de Defender |
| `cveId`, `vulnerabilityId?` | CVE y FK opcional al registro de ARGOS |
| `productVendor`, `productName`, `productVersion` | Software afectado |
| `defenderSeverity`, `defenderCvss?`, `exploitabilityLevel?` | Lo que dice Defender |
| `fixingKbId?`, `recommendedUpdate?` | Remediación indicada por Defender |
| `diskPaths?`, `registryPaths?` | Evidencia (si viene del export/delta) |
| `status` | `open`, `fixed` |
| `firstSeenAt`, `lastSeenAt`, `fixedAt?` | Linaje |

Única: `[teamSystemId, cveId, productVendor, productName, productVersion]`. Índices por `cveId`, `teamSystemId + status`, `fixingKbId`.

Si la CVE no existe en `Vulnerability`, se encola su enriquecimiento con los collectors actuales (NVD/OSV/KEV/EPSS) y el hallazgo queda con `vulnerabilityId = null` hasta entonces.

**`DeviceExposureContext`** (1:1 con `TeamSystem`): `internetFacing` (`true`/`false`/`unknown`), `exposureLevel`, `deviceValue`, `assetCriticality` (manual en ARGOS, prevalece sobre `deviceValue`), `insecureConfigs` (JSON), `observedAt`.

**`DeviceRiskAssessment`** (una fila por análisis):

| Campo | Uso |
|---|---|
| `teamSystemId`, `requestedBy` | Equipo y usuario que lo lanza |
| `status` | `queued`, `running`, `completed`, `completed_without_ai`, `failed` |
| `nominalSeverity` | Peor severidad de Defender en el equipo |
| `deterministicScore`, `finalScore`, `finalTier` | Score antes y después de la IA |
| `verdict` | `exploitable_path`, `conditional_path`, `no_realistic_path`, `insufficient_data` |
| `findingsSnapshot` | Hallazgos usados (JSON) |
| `candidatePaths` | Salida del motor determinista (JSON) |
| `aiReview` | Salida validada de la IA (JSON) |
| `remediationPlan` | Acciones agrupadas por KB/actualización (JSON) |
| `inputHash`, `rulesVersion`, `promptVersion`, `aiModel` | Auditoría |
| `reportPath?`, `reportGeneratedAt?` | Informe generado |
| `startedAt`, `completedAt`, `error?` | Ejecución |

**`DeviceRiskReportDelivery`**: `assessmentId`, `recipientEmail`, `sentBy`, `sentAt`, `status`, `messageId`, `error?`. Registra cada envío.

### 3. Capa de estudio: correlación y caminos de ataque

`AttackPathEngine` es una función pura: recibe hallazgos enriquecidos + contexto de exposición y devuelve caminos candidatos y score. Sin acceso a BD ni a red, para poder probarla con fixtures.

#### 3.1 Enriquecimiento

Por hallazgo se reúne: CVSS v3.1/v4.0 (vector completo), KEV y fecha, EPSS y percentil, `hasPublicExploit`/`exploitStatus`, `ExploitabilityLevel` de Defender, CWE y `weaknessCategory`, `patchAvailable` y `remediationInfo`. Cuando ARGOS y Defender discrepan, prevalece la señal de explotación más fuerte y se guardan ambas.

#### 3.2 Capacidades: qué necesita y qué otorga cada CVE

Cada CVE se traduce a **precondición** (qué necesita el atacante) y **capacidad otorgada** (qué consigue). Reglas, por orden de prioridad:

| Señal | Precondición | Capacidad otorgada |
|---|---|---|
| `AV:N` + `PR:N` + `UI:N` | Alcance de red al servicio | `code_exec_user` o `code_exec_system` según impacto/CWE |
| `AV:N` + `UI:R` | Usuario que abre contenido o enlace | `code_exec_user` |
| `AV:N`/`AV:A` + `PR:L` | Credenciales válidas de usuario | Según impacto |
| `AV:L` + "Elevation of Privilege" / CWE-269, 250, 732 | `code_exec_user` | `code_exec_system` |
| Revelación de credenciales/hashes, CWE-522, 256, 312 | Según vector | `credential_access` |
| "Security Feature Bypass" | Según vector | `defense_evasion` (modificador, no paso final) |
| Impacto `C:N/I:N/A:H` únicamente | Según vector | `denial_of_service` (no avanza el camino) |
| `AV:P` | Acceso físico | Excluido salvo que se configure |

CWE de ejecución (78, 77, 94, 95, 502, 787, 416, 122) refuerzan `code_exec_*`. Si no hay vector CVSS, la CVE se clasifica como `unclassified` y se envía a la IA como hallazgo no estructurado, nunca como inexistente. Las reglas se versionan en `rulesVersion`.

#### 3.3 Relaciones entre CVEs

- **Causalidad (aristas del grafo).** A → B si la capacidad que otorga A satisface la precondición de B. Ejemplo: RCE remoto sin autenticación (`code_exec_user`) → elevación local (`AV:L/PR:L`) → `code_exec_system`.
- **Mismo componente.** Mismo `productVendor/productName` en el equipo: se presentan juntas y comparten remediación.
- **Misma remediación.** Mismo `fixingKbId` o actualización recomendada: permite calcular qué parche rompe más caminos.
- **Puntos de entrada.** Nodos raíz según la posición del atacante: `internet` (si el equipo está expuesto), `internal_network`, `authenticated_user`.

#### 3.4 Caminos candidatos

Se recorren los caminos desde cada punto de entrada hasta un objetivo (`code_exec_system`, `credential_access` o `code_exec_user` si no hay escalada), con profundidad máxima 4. Se conservan los **10 mejores** por score.

Supuestos explícitos cuando falta contexto:
- `internetFacing = unknown` → se evalúa desde `internal_network` y se marca el supuesto en el informe.
- Al limitarse a servidores, no se modelan saltos desde puestos de trabajo; el informe lo declara como limitación.

#### 3.5 Score determinista

Probabilidad de explotar cada paso:

| Señal | Peso |
|---|---|
| KEV | 1.0 |
| `ExploitIsInKit` / `ExploitIsVerified` | 0.9 |
| Exploit público / `ExploitIsPublic` | 0.7 |
| EPSS ≥ 0.1 | max(EPSS, 0.5) |
| Resto | max(EPSS, 0.1); `unknown` → 0.3 |

```
pathScore   = Π(peso de cada paso) × impactoFinal × exposición
deviceScore = max(pathScore) × criticidadActivo
```

- `impactoFinal`: `code_exec_system` 1.0, `credential_access` 0.9, `code_exec_user` 0.7.
- `exposición`: internet 1.0, red interna 0.6, requiere credenciales 0.4.
- `criticidadActivo`: alta 1.0, normal 0.8, baja 0.6.

Score a escala 0–100. Tramos: **Crítico real** ≥ 70, **Alto** ≥ 45, **Medio** ≥ 20, **Bajo** < 20. Sin caminos → máximo **Medio** si hay CVEs KEV/explotables aisladas, si no **Bajo**. Pesos y umbrales en configuración, versionados con `rulesVersion`.

### 4. Capa de IA

`AttackPathAiReviewer` usa `AiService.chatStructuredJson` con un prompt versionado (`promptVersion`).

**Entrada:** contexto del equipo (SO, exposición, criticidad, configuraciones inseguras), los 10 caminos candidatos con cada paso enriquecido, hallazgos `unclassified` (máx. 20, por riesgo) y los supuestos aplicados. Identificadores seudonimizados si el proveedor no es local.

**Salida (esquema fijo):**

```json
{
  "verdict": "exploitable_path | conditional_path | no_realistic_path | insufficient_data",
  "paths": [
    {
      "pathId": "p1",
      "assessment": "confirmed | plausible | refuted",
      "attackerPosition": "internet | internal_network | authenticated_user",
      "missingPreconditions": ["…"],
      "breakingMitigations": ["…"],
      "confidence": 0.0,
      "rationale": "…"
    }
  ],
  "unclassifiedPromotions": [{ "cveId": "…", "role": "…", "rationale": "…" }],
  "scoreAdjustment": 0,
  "executiveSummary": "…"
}
```

**Validación de la salida:**
- JSON válido según el esquema; si no, un reintento y después `completed_without_ai`.
- Todo `cveId` y `pathId` debe existir en la entrada; si no, se descarta ese elemento y se registra.
- `scoreAdjustment` se recorta a ±15 puntos. Un camino `refuted` solo baja el score si la IA da una mitigación o precondición concreta.
- La IA nunca puede bajar a **Bajo** un equipo con un paso KEV alcanzable desde internet.

**Modelo.** El modelo Ollama por defecto actual (`qwen2.5-32b-instruct:IQ1_M`) no es suficiente para este razonamiento. El análisis permite fijar un modelo propio en la configuración de Defender (`aiModel`) distinto del chat general. La elección del proveedor (local o cloud) queda pendiente de la política de datos.

### 5. Informe y envío

`DeviceRiskReportService` genera, con una plantilla Handlebars nueva (`device-risk-report.template.hbs`) y Puppeteer, un PDF en `VULN_REPORT_OUTPUT_DIR/device-risk/`.

Secciones:
1. **Resumen ejecutivo:** veredicto, criticidad real frente a nominal, número de CVEs frente a número de CVEs que forman parte de un camino real.
2. **Caminos de ataque:** diagrama por camino (pasos como cajas HTML/SVG: entrada → CVE → capacidad → objetivo), con la valoración de la IA y su justificación.
3. **Remediación priorizada:** acciones agrupadas por KB/actualización, ordenadas por caminos que rompen y score que eliminan.
4. **Supuestos y limitaciones:** contexto `unknown`, ámbito solo servidores, análisis sin IA si aplica.
5. **Anexo:** todos los hallazgos con señales (KEV, EPSS, exploit, KB).
6. **Metadatos:** fecha, `rulesVersion`, `promptVersion`, modelo e identificador del análisis.

Exportación también en JSON (el `DeviceRiskAssessment` proyectado) y CSV (anexo de hallazgos).

**Responsable del equipo.** Se resuelve por este orden: `TeamSystem → SubscriberTeam → NotificationRecipient` activos; si no hay, el tag de Defender con prefijo configurable (`owner:`); si no, se pide en la UI. El envío lo dispara una persona desde la UI tras previsualizar destinatarios; el PDF va adjunto y se registra en `DeviceRiskReportDelivery`. Los informes no se envían automáticamente.

## Contrato API

Todas bajo `/api/defender`, rol `ADMIN` salvo indicación. Implementado en la fase 1: `config`, `config/test`, `sync`, `sync/runs`, `devices` y `devices/:id/findings`.

| Método | Ruta | Uso |
|---|---|---|
| `GET`/`PUT` | `/config` | Configuración (sin secreto en la respuesta) |
| `POST` | `/config/test` | Prueba token + `GET /api/machines?$top=1` |
| `POST` | `/sync` | Lanza sync completo o delta (`{ mode }`), devuelve `runId` |
| `GET` | `/sync/runs` | Historial de ejecuciones |
| `GET` | `/devices` | Servidores sincronizados con resumen de riesgo |
| `GET` | `/devices/:id/findings` | Hallazgos del servidor |
| `POST` | `/devices/:id/assessments` | Lanza análisis, devuelve `assessmentId` |
| `GET` | `/assessments/:id` | Estado y resultado |
| `GET` | `/assessments/:id/report?format=pdf\|json\|csv` | Descarga |
| `POST` | `/assessments/:id/send` | Envía al responsable (`{ recipients[] }`) |

Más adelante (no en la fase 1, que es solo `ADMIN`), los miembros de un `SubscriberTeam` (rol `SUBSCRIBER`) podrán consultar dispositivos, hallazgos, análisis e informes de sus propios equipos mediante `TeamAccessService`.

## Ejecución en segundo plano

No hay cola instalada. El endpoint crea un `DefenderSyncRun` en `queued` y lanza el worker; un cron de `@nestjs/schedule` (cada minuto) recoge lo pendiente y otro (cada 10 minutos) programa los syncs automáticos según los intervalos. La toma del run es atómica en BD (`queued → running`), solo se admite un sync pendiente a la vez y los runs en `running` más de 4 h se marcan como abandonados. Los análisis se procesan de 2 en 2 como máximo. Si más adelante el volumen lo pide, se puede migrar a BullMQ sobre el Redis ya desplegado.

## Frontend

- **Ajustes → Defender:** configuración, tags, prueba de conexión, historial de sync.
- **Servidores:** tabla con criticidad nominal frente a real, último análisis y botón "Analizar".
- **Detalle de servidor:** hallazgos, caminos de ataque, remediación, descarga e "Enviar al responsable".

Se usa el design system ARGOS existente (`ds-tokens.css`).

## Manejo de errores y seguridad

- Defender no configurado o con credenciales inválidas → `CollectorSourceHealth` en error; la UI lo muestra, no lista "0 vulnerabilidades".
- Fallo parcial del sync (algunos servidores) → la ejecución termina `partial` con la lista de fallidos; los datos previos de esos servidores no se marcan como corregidos.
- IA caída o salida inválida → `completed_without_ai`, informe con score determinista.
- Los textos que vienen de Defender o de la IA se escapan en el HTML del informe (Handlebars `{{ }}`, nunca `{{{ }}}`).
- La salida de la IA no se interpreta como instrucciones ni se usa para construir consultas.
- Logs sin secretos ni tokens.

## Fases de entrega

1. **Conector + ingesta:** app de Entra, `DefenderClient` (token, rate limit, reintentos), sync completo y delta de servidores por tag, `DeviceVulnerabilityFinding`, endpoints de config/sync/devices/findings y pantallas de ajustes y servidores. Sustituye al stub.
2. **Motor determinista:** clasificación, grafo, caminos, score y plan de remediación por KB; `DeviceRiskAssessment` sin IA.
3. **Capa de IA:** prompt versionado, validación, seudonimización, ajuste acotado.
4. **Informe y envío:** plantilla PDF, exportación JSON/CSV, resolución del responsable, envío con confirmación.

1b (contexto de exposición vía Advanced Hunting) se puede intercalar tras la fase 2 si hay permiso y licencia.

## Pruebas y criterios de aceptación

- `DefenderClient`: token cacheado y renovado; `429` con `Retry-After`; paginación; el secreto nunca sale en respuesta ni log (tests con mocks HTTP).
- Sync: solo entran equipos con los tags configurados; los que desaparecen pasan a inactivos; el delta descarta equipos no sincronizados y deduplica movimientos RBAC.
- `AttackPathEngine` (tests con fixtures):
  - RCE de red sin auth + elevación local → camino `code_exec_system`.
  - Solo elevaciones locales → sin camino desde red; score limitado.
  - CVE sin vector → `unclassified`, no puntúa como bajo.
  - KEV alcanzable desde internet → nunca por debajo de Alto.
  - Mismo KB en varias CVEs → una acción de remediación que rompe todos sus caminos.
- Revisor IA: rechaza CVEs inventadas, recorta el ajuste a ±15, cae a `completed_without_ai` con JSON inválido.
- Informe: genera PDF con todas las secciones; escapa contenido; el envío solo ocurre tras `POST /send` y queda registrado.
- Rendimiento: sync de 200 servidores sin superar los límites de la API; análisis de un servidor con 300 hallazgos en menos de 2 minutos (sin contar la IA).

## Decisiones pendientes

- **Licencia:** las APIs de vulnerabilidades requieren MDE Plan 2 o Defender Vulnerability Management; Advanced Hunting no está en Defender for Business.
- **Proveedor y modelo de IA** permitidos con estos datos (local o cloud).
- **Tags reales** que marcan servidores en el tenant y si basta con ellos o se combina con `osPlatform`.
- **Origen del responsable** de cada servidor (equipo ARGOS, tag de Defender o grupo RBAC).
- **Registro de la app en Entra ID:** quién la crea y si se usa secreto o certificado.

## Entregas posteriores, fuera del alcance

- Puestos de trabajo y caminos de movimiento lateral entre equipos.
- Integración con Microsoft Security Exposure Management (`ExposureGraphNodes/Edges`) para contrastar caminos.
- Ejecución de acciones en Defender desde `DefenderActionRequest`.
- Reanálisis automático cuando llega un delta o una CVE pasa a KEV.
- Cifrado de los secretos que hoy se guardan en claro en `ApiConfiguration`.
