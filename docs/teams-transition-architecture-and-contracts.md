# Arquitectura y Contratos de Transición: SubscriberTeam e Idempotencia (Fase 0 y Fase 1)

Este documento recoge los contratos técnicos, la auditoría empírica del esquema Prisma y los modelos de dominio para la adopción de `SubscriberTeam` como titular operativo en ARGOS.

---

## 1. Auditoría Empírica del Esquema y Desviaciones Observadas

A continuación se documentan los hechos comprobados en el código y el esquema actual (`prisma/schema.prisma`), registrando explícitamente cualquier desviación respecto a asunciones previas:

### A. Modelo `UserSubscription` (`schema.prisma:434`)
- **Campos verificados**: `id`, `user_id`, `vendor`, `product`, `versions`, `is_active`, `created_at`, `updated_at`.
- **Restricción única**: `@@unique([userId, vendor, product])` en `schema.prisma:445`.
- **Formato de versiones**: `versions` es un campo `String? @db.Text`. En el código de negocio ([`vulnerability-collector.service.ts:1071`](file:///Users/sansano/programacion/GitHub/ARGOS/src/modules/vulnerability-collector/vulnerability-collector.service.ts#L1071)), se deserializa mediante `JSON.parse` como un array de strings. Si el texto en base de datos es `null` o no es un JSON válido, debe tratarse defensivamente.

### B. Modelo `VulnerabilityNotification` (`schema.prisma:454`)
- **Campos verificados**: `id`, `vulnerability_id`, `contact_id`, `subscriber_user_id`, `recipient_email`, `recipient_name`, `sent_at`, `status`, `notification_log_id`.
- **Desviación detectada respecto a `notification_log_id`**:
  - `[HECHO]` La columna `notification_log_id` existe como tipo `Int?` en `schema.prisma:464`.
  - `[DESVIACIÓN]` **No tiene relación foránea `@relation` declarada en Prisma con el modelo `NotificationLog`**. Es un entero escalar desacoplado. En `schema.prisma:466-468` solo existen relaciones formales con `vulnerability` y `subscriberUser`.
- **Representación de `status = sent`**:
  - `[HECHO]` El campo `status` es de tipo `String` con valor por defecto `@default("sent")` (`schema.prisma:463`). En el recolector ([`vulnerability-collector.service.ts:1197`](file:///Users/sansano/programacion/GitHub/ARGOS/src/modules/vulnerability-collector/vulnerability-collector.service.ts#L1197)) se almacena `'sent'` o `'failed'`.
- **Múltiples filas históricas para la misma vulnerabilidad por usuario**:
  - `[HECHO]` **SÍ es posible**. En `schema.prisma:470-474` no existe ningún índice único sobre `(vulnerability_id, subscriber_user_id)`. Por tanto, un usuario puede tener 2 o más registros para el mismo CVE (por ejemplo, reintentos o ejecuciones repetidas).

---

## 2. Contratos de Dominio Puros (TypeScript)

Los contratos están implementados en `src/modules/subscriber-teams/contracts/`:

### A. `TeamVulnerabilityAssessmentContract`
Define el estado de afectación consolidado de un equipo ante un CVE:
- **`primaryTrigger`**: `'CONFIRMED_ASSET'` (evidencia SBOM/inventario) o `'SUBSCRIPTION_WATCH'` (regla de vigilancia vendor/product).
- **Consolidación Multi-Activo**: Agrupa en `confirmedAssets` todos los servidores/activos del equipo afectados por el mismo CVE, evitando correos duplicados.
- **`computeEvidenceFingerprint(...)`**: Genera un hash SHA-256 determinista insensible al orden de activos o reglas.
- **`evaluateEvidenceEscalation(previous, current)`**: Evalúa de forma pura si el cambio en la evidencia amerita una renotificación inmediata (`SEVERITY_ESCALATION`, `NEW_CRITICAL_ASSET`, `REMEDIATION_AVAILABLE`) o si debe silenciarse (`NONE`).

### B. `NotificationDeliveryContract`
Define el intento operativo de entrega:
- **`calculateDeliveryIdempotencyKey(...)`**:
  $$\text{idempotencyKey} = \text{SHA256}(\text{teamId} + \text{":"} + \text{vulnerabilityId} + \text{":"} + \text{revision} + \text{":"} + \text{deliveryChannel} + \text{":"} + \text{dispatchPriority})$$
- **`resolvePendingRecipients(...)`**: Permite reintentos selectivos ante fallos parciales de entrega (`PARTIALLY_DELIVERED`) sin reenviar a los destinatarios que ya recibieron el correo con éxito.

### C. `UserMigrationCandidate` y `MigrationAnalysisReport`
Estructuras para el análisis en modo lectura (`--dry-run`) de la migración de suscriptores a equipos.

---

## 3. Arquitectura de Tres Capas

```text
1. TeamVulnerabilityAlert (Afectacion)
   - Clave unica: UQ(team_id, vulnerability_id)
   - Contiene: current_revision, evidence_fingerprint, status

2. NotificationDelivery (Intento de entrega)
   - Clave unica: UQ(idempotency_key)
   - Contiene: status (PREPARED, SENT, PARTIALLY_DELIVERED, FAILED)

3. NotificationLog (Transporte SMTP)
   - Registro fisico de cada correo emitido por Nodemailer hacia cada buzon.
```

---

## 4. Puente Histórico y Prevención de Duplicados en Cutover

Para que el corte a `TEAMS` no reenvíe correos históricos:
1. Todo usuario suscriptor con membresía resuelta mapea a un `targetTeamId`.
2. Las alertas de `vulnerability_notifications` con `status = 'sent'` se backfillean en `TeamVulnerabilityAlert` (revisión 1) y `NotificationDelivery` (`status = 'SENT'`).
3. El primer ciclo `TEAMS` comprueba la existencia de la alerta en revisión 1. Al no existir escalada de evidencia, **omite el envío sin generar tráfico SMTP**.
