# Prisma Migration Baseline — argos

## Contexto

El proyecto se creó originalmente usando `prisma db push`, que sincroniza el esquema directamente sin generar historial de migraciones. Para adoptar `prisma migrate` como flujo de producción se necesita una migración baseline que represente el estado inicial de la DB.

## Estructura de migraciones

| Migración | Descripción |
|-----------|-------------|
| `20260320000000_initial_schema_baseline` | **Baseline**: esquema original vía db push |
| `20260321160000_auth_provider_mfa` | Añade auth_provider, external_id, MFA a users |
| `20260321193000_local_signup_requests` | Crea tabla local_signup_requests |
| `20260321195000_user_auth_and_local_signup` | No-op (ya aplicado) |
| `20260323000000_add_cvss_v40_and_cwe_fields` | Añade CVSS v4.0, CWE a vulnerabilities |
| `20260323200000_notification_policy_3_levels` | Añade periodic_* y smart_* a notification_policies |
| `20260324143000_notification_center_rework` | Rework notificaciones: immediate_*, digest_*, intelligent_* |
| `20260324190000_intelligent_notifications_runtime` | Tablas de notificaciones inteligentes |
| `20260325091500_align_notification_policy_exclusion_mappings` | No-op (corrección Prisma @map) |
| `20260402160000_api_keys_table` | Crea tabla api_keys |
| `20260405120000_add_is_notificable` | Añade is_notificable a vulnerabilities |

## Qué incluye la baseline

### Tablas creadas (27 + 1 join M2M)

- `users` (sin: auth_provider, external_id, mfa_*, last_login_at, can_receive_notifications, notifications_paused*, last_notification_sent_at, communication_language)
- `user_sessions`
- `login_attempts`
- `password_resets`
- `vulnerabilities` (sin: cvss_v40_*, cvss_version, cwe_ids, cwe_names, weakness_category, is_notificable)
- `vulnerability_change_events`
- `vulnerability_source_records`
- `collector_source_health`
- `collector_runs`
- `product_assets`
- `dependency_evidence_imports`
- `product_dependency_inventory`
- `vulnerability_product_impacts`
- `vulnerability_reports`
- `api_configurations`
- `notification_logs` (sin: notification_type, template_key, channel, vulnerability_count, trigger_reason, error_message, metadata_json)
- `vulnerability_tags`
- `_VulnerabilityToVulnerabilityTag` (join M2M implícita Prisma)
- `vulnerability_notifications`
- `software_catalog`
- `manufacturers`
- `user_subscriptions`
- `subscriber_owned_systems`
- `defender_action_requests`
- `subscriber_patched_cves`
- `smart_notification_reports`
- `notification_policies` (sólo: immediate_for_critical, immediate_for_exploitable, min_cvss_for_immediate, digest_frequency, digest_hour, digest_day_of_week, is_active)
- `pending_digest_notifications`

### Tablas excluidas (creadas por migraciones posteriores)

- `local_signup_requests`
- `notification_job_runs`
- `intelligent_notification_findings`
- `intelligent_notification_subscriber_matches`
- `intelligent_notification_test_runs`
- `api_keys`

## Correcciones aplicadas

### Identificadores MySQL > 64 chars (error 1059)

MySQL limita los nombres de identificadores a 64 bytes. Dos nombres generados automáticamente superaban el límite:

| Archivo | Identificador original (truncado) | Nuevo nombre |
|---------|----------------------------------|--------------|
| `20260320000000.../migration.sql` | `vulnerability_product_impacts_vulnerability_id_product_asset_id_dependency_inventory_id_key` (91 chars) | `vpi_vuln_product_dep_unique` |
| `20260324190000.../migration.sql` | `intelligent_notification_subscriber_matches_subscriber_user_id_idx` (66 chars) | `insm_subscriber_user_id_idx` |
| `20260324190000.../migration.sql` | `intelligent_notification_subscriber_matches_subscriber_user_id_fkey` (67 chars) | `insm_subscriber_user_id_fkey` |

Estos cambios son puramente de nombre; la semántica (columnas referenciadas, ON DELETE/UPDATE) es idéntica.

## Flujo para DB nueva

```bash
# Aplicar todas las migraciones sobre DB vacía
DATABASE_URL="mysql://user:pass@host:3306/dbname" npx prisma migrate deploy

# Verificar estado
DATABASE_URL="mysql://user:pass@host:3306/dbname" npx prisma migrate status
```

## Flujo para DB existente (creada con db push)

Si la DB ya existe con el esquema completo, marca la baseline como aplicada sin ejecutarla:

```bash
npx prisma migrate resolve --applied 20260320000000_initial_schema_baseline
npx prisma migrate deploy
```

## Test sobre MySQL efímero

```bash
bash scripts/test-prisma-migrate-empty-db.sh
```

El script levanta MySQL 8.0 en Docker (puerto 3399), aplica las 11 migraciones, verifica el estado y destruye el contenedor al terminar.

## Riesgos pendientes

| Riesgo | Mitigación |
|--------|------------|
| DB de producción creada vía `db push` necesita `migrate resolve` manual | Documentado arriba |
| Advertencia Prisma `package.json#prisma` deprecated → Prisma 7 | Migrar a `prisma.config.ts` antes de actualizar a v7 |
| Columna `contact_id` en `vulnerability_notifications` sin FK (tabla it_contacts eliminada) | Columna legacy, solo lectura histórica |
