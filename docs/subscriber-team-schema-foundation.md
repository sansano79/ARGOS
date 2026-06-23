# Schema foundation: suscriptores como equipos — Fase 1A

**Issue:** GitHub #5 — Rediseñar suscriptores como equipos con miembros y notificadores  
**Rama:** `feature/mejoras-v1.1`  
**Migración:** `20260623000000_add_subscriber_teams`  
**Fase:** 1A — modelos Prisma aditivos, migración SQL, validaciones

---

## Alcance de esta fase

Introduce cinco tablas nuevas sin modificar ni eliminar ninguna tabla legacy.
No incluye controladores, servicios, guards, endpoints ni cambios en el motor de notificaciones.

---

## Modelos añadidos

### `SubscriberTeam` → `subscriber_teams`

Unidad organizativa suscriptora. Sustituye progresivamente el papel del `User` con `isSubscriber=true`.

| Campo | Tipo | Notas |
|-------|------|-------|
| `id` | `Int PK autoincrement` | |
| `name` | `String` | Nombre visible del equipo |
| `code` | `String @unique` | Identificador corto; slug corporativo |
| `description` | `String? @db.Text` | |
| `isActive` | `Boolean default(true)` | Soft delete |
| `createdAt` / `updatedAt` | `DateTime` | |

Relaciones: `TeamMember[]`, `NotificationRecipient[]`, `TeamSubscription[]`, `TeamSystem[]`

---

### `TeamMember` → `team_members`

Relación `User ↔ SubscriberTeam` con rol de equipo.

| Campo | Tipo | Notas |
|-------|------|-------|
| `teamId` | `Int FK → subscriber_teams` | CASCADE delete |
| `userId` | `Int FK → users` | CASCADE delete |
| `role` | `String` | `"TEAM_MANAGER"` \| `"TEAM_VIEWER"` |
| `isActive` | `Boolean default(true)` | Revocación inmediata sin borrar fila |

Restricción única: `(teamId, userId)` — un usuario no puede tener dos roles distintos en el mismo equipo.

---

### `NotificationRecipient` → `notification_recipients`

Destinatario de correo sin obligación de tener cuenta de login.

| Campo | Tipo | Notas |
|-------|------|-------|
| `teamId` | `Int FK → subscriber_teams` | CASCADE delete |
| `email` | `String` | |
| `type` | `String default("MAILBOX")` | `USER` \| `MAILBOX` \| `DISTRIBUTION_LIST` \| `EXTERNAL_CONTACT` |
| `language` / `timezone` | `String` | Preferencias de entrega |
| `verifiedAt` | `DateTime?` | Para doble opt-in futuro |

Restricción única: `(teamId, email)` — sin duplicados por equipo.

---

### `TeamSubscription` → `team_subscriptions`

Suscripción vendor/product propiedad del equipo (equivalente a `UserSubscription` para individuos).

Restricción única: `(teamId, vendor, product)`.

---

### `TeamSystem` → `team_systems`

Sistema o unidad propiedad del equipo. Conserva todos los campos ricos de `SubscriberOwnedSystem`
(`hostname`, `fqdn`, `platform`, `osVersion`, `riskLevel`, `rawData`) para no degradar
el motor de notificaciones inteligentes en fases posteriores.

Restricción única: `(teamId, externalId)` — MySQL permite múltiples NULL en columnas de clave única.

---

## Cambio en `User`

Única modificación aditiva sobre modelos existentes:

```prisma
teamMemberships TeamMember[]
```

Sin eliminar ni modificar ningún campo legacy (`isSubscriber`, `notificationEmail`, etc.).

---

## Migración SQL

Archivo: `prisma/migrations/20260623000000_add_subscriber_teams/migration.sql`

- Cinco `CREATE TABLE` en orden de dependencia: `subscriber_teams` primero, luego las que la referencian.
- FK con `ON DELETE CASCADE ON UPDATE CASCADE` hacia `subscriber_teams` e `users`.
- Todos los identificadores MySQL ≤ 46 caracteres (límite de 64 bytes de MySQL).
- Compatible con `prisma migrate deploy` tanto en base vacía como en base con migraciones previas.

---

## Validaciones ejecutadas

| Escenario | Resultado |
|-----------|-----------|
| `prisma validate` | Schema válido |
| MySQL vacío + `prisma migrate deploy` (12 migraciones) | 40 tablas creadas, 5/5 tablas nuevas ✓ |
| MySQL con 11 migraciones previas + `prisma migrate deploy` | Solo migración 12 aplicada, datos legacy intactos ✓ |

Scripts: `scripts/test-prisma-migrate-empty-db.sh` y `scripts/test-prisma-migrate-existing-db.sh`

---

## Tablas legacy no modificadas

`users`, `user_subscriptions`, `subscriber_owned_systems`, `notification_policies`,
`vulnerability_notifications`, `pending_digest_notifications`, `subscriber_patched_cves`,
`smart_notification_reports`, `intelligent_notification_subscriber_matches`,
`defender_action_requests`

---

## Rollback

```sql
DROP TABLE IF EXISTS team_systems;
DROP TABLE IF EXISTS team_subscriptions;
DROP TABLE IF EXISTS notification_recipients;
DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS subscriber_teams;
```

El rollback no afecta ninguna tabla legacy.

---

## Siguiente fase

Fase 1B: módulo NestJS `SubscriberTeamsModule`, DTOs, `TeamAccessService`, `TeamRoleGuard`,
endpoints admin `/api/admin/teams` y `GET /api/me/teams`.
