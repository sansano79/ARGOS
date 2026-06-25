# Subscriber Teams — Backend API (Fase 1B)

**Issue:** GitHub #5 — Rediseñar suscriptores como equipos con miembros y notificadores
**Rama:** `feature/mejoras-v1.1`
**Fase:** 1B — módulo NestJS, DTOs, servicios, endpoints, tests
**Estado:** Revisión de seguridad completada

---

## Arquitectura del módulo

```
src/modules/subscriber-teams/
├── constants/team-roles.ts           TEAM_MANAGER | TEAM_VIEWER
├── dto/
│   ├── create-team.dto.ts
│   ├── update-team.dto.ts
│   ├── add-member.dto.ts
│   ├── update-member.dto.ts
│   ├── create-recipient.dto.ts
│   ├── update-recipient.dto.ts
│   ├── create-subscription.dto.ts
│   ├── update-subscription.dto.ts    ← PATCH subscriptions
│   ├── create-system.dto.ts
│   └── update-system.dto.ts
├── team-access.service.ts            barrera centralizada de autorización
├── team-access.service.spec.ts
├── subscriber-teams.service.ts       CRUD + normalización
├── subscriber-teams.service.spec.ts
├── subscriber-teams.controller.ts    endpoints admin (ADMIN)
├── subscriber-teams.controller.spec.ts
├── team-portal.controller.ts         endpoints portal (miembros)
├── team-portal.controller.spec.ts
└── subscriber-teams.module.ts
```

`SubscriberTeamsModule` registrado en `AppModule`. Importa `PrismaModule`. Exporta `TeamAccessService`.

---

## Política anti-IDOR

Todos los recursos hijos se validan con `id + teamId` en la misma consulta:

```typescript
// CORRECTO — una sola consulta
await prisma.teamSystem.findFirst({ where: { id: systemId, teamId } })

// INCORRECTO — nunca se usa este patrón
await prisma.teamSystem.findUnique({ where: { id: systemId } })
// luego verificar teamId en memoria → vulnerable a IDOR
```

Recursos protegidos: `memberId`, `recipientId`, `subscriptionId`, `systemId`.

---

## Política de acceso

### TeamAccessService

| Método | Comportamiento |
|--------|---------------|
| `assertAdmin(user)` | 403 si `role !== 'ADMIN'` |
| `assertTeamReadable(userId, teamId)` | 404 si no hay membresía activa O equipo inactivo |
| `assertTeamWritable(userId, teamId)` | 404 si no es miembro activo del equipo activo; 403 si es miembro pero no MANAGER |
| `getAccessibleTeams(userId)` | Solo equipos activos con membresía activa; incluye flags de permisos |
| `getTeamForMember(userId, teamId)` | Detalle del equipo con role y flags de permisos |
| `assertResourceBelongsToTeam(resource, id, teamId)` | 404 si recurso no pertenece al equipo |

### Diseño de 404 vs 403

- No-miembro intenta acceder a equipo → **404** (no revela existencia del equipo)
- Miembro con rol insuficiente intenta escribir → **403** (usuario ya sabe que el equipo existe)
- Equipo inactivo → **404** desde portal (admin puede seguir accediendo)

---

## Matriz de permisos

| Acción | ADMIN | TEAM_MANAGER | TEAM_VIEWER |
|--------|-------|--------------|-------------|
| Crear/listar/modificar equipos | ✓ | — | — |
| Gestionar miembros | ✓ | — | — |
| Ver miembros del propio equipo | ✓ | — | — |
| `GET /me/teams` | — | ✓ | ✓ |
| `GET /teams/:teamId` | — | ✓ | ✓ |
| Leer suscripciones | ✓ | ✓ | ✓ |
| Escribir suscripciones | ✓ | ✓ | — |
| Leer sistemas | ✓ | ✓ | ✓ |
| Escribir sistemas | ✓ | ✓ | — |
| Leer destinatarios | ✓ | ✓ | ✓ |
| Escribir destinatarios | ✓ | ✓ | — |
| Acceder equipo inactivo | ✓ | — | — |

---

## Endpoints administrativos

Base path: `/api/subscriber-teams` · Requiere: `JwtAuthGuard + RolesGuard + @Roles('ADMIN')`

### Equipos

| Método | Path | Descripción |
|--------|------|-------------|
| `GET` | `/subscriber-teams` | Lista todos los equipos (con conteo de miembros activos) |
| `POST` | `/subscriber-teams` | Crea un equipo |
| `GET` | `/subscriber-teams/:teamId` | Detalle del equipo con miembros activos |
| `PATCH` | `/subscriber-teams/:teamId` | Actualiza campos del equipo |

### Miembros

| Método | Path | Descripción |
|--------|------|-------------|
| `GET` | `/subscriber-teams/:teamId/members` | Lista miembros (activos e inactivos) |
| `POST` | `/subscriber-teams/:teamId/members` | Añade usuario como miembro con rol |
| `PATCH` | `/subscriber-teams/:teamId/members/:memberId` | Cambia rol o activa/desactiva membresía |
| `DELETE` | `/subscriber-teams/:teamId/members/:memberId` | Elimina membresía permanentemente |

### Destinatarios

| Método | Path | Descripción |
|--------|------|-------------|
| `GET` | `/subscriber-teams/:teamId/recipients` | Lista destinatarios |
| `POST` | `/subscriber-teams/:teamId/recipients` | Crea destinatario |
| `PATCH` | `/subscriber-teams/:teamId/recipients/:recipientId` | Actualiza destinatario |
| `DELETE` | `/subscriber-teams/:teamId/recipients/:recipientId` | Elimina destinatario |

### Suscripciones

| Método | Path | Descripción |
|--------|------|-------------|
| `GET` | `/subscriber-teams/:teamId/subscriptions` | Lista suscripciones |
| `POST` | `/subscriber-teams/:teamId/subscriptions` | Crea suscripción |
| `PATCH` | `/subscriber-teams/:teamId/subscriptions/:subscriptionId` | Actualiza versiones/isActive |
| `DELETE` | `/subscriber-teams/:teamId/subscriptions/:subscriptionId` | Elimina suscripción |

### Sistemas

| Método | Path | Descripción |
|--------|------|-------------|
| `GET` | `/subscriber-teams/:teamId/systems` | Lista sistemas (sin rawData) |
| `POST` | `/subscriber-teams/:teamId/systems` | Registra sistema |
| `PATCH` | `/subscriber-teams/:teamId/systems/:systemId` | Actualiza sistema |
| `DELETE` | `/subscriber-teams/:teamId/systems/:systemId` | Elimina sistema |

---

## Endpoints de portal (miembros del equipo)

Base path: `/api` · Requiere: `JwtAuthGuard` · Autorización: `TeamAccessService`

| Método | Path | Requiere | Descripción |
|--------|------|----------|-------------|
| `GET` | `/me/teams` | activo | Equipos del usuario con role y flags de permisos |
| `GET` | `/teams/:teamId` | read | Detalle del equipo con role y flags |
| `GET` | `/teams/:teamId/subscriptions` | read | Lee suscripciones del equipo |
| `POST` | `/teams/:teamId/subscriptions` | write | Crea suscripción |
| `PATCH` | `/teams/:teamId/subscriptions/:subscriptionId` | write | Actualiza suscripción |
| `DELETE` | `/teams/:teamId/subscriptions/:subscriptionId` | write | Elimina suscripción |
| `GET` | `/teams/:teamId/systems` | read | Lista sistemas (sin rawData) |
| `POST` | `/teams/:teamId/systems` | write | Registra sistema |
| `PATCH` | `/teams/:teamId/systems/:systemId` | write | Actualiza sistema |
| `DELETE` | `/teams/:teamId/systems/:systemId` | write | Elimina sistema |
| `GET` | `/teams/:teamId/recipients` | read | Lista destinatarios |
| `POST` | `/teams/:teamId/recipients` | write | Crea destinatario |
| `PATCH` | `/teams/:teamId/recipients/:recipientId` | write | Actualiza destinatario |
| `DELETE` | `/teams/:teamId/recipients/:recipientId` | write | Elimina destinatario |

> **read** = membresía activa (cualquier rol) en equipo activo · **write** = TEAM_MANAGER en equipo activo

---

## Respuesta de `/me/teams`

```json
[
  {
    "id": 1,
    "name": "Equipo Alpha",
    "code": "alpha",
    "description": "Equipo de infraestructura",
    "isActive": true,
    "role": "TEAM_MANAGER",
    "canRead": true,
    "canManageSubscriptions": true,
    "canManageSystems": true,
    "canManageRecipients": true,
    "createdAt": "2026-06-23T00:00:00.000Z",
    "updatedAt": "2026-06-23T00:00:00.000Z"
  }
]
```

---

## DTOs definitivos

| Clase | Campos obligatorios | Campos opcionales | Notas |
|-------|--------------------|--------------------|-------|
| `CreateTeamDto` | `name`, `code` | `description`, `isActive` | `code` normalizado a minúsculas |
| `UpdateTeamDto` | — | `name`, `code`, `description`, `isActive` | Todos opcionales |
| `AddMemberDto` | `userId` (Int+), `role` | — | `role` ∈ {TEAM_MANAGER, TEAM_VIEWER} |
| `UpdateMemberDto` | — | `role`, `isActive` | Para revocar: `isActive: false` |
| `CreateRecipientDto` | `email` (IsEmail) | `name`, `type`, `language`, `timezone`, `isActive` | `type` ∈ {USER, MAILBOX, DISTRIBUTION_LIST, EXTERNAL_CONTACT} |
| `UpdateRecipientDto` | — | mismos que create | `verifiedAt` no aceptado |
| `CreateSubscriptionDto` | `vendor`, `product` | `versions` (string[]), `isActive` | Normalizados a minúsculas |
| `UpdateSubscriptionDto` | — | `vendor`, `product`, `versions`, `isActive` | `teamId` no aceptado |
| `CreateSystemDto` | `name` | `externalId`, `source`, `description`, `hostname`, `fqdn`, `platform`, `osVersion`, `riskLevel`, `isSelected`, `isActive` | `rawData` no aceptado |
| `UpdateSystemDto` | — | mismos que create | |

**Nota:** `teamId`, `userId` e IDs internos no son aceptados desde el cuerpo de la petición. `verifiedAt` y `rawData` no son aceptados desde el cliente. `ValidationPipe(whitelist:true, forbidNonWhitelisted:true)` rechaza campos desconocidos con 400.

---

## Normalización backend

| Campo | Normalización |
|-------|--------------|
| `email` | `trim() + toLowerCase()` antes de persistir |
| `team.code` | `trim() + toLowerCase()` |
| `team.name` | `trim()` |
| `system.hostname` | `trim() + toLowerCase()` |
| `system.fqdn` | `trim() + toLowerCase()` |
| `system.name` | `trim()` |
| `subscription.vendor` | `trim() + toLowerCase()` |
| `subscription.product` | `trim() + toLowerCase()` |

---

## Mapeo de errores Prisma

| Código | HTTP | Descripción |
|--------|------|-------------|
| `P2002` | 409 Conflict | Violación de restricción única (code duplicado, email duplicado en equipo, etc.) |
| `P2003` | 400 Bad Request | FK inválida (userId inexistente, etc.) |
| `P2025` | 404 Not Found | Registro no encontrado en operación de escritura |
| Otros | Re-throw | No se filtran al cliente; NestJS los convierte a 500 sin detalles internos |

---

## Campos excluidos de listados

`findSystems` y `getSystems` excluyen `rawData` (campo `LONGTEXT`) de los listados para evitar payloads grandes. Si se necesita el campo, añadir un endpoint `GET /teams/:teamId/systems/:systemId` en fase posterior.

---

## Compatibilidad legacy

- No se modifican: `users`, `user_subscriptions`, `subscriber_owned_systems`, `notification_policies`, ni ninguna otra tabla legacy.
- No se modifica `SubscriberPortalModule`, `SubscriberPortalService`, ni el motor de notificaciones.
- Los campos legacy de `User` (`isSubscriber`, `notificationEmail`, etc.) permanecen intactos.

---

## Ejemplos de petición/respuesta

### POST /api/subscriber-teams

```http
POST /api/subscriber-teams
Authorization: Bearer <admin-jwt>
Content-Type: application/json

{ "name": "Equipo Alpha", "code": "alpha" }
```

```json
{ "id": 1, "name": "Equipo Alpha", "code": "alpha", "description": null, "isActive": true, "createdAt": "...", "updatedAt": "..." }
```

### POST /api/subscriber-teams/1/members

```http
POST /api/subscriber-teams/1/members
Authorization: Bearer <admin-jwt>

{ "userId": 42, "role": "TEAM_MANAGER" }
```

```json
{ "id": 10, "role": "TEAM_MANAGER", "isActive": true, "createdAt": "...", "user": { "id": 42, "email": "mgr@example.com", "name": "Manager" } }
```

### POST /api/teams/1/subscriptions (portal, TEAM_MANAGER)

```http
POST /api/teams/1/subscriptions
Authorization: Bearer <member-jwt>

{ "vendor": "Microsoft", "product": "Windows Server", "versions": ["2022"] }
```

```json
{ "id": 5, "teamId": 1, "vendor": "microsoft", "product": "windows server", "versions": "[\"2022\"]", "isActive": true, "createdAt": "..." }
```

---

## Tests

**203 tests totales (5 suites nuevas en subscriber-teams)**

| Suite | Tests |
|-------|-------|
| `team-access.service.spec.ts` | 24 |
| `subscriber-teams.service.spec.ts` | 43 |
| `subscriber-teams.controller.spec.ts` | 22 |
| `team-portal.controller.spec.ts` | 45 |
| `dto/subscriber-teams-dto.spec.ts` | 45 |
| **Total subscriber-teams** | **179** |

Cobertura incluye: ADMIN CRUD completo, TEAM_MANAGER lectura+escritura, TEAM_VIEWER solo lectura,
prevención de IDOR en 4 tipos de recursos, equipos inactivos bloqueados desde portal, miembros
inactivos bloqueados, mapeo de errores Prisma P2002/P2003/P2025, normalización de campos,
verificación de metadatos de guards, escenarios de acceso cruzado entre equipos, validación de DTOs
(rol inválido → 400, type de recipient inválido → 400, campos desconocidos rechazados con
`forbidNonWhitelisted:true`, MaxLength, IsEmail, IsPositive).

---

## Limitaciones conocidas

- No existe `GET /teams/:teamId/systems/:systemId` (rawData no disponible en API pública todavía)
- `verifiedAt` en `NotificationRecipient` no se gestiona desde esta API (reservado para doble opt-in futuro)
- `tags` y `rawData` en `TeamSystem` no son aceptados desde DTOs de creación/actualización

---

## Siguiente fase

Fase 1C: integración frontend — panel de administración de equipos y portal de miembro.
