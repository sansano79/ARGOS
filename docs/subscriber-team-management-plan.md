# Plan técnico: rediseño de suscriptores como equipos con miembros y notificadores

**Referencia:** GitHub issue #5 — "Rediseñar suscriptores como equipos con miembros y notificadores"  
**Fecha de análisis:** 2026-06-22  
**Rama analizada:** `feature/mejoras-v1.1`  
**HEAD:** `1fe0b85a66593a215768cb21d0f897fe2f25f7a3`  
**Estado del árbol:** limpio  

---

## 1. Objetivo funcional

Sustituir progresivamente el modelo actual, donde un `User` actúa directamente como suscriptor, por un modelo organizativo donde un `SubscriberTeam` es el propietario de suscripciones, sistemas/unidades, preferencias y destinatarios de notificación.

La migración debe ser incremental, no destructiva y reversible en cada fase. No debe romper la autenticación, el panel administrativo, el motor de notificaciones existente ni los datos de usuarios actuales.

---

## 2. Estado actual real

Se inspeccionaron los siguientes archivos del repositorio:

- `prisma/schema.prisma`
- `prisma/migrations/**` (10 migraciones)
- `prisma/seed.ts` y `prisma/seed-test-subscriber.ts`
- `src/auth/**` (guards, decorators, strategies, controller, service)
- `src/modules/subscriber-portal/**`
- `src/modules/notification/**`
- `src/modules/smart-notifications/**`
- `src/modules/users/**`
- `src/app.module.ts`
- `frontend/src/App.jsx`, `frontend/src/utils/appNavigation.js`
- `docker-compose.yml`, `docker/entrypoint.sh`
- `scripts/**`
- `tests/**`

Se ejecutaron búsquedas de símbolos para: `isSubscriber`, `notificationEmail`, `UserSubscription`, `SubscriberOwnedSystem`, `canReceiveNotifications`, `notificationPolicy`, `SUBSCRIBER`, `teamId`, `@Roles`, `JwtAuthGuard`, `prisma migrate`, `db push`.

### Resumen del estado actual

El modelo de suscriptor está completamente concentrado en el modelo `User`. El rol global `SUBSCRIBER` actúa simultáneamente como categoría de acceso y como condición funcional. No existe ningún concepto de equipo en el código actual.

---

## 3. Modelo de datos actual

### 3.1 Usuario (`User` / tabla `users`)

```
User {
  id                         Int       PK autoincrement
  email                      String    unique
  passwordHash               String?
  name                       String
  role                       String    "ADMIN"|"VIEWER"|"USER"|"SUBSCRIBER"
  authProvider               String    "LOCAL"|"SAML"|"OIDC"
  externalId                 String?   unique
  canLogin                   Boolean
  isActive                   Boolean

  // Flags de suscriptor — MEZ CLA identidad con función organizativa
  isSubscriber               Boolean   @default(false)
  notificationEmail          String?
  canReceiveNotifications    Boolean   @default(true)
  notificationsPaused        Boolean   @default(false)
  notificationsPausedUntil   DateTime?
  communicationLanguage      String    @default("es")
  contactPerson              String?
  department                 String?
  phone                      String?
  notes                      Text?

  // MFA
  mfaEnabled                 Boolean
  mfaSecretEnc               Text?
  mfaSecretIv                String?
  mfaSecretTag               String?

  // Relaciones
  subscriptions              UserSubscription[]
  ownedSystems               SubscriberOwnedSystem[]
  notificationPolicy         NotificationPolicy?
  subscriberNotifications    VulnerabilityNotification[]
  smartReports               SmartNotificationReport[]
  intelligentMatches         IntelligentNotificationSubscriberMatch[]
  intelligentTests           IntelligentNotificationTestRun[]
  defenderActions            DefenderActionRequest[]
  pendingDigestNotifications PendingDigestNotification[]
  patchedCves                SubscriberPatchedCve[]
  apiKeys                    ApiKey[]
  sessions                   UserSession[]
}
```

### 3.2 Suscripciones (`UserSubscription` / tabla `user_subscriptions`)

```
UserSubscription {
  id        Int    PK
  userId    Int    FK → User.id (CASCADE)
  vendor    String
  product   String
  versions  Text?  (JSON array)
  isActive  Boolean
  createdAt DateTime
  updatedAt DateTime

  @@unique([userId, vendor, product])
  @@index([userId])
}
```

Propietario: `User` individual. Un equipo no puede tener suscripciones compartidas con el modelo actual.

### 3.3 Sistemas propios (`SubscriberOwnedSystem` / tabla `subscriber_owned_systems`)

```
SubscriberOwnedSystem {
  id               Int    PK
  subscriberUserId Int    FK → User.id (CASCADE)
  externalId       String unique(pair)
  source           String "manual"|"defender"
  hostname         String
  fqdn             String?
  platform         String?
  osVersion        String?
  riskLevel        String?
  healthStatus     String?
  onboardingStatus String?
  lastSeenAt       DateTime?
  isSelected       Boolean
  isActive         Boolean
  tags             Text?   (JSON)
  rawData          LongText? (JSON)

  @@unique([subscriberUserId, externalId])
  @@index([subscriberUserId])
}
```

Propietario: `User` individual por `subscriberUserId`.

### 3.4 Política de notificaciones (`NotificationPolicy` / tabla `notification_policies`)

Relación 1-to-1 con `User`. Contiene más de 50 campos para configurar 4 niveles de notificación: inmediatas, periódicas/digest, inteligentes y smart reports. No existe política por equipo ni por destinatario.

### 3.5 Motor de notificaciones — tablas relacionadas

| Tabla | Propietario | Propósito |
|-------|-------------|-----------|
| `VulnerabilityNotification` | `subscriberUserId` (FK nullable → User) | Historial de notificaciones enviadas |
| `PendingDigestNotification` | `userId` (FK → User) | Cola de digest pendientes |
| `SmartNotificationReport` | `subscriberUserId` (FK → User) | Reportes semanales de IA |
| `IntelligentNotificationSubscriberMatch` | `subscriberUserId` (FK → User) | Matches de notificaciones inteligentes |
| `IntelligentNotificationTestRun` | `subscriberUserId?` (FK nullable) | Ejecuciones de test de notificaciones |
| `SubscriberPatchedCve` | `userId` (FK → User) | CVEs marcadas como parchadas |
| `DefenderActionRequest` | `subscriberUserId` (FK → User) | Acciones en Defender por usuario |

### 3.6 Autenticación

- **JWT payload:** `{ sub: userId, email, role }` — sin concepto de equipo ni membresía.
- **JwtStrategy.validate:** devuelve `{ id, email, name, role, isSubscriber, authProvider }`.
- **RolesGuard:** valida `requiredRoles.includes(user.role)` — solo rol global, sin rol de equipo.
- **Decorador:** `@Roles('SUBSCRIBER', 'ADMIN')` en rutas de portal.

### 3.7 Rutas actuales del portal

```
GET    /subscriber-portal/profile
PUT    /subscriber-portal/subscriptions
GET    /subscriber-portal/subscription-catalog
GET    /subscriber-portal/notifications
GET    /subscriber-portal/vulnerabilities
POST   /subscriber-portal/vulnerabilities/:cveId/patched
DELETE /subscriber-portal/vulnerabilities/:cveId/patched
```

Todas protegidas por `@Roles('SUBSCRIBER', 'ADMIN')` y usan `req.user.id` directamente.

---

## 4. Problemas del modelo actual

1. **Mezcla de conceptos:** `User` combina identidad, autenticación, rol global, datos de contacto organizativo y condición de suscriptor en una sola tabla. Esto viola la separación de responsabilidades y dificulta la evolución independiente de cada concepto.

2. **Suscripciones individuales:** `UserSubscription` y `SubscriberOwnedSystem` pertenecen a un solo usuario. No existe modelo de propiedad compartida para equipos.

3. **Notificaciones acopladas al usuario:** El motor de notificaciones busca `User` con `isSubscriber=true` y entrega a `notificationEmail || email`. Cambiar el destinatario requiere modificar el motor, no solo el schema.

4. **Destinatarios = usuarios con login:** No existe la posibilidad de enviar notificaciones a un buzón corporativo o lista de distribución sin crear un usuario con credenciales.

5. **Rol global `SUBSCRIBER` como función:** `SUBSCRIBER` funciona simultáneamente como permiso de acceso y como categoría organizativa. Un usuario no puede ser suscriptor en un equipo y viewer en otro.

6. **Sin autorización por contexto de equipo:** No existe guard de membresía. Un usuario con rol `SUBSCRIBER` accede a sus propios datos pero el sistema no permite que dos usuarios accedan a los mismos datos de forma controlada.

7. **Política de notificaciones no escalable:** `NotificationPolicy` es 1-to-1 con `User`. No hay política por equipo, ni posibilidad de que un destinatario sin login tenga preferencias propias.

8. **Problema de migraciones:** La cadena actual no puede ejecutarse sobre una base de datos vacía (ver sección 20).

---

## 5. Modelo objetivo

### 5.1 Separación conceptual obligatoria

| Concepto | Responsabilidad | Tabla |
|----------|-----------------|-------|
| `User` | Identidad, autenticación, login, rol global, MFA | `users` (sin cambios destructivos) |
| `SubscriberTeam` | Unidad organizativa suscriptora | `subscriber_teams` (nueva) |
| `TeamMember` | Relación User ↔ Team con rol de equipo | `team_members` (nueva) |
| `NotificationRecipient` | Destinatario de correo, sin obligación de login | `notification_recipients` (nueva) |
| `TeamSubscription` | Suscripción propiedad del equipo | `team_subscriptions` (nueva) |
| `TeamSystem` | Sistema/unidad propiedad del equipo | `team_systems` (nueva) |

### 5.2 Propuesta Prisma ajustada al proyecto

El proyecto usa MySQL, `Int @id @default(autoincrement())`, nombres camelCase en Prisma con `@map` a snake_case, `createdAt`/`updatedAt`, booleanos `isActive` y `String` para roles y tipos (sin enums Prisma en esta primera versión, por coherencia con el resto del schema).

```prisma
model SubscriberTeam {
  id          Int      @id @default(autoincrement())
  name        String
  code        String   @unique
  description String?  @db.Text
  isActive    Boolean  @default(true) @map("is_active")
  createdAt   DateTime @default(now()) @map("created_at")
  updatedAt   DateTime @updatedAt @map("updated_at")

  members       TeamMember[]
  recipients    NotificationRecipient[]
  subscriptions TeamSubscription[]
  systems       TeamSystem[]

  @@index([name])
  @@index([isActive])
  @@map("subscriber_teams")
}

model TeamMember {
  id        Int      @id @default(autoincrement())
  teamId    Int      @map("team_id")
  userId    Int      @map("user_id")
  role      String   // "TEAM_MANAGER" | "TEAM_VIEWER"
  isActive  Boolean  @default(true) @map("is_active")
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @updatedAt @map("updated_at")

  team SubscriberTeam @relation(fields: [teamId], references: [id], onDelete: Cascade)
  user User           @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([teamId, userId])
  @@index([userId])
  @@index([teamId, role])
  @@map("team_members")
}

model NotificationRecipient {
  id         Int       @id @default(autoincrement())
  teamId     Int       @map("team_id")
  name       String?
  email      String
  type       String    @default("MAILBOX") // "USER"|"MAILBOX"|"DISTRIBUTION_LIST"|"EXTERNAL_CONTACT"
  isActive   Boolean   @default(true) @map("is_active")
  verifiedAt DateTime? @map("verified_at")
  language   String    @default("es")
  timezone   String    @default("Europe/Madrid")
  createdAt  DateTime  @default(now()) @map("created_at")
  updatedAt  DateTime  @updatedAt @map("updated_at")

  team SubscriberTeam @relation(fields: [teamId], references: [id], onDelete: Cascade)

  @@unique([teamId, email])
  @@index([email])
  @@index([teamId, isActive])
  @@map("notification_recipients")
}

model TeamSubscription {
  id        Int      @id @default(autoincrement())
  teamId    Int      @map("team_id")
  vendor    String
  product   String
  versions  String?  @db.Text
  isActive  Boolean  @default(true) @map("is_active")
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @updatedAt @map("updated_at")

  team SubscriberTeam @relation(fields: [teamId], references: [id], onDelete: Cascade)

  @@unique([teamId, vendor, product])
  @@index([vendor, product])
  @@map("team_subscriptions")
}

model TeamSystem {
  id           Int      @id @default(autoincrement())
  teamId       Int      @map("team_id")
  externalId   String?  @map("external_id")
  source       String   @default("manual") // "manual"|"defender"
  name         String
  description  String?  @db.Text
  hostname     String?
  fqdn         String?
  platform     String?
  osVersion    String?  @map("os_version")
  riskLevel    String?  @map("risk_level")
  healthStatus String?  @map("health_status")
  isSelected   Boolean  @default(true) @map("is_selected")
  isActive     Boolean  @default(true) @map("is_active")
  tags         String?  @db.Text
  rawData      String?  @map("raw_data") @db.LongText
  createdAt    DateTime @default(now()) @map("created_at")
  updatedAt    DateTime @updatedAt @map("updated_at")

  team SubscriberTeam @relation(fields: [teamId], references: [id], onDelete: Cascade)

  @@unique([teamId, externalId])
  @@index([teamId])
  @@map("team_systems")
}
```

Cambio aditivo en `User` (sin eliminar ningún campo existente):

```prisma
model User {
  // ... campos existentes sin modificar ...
  teamMemberships TeamMember[]   // nueva relación
}
```

---

## 6. Diagrama textual de entidades y relaciones

```
┌──────────────────────────────────────────────────────────────────┐
│                           IDENTIDAD                              │
│                                                                  │
│   User ──────────────────────────────────────────────────────┐  │
│   id, email, passwordHash, role (global), canLogin, MFA      │  │
│   isSubscriber (legacy), notificationEmail (legacy)          │  │
└──────────────────────────────────────────────────────────────┼──┘
                                                               │
                          ┌────────────────────────────────────┘
                          │ (nuevo) teamMemberships
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                       MEMBRESÍA DE EQUIPO                       │
│                                                                 │
│   TeamMember                                                    │
│   id, teamId, userId, role (TEAM_MANAGER|TEAM_VIEWER), isActive │
│                                                                 │
│   FK(teamId) → SubscriberTeam                                   │
│   FK(userId) → User                                             │
│   UNIQUE(teamId, userId)                                        │
└──────────────────────────────────┬──────────────────────────────┘
                                   │ N membresías → 1 equipo
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                       EQUIPO SUSCRIPTOR                         │
│                                                                 │
│   SubscriberTeam                                                │
│   id, name, code (unique), description, isActive                │
│                                                                 │
│   ├─── TeamMember[]          (usuarios del equipo)             │
│   ├─── TeamSubscription[]    (suscripciones del equipo)        │
│   ├─── TeamSystem[]          (sistemas/unidades del equipo)    │
│   └─── NotificationRecipient[] (destinatarios del equipo)      │
└────────┬────────────────┬────────────────┬──────────────────────┘
         │                │                │
         ▼                ▼                ▼
┌────────────────┐ ┌──────────────┐ ┌───────────────────────────┐
│TeamSubscription│ │  TeamSystem  │ │   NotificationRecipient   │
│ teamId         │ │ teamId       │ │ teamId                    │
│ vendor         │ │ externalId   │ │ name?                     │
│ product        │ │ source       │ │ email                     │
│ versions       │ │ hostname     │ │ type (USER|MAILBOX|        │
│ isActive       │ │ platform     │ │       DISTRIBUTION_LIST|  │
│                │ │ riskLevel    │ │       EXTERNAL_CONTACT)   │
│ UNIQUE(teamId, │ │ isSelected   │ │ language, timezone        │
│ vendor,product)│ │ isActive     │ │ isActive, verifiedAt      │
└────────────────┘ └──────────────┘ │ NO requiere User ni login │
                                    └───────────────────────────┘

LEGACY (sin eliminar):
┌────────────────────────────────────────────────────────────────┐
│  UserSubscription  │  SubscriberOwnedSystem  │ NotificationPolicy │
│  userId (FK→User)  │  subscriberUserId (FK)  │  userId (FK→User) │
└────────────────────────────────────────────────────────────────┘
```

---

## 7. Matriz de roles globales y roles de equipo

| Dimensión | Valores | Origen | Alcance |
|-----------|---------|--------|---------|
| **Rol global** | `ADMIN`, `VIEWER`, `USER`, `SUBSCRIBER` (legacy) | `User.role` / JWT | Toda la aplicación |
| **Rol de equipo** | `TEAM_MANAGER`, `TEAM_VIEWER` | `TeamMember.role` | Un equipo concreto |

### Combinaciones válidas

| Usuario | Rol global | Rol en equipo A | Rol en equipo B | Acceso |
|---------|-----------|-----------------|-----------------|--------|
| admin@empresa.com | ADMIN | — | — | Todos los equipos (administración global) |
| manager@it-es.com | USER | TEAM_MANAGER | — | Gestión de equipo A |
| viewer@it-es.com | USER | TEAM_VIEWER | — | Solo consulta de equipo A |
| dual@empresa.com | USER | TEAM_MANAGER | TEAM_VIEWER | Gestión de A, consulta de B |
| legacy@empresa.com | SUBSCRIBER | — | — | Portal legacy durante transición |
| sinequipo@empresa.com | USER | — | — | Sin acceso a equipos (403 controlado) |

### Principios de separación

- `User.role` y `TeamMember.role` nunca se mezclan en la misma evaluación.
- `ADMIN` global puede administrar todos los equipos sin `TeamMember`.
- `TEAM_MANAGER`/`TEAM_VIEWER` solo operan dentro del `teamId` validado.
- Un `SUBSCRIBER` legacy mantiene acceso al portal legacy mientras coexistan.

---

## 8. Matriz de permisos por operación

### Administración global (prefijo `/api/admin/teams`)

| Operación | ADMIN | TEAM_MANAGER | TEAM_VIEWER | USER sin equipo |
|-----------|:-----:|:------------:|:-----------:|:---------------:|
| Listar todos los equipos | ✅ | ❌ | ❌ | ❌ |
| Crear equipo | ✅ | ❌ | ❌ | ❌ |
| Ver cualquier equipo | ✅ | ❌ | ❌ | ❌ |
| Modificar cualquier equipo | ✅ | ❌ | ❌ | ❌ |
| Añadir miembro a cualquier equipo | ✅ | ❌ | ❌ | ❌ |
| Modificar miembro de cualquier equipo | ✅ | ❌ | ❌ | ❌ |
| Eliminar miembro de cualquier equipo | ✅ | ❌ | ❌ | ❌ |
| Gestionar destinatarios de cualquier equipo | ✅ | ❌ | ❌ | ❌ |

### Autoservicio de equipo (prefijo `/api/teams/:teamId`)

| Operación | ADMIN | TEAM_MANAGER (propio equipo) | TEAM_VIEWER (propio equipo) | Otro equipo |
|-----------|:-----:|:----------------------------:|:---------------------------:|:-----------:|
| Ver resumen del equipo | ✅ | ✅ | ✅ | ❌ 403 |
| Listar suscripciones | ✅ | ✅ | ✅ | ❌ 403 |
| Modificar suscripciones | ✅ | ✅ | ❌ 403 | ❌ 403 |
| Listar sistemas | ✅ | ✅ | ✅ | ❌ 403 |
| Modificar sistemas | ✅ | ✅ | ❌ 403 | ❌ 403 |
| Listar destinatarios | ✅ | ✅ | ✅ | ❌ 403 |
| Añadir/modificar destinatarios | ✅ | ✅ | ❌ 403 | ❌ 403 |
| Ver vulnerabilidades aplicables | ✅ | ✅ | ✅ | ❌ 403 |
| Marcar CVE como parchada | ✅ | ✅ | ❌ 403 | ❌ 403 |
| Listar equipos propios | ✅ | ✅ | ✅ | — |

---

## 9. Diseño de aislamiento entre equipos

### Principio de aislamiento obligatorio

Toda consulta a recursos de un equipo debe incluir `teamId` como filtro forzado desde el backend. No se permite filtrar por `teamId` recibido del cliente sin validar la membresía activa del usuario solicitante.

### Patrón de implementación: `TeamAccessService`

```typescript
// Pseudocódigo — no implementar hasta Fase 1

class TeamAccessService {
  async assertMembership(
    userId: number,
    teamId: number,
    requiredRole?: 'TEAM_MANAGER' | 'TEAM_VIEWER'
  ): Promise<TeamMember> {
    // 1. Si user.role === 'ADMIN', crear contexto admin y continuar
    // 2. Buscar TeamMember activo: { teamId, userId, isActive: true }
    // 3. Si no existe → lanzar ForbiddenException
    // 4. Si team.isActive === false → lanzar ForbiddenException
    // 5. Si requiredRole === 'TEAM_MANAGER' y member.role !== 'TEAM_MANAGER' → lanzar ForbiddenException
    // 6. Devolver el TeamMember validado
  }
}
```

### Reglas de consulta

- Todas las queries de recursos de equipo incluyen `WHERE team_id = :validatedTeamId`.
- El `teamId` validado proviene siempre de `TeamAccessService`, nunca del body/query del cliente.
- Los recursos no tienen campo `userId` de propietario directo (pertenecen al equipo, no al usuario que los crea).

### Consulta de membresía en base de datos (no en JWT)

El JWT no debe incluir `teams: [{id, role}]` en la primera versión para evitar tokens con membresías obsoletas y complejidad de revocación. La membresía se consulta en base de datos en cada request protegido. El impacto de rendimiento es mitigable con cache Redis por `userId` (TTL corto: 30-60 segundos).

---

## 10. Estrategia contra IDOR

### Vectores de ataque identificados

1. Modificar `teamId` en URL: `GET /api/teams/2/subscriptions` cuando el usuario solo pertenece al equipo 1.
2. Modificar `teamId` en body de un `PUT`.
3. Modificar `memberId` o `recipientId` para acceder a miembros/destinatarios de otro equipo.

### Mitigaciones

| Vector | Mitigación |
|--------|-----------|
| `teamId` en URL | `TeamAccessService.assertMembership(userId, params.teamId)` antes de cualquier query |
| `teamId` en body | Ignorar `teamId` del body; usar siempre el `teamId` del path validado |
| `memberId` / `recipientId` | Filtrar `{ id: memberId, teamId: validatedTeamId }` — la combinación no puede pertenecer a otro equipo |
| Acceso a admin endpoints | Guard adicional: `User.role === 'ADMIN'` requerido estrictamente |
| Token con membresía obsoleta | Consulta en BD en cada request; la revocación de `TeamMember.isActive=false` es inmediata |

### Regla de oro

```
Nunca usar el teamId recibido del cliente directamente en una query.
Siempre: validar membresía → obtener teamId confiable → usar en query.
```

---

## 11. Propuesta de endpoints

### 11.1 Endpoints de administración global

```
POST   /api/admin/teams                              Crear equipo
GET    /api/admin/teams                              Listar todos los equipos
GET    /api/admin/teams/:teamId                      Ver un equipo
PATCH  /api/admin/teams/:teamId                      Modificar equipo (nombre, estado, etc.)

POST   /api/admin/teams/:teamId/members              Añadir miembro
PATCH  /api/admin/teams/:teamId/members/:memberId    Modificar rol o estado de miembro
DELETE /api/admin/teams/:teamId/members/:memberId    Desactivar miembro (soft delete)

POST   /api/admin/teams/:teamId/recipients           Añadir destinatario
PATCH  /api/admin/teams/:teamId/recipients/:id       Modificar destinatario
DELETE /api/admin/teams/:teamId/recipients/:id       Desactivar destinatario
```

Todos requieren `User.role === 'ADMIN'`.

### 11.2 Endpoints de autoservicio de equipo

```
GET    /api/me/teams                                 Listar equipos propios con rol

GET    /api/teams/:teamId/overview                   Resumen del equipo
GET    /api/teams/:teamId/subscriptions              Listar suscripciones
PUT    /api/teams/:teamId/subscriptions              Reemplazar suscripciones (TEAM_MANAGER)
GET    /api/teams/:teamId/systems                    Listar sistemas/unidades
PUT    /api/teams/:teamId/systems                    Actualizar sistemas (TEAM_MANAGER)
GET    /api/teams/:teamId/recipients                 Listar destinatarios
POST   /api/teams/:teamId/recipients                 Añadir destinatario (TEAM_MANAGER)
PATCH  /api/teams/:teamId/recipients/:id             Modificar destinatario (TEAM_MANAGER)
DELETE /api/teams/:teamId/recipients/:id             Desactivar destinatario (TEAM_MANAGER)

GET    /api/teams/:teamId/vulnerabilities            Vulnerabilidades aplicables al equipo
POST   /api/teams/:teamId/vulnerabilities/:cveId/patched   Marcar CVE como parchada (TEAM_MANAGER)
DELETE /api/teams/:teamId/vulnerabilities/:cveId/patched   Desmarcar (TEAM_MANAGER)
```

### 11.3 Decisiones de diseño de endpoints

- Se usa `teamId` explícito en la URL (no contexto activo en sesión) para simplificar el backend y soportar multi-equipo en frontend sin estado de sesión complejo.
- `GET /api/me/teams` provee la lista de equipos con rol; el frontend gestiona el selector de equipo activo.
- El `teamId` del JWT no se contempla en la primera versión por los riesgos de membresías obsoletas.
- Los endpoints de administración usan prefijo `/api/admin/` para separación conceptual y de guard clara.

---

## 12. Propuesta de servicios y módulos NestJS

### 12.1 Nuevo módulo: `SubscriberTeamsModule`

```
src/modules/subscriber-teams/
├── subscriber-teams.module.ts
├── dto/
│   ├── create-team.dto.ts
│   ├── update-team.dto.ts
│   ├── create-team-member.dto.ts
│   ├── update-team-member.dto.ts
│   ├── create-notification-recipient.dto.ts
│   ├── update-notification-recipient.dto.ts
│   └── update-team-subscriptions.dto.ts
├── guards/
│   └── team-role.guard.ts
├── decorators/
│   └── team-roles.decorator.ts
├── services/
│   ├── team-access.service.ts       (validación de membresía y aislamiento)
│   ├── subscriber-teams.service.ts  (CRUD de equipos)
│   ├── team-members.service.ts      (gestión de miembros)
│   ├── team-recipients.service.ts   (gestión de destinatarios)
│   ├── team-subscriptions.service.ts (gestión de suscripciones)
│   └── team-systems.service.ts      (gestión de sistemas)
├── subscriber-teams-admin.controller.ts  (endpoints /api/admin/teams)
└── subscriber-teams.controller.ts        (endpoints /api/teams)
```

### 12.2 Guard de equipo: `TeamRoleGuard`

Complementa `JwtAuthGuard`. Extrae `teamId` del parámetro de ruta, invoca `TeamAccessService.assertMembership` y añade el `TeamMember` validado al request.

```typescript
// Uso en controlador
@UseGuards(JwtAuthGuard, TeamRoleGuard)
@TeamRoles('TEAM_MANAGER')
@Put(':teamId/subscriptions')
updateSubscriptions(...) {}
```

### 12.3 `TeamAccessService` — responsabilidades

- `assertMembership(userId, teamId, requiredRole?)` — valida membresía activa; retorna `TeamMember` o lanza 403.
- `getTeamsForUser(userId)` — lista equipos activos con rol del usuario.
- `isAdmin(user)` — comprueba `user.role === 'ADMIN'`.

### 12.4 Módulos existentes afectados (solo en fases posteriores)

| Módulo | Impacto | Fase |
|--------|---------|------|
| `subscriber-portal` | Añadir selector de equipo; delegar a servicios de equipo | 3 |
| `notification` | Capa `NotificationAudienceService` | 4 |
| `smart-notifications` | Adaptar matching a `TeamSubscription` y `TeamSystem` | 4 |
| `users` | Añadir relación `teamMemberships` en respuestas admin | 1 |
| `auth` | Incluir `GET /me/teams` o ampliar `/auth/me` | 3 |

---

## 13. Impacto en frontend

### Estado actual

- La SPA React en `App.jsx` gestiona `portalProfile`, `portalSubscriptions`, `portalVendors`, `portalActiveVendor` como estado de usuario individual.
- `appNavigation.js` da acceso al portal solo a usuarios con `role === 'SUBSCRIBER'`.
- Las vistas de gestión de usuarios (`/admin/users`) muestran `isSubscriber`, `role`, `notificationEmail` como columnas.
- El término `contacts` se usa en algunos lugares para referirse a suscriptores con `isSubscriber=true`.

### Cambios necesarios por fase

**Fase 3:**
- Añadir componente selector de equipo activo (dropdown o sidebar).
- Cargar `GET /api/me/teams` al iniciar sesión; almacenar lista en estado global.
- Cambiar las llamadas del portal de `/subscriber-portal/*` a `/api/teams/:teamId/*` para usuarios con membresía.
- Mostrar/ocultar elementos según `TeamMember.role` del equipo activo.
- Mantener acceso al portal legacy para usuarios con `role === 'SUBSCRIBER'` durante la transición.

**Fases 4-5:**
- Retirar referencias a `isSubscriber`, `notificationEmail` en vistas de gestión.
- Adaptar historial de notificaciones para mostrar por equipo.

### Principio de seguridad frontend

La UI oculta o muestra elementos según el rol, pero el backend valida siempre la membresía y el rol de equipo. Ocultar un botón en frontend no constituye autorización.

---

## 14. Impacto en notificaciones

### Motor actual

`VulnerabilityCollectorService.sendAutomaticSubscriberNotifications` itera sobre `User` con `isSubscriber=true`, `canReceiveNotifications=true`, `notificationsPaused=false`. Entrega a `subscriber.notificationEmail || subscriber.email`. Registra en `VulnerabilityNotification` por `subscriberUserId`.

### Cambio requerido (Fase 4)

Introducir `NotificationAudienceService` que proporcione "perfiles notificables" tanto legacy como team-based:

```typescript
interface NotifiableAudience {
  type: 'legacy_user' | 'team_recipient';
  recipientEmail: string;
  subscriptions: { vendor: string; product: string; versions?: string }[];
  notificationPolicy: PolicyShape;
  teamId?: number;
  userId?: number;
}
```

- Para legacy: construir desde `User` con `isSubscriber=true`.
- Para equipo: construir desde `NotificationRecipient` activos del equipo + `TeamSubscription` + política del equipo.

El motor de notificaciones llama a `NotificationAudienceService.getAudiences()` en lugar de consultar directamente `User`. Esto desacopla el motor del modelo de datos.

### Cambios de schema necesarios en Fase 4 (opcionales, no en Fase 1)

- `VulnerabilityNotification.teamId` (nullable FK)
- `VulnerabilityNotification.notificationRecipientId` (nullable FK)
- `PendingDigestNotification.teamId` (nullable FK)
- `SmartNotificationReport.teamId` (nullable FK)
- `IntelligentNotificationSubscriberMatch.teamId` (nullable FK)

Todos nullable para mantener compatibilidad con registros legacy existentes.

### Deduplicación con equipos

La deduplicación actual es por `(cveId, recipientEmail)`. Con equipos debe ser por `(cveId, teamId, recipientEmail)` o `(cveId, notificationRecipientId)` para evitar que dos equipos con la misma suscripción bloqueen sus notificaciones entre sí.

---

## 15. Impacto en suscripciones

| Aspecto | Estado actual | Estado objetivo |
|---------|--------------|-----------------|
| Tabla | `UserSubscription` (userId FK) | `TeamSubscription` (teamId FK) |
| Propietario | Un usuario | Un equipo |
| Acceso compartido | No | Sí (todos los miembros activos) |
| Consulta | Por `userId` en `req.user.id` | Por `teamId` validado por `TeamAccessService` |
| Restricción única | `(userId, vendor, product)` | `(teamId, vendor, product)` |

**Compatibilidad:** `UserSubscription` no se elimina. Coexiste con `TeamSubscription`. El motor de notificaciones usa ambas durante la transición mediante `NotificationAudienceService`.

---

## 16. Impacto en sistemas/unidades

| Aspecto | Estado actual | Estado objetivo |
|---------|--------------|-----------------|
| Tabla | `SubscriberOwnedSystem` (subscriberUserId FK) | `TeamSystem` (teamId FK) |
| Propietario | Un usuario | Un equipo |
| Fuente | `"manual"` / `"defender"` | Mantener mismos valores |
| Campos ricos | Sí (hostname, fqdn, platform, riskLevel, rawData) | Mantener todos para notificaciones inteligentes |
| Restricción única | `(subscriberUserId, externalId)` | `(teamId, externalId)` |

**Nota:** `SubscriberOwnedSystem` contiene campos más ricos que el mínimo de la issue. `TeamSystem` debe preservar todos para no degradar las notificaciones inteligentes que usan `platform`, `riskLevel`, `rawData` para calcular relevancia.

---

## 17. Compatibilidad con datos legacy

### Campos que no se eliminarán en fases 0–3

- `User.isSubscriber`
- `User.notificationEmail`
- `User.canReceiveNotifications`
- `User.notificationsPaused`, `User.notificationsPausedUntil`
- `User.communicationLanguage`
- `User.contactPerson`, `User.department`
- `UserSubscription` (tabla completa)
- `SubscriberOwnedSystem` (tabla completa)
- `NotificationPolicy.userId` (relación 1-to-1)
- `VulnerabilityNotification.subscriberUserId`
- `PendingDigestNotification.userId`
- `SmartNotificationReport.subscriberUserId`
- `IntelligentNotificationSubscriberMatch.subscriberUserId`
- `SubscriberPatchedCve.userId`
- `DefenderActionRequest.subscriberUserId`

### Portal legacy

`/subscriber-portal` sigue funcionando para usuarios con `role === 'SUBSCRIBER'` mientras se ejecuta la transición. No se modifica su lógica en fases 0–2.

---

## 18. Estrategia de migración de datos

La migración no debe ejecutarse automáticamente al desplegar migraciones de schema. Debe ser explícita, reversible y auditable.

### Fase A — Schema aditivo (Fase 1 del plan)

Crear las tablas nuevas vacías (`subscriber_teams`, `team_members`, `notification_recipients`, `team_subscriptions`, `team_systems`). Sin mover datos. Sin modificar tablas legacy.

### Fase B — Script dry-run

Crear `scripts/migrate-user-subscribers-to-teams.ts` con modo `--dry-run`:

```
Por cada User con isSubscriber=true:
  → Proponer SubscriberTeam
      name = user.department || user.name
      code = slug(user.email | user.department) + sufijo si colisión
  → Si user.canLogin=true:
      Proponer TeamMember (role=TEAM_MANAGER)
  → Si user.notificationEmail || (user.canReceiveNotifications && user.email):
      Proponer NotificationRecipient (email=notificationEmail || email)
  → Por cada UserSubscription activa:
      Proponer TeamSubscription
  → Por cada SubscriberOwnedSystem activo:
      Proponer TeamSystem
```

Usuarios con `canLogin=false` (contactos legacy) deben convertirse principalmente en `NotificationRecipient`, no en `TeamMember`.

### Fase C — Ejecución opt-in

```bash
npx ts-node scripts/migrate-user-subscribers-to-teams.ts --execute
```

El script registra:
- Usuarios legacy considerados
- Equipos creados / omitidos por colisión
- Miembros creados
- Destinatarios creados
- Suscripciones copiadas
- Sistemas copiados
- Errores por fila

### Fase D — Trazabilidad (opcional)

Tabla técnica de mapeo para auditoría y rollback:

```prisma
model LegacySubscriberTeamMapping {
  id              Int      @id @default(autoincrement())
  legacyUserId    Int      @map("legacy_user_id")
  teamId          Int      @map("team_id")
  migrationBatchId String  @map("migration_batch_id")
  createdAt       DateTime @default(now()) @map("created_at")

  @@index([legacyUserId])
  @@index([teamId])
  @@map("legacy_subscriber_team_mappings")
}
```

Si no se quiere la tabla, el script debe emitir JSON/CSV persistido en `storage/migrations/` para auditoría fuera de BD.

### Fase E — Validación post-migración

```
- Cada usuario legacy migrado tiene exactamente un equipo.
- COUNT(TeamSubscription WHERE teamId=X) = COUNT(UserSubscription WHERE userId=Y AND isActive=true).
- COUNT(TeamSystem WHERE teamId=X) = COUNT(SubscriberOwnedSystem WHERE subscriberUserId=Y AND isActive=true).
- Ningún email duplicado dentro del mismo equipo en notification_recipients.
```

---

## 19. Estrategia de rollback

### Rollback de schema (Fase 1)

Las tablas nuevas son aditivas. Para revertirlas:

```sql
DROP TABLE IF EXISTS team_systems;
DROP TABLE IF EXISTS team_subscriptions;
DROP TABLE IF EXISTS notification_recipients;
DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS subscriber_teams;
-- Opcionalmente:
DROP TABLE IF EXISTS legacy_subscriber_team_mappings;
```

Ninguna tabla legacy es modificada, por lo que el rollback de schema no afecta datos existentes.

### Rollback lógico (Fases 3–4)

Desactivar la lectura/escritura team-based mediante feature flag o variable de entorno (`TEAM_FEATURES_ENABLED=false`). El portal legacy sigue operativo porque `UserSubscription` y `NotificationPolicy` no se han eliminado.

### Principio de rollback

- **Nunca** borrar `UserSubscription`, `SubscriberOwnedSystem` ni `NotificationPolicy` hasta que la Fase 5 esté completa y validada.
- **Nunca** eliminar `User.isSubscriber`, `User.notificationEmail` hasta la Fase 5.
- Si un equipo migrado debe revertirse, basta con desactivar `SubscriberTeam.isActive=false` y el usuario legacy sigue siendo funcional.

---

## 20. Solución propuesta para la baseline Prisma

### Problema actual

La cadena de migraciones Prisma no contiene una migración inicial que cree el esquema desde cero. La primera migración real (`20260321160000_auth_provider_mfa`) asume que la tabla `users` ya existe y solo añade columnas con `ALTER TABLE`. Migraciones posteriores asumen `vulnerabilities`, `notification_policies`, `notification_logs`, etc.

**Consecuencia:** `npx prisma migrate deploy` falla en una base de datos vacía. El entrypoint de Docker (`docker/entrypoint.sh`) ejecuta `prisma migrate deploy` por defecto, lo que provoca fallo en primer arranque en bases vacías.

### Solución propuesta

#### Paso 1 — Crear migración baseline

Crear `prisma/migrations/20260320000000_initial_schema_baseline/migration.sql` con el `CREATE TABLE IF NOT EXISTS` completo del schema original (estado pre-primera-migración).

- El timestamp `20260320000000` es anterior a `20260321160000`, por lo que Prisma la aplicará primero.
- Usar `CREATE TABLE IF NOT EXISTS` para que sea idempotente en bases que ya tengan las tablas.
- No incluir las tablas nuevas de equipos (esas van en su propia migración en Fase 1).

```sql
-- Ejemplo parcial:
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `email` VARCHAR(191) NOT NULL,
  `password_hash` VARCHAR(191) NULL,
  `name` VARCHAR(191) NOT NULL,
  `role` VARCHAR(191) NOT NULL DEFAULT 'USER',
  -- ... resto de columnas del estado original ...
  PRIMARY KEY (`id`),
  UNIQUE KEY `users_email_key` (`email`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ... CREATE TABLE IF NOT EXISTS para cada tabla original ...
```

#### Paso 2 — Bases existentes

Para bases existentes creadas con `db push` o ya con datos, ejecutar:

```bash
npx prisma migrate resolve --applied 20260320000000_initial_schema_baseline
```

Esto marca la baseline como aplicada sin ejecutar el SQL (el schema ya existe).

#### Paso 3 — Validación en base vacía

Añadir un test/script de CI que arranque MySQL limpio y ejecute:

```bash
npx prisma migrate deploy && npx prisma generate
```

Sin `db push`, sin intervención manual.

#### Paso 4 — Actualizar documentación

- Eliminar referencias a `db push` como camino normal en `README.md`.
- Documentar `migrate resolve` para bases existentes.
- Mantener `PRISMA_DB_PUSH_ON_START` solo como escape de emergencia documentado, no como flujo estándar.

#### Notas adicionales

- Las migraciones deploy-safe existentes con `information_schema` son compatibles con la baseline: si la tabla existe, el `ALTER TABLE` comprueba antes y no falla.
- El baseline debe generarse desde el schema del estado original (sin tablas de equipo). Las tablas nuevas van en su propia migración numerada posterior al baseline.
- Prisma ordena migraciones lexicográficamente por nombre de directorio, por lo que el timestamp prefijo garantiza el orden.

---

## 21. Fases de implementación

### Fase 0 — Saneamiento de migraciones (prerequisito)

**Objetivo:** `npx prisma migrate deploy` funciona en MySQL vacío.

**Tareas:**
- [ ] Generar SQL de baseline desde schema actual (sin tablas de equipo).
- [ ] Crear `prisma/migrations/20260320000000_initial_schema_baseline/migration.sql`.
- [ ] Documentar `migrate resolve` para bases existentes.
- [ ] Añadir script/test de CI con MySQL efímero vacío.
- [ ] Actualizar `README.md`: eliminar `db push` como camino estándar.

**Criterio de verificación:**
- MySQL vacío + `npx prisma migrate deploy` termina sin error.
- `npx prisma generate` funciona.
- `npm test` sigue pasando.
- El portal y jobs legacy siguen funcionando.

---

### Fase 1 — Schema y servicios base de equipos

**Objetivo:** Añadir modelo de equipos sin tocar comportamiento legacy.

**Tareas:**
- [ ] Añadir modelos Prisma: `SubscriberTeam`, `TeamMember`, `NotificationRecipient`, `TeamSubscription`, `TeamSystem`.
- [ ] Añadir `User.teamMemberships TeamMember[]`.
- [ ] Crear migración numerada posterior al baseline.
- [ ] Crear `SubscriberTeamsModule` con estructura propuesta en sección 12.
- [ ] Crear DTOs con validación (`class-validator`).
- [ ] Crear `TeamAccessService`.
- [ ] Crear `TeamRoleGuard` y `@TeamRoles()`.
- [ ] Implementar endpoints admin (`/api/admin/teams/*`).
- [ ] Implementar `GET /api/me/teams`.
- [ ] Pruebas unitarias de `TeamAccessService` y `TeamRoleGuard`.
- [ ] Pruebas de integración de endpoints admin.

**Criterio de verificación:**
- Admin crea equipo, añade miembro y destinatario.
- `TEAM_MANAGER` accede a su equipo; recibe 403 en otro.
- `TEAM_VIEWER` consulta su equipo; recibe 403 al intentar modificar.
- `teamId` manipulado en URL devuelve 403.
- Legacy `/subscriber-portal` y jobs sin cambios.

---

### Fase 2 — Migración opt-in de datos legacy

**Objetivo:** Copiar datos legacy hacia equipos sin desactivar legacy.

**Tareas:**
- [ ] Crear `scripts/migrate-user-subscribers-to-teams.ts` con `--dry-run` y `--execute`.
- [ ] Implementar validadores de conteo post-migración.
- [ ] Documentar procedimiento de rollback: desactivar `SubscriberTeam.isActive=false`.
- [ ] Ejecutar dry-run en entorno de prueba; revisar propuestas.
- [ ] Confirmar estrategia de trazabilidad (tabla o CSV).

**Criterio de verificación:**
- Dry-run no escribe datos.
- Execute es idempotente (segunda ejecución no duplica).
- No borra `UserSubscription` ni `SubscriberOwnedSystem`.
- Conteos de suscripciones y sistemas coinciden.
- Script emite resumen con errores por fila.

---

### Fase 3 — Portal team-aware

**Objetivo:** Usuarios con membresía pueden gestionar recursos del equipo desde el portal.

**Tareas:**
- [ ] Implementar endpoints `GET/PUT /api/teams/:teamId/subscriptions`, `GET/PUT /api/teams/:teamId/systems`, `GET/POST/PATCH/DELETE /api/teams/:teamId/recipients`.
- [ ] Implementar `GET/POST /api/teams/:teamId/vulnerabilities`.
- [ ] Añadir selector de equipo activo en frontend.
- [ ] Cargar equipos en estado global tras login.
- [ ] Adaptar vistas de suscripciones/sistemas/destinatarios para contexto de equipo.
- [ ] Mantener acceso legacy para `role === 'SUBSCRIBER'`.

**Criterio de verificación:**
- Usuario con dos equipos ve ambos y cambia contexto.
- `TEAM_MANAGER` edita solo su equipo.
- `TEAM_VIEWER` consulta pero no guarda.
- Usuario de equipo A no accede a equipo B modificando `teamId`.
- Usuario sin membresía recibe 403 controlado (no 500).

---

### Fase 4 — Notificaciones por equipo

**Objetivo:** Desacoplar destinatarios de notificaciones del modelo `User`.

**Tareas:**
- [ ] Crear `NotificationAudienceService`.
- [ ] Adaptar motor legacy para usar `NotificationAudienceService`.
- [ ] Añadir audiencias team-based: `NotificationRecipient` + `TeamSubscription`.
- [ ] Añadir campos nullable `teamId`, `notificationRecipientId` en tablas de historial.
- [ ] Actualizar deduplicación a nivel de `(cveId, teamId, email)`.
- [ ] Adaptar `SmartNotificationsService` para `TeamSubscription` y `TeamSystem`.

**Criterio de verificación:**
- Usuario miembro sin `NotificationRecipient` asociado no recibe correo.
- Destinatario sin login recibe correo.
- Dos equipos con la misma suscripción no comparten historial ni bloquean deduplicación entre sí.
- Jobs legacy siguen enviando a suscriptores legacy durante la transición.

---

### Fase 5 — Retirada gradual de legacy

**Objetivo:** Dejar `User` como identidad pura; retirar acoplamientos de suscriptor.

**Tareas:**
- [ ] Marcar campos legacy como deprecated en código y documentación.
- [ ] Bloquear nuevas escrituras a `UserSubscription` para flujos nuevos.
- [ ] Migrar `SmartNotificationReport`, `SubscriberPatchedCve` y `DefenderActionRequest` a team-based.
- [ ] Planificar eliminación de columnas/tablas legacy en release posterior.
- [ ] Actualizar seed para no crear usuarios `SUBSCRIBER` legacy por defecto.

**Criterio de verificación:**
- Ningún flujo nuevo escribe en `UserSubscription` ni `SubscriberOwnedSystem`.
- Jobs trabajan exclusivamente con `NotificationAudienceService`.
- Datos históricos siguen siendo consultables.
- Tests de regresión legacy siguen pasando.

---

## 22. Pruebas necesarias

### 22.1 Autenticación y autorización de equipo

| Caso | Resultado esperado |
|------|--------------------|
| Admin accede a cualquier equipo | 200 OK |
| `TEAM_MANAGER` accede a su equipo | 200 OK |
| `TEAM_MANAGER` accede a otro equipo modificando `teamId` | 403 Forbidden |
| `TEAM_VIEWER` consulta su equipo | 200 OK |
| `TEAM_VIEWER` intenta PUT en su equipo | 403 Forbidden |
| Usuario sin membresía activa en ningún equipo | 403 con mensaje controlado |
| `teamId` manipulado en URL (IDOR) | 403 Forbidden |
| Miembro con `isActive=false` | 403 Forbidden |
| Equipo con `isActive=false` | 403 Forbidden |

### 22.2 Separación usuario/destinatario

| Caso | Resultado esperado |
|------|--------------------|
| `NotificationRecipient` sin `User` recibe notificación | Email enviado correctamente |
| Usuario miembro sin `NotificationRecipient` | No recibe email (solo acceso UI) |
| Usuario puede pertenecer a dos equipos | Acceso a ambos con roles distintos |

### 22.3 Integridad de datos

| Caso | Resultado esperado |
|------|--------------------|
| Crear dos `TeamMember` con mismo `(teamId, userId)` | Error de restricción unique |
| Crear dos `NotificationRecipient` con mismo `(teamId, email)` | Error de restricción unique |
| Crear dos `TeamSubscription` con mismo `(teamId, vendor, product)` | Error de restricción unique |
| Eliminar usuario miembro | Equipo persiste; `TeamMember` desactivado o cascade según configuración |
| Eliminar equipo | Cascades aplican sobre miembros, destinatarios, suscripciones, sistemas |

### 22.4 Migraciones

| Caso | Resultado esperado |
|------|--------------------|
| Base MySQL vacía + `prisma migrate deploy` | Completa sin error |
| Base existente (sin baseline) + `migrate resolve` + `prisma migrate deploy` | Aplica migraciones incrementales sin error |
| Script dry-run sobre datos legacy | No escribe; genera propuesta |
| Script execute idempotente | Segunda ejecución no duplica registros |
| Migración preserva datos existentes | COUNT legacy igual antes y después |

### 22.5 Legacy

| Caso | Resultado esperado |
|------|--------------------|
| Portal `/subscriber-portal` durante Fases 0–2 | Funciona igual que antes |
| Jobs de notificaciones durante Fases 0–3 | Funcionan igual que antes |
| `UserSubscription` y `SubscriberOwnedSystem` después de Fase 1 | No eliminados, accesibles |

---

## 23. Riesgos y mitigaciones

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|-------------|---------|-----------|
| IDOR por `teamId` del cliente sin validar | Alta | Alto | `TeamAccessService` obligatorio; nunca usar `teamId` del body directamente |
| Mezcla de `User.role` con `TeamMember.role` en guards | Media | Alto | Guards separados: `RolesGuard` para global, `TeamRoleGuard` para equipo |
| Duplicación de notificaciones al activar motor team-based | Alta | Medio | `NotificationAudienceService` con deduplicación por `(cveId, teamId, email)` |
| Borrado accidental de `UserSubscription` legacy | Media | Alto | No reutilizar `SubscriberPortalService.updateSubscriptions` en flujos nuevos |
| Usuario multi-equipo ve datos agregados sin filtro | Media | Alto | Todas las queries incluyen `WHERE team_id = :validatedTeamId` |
| Baseline Prisma ejecutada en BD ya poblada | Alta | Alto | `migrate resolve --applied` documentado; `CREATE TABLE IF NOT EXISTS` como fallback |
| Frontend oculta botones sin respaldo backend | Alta | Medio | Backend valida siempre; frontend es solo presentación |
| `NotificationPolicy` no migrada a equipo | Media | Medio | Política de equipo diseñada en Fase 4; hasta entonces usa política del primer miembro TEAM_MANAGER |
| Scripts de seed crean `SUBSCRIBER` legacy en pruebas | Baja | Bajo | Marcar scripts de seed legacy como opcionales; seed principal sin `SUBSCRIBER` en Fase 5 |
| `TeamSystem` sin campos ricos degrada notificaciones inteligentes | Alta | Alto | `TeamSystem` preserva todos los campos de `SubscriberOwnedSystem`, incluyendo `rawData` |
| Token JWT con membresías obsoletas | Media | Alto | Membresía siempre consultada en BD; `TeamMember.isActive=false` revoca acceso inmediatamente |

---

## 24. Decisiones pendientes

Las siguientes decisiones requieren confirmación funcional antes de implementar las fases correspondientes:

1. **Rol `SUBSCRIBER` durante la transición:** ¿Sigue existiendo como rol global durante toda la transición, o los usuarios nuevos de equipo usarán `USER`/`VIEWER` global + roles de equipo? Afecta a guard de portal legacy y a seed.

2. **Política de notificaciones por equipo:** ¿La `NotificationPolicy` futura pertenece al equipo (una por equipo), al destinatario (una por `NotificationRecipient`) o a una combinación? Afecta al diseño de Fase 4.

3. **Gestión de miembros por `TEAM_MANAGER`:** ¿El `TEAM_MANAGER` gestionará miembros en Fase 1 o esa capacidad se reserva para fases posteriores y solo la gestiona `ADMIN` inicialmente?

4. **Formato del campo `code` de equipo:** ¿Slug generado automáticamente desde `name`, código corporativo introducido manualmente, o ambos con fallback?

5. **Históricos por equipo:** ¿`SmartNotificationReport`, historial de `VulnerabilityNotification` y `SubscriberPatchedCve` deben visualizarse por equipo desde la primera versión del portal de equipos, o solo después de migrar los jobs en Fase 4?

6. **Política de eliminación de equipos:** ¿Soft delete (`isActive=false`) siempre, o hard delete permitido para admins con datos migrados? Define el comportamiento de `onDelete` en `TeamMember`, `TeamSubscription`, `TeamSystem`, `NotificationRecipient`.

7. **Cache de membresía:** ¿Se implementa cache Redis para `TeamAccessService` desde Fase 1, o se añade en Fase 3 cuando haya carga real?

---

## 25. Criterios de aceptación

### Fase 0
- [ ] `npx prisma migrate deploy` completa en MySQL vacío sin intervención manual.
- [ ] Tests existentes pasan sin modificación.
- [ ] Portal legacy y jobs de notificación funcionan igual.

### Fase 1
- [ ] Un ADMIN puede crear, listar y modificar equipos y sus miembros/destinatarios.
- [ ] Un `TEAM_MANAGER` puede acceder a su equipo y recibe 403 al acceder a otro.
- [ ] Un `TEAM_VIEWER` puede consultar su equipo y recibe 403 al intentar modificar.
- [ ] Un usuario sin membresía recibe 403 controlado (no 500 ni filtración de datos).
- [ ] Un `teamId` manipulado en URL devuelve 403.
- [ ] Restricciones unique funcionan en BD.
- [ ] Schema legacy sin modificaciones destructivas.
- [ ] Tests unitarios de `TeamAccessService` con cobertura de todos los casos de autorización.

### Fase 2
- [ ] Script dry-run no modifica datos.
- [ ] Script execute es idempotente.
- [ ] Conteos de datos migrados coinciden con legacy.
- [ ] Trazabilidad disponible (tabla o CSV).

### Fase 3
- [ ] Usuario con múltiples equipos puede cambiar de contexto.
- [ ] Recursos del equipo A no son visibles desde el contexto del equipo B.
- [ ] Portal legacy sigue funcional para usuarios `SUBSCRIBER`.
- [ ] Backend valida membresía en cada request; ocultar UI no es suficiente.

### Fase 4
- [ ] `NotificationRecipient` sin cuenta de usuario recibe notificaciones correctamente.
- [ ] Usuario con cuenta pero sin `NotificationRecipient` no recibe notificaciones de equipo.
- [ ] Deduplicación no bloquea envíos entre equipos distintos con la misma suscripción.
- [ ] Historial de notificaciones registra `teamId` y `notificationRecipientId`.

### Fase 5
- [ ] Ningún flujo nuevo escribe en tablas legacy de suscriptor.
- [ ] Datos históricos legacy siguen siendo consultables en modo solo lectura.
- [ ] El término `SUBSCRIBER` no aparece en flujos nuevos de código.

---

## Apéndice — Símbolos legacy localizados en el repositorio

Referencias encontradas durante el análisis (archivos y contextos):

| Símbolo | Ubicaciones principales |
|---------|------------------------|
| `isSubscriber` | `User` (schema), `jwt.strategy.ts`, `auth.service.ts` (SAML/OIDC), `users.service.ts`, `subscriber-portal.*`, `notification.*`, `smart-notifications.*`, scripts de seed, `App.jsx` |
| `notificationEmail` | `User` (schema), `/auth/me`, `users.service.ts`, `password-reset.*`, `notification.*`, `smart-notifications.*`, scripts, `App.jsx` |
| `UserSubscription` | `schema.prisma`, `users.service.ts`, `subscriber-portal.service.ts`, `vulnerability-collector.*`, `smart-notifications.*`, `seed.ts` |
| `SubscriberOwnedSystem` | `schema.prisma`, `smart-notifications.*` |
| `canReceiveNotifications` | `User` (schema), `users.service.ts`, `notification.*`, `smart-notifications.*`, `App.jsx` |
| `notificationPolicy` | `schema.prisma`, `notification.service.ts`, `vulnerability-collector.*`, `smart-notifications.*` |
| `SUBSCRIBER` | `roles.guard.ts`, `auth.service.ts`, `subscriber-portal.controller.ts`, OIDC/SAML mappers, `appNavigation.js` |
| `subscriberUserId` | 8 modelos Prisma, múltiples servicios de notificación |
| `teamId` | No existe en el repositorio actual |

---

*Documento generado en sesión de análisis 2026-06-22. No implementa ningún cambio funcional. El documento previo `docs/team-subscriber-migration-plan.md` contiene análisis complementario y puede consultarse para referencias adicionales.*
