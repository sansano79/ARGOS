# Plan tecnico: suscriptores basados en equipos

Referencia: GitHub issue #5, "Redisenar suscriptores como equipos con miembros y notificadores".

Fecha de analisis: 2026-06-22.

## Objetivo

Sustituir progresivamente el modelo actual donde un `User` puede actuar como suscriptor por un modelo organizativo donde un equipo es el propietario de suscripciones, sistemas/unidades, preferencias y destinatarios de notificacion.

Este documento no implementa el cambio funcional. Define el estado real del repositorio, dependencias, riesgos, modelo objetivo y una estrategia incremental sin perdida de datos.

## Estado actual inspeccionado

Se revisaron estos puntos del repositorio:

- `prisma/schema.prisma`
- `prisma/migrations/**`
- `prisma/seed.ts` y `prisma/seed-test-subscriber.ts`
- `src/auth/**`
- `src/modules/**`
- `src/app.module.ts`
- `frontend/src/**`
- `package.json`, `frontend/package.json`
- `docker-compose.yml`, `docker/entrypoint.sh`
- `scripts/**`
- `tests/**`

Tambien se consulto la issue #5 mediante `gh issue view 5`.

## Modelo legacy real

El modelo de suscriptor esta concentrado en `User`.

`User` mezcla identidad, login, rol global, estado de cuenta, datos de contacto, flags de notificacion y condicion de suscriptor:

- `role`: rol global textual (`ADMIN`, `VIEWER`, `USER`, `SUBSCRIBER`).
- `canLogin`, `isActive`, `authProvider`, MFA y `lastLoginAt`: control de cuenta.
- `isSubscriber`: marca al usuario como suscriptor.
- `notificationEmail`, `canReceiveNotifications`, `notificationsPaused`, `notificationsPausedUntil`, `communicationLanguage`: preferencias y destino de notificaciones.
- `contactPerson`, `department`, `phone`, `notes`: datos organizativos/contacto.

Tablas directamente ligadas a `User` como suscriptor:

- `UserSubscription` (`user_subscriptions`): suscripciones por usuario (`userId`, `vendor`, `product`, `versions`, `isActive`), con `@@unique([userId, vendor, product])`.
- `SubscriberOwnedSystem` (`subscriber_owned_systems`): sistemas/unidades por `subscriberUserId`, con `@@unique([subscriberUserId, externalId])`.
- `NotificationPolicy` (`notification_policies`): politica por `userId` unico.
- `VulnerabilityNotification` (`vulnerability_notifications`): conserva `contactId` legacy y usa `subscriberUserId`.
- `SmartNotificationReport`: informes inteligentes por `subscriberUserId`.
- `IntelligentNotificationSubscriberMatch`: matches por `subscriberUserId`.
- `IntelligentNotificationTestRun`: pruebas por `subscriberUserId` opcional.
- `PendingDigestNotification`: cola digest por `userId`.
- `SubscriberPatchedCve`: estado parcheado por `userId`.
- `DefenderActionRequest`: acciones por `subscriberUserId`.

El antiguo `ItContact` ya no esta en Prisma. El comentario del schema indica que la tabla historica puede seguir existiendo en base de datos, pero ya no se gestiona desde Prisma. Existe `scripts/migrate-contacts-to-users.ts`, que migra contactos a `User` con `isSubscriber=true`, `canLogin=false`, `notificationEmail` y `UserSubscription`.

## Uso actual en backend

### Autenticacion y autorizacion

- `AuthService.issueAccessToken` firma JWT con `{ sub, email, role }`.
- `JwtStrategy.validate` recarga el usuario y devuelve `id`, `email`, `name`, `role`, `isSubscriber`, `authProvider`.
- `RolesGuard` solo valida `requiredRoles.includes(user.role)`.
- Los roles globales y el concepto de suscriptor estan acoplados: `SUBSCRIBER` es un rol global y tambien se usa como categoria funcional.
- SAML y Azure OIDC mapean roles hacia `ADMIN`, `VIEWER`, `USER`, `SUBSCRIBER`; cuando el rol es `SUBSCRIBER`, tambien activan `isSubscriber`.

No existe autorizacion por equipo ni validacion de membresia, porque no hay `teamId` ni modelo de equipo.

### Usuarios

`UsersService` administra usuarios y suscripciones en el mismo flujo:

- Al crear, si `isSubscriber=true`, fuerza `role='SUBSCRIBER'` y crea `UserSubscription`.
- Al actualizar, si se desactiva `isSubscriber`, borra las `UserSubscription` del usuario.
- Si `canReceiveNotifications=false`, pone `notificationEmail=null`.
- `findAll` y `findOne` devuelven datos de notificacion y suscripciones.

Riesgo: esta logica no debe trasladarse tal cual a equipos, porque borraria suscripciones legacy y mezcla rol global con pertenencia organizativa.

### Portal de suscriptor

`SubscriberPortalController` esta protegido por `@Roles('SUBSCRIBER', 'ADMIN')`.

`SubscriberPortalService` usa siempre `req.user.id`:

- `getProfile(userId)` lee `User` y `UserSubscription`.
- `updateSubscriptions(userId, subscriptions)` reemplaza todas las suscripciones del usuario.
- `getNotifications(userId)` lee `SmartNotificationReport` y `VulnerabilityNotification` por usuario.
- `getVulnerabilities(userId)` deriva CVEs desde informes inteligentes y lee `SubscriberPatchedCve` por usuario.
- `markAsPatched` y `unmarkAsPatched` operan por `userId`.

Este modulo sera uno de los puntos principales para introducir seleccion de equipo y autorizacion por membresia.

### Motor de notificaciones

El motor actual depende intensamente de usuarios suscriptores:

- `VulnerabilityCollectorService.sendAutomaticSubscriberNotifications` busca `user.findMany` con `isSubscriber=true`, `canReceiveNotifications=true`, `notificationsPaused=false`.
- Matchea vulnerabilidades contra `subscriber.subscriptions`.
- Usa `subscriber.notificationEmail || subscriber.email`.
- Registra deduplicacion en `VulnerabilityNotification` por `subscriberUserId` y cola digest en `PendingDigestNotification.userId`.
- `NotificationService` resume destinatarios desde `users` y gestiona `NotificationPolicy` por `userId`.
- `NotificationService.runDigestNotificationJob` agrupa `PendingDigestNotification` por usuario y envia a `user.notificationEmail || user.email`.
- `SmartNotificationsService` carga suscriptores desde `User`, usa `UserSubscription`, `SubscriberOwnedSystem`, `NotificationPolicy`, `SmartNotificationReport`, `IntelligentNotificationSubscriberMatch` e `IntelligentNotificationTestRun`.

Conclusion: el motor de notificaciones no puede migrarse con un simple cambio de schema. Requiere una capa de compatibilidad que entregue "perfiles notificables" tanto legacy como team-based.

### Sistemas/unidades

Hay dos conceptos relacionados pero distintos:

- `ProductAsset`, `DependencyEvidenceImport`, `ProductDependencyInventory` y `VulnerabilityProductImpact` modelan activos/productos para correlacion tecnica.
- `SubscriberOwnedSystem` modela sistemas propiedad del suscriptor legacy, por `subscriberUserId`, usado por notificaciones inteligentes.

El nuevo `TeamSystem` debe partir de `SubscriberOwnedSystem` para compatibilidad con el portal y motor inteligente. No conviene reutilizar directamente `ProductAsset` como sistema de equipo sin un diseno de integracion explicito.

## Uso actual en frontend

El frontend es una SPA React grande en `frontend/src/App.jsx`, con helpers en `frontend/src/utils/appNavigation.js`.

Dependencias relevantes:

- `isViewAllowedForRole` da acceso total a `ADMIN`, portal a `SUBSCRIBER`, y vistas de consulta a `VIEWER`.
- `/subscriber-portal/profile` y `/subscriber-portal/subscriptions` alimentan "Mis Suscripciones".
- La gestion de usuarios muestra `isSubscriber`, `role`, estado de notificaciones y `notificationEmail`.
- Las vistas de notificaciones/recipients muestran usuarios como destinatarios.
- El codigo todavia usa el termino `contacts` para suscriptores filtrados desde `/users` con `u.isSubscriber`.
- Las acciones de notificacion manual usan `contactId` aunque internamente representa `subscriberUserId`.

El frontend oculta/expone vistas por rol global, pero la autorizacion real debe implementarse en backend. En el modelo objetivo, la UI debe seleccionar equipo activo y el backend debe validar siempre membresia y rol de equipo.

## Scripts, seed y despliegue

- `prisma/seed.ts` crea admin/viewer y, opcionalmente, un usuario suscriptor de prueba con `UserSubscription`.
- `prisma/seed-test-subscriber.ts`, `scripts/add-test-subscriber.ts` y `scripts/create-test-subscriber.js` crean usuarios `SUBSCRIBER`.
- `docker/entrypoint.sh` ejecuta `prisma migrate deploy` por defecto y solo despues intenta seed.
- `PRISMA_DB_PUSH_ON_START` existe pero no debe usarse como solucion permanente.
- `README.md` todavia documenta `prisma db push` para algunos escenarios de produccion, lo que contradice el objetivo de migraciones reproducibles.

## Problema de migraciones

La cadena actual de Prisma no contiene una migracion inicial que cree el esquema completo. La primera migracion real (`20260321160000_auth_provider_mfa`) presupone que `users` ya existe y solo anade columnas. Migraciones posteriores tambien presuponen tablas como `vulnerabilities`, `notification_policies` y `notification_logs`.

Consecuencias:

- `npx prisma migrate deploy` falla sobre una base vacia.
- El entorno de pruebas tuvo que inicializarse con `prisma db push` y luego marcar migraciones como baseline.
- El entrypoint de Docker falla en primer arranque contra una base vacia si no existe un baseline real.

Solucion permanente propuesta:

1. Crear una migracion baseline inicial anterior a todas las migraciones existentes, por ejemplo `prisma/migrations/20260320000000_initial_schema_baseline/migration.sql`.
2. Esa migracion debe crear el esquema legacy completo necesario para que las migraciones posteriores puedan aplicarse en una base vacia.
3. Generar el SQL desde `prisma/schema.prisma` actual, pero revisarlo manualmente para evitar incluir tablas nuevas de equipos antes de su fase.
4. Validar en base efimera vacia: `npx prisma migrate deploy` debe aplicar baseline + migraciones existentes sin `db push`.
5. Para bases existentes creadas por `db push`, documentar un procedimiento de `prisma migrate resolve --applied 20260320000000_initial_schema_baseline` si el esquema ya coincide.
6. No modificar ni borrar migraciones ya aplicadas en entornos compartidos.
7. Anadir una prueba/script CI de migracion en MySQL vacio que ejecute `prisma migrate deploy`.

Notas:

- Prisma ordena migraciones por nombre, asi que el timestamp del baseline debe ser anterior a `20260321160000_auth_provider_mfa`.
- El baseline debe ser idempotente o, como minimo, solo aplicarse en bases vacias. Para bases con datos, debe marcarse como aplicada, no ejecutarse.
- Las migraciones deploy-safe existentes con `information_schema` ayudan a bases ya evolucionadas, pero no sustituyen la creacion inicial de tablas.

## Modelo objetivo inicial

Mantener separados estos conceptos:

- `User`: identidad, autenticacion, login, rol global, MFA, estado de cuenta.
- `SubscriberTeam`: unidad organizativa suscriptora.
- `TeamMember`: relacion entre usuario y equipo, con rol de equipo y estado.
- `NotificationRecipient`: destinatario de correo sin obligacion de login.
- `TeamSubscription`: suscripcion propiedad del equipo.
- `TeamSystem`: sistema/unidad propiedad del equipo.

### Propuesta Prisma ajustada al proyecto

El proyecto usa MySQL, `Int @id @default(autoincrement())`, nombres camelCase en Prisma, snake_case con `@map`, `createdAt`/`updatedAt`, booleans `isActive`, strings para roles y tipos, y JSON almacenado como `String? @db.Text` o `@db.LongText`.

Propuesta inicial aditiva:

```prisma
model SubscriberTeam {
  id          Int      @id @default(autoincrement())
  name        String
  code        String   @unique
  description String?  @db.Text
  isActive    Boolean  @default(true) @map("is_active")
  createdAt   DateTime @default(now()) @map("created_at")
  updatedAt   DateTime @updatedAt @map("updated_at")

  members      TeamMember[]
  recipients   NotificationRecipient[]
  subscriptions TeamSubscription[]
  systems      TeamSystem[]

  @@index([name])
  @@index([isActive])
  @@map("subscriber_teams")
}

model TeamMember {
  id        Int      @id @default(autoincrement())
  teamId    Int      @map("team_id")
  userId    Int      @map("user_id")
  role      String
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
  type       String    @default("MAILBOX")
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
  id          Int      @id @default(autoincrement())
  teamId      Int      @map("team_id")
  externalId  String?  @map("external_id")
  source      String   @default("manual")
  name        String
  description String?  @db.Text
  hostname    String?
  fqdn        String?
  platform    String?
  osVersion   String?  @map("os_version")
  riskLevel   String?  @map("risk_level")
  healthStatus String? @map("health_status")
  isSelected  Boolean  @default(true) @map("is_selected")
  isActive    Boolean  @default(true) @map("is_active")
  tags        String?  @db.Text
  rawData     String?  @map("raw_data") @db.LongText
  createdAt   DateTime @default(now()) @map("created_at")
  updatedAt   DateTime @updatedAt @map("updated_at")

  team SubscriberTeam @relation(fields: [teamId], references: [id], onDelete: Cascade)

  @@unique([teamId, externalId])
  @@index([teamId])
  @@map("team_systems")
}
```

Cambios necesarios en `User`:

```prisma
teamMemberships TeamMember[]
```

No se recomienda usar enums Prisma en la primera iteracion porque el proyecto usa `String` para roles y estados, incluyendo `User.role`. Si se decide introducir enums, debe hacerse de forma consistente y con migracion cuidada en MySQL.

### Roles iniciales

Roles globales de aplicacion:

- `ADMIN`: administracion global.
- `VIEWER`/`USER`: acceso general segun politica actual.
- `SUBSCRIBER`: legacy, debe mantenerse mientras exista portal legacy.

Roles de equipo:

- `TEAM_MANAGER`: consulta equipo, gestiona suscripciones, sistemas/unidades y destinatarios; gestion de miembros puede quedar para una fase posterior si se desea reducir alcance.
- `TEAM_VIEWER`: consulta vision general, catalogo, vulnerabilidades relevantes, sistemas, suscripciones; no modifica configuracion ni recursos.

No mezclar `User.role` con `TeamMember.role`.

## Autorizacion e aislamiento

Principio obligatorio: ningun endpoint debe confiar en `teamId` recibido del cliente sin validar membresia.

Patron recomendado:

1. Crear un servicio `TeamAccessService`.
2. Para cada request con `teamId`, resolver `userId` desde JWT.
3. Si `User.role === 'ADMIN'`, permitir segun accion administrativa, idealmente registrando modo admin.
4. Si no es admin, buscar `TeamMember` activo por `{ teamId, userId, isActive: true }`.
5. Validar rol de equipo contra accion:
   - lectura: `TEAM_MANAGER` o `TEAM_VIEWER`;
   - escritura: `TEAM_MANAGER`.
6. Usar el `teamId` validado para todas las queries posteriores.
7. No aceptar `userId`/`subscriberUserId` arbitrario desde cliente en endpoints de equipo.

Este patron evita IDOR por cambio manual de `teamId`.

Endpoints sugeridos:

- Admin:
  - `GET /subscriber-teams`
  - `POST /subscriber-teams`
  - `GET /subscriber-teams/:teamId`
  - `PUT /subscriber-teams/:teamId`
  - `POST /subscriber-teams/:teamId/members`
  - `PUT /subscriber-teams/:teamId/members/:memberId`
  - `POST /subscriber-teams/:teamId/recipients`
  - `PUT /subscriber-teams/:teamId/recipients/:recipientId`
- Equipo:
  - `GET /teams/:teamId/overview`
  - `GET /teams/:teamId/subscriptions`
  - `PUT /teams/:teamId/subscriptions` (`TEAM_MANAGER`)
  - `GET /teams/:teamId/systems`
  - `PUT /teams/:teamId/systems` (`TEAM_MANAGER`)
  - `GET /teams/:teamId/recipients`
  - `POST /teams/:teamId/recipients` (`TEAM_MANAGER`)

El naming final puede adaptarse al estilo actual (`subscriber-portal`) pero conviene evitar que el portal nuevo parezca una extension de `UserSubscription`.

## Compatibilidad progresiva

No eliminar en esta etapa:

- `User.isSubscriber`
- `User.notificationEmail`
- `User.canReceiveNotifications`
- `UserSubscription`
- `SubscriberOwnedSystem`
- `NotificationPolicy.userId`
- `PendingDigestNotification.userId`
- `VulnerabilityNotification.subscriberUserId`
- `SmartNotificationReport.subscriberUserId`
- `IntelligentNotificationSubscriberMatch.subscriberUserId`
- `SubscriberPatchedCve.userId`

Estrategia de compatibilidad:

1. Mantener el motor legacy sin cambios mientras se introducen tablas de equipo.
2. Crear servicios nuevos que lean/escriban `SubscriberTeam`, `TeamMember`, `NotificationRecipient`, `TeamSubscription`, `TeamSystem`.
3. Introducir una capa de lectura comun para notificaciones, por ejemplo `NotificationAudienceService`, que pueda devolver:
   - audiencias legacy por `User`;
   - audiencias team-based por `SubscriberTeam` + `NotificationRecipient`.
4. Durante la transicion, permitir que un equipo tenga datos migrados desde un usuario legacy sin borrar el usuario ni sus suscripciones.
5. Solo cuando los jobs usen la capa comun, activar notificaciones por equipo con feature flag o configuracion.

## Migracion de datos propuesta

La migracion debe ser explicita, reversible y auditable. No debe ejecutarse automaticamente al desplegar la migracion de schema.

### Paso A: schema aditivo

Crear tablas de equipo vacias. Sin mover datos. Sin modificar tablas legacy salvo relacion Prisma `User.teamMemberships`.

### Paso B: script dry-run

Crear un script de migracion con `--dry-run` que proponga equipos a partir de usuarios legacy:

- Por cada `User` con `isSubscriber=true`, crear candidato `SubscriberTeam`.
- `name`: `department` si existe, si no `name`.
- `code`: slug estable basado en email/departamento con sufijo si colisiona.
- Crear `TeamMember` para el propio usuario solo si `canLogin=true`, rol `TEAM_MANAGER`.
- Crear `NotificationRecipient` si existe `notificationEmail` o `email` y `canReceiveNotifications=true`.
- Copiar `UserSubscription` a `TeamSubscription`.
- Copiar `SubscriberOwnedSystem` a `TeamSystem`.

No crear miembros para usuarios `canLogin=false`; esos usuarios legacy representan hoy contactos/notificadores y deben convertirse principalmente en `NotificationRecipient`.

### Paso C: ejecucion opt-in

Ejecutar con un flag explicito, por ejemplo:

```bash
npx ts-node scripts/migrate-user-subscribers-to-teams.ts --execute
```

Debe registrar un resumen:

- usuarios legacy considerados;
- equipos creados;
- equipos omitidos por colision;
- miembros creados;
- destinatarios creados;
- suscripciones copiadas;
- sistemas copiados;
- errores por fila.

### Paso D: trazabilidad

Para reversibilidad sin borrar datos legacy, la forma mas segura es no mover ni borrar, solo copiar. Opcionalmente se puede anadir una tabla tecnica de mapeo:

- `LegacySubscriberTeamMapping`
  - `legacyUserId`
  - `teamId`
  - `migrationBatchId`
  - `createdAt`

Si no se quiere nueva tabla, el script debe emitir JSON/CSV persistido fuera de la DB para poder auditar.

### Paso E: validacion

Validar conteos antes de activar lectura/escritura:

- Cada usuario legacy migrado tiene un equipo.
- Numero de `TeamSubscription` por equipo coincide con `UserSubscription` activa del usuario.
- Numero de `TeamSystem` coincide con `SubscriberOwnedSystem` activo.
- Destinatarios normalizados no duplican email dentro de equipo.

## Fases de implementacion verificables

### Fase 0: saneamiento de migraciones

Objetivo: `npx prisma migrate deploy` funciona sobre MySQL vacio.

Tareas:

- Crear baseline inicial anterior a las migraciones existentes.
- Documentar `migrate resolve` para bases existentes.
- Anadir prueba/script de migracion sobre base vacia.
- Actualizar README/operativa para dejar de recomendar `db push` como camino normal.

Verificacion:

- MySQL vacio + `npx prisma migrate deploy` termina correctamente.
- `npx prisma generate` funciona.
- `npm test` sigue pasando.

### Fase 1: schema y servicios base de equipos

Objetivo: anadir modelo de equipos sin tocar comportamiento legacy.

Tareas:

- Anadir modelos Prisma aditivos.
- Crear modulo NestJS de equipos.
- Crear DTOs y validaciones.
- Crear `TeamAccessService`.
- Crear endpoints admin minimos.
- Pruebas unitarias de autorizacion y aislamiento.

Verificacion:

- Admin crea equipo, miembro y destinatario.
- Usuario miembro puede leer solo su equipo.
- `TEAM_VIEWER` no puede escribir.
- Cambiar `teamId` a otro equipo devuelve 403/404.
- Legacy `/subscriber-portal` y jobs siguen funcionando igual.

### Fase 2: migracion opt-in de datos legacy

Objetivo: copiar datos legacy hacia equipos sin desactivar legacy.

Tareas:

- Script dry-run/execute.
- Mapeo o reporte persistente.
- Validadores de conteo.
- Documentacion de rollback logico: desactivar uso team-based y conservar legacy.

Verificacion:

- Dry-run no escribe.
- Execute es idempotente.
- No borra `UserSubscription` ni `SubscriberOwnedSystem`.
- Conteos coinciden.

### Fase 3: portal team-aware

Objetivo: permitir que usuarios con membresia gestionen recursos del equipo.

Tareas:

- Endpoint `GET /me/teams` o ampliar `/auth/me` con equipos activos.
- Selector de equipo activo en frontend.
- Vistas de suscripciones/sistemas/destinatarios por equipo.
- Backend valida membresia en cada request.
- Mantener portal legacy para `SUBSCRIBER` durante transicion.

Verificacion:

- Un usuario con dos equipos ve ambos y cambia contexto.
- `TEAM_MANAGER` edita solo su equipo.
- `TEAM_VIEWER` ve pero no guarda.
- Usuario de equipo A no accede a equipo B modificando `teamId`.

### Fase 4: notificaciones por equipo

Objetivo: desacoplar destinatarios de usuarios.

Tareas:

- Crear capa `NotificationAudienceService`.
- Adaptar matching de suscripciones para `TeamSubscription`.
- Enviar a `NotificationRecipient` activos del equipo.
- Registrar logs con metadatos de `teamId` y `recipientId` sin romper logs legacy.
- Definir deduplicacion por equipo, vulnerabilidad y destinatario/equipo.

Posibles cambios de schema adicionales:

- `VulnerabilityNotification.teamId`
- `VulnerabilityNotification.notificationRecipientId`
- `PendingDigestNotification.teamId`
- `SmartNotificationReport.teamId`
- `IntelligentNotificationSubscriberMatch.teamId`
- `SubscriberPatchedCve.teamId` o nueva `TeamPatchedCve`

Verificacion:

- Un usuario miembro sin notificaciones no recibe correo.
- Un destinatario sin login recibe correo.
- Dos equipos con la misma suscripcion no comparten historico ni estado.
- Deduplicacion no bloquea envios de otro equipo.

### Fase 5: retirada gradual de legacy

Objetivo: dejar `User` como identidad y retirar acoplamientos de suscriptor cuando ya no haya consumidores.

Tareas:

- Marcar campos legacy como deprecated en codigo y documentacion.
- Bloquear nuevas escrituras legacy salvo compatibilidad.
- Migrar informes, patched CVEs y acciones a team-based.
- Mantener scripts de auditoria.
- Plan posterior para eliminar columnas/tablas legacy.

Verificacion:

- No quedan llamadas funcionales a `UserSubscription` para flujos nuevos.
- Jobs trabajan solo con equipos o con capa comun.
- Los datos historicos se siguen consultando.

## Riesgos principales

- IDOR por aceptar `teamId` del cliente sin validar `TeamMember`.
- Mezcla accidental de rol global `USER/ADMIN` con rol de equipo `TEAM_MANAGER/TEAM_VIEWER`.
- Duplicacion o perdida de notificaciones si se cambia deduplicacion de usuario a equipo sin periodo de compatibilidad.
- Borrado destructivo de suscripciones legacy por reutilizar `UsersService.update` o `SubscriberPortalService.updateSubscriptions`.
- Que un usuario con acceso a varios equipos vea datos agregados sin filtro por equipo.
- Incompatibilidad de migraciones en bases existentes si el baseline se ejecuta en una DB ya poblada.
- Frontend ocultando botones sin respaldo backend.
- Scripts de test/seed creando `SUBSCRIBER` legacy y generando datos paralelos no migrados.
- `NotificationPolicy` por usuario no representa preferencias de equipo; migrarla exige decidir si la politica pertenece al equipo, al destinatario o a ambos.
- `SubscriberOwnedSystem` tiene campos mas ricos que el `TeamSystem` minimo de la issue; conviene conservar campos operativos para no degradar notificaciones inteligentes.

## Decisiones recomendadas antes de implementar

- Confirmar si `SUBSCRIBER` seguira existiendo como rol global durante toda la transicion o si los usuarios de equipo usaran `USER`/`VIEWER` global + roles de equipo.
- Confirmar si `NotificationPolicy` futura pertenece al equipo, al destinatario o a una combinacion.
- Confirmar si `TEAM_MANAGER` gestionara miembros en Fase 1 o se limita inicialmente a suscripciones/sistemas/destinatarios.
- Confirmar formato de `code` de equipo: slug manual, autogenerado o codigo corporativo.
- Confirmar si los historicos (`SmartNotificationReport`, `VulnerabilityNotification`, patched CVEs) deben verse por equipo desde la primera version o solo despues de migrar jobs.

## Referencias legacy localizadas

Referencias relevantes encontradas:

- `isSubscriber`: `User`, auth, usuarios, portal, notificaciones, smart notifications, scripts y frontend.
- `notificationEmail`: auth/me, usuarios, password reset, notificaciones, smart notifications, scripts y frontend.
- `UserSubscription`: schema, usuarios, portal, collector, smart notifications, scripts y seeds.
- `SubscriberOwnedSystem`: schema y smart notifications.
- `subscriptions`: relaciones Prisma, servicios de usuarios/portal, collector, smart notifications y frontend.
- `ownedSystems`: smart notifications.
- `canReceiveNotifications`: usuarios, notificaciones, smart notifications, frontend.
- `notificationPolicy`: schema, notification service, collector, smart notifications.
- `role`, `ADMIN`, `USER`, `VIEWER`, `SUBSCRIBER`: guards, auth, OIDC/SAML, controladores y navegacion frontend.

## Proximo paso recomendado

Empezar por Fase 0. Sin una cadena de migraciones reproducible, cualquier schema nuevo de equipos agrava el problema actual y deja el despliegue dependiendo de `db push` o baselines manuales.
