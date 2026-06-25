# User / Team Responsibility Model

## Alcance

Este ajuste introduce un modelo provisional de autorización y responsabilidad para separar:

- administración global de usuarios;
- gestión funcional de equipos suscriptores;
- compatibilidad temporal con el modelo legacy de notificaciones.

No elimina roles, enums, columnas ni lógica histórica. Oculta en la UI ordinaria lo que no se usa en esta fase y conserva el resto para evolución posterior.

## Responsabilidad de `User`

`User` queda limitado a:

- identidad;
- autenticación;
- email de acceso;
- permiso de inicio de sesión;
- rol global;
- estado activo/inactivo;
- contraseña en alta o cambio explícito;
- asignación administrativa inicial a equipos existentes.

La interfaz ordinaria de usuarios ya no expone suscripciones, destinatarios ni sistemas individuales.

## Responsabilidad de `SubscriberTeam`

`SubscriberTeam` representa la unidad funcional que agrupa:

- contexto organizativo;
- miembros con acceso;
- destinatarios de notificación;
- suscripciones del equipo;
- sistemas y unidades del equipo.

## Responsabilidad de `TeamMember`

`TeamMember` gestiona:

- pertenencia de un usuario a un equipo;
- rol interno dentro del equipo;
- activación o desactivación de esa pertenencia.

No sustituye el rol global del usuario.

## Responsabilidad de `NotificationRecipient`

`NotificationRecipient` gestiona:

- destino de notificaciones;
- email;
- idioma;
- zona horaria;
- tipo de destinatario;
- estado activo.

Puede existir sin acceso a la aplicación.

## Responsabilidad de `TeamSubscription`

`TeamSubscription` centraliza:

- vendor;
- product;
- versions;
- estado activo.

Sustituye funcionalmente la creación de nuevas suscripciones individuales desde la UI ordinaria.

## Responsabilidad de `TeamSystem`

`TeamSystem` centraliza:

- sistemas y unidades del equipo;
- datos técnicos asociados;
- estado operativo;
- selección funcional.

No se crean ni se editan ya desde la gestión ordinaria de usuarios.

## Roles globales visibles en esta fase

La UI ordinaria muestra inicialmente:

- `ADMIN` → Administrador de plataforma
- `TEAM_MANAGER` → Gestor de equipo
- `USER` → Usuario

Otros roles globales existentes se conservan internamente, no se eliminan y quedan reservados para fases posteriores.

## Roles internos de equipo activos

La asignación ordinaria de equipos usa inicialmente:

- `TEAM_MANAGER` → Gestor del equipo
- `TEAM_VIEWER` → Solo consulta

Otros roles internos preexistentes, si existen, deben permanecer compatibles a nivel de datos aunque no se expongan en esta fase.

## Matriz provisional de permisos

### `ADMIN`

Solo `ADMIN` puede:

- crear usuarios globales;
- editar usuarios globales;
- activar o desactivar usuarios;
- asignar roles globales;
- crear equipos;
- editar cualquier equipo;
- activar o desactivar cualquier equipo;
- asignar inicialmente usuarios a equipos;
- asignar o modificar el rol interno de cualquier miembro.

### `TEAM_MANAGER`

`TEAM_MANAGER` global significa que la plataforma autoriza al usuario a poder gestionar equipos, pero no le concede por sí solo acceso operativo.

Para gestionar un equipo deben cumplirse ambas condiciones:

- tener rol global `TEAM_MANAGER` o `ADMIN`;
- tener membresía activa en ese equipo con rol interno `TEAM_MANAGER`.

Un `TEAM_MANAGER` no puede:

- crear usuarios globales;
- editar usuarios globales;
- cambiar roles globales;
- asignar `ADMIN`;
- conceder el rol global `TEAM_MANAGER`;
- administrar equipos ajenos a sus membresías activas;
- eliminar equipos;
- modificar configuración global.

### `USER`

`USER` puede mantener acceso ordinario a la aplicación según la navegación que tenga habilitada, pero en esta fase:

- no administra usuarios globales;
- no administra equipos por sí mismo;
- solo puede recibir asignación inicial como miembro con rol interno `TEAM_VIEWER`.

## Reglas de compatibilidad entre rol global y rol interno

Las reglas activas en esta fase son:

- un `ADMIN` puede asignarse a cualquier equipo con `TEAM_MANAGER` o `TEAM_VIEWER`;
- un `TEAM_MANAGER` global puede asignarse con `TEAM_MANAGER` o `TEAM_VIEWER`;
- un `USER` solo puede asignarse inicialmente como `TEAM_VIEWER`;
- el frontend no permite roles internos desconocidos;
- el backend valida la compatibilidad para impedir escaladas por payload manual.

## Flujo de creación y edición de usuarios

El formulario global de usuario conserva:

- nombre;
- email;
- permitir inicio de sesión;
- rol global;
- contraseña en alta o cambio explícito;
- estado en edición;
- sección `Equipos asignados`.

Se retiran de la UI ordinaria:

- usuario suscriptor de alertas;
- puede recibir notificaciones;
- notificaciones en pausa;
- pausa hasta;
- email de notificación;
- idioma de comunicación de alertas;
- suscripciones individuales;
- sistemas individuales.

La pantalla muestra además la nota:

`Los accesos se gestionan desde Usuarios. Los destinatarios, suscripciones y sistemas se gestionan desde Equipos suscriptores.`

## Asignación inicial a equipos

La sección `Equipos asignados` permite al `ADMIN`:

- ver equipos existentes;
- seleccionar uno o varios equipos sin introducir IDs manualmente;
- escoger un rol interno compatible por equipo;
- retirar asignaciones del formulario.

La sincronización actual se trata como estado completo del formulario:

- las asignaciones incluidas se crean o reactivan;
- las asignaciones existentes omitidas se desactivan;
- todo se ejecuta en una transacción para evitar estados parciales.

## Separación entre gestión de usuarios y gestión de equipos

Gestión de usuarios:

- identidad;
- acceso;
- rol global;
- asignación inicial a equipos.

Gestión de equipos:

- miembros;
- roles internos;
- destinatarios;
- suscripciones;
- sistemas.

La pantalla del equipo no puede cambiar el rol global del usuario.

## Campos legacy conservados

Se mantienen temporalmente por compatibilidad:

- `User.isSubscriber`;
- `User.notificationEmail`;
- `User.canReceiveNotifications`;
- `User.notificationsPaused`;
- `User.notificationsPausedUntil`;
- `User.communicationLanguage`;
- `UserSubscription`.

No se eliminan ni se migran en esta fase.

## Estrategia de transición incremental

- Los usuarios nuevos creados desde la UI ordinaria no envían campos legacy de suscripción o notificación.
- El backend asigna valores neutros cuando esos campos no llegan.
- La edición ordinaria no sobrescribe preferencias legacy ni borra `UserSubscription` si el formulario no las modifica.
- La administración debe gestionar destinatarios, suscripciones y sistemas desde `Equipos suscriptores`.
- Los roles no visibles en esta fase quedan conservados para uso futuro.

## Riesgos de duplicidad y limitaciones actuales

Mientras siga existiendo el motor legacy, pueden convivir:

- usuarios históricos con `isSubscriber=true`;
- `UserSubscription` activas heredadas;
- nuevos equipos con `NotificationRecipient`, `TeamSubscription` y `TeamSystem`.

Limitaciones actuales:

- la visibilidad inicial de roles globales en la UI está restringida a `ADMIN`, `TEAM_MANAGER` y `USER`;
- la compatibilidad de roles internos está acotada a `TEAM_MANAGER` y `TEAM_VIEWER`;
- la sincronización de equipos desde usuarios usa reemplazo completo del estado enviado por el formulario;
- no se ha migrado todavía el motor real de notificaciones.

## Fase futura

La siguiente transición deberá:

- mover la lógica de audiencia del motor de notificaciones a equipos;
- migrar datos legacy a `SubscriberTeam`;
- retirar escrituras nuevas sobre `UserSubscription`;
- decidir la apertura de más roles globales e internos en UI;
- eliminar la semántica de `User` como suscriptor funcional.
