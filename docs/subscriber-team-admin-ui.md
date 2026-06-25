# Subscriber Team Admin UI (Fase 1C)

## 1. Alcance

Esta fase añade una interfaz administrativa en el frontend para gestionar equipos suscriptores usando los endpoints backend de Fase 1B.

Incluye:

- listado de equipos suscriptores;
- alta y edición de equipos;
- detalle por pestañas;
- gestión de miembros;
- gestión de destinatarios;
- gestión de suscripciones;
- gestión de sistemas/unidades;
- control visual por permisos;
- estados de carga, vacío, error, guardado y confirmación;
- pruebas frontend con la infraestructura actual del repositorio.

No incluye:

- migración automática del modelo legacy;
- cambios en Prisma;
- cambios en el motor de notificaciones;
- sustitución del portal legacy;
- cambios de backend fuera del contrato ya disponible.

---

## 2. Navegación

Se añade una nueva entrada administrativa visible solo para `ADMIN`:

- `Equipos suscriptores`

Rutas soportadas en el frontend:

- `/admin/subscriber-teams`
- `/admin/subscriber-teams/:teamId`

La visibilidad del menú es solo una medida de UX. La autorización real sigue dependiendo del backend.

---

## 3. Arquitectura

Se crea el módulo:

```text
frontend/src/features/subscriber-teams/
├── api/
│   ├── subscriberTeamsApi.js
│   └── subscriberTeamsApi.test.js
├── components/
│   ├── ConfirmDialog.jsx
│   ├── EmptyState.jsx
│   ├── MemberForm.jsx
│   ├── RecipientForm.jsx
│   ├── SubscriptionForm.jsx
│   ├── SystemForm.jsx
│   ├── TeamForm.jsx
│   ├── TeamMembersPanel.jsx
│   ├── TeamRecipientsPanel.jsx
│   ├── TeamsList.jsx
│   ├── TeamStatusBadge.jsx
│   ├── TeamSubscriptionsPanel.jsx
│   ├── TeamSummary.jsx
│   ├── TeamSystemsPanel.jsx
│   └── TeamUi.jsx
├── pages/
│   ├── SubscriberTeamDetailPage.jsx
│   └── SubscriberTeamsPage.jsx
└── utils/
    ├── teamForms.js
    ├── teamForms.test.js
    ├── teamPermissions.js
    ├── teamPermissions.test.js
    ├── teamViewModel.js
    └── teamViewModel.test.js
```

La integración global se limita a:

- `frontend/src/App.jsx`
- `frontend/src/utils/appNavigation.js`
- `frontend/src/utils/appNavigation.test.js`

---

## 4. Llamadas API

Cliente centralizado: `subscriberTeamsApi.js`

Operaciones cubiertas:

- `listTeams`
- `createTeam`
- `getTeam`
- `updateTeam`
- `listMembers`
- `addMember`
- `updateMember`
- `removeMember`
- `listRecipients`
- `createRecipient`
- `updateRecipient`
- `removeRecipient`
- `listSubscriptions`
- `createSubscription`
- `updateSubscription`
- `removeSubscription`
- `listSystems`
- `createSystem`
- `updateSystem`
- `removeSystem`
- `listUsers`

El cliente reutiliza el `apiFetch` ya existente en `App.jsx`, por lo que conserva:

- token actual;
- cabecera `Authorization`;
- base URL `/api`;
- limpieza de sesión cuando el backend devuelve `401`.

---

## 5. Pantallas

### Listado

Título: `Equipos suscriptores`

Contenido:

- nombre;
- código;
- estado;
- número de miembros;
- número de destinatarios;
- número de suscripciones;
- número de sistemas;
- fecha de actualización;
- acciones `Abrir`, `Editar`, `Activar/Desactivar`.

Extras:

- búsqueda por nombre o código;
- filtro activo/inactivo;
- orden estable;
- estado vacío;
- estado de carga;
- error controlado;
- botón `Crear equipo`.

### Detalle

Cabecera:

- nombre;
- código;
- estado;
- botón de vuelta al listado.

Pestañas:

1. `Resumen`
2. `Miembros`
3. `Destinatarios`
4. `Suscripciones`
5. `Sistemas / unidades`

---

## 6. Formularios

### Equipo

Campos:

- nombre;
- código;
- descripción;
- activo.

### Miembro

Campos:

- usuario existente;
- rol de equipo;
- activo.

El selector usa `/api/users` y marca como deshabilitados los usuarios que ya son miembros.

### Destinatario

Campos:

- email;
- nombre;
- tipo;
- idioma;
- zona horaria;
- activo.

`verifiedAt` no se muestra como editable y no se envía al backend.

### Suscripción

Campos:

- fabricante;
- producto;
- versiones en CSV;
- activa.

### Sistema / unidad

Secciones:

- `Información principal`
- `Datos técnicos`
- `Estado`

Campos usados en esta fase:

- name;
- externalId;
- source solo en alta;
- hostname;
- fqdn;
- platform;
- osVersion;
- description;
- riskLevel;
- healthStatus;
- isSelected;
- isActive.
- tags.

`rawData` no aparece ni se envía.

---

## 7. Permisos

Utilidades centralizadas en `teamPermissions.js`:

- `canAccessSubscriberTeamsAdmin`
- `canViewTeam`
- `canManageTeam`
- `canManageMembers`
- `canManageRecipients`
- `canManageSubscriptions`
- `canManageSystems`

En esta fase la UI admin queda limitada a `ADMIN`.

---

## 8. Estados

Estados contemplados:

- loading;
- empty;
- error;
- success;
- saving;
- deleting;
- disabled.

Se usan:

- mensajes inline de error y éxito;
- modales de confirmación;
- tablas compactas;
- badges de estado para activo/inactivo.

---

## 9. Errores

Mapeo frontend:

- `400` → revisar campos;
- `401` → sesión caducada;
- `403` → sin permisos;
- `404` → recurso no disponible;
- `409` → duplicado o conflicto;
- `500+` → error interno;
- red / fetch → servicio no disponible.

No se muestran trazas internas ni payloads completos del backend.

---

## 10. Accesibilidad

Medidas aplicadas:

- `label` asociado a inputs;
- diálogos con `role="dialog"` y `aria-modal`;
- foco inicial en modal;
- restauración de foco al cerrar;
- botones con texto;
- tablas con cabeceras;
- estados activos/inactivos con texto;
- confirmaciones sin depender de `window.confirm`.

---

## 11. Pruebas

Infraestructura real disponible en frontend:

- no existe script `npm test`;
- el repositorio ya usa `node:test` en archivos `.test.js`.

Cobertura añadida:

- permisos admin y no admin;
- navegación admin `/admin/subscriber-teams`;
- validaciones de formularios;
- normalización de payloads;
- exclusión de campos no permitidos (`verifiedAt`, `rawData`);
- `source` omitido en update de sistemas;
- filtros y resumen de workspace;
- mapeo de errores;
- cliente API del módulo.

Limitación:

- no se ha introducido un framework DOM/E2E nuevo en esta fase;
- por tanto, varias comprobaciones visuales/interactivas quedan cubiertas indirectamente por utilidades y por build del frontend, no por pruebas de click/render completo.

---

## 12. Procedimiento manual

Preparado para ejecutar más adelante en LXC:

1. Entrar como `ADMIN`.
2. Abrir `Equipos suscriptores`.
3. Crear `IT España` con código `it-es`.
4. Abrir el detalle del equipo creado.
5. Añadir al administrador actual como `Gestor del equipo`.
6. Añadir destinatario `vulnerabilidades-it@example.local`.
7. Añadir suscripción `vendor=microsoft`, `product=windows server`.
8. Añadir sistema `Servidor ERP España`.
9. Editar equipo, miembro, destinatario, suscripción y sistema.
10. Validar estados vacíos en un equipo sin datos.
11. Desactivar y volver a activar el equipo.
12. Confirmar que la configuración global sigue limitada a `ADMIN`.

No se ha ejecutado aún contra el LXC.

---

## 13. Limitaciones

1. `GET /subscriber-teams` solo devuelve conteo nativo de miembros activos. Para los demás contadores del listado se hace enriquecimiento frontend con llamadas adicionales.
2. No hay paginación backend para equipos; la tabla muestra la colección completa.
3. `UpdateSystemDto` no acepta `source`; la UI lo mantiene en alta y lo omite en edición para evitar `400`.
4. No se ha añadido framework de test de componentes o navegador en esta fase.

---

## 14. Siguiente fase

Trabajo posterior recomendado:

- ampliar contrato backend de sistemas para `healthStatus` y `tags` si se confirma como requisito de edición;
- validar el flujo completo con navegador en entorno local/LXC;
- preparar integración del modelo team-based con el portal y el motor de notificaciones sin sustituir todavía el legacy.
