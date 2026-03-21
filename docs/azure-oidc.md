# Azure AD (Entra ID) OIDC — Login con client secret (intranet)

Este modo usa Authorization Code + PKCE en backend y un “redirect con token” al frontend.

## URLs

- Login: `https://TU_HOST/api/auth/azure/login`
- Callback: `https://TU_HOST/api/auth/azure/callback`

En `.env.prod`:
- `FRONTEND_BASE_URL=https://TU_HOST/`
- `AZURE_OIDC_REDIRECT_URI=https://TU_HOST/api/auth/azure/callback`

## Azure: qué configurar

Azure Portal → App registrations → tu app.

- Authentication
  - Add a platform → Web
  - Redirect URI:
    - `https://TU_HOST/api/auth/azure/callback`
- Certificates & secrets
  - New client secret
  - Copia el valor a `AZURE_OIDC_CLIENT_SECRET`
- Overview
  - Copia:
    - Directory (tenant) ID → `AZURE_TENANT_ID`
    - Application (client) ID → `AZURE_OIDC_CLIENT_ID`

## Roles por grupos (recomendado)

La forma más estable es asignar **App Roles** a **grupos** (en lugar de depender del claim `groups`).

1) App registration → App roles:
   - Crea roles con valores: `ADMIN`, `VIEWER`, `SUBSCRIBER`
2) Enterprise application (Service principal) → Users and groups:
   - Asigna el grupo correspondiente a cada App Role
3) Azure emitirá el claim `roles` en el token y la aplicación lo prioriza automáticamente.

## Roles por usuarios (tenant de prueba)

Si en tu tenant solo puedes asignar **usuarios** (y no grupos), asigna el App Role directamente al usuario en:

- Enterprise application (Service principal) → Users and groups → Add user/group

La aplicación leerá igualmente el claim `roles`.

Si en Azure tus App Roles tienen valores “humanos” (ej. `administradores`) y no `ADMIN/VIEWER/SUBSCRIBER`, puedes mapearlos en:

`AZURE_OIDC_APP_ROLE_VALUE_MAP={"administradores":"ADMIN","viewer":"VIEWER","suscriptor":"SUBSCRIBER"}`

Alternativa: si prefieres el claim `groups`, configura groupMembershipClaims y mapea ObjectId de grupos en:

`AZURE_OIDC_GROUP_ROLE_MAP={"<GROUP_OBJECT_ID_ADMIN>":"ADMIN","<GROUP_OBJECT_ID_SUBSCRIBER>":"SUBSCRIBER"}`

Si no hay grupos o el mapa está vacío, aplica `AZURE_OIDC_DEFAULT_ROLE`.

## Override por usuario (fallback)

Si no puedes (o no quieres) usar App Roles/grupos todavía, puedes forzar el rol por email:

`AZURE_OIDC_USER_ROLE_MAP={"admin@empresa.com":"ADMIN","viewer@empresa.com":"VIEWER"}`

## Variables de entorno requeridas

```env
AZURE_OIDC_ENABLED=true
AZURE_TENANT_ID=...
AZURE_OIDC_CLIENT_ID=...
AZURE_OIDC_CLIENT_SECRET=...
AZURE_OIDC_REDIRECT_URI=https://TU_HOST/api/auth/azure/callback
AZURE_OIDC_DEFAULT_ROLE=USER
AZURE_OIDC_GROUP_ROLE_MAP={}
AZURE_OIDC_USER_ROLE_MAP={}
AZURE_OIDC_APP_ROLE_VALUE_MAP={}
```
