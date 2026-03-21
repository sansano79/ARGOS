# Azure AD (Entra ID) SAML — Configuración

## URLs en este despliegue (con Nginx reverse proxy)

- URL pública de la app: `https://TU_HOST/`
- API pública (proxy): `https://TU_HOST/api/`
- ACS (Reply URL): `https://TU_HOST/api/auth/saml/acs`
- Metadata SP: `https://TU_HOST/api/auth/saml/metadata`

Si accedes a la API por `:3000`, Azure seguirá redirigiendo al navegador a ese puerto. En producción se recomienda usar siempre la URL pública detrás de Nginx (443).

## Dónde sacar cada variable

En Azure Portal → Microsoft Entra ID → Enterprise applications → tu app SAML → Single sign-on → SAML.

- `AZURE_SAML_ENTRY_POINT`
  - Es el **Login URL** del IdP (o el `SingleSignOnService Location` del Federation Metadata XML).
- `AZURE_SAML_ISSUER`
  - Es el **Identifier (Entity ID)** del IdP (o el `entityID` del Federation Metadata XML).
- `AZURE_SAML_CALLBACK_URL`
  - Es el **Reply URL (Assertion Consumer Service URL)**. Debe coincidir con:
    - `https://TU_HOST/api/auth/saml/acs`
- `AZURE_SAML_CERT`
  - Es el certificado **X.509** del IdP (Azure). En Azure suele aparecer como:
    - “Certificate (Base64)”
  - En `.env` se recomienda guardarlo como PEM con `\n`:
    - `AZURE_SAML_CERT="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"`
- `AZURE_SAML_DEFAULT_ROLE`
  - Rol aplicado cuando el usuario no trae grupos mapeados.
- `AZURE_SAML_GROUP_ROLE_MAP`
  - JSON que mapea **ObjectId de grupos** → rol interno:
    - `{"<GROUP_OBJECT_ID_ADMIN>":"ADMIN","<GROUP_OBJECT_ID_SUBSCRIBER>":"SUBSCRIBER"}`

## Grupos (claim `groups`) recomendado

En “User Attributes & Claims”, añade un claim de grupos que entregue **Group ID** (ObjectId).
Recomendación: “Groups assigned to the application” para evitar listas enormes.

Luego, usa el ObjectId de cada grupo en `AZURE_SAML_GROUP_ROLE_MAP`.

## Ejemplo `.env.prod`

```env
FRONTEND_BASE_URL=https://192.168.1.211/

AZURE_SAML_ENABLED=true
AZURE_SAML_CALLBACK_URL=https://192.168.1.211/api/auth/saml/acs
AZURE_SAML_ENTRY_POINT=https://login.microsoftonline.com/<TENANT_ID>/saml2
AZURE_SAML_ISSUER=https://sts.windows.net/<TENANT_ID>/
AZURE_SAML_CERT="-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"

AZURE_SAML_DEFAULT_ROLE=USER
AZURE_SAML_GROUP_ROLE_MAP={}
```

## Validación rápida

1) Abre `https://TU_HOST/api/auth/saml/metadata` y verifica que Azure pueda consumir el XML.
2) Pulsa “Entrar con Azure (SAML)” en la UI y valida que vuelve a `/#token=...`.
3) Si el rol no se asigna por grupos, revisa la configuración del claim `groups` en Azure.

