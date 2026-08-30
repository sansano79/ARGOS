# 03 — Evaluación de seguridad (Security Assessment)

> **Consulta 1 — OCC-TVM.** Rama `feature/mejoras-v1.1-sin-keycloak`, HEAD `64bb678`.
> Revisión estática de la rama; **sin ejecución de exploits ni pruebas dinámicas**. Marcas de evidencia según convención del doc 01.
> Clasificación por hallazgo: **ID · Categoría · Severidad · Evidencia · Símbolo · Impacto · Causa raíz · Recomendación · Esfuerzo · Decisión**.
> Ámbito: pruebas de seguridad **defensivas** sobre el propio repositorio autorizado. No se incluyen técnicas ofensivas.

---

## Tabla resumen

| ID | Categoría | Severidad | Símbolo | Decisión |
|----|-----------|-----------|---------|----------|
| SEC-01 | Autorización / aislamiento | **Alta** | `RolesGuard`, `TeamAccessService` (por convención) | Refactorizar |
| SEC-02 | SSRF / plantillas | **Alta** | `report-generator.service.ts` Puppeteer `setContent` | Corregir |
| SEC-03 | Datos / migraciones | **Alta** | `entrypoint.sh` `db push --accept-data-loss` | Corregir |
| SEC-04 | Sandbox navegador | Media | Puppeteer `--no-sandbox` | Corregir/mitigar |
| SEC-05 | Plantillas / XSS-email | Media | Handlebars `compile` en informes/emails | Verificar/corregir |
| SEC-06 | Secretos | Media | `.env.prod` local, `reset_pwd.js`, artefacto `Zone.Identifier` | Corregir |
| SEC-07 | Autenticación MFA | Baja-Media | SAML/OIDC omiten MFA propio | Verificar |
| SEC-08 | API keys | Baja | Búsqueda por prefijo + bcrypt (correcto); rotación/rate-limit | Conservar/mejorar |
| SEC-09 | Supply chain | Media | Sin lockfile audit / pin; Puppeteer, openid-client | Corregir |
| SEC-10 | Logging sensible | Baja | Log de email en bypass; revisar PII en logs | Verificar |
| SEC-11 | TLS / cabeceras | Baja | Helmet condicional a `NODE_ENV=production` | Conservar/verificar |

---

## Detalle

### SEC-01 — Aislamiento de datos por autorización de convención
- **Categoría:** Autorización / aislamiento multi-cliente · **Severidad:** Alta
- **Evidencia `[HECHO]`:** `RolesGuard` (`src/auth/guards/roles.guard.ts`) sólo verifica `requiredRoles.includes(user.role)`. El aislamiento por equipo depende de invocar manualmente `TeamAccessService.assertTeamReadable/assertTeamWritable` (`team-access.service.ts`), con bypass total para `role === 'ADMIN'`. No hay política transversal (interceptor/policy) que garantice el filtro.
- **Impacto `[RIESGO]`:** un endpoint que olvide la comprobación filtra datos entre equipos/suscriptores (IDOR). Bloqueante para CTEM multi-cliente.
- **Causa raíz:** ausencia de capa de autorización basada en políticas centralizada; modelo single-tenant sin RLS.
- **Recomendación:** política declarativa por recurso + tests de autorización obligatorios; evaluar scoping a nivel de query. No introducir tenancy aquí (decisión de diseño CTEM), pero cerrar la brecha de convención.
- **Esfuerzo:** L · **Decisión:** Refactorizar. *(Espejo de TD-10.)*

### SEC-02 — SSRF potencial en generación de informes (Puppeteer)
- **Categoría:** SSRF / renderizado · **Severidad:** Alta
- **Evidencia `[HECHO]`:** `report-generator.service.ts:159-166`: `puppeteer.launch(...)`, `page.setContent(html, { waitUntil: 'networkidle0' })`. El HTML se compila desde plantilla Handlebars (`:125`) con datos de vulnerabilidad; `networkidle0` implica que el navegador **resolverá recursos remotos** (imágenes/CSS) embebidos en el HTML.
- **Impacto `[RIESGO]`:** si el HTML puede incluir URLs controladas por datos (p. ej. `sourceUrl`, referencias externas, imagen de cabecera de plantilla que `main.ts:56` permite como data URL base64), Puppeteer podría emitir peticiones a destinos internos → SSRF, o exfiltración vía carga de recursos. La superficie crece si las plantillas admiten HTML de fuentes externas.
- **Causa raíz:** render server-side de HTML con datos parcialmente externos y navegador con acceso de red.
- **Recomendación:** deshabilitar red del navegador durante el render (interceptar/`request.abort()` para dominios no permitidos), o servir sólo recursos locales/inlined; validar/allowlist de URLs en plantillas. Confirmar origen real de las URLs incrustadas `[N/D]`.
- **Esfuerzo:** M · **Decisión:** Corregir.

### SEC-03 — Pérdida de datos por bandera de arranque
- **Categoría:** Integridad de datos · **Severidad:** Alta
- **Evidencia `[HECHO]`:** `docker/entrypoint.sh:20-24`, `PRISMA_DB_PUSH_ON_START=true` ejecuta `prisma db push --skip-generate --accept-data-loss` en el arranque, sin guard de entorno.
- **Impacto `[RIESGO]`:** una variable mal configurada en producción puede destruir datos silenciosamente al iniciar el contenedor.
- **Causa raíz:** rama de conveniencia de desarrollo expuesta en el mismo entrypoint de producción.
- **Recomendación:** eliminar la rama en producción o condicionarla a `OCC_ENV != prod`; el flujo canónico ya es `migrate deploy` (`entrypoint.sh:11`).
- **Esfuerzo:** S · **Decisión:** Corregir. *(Espejo de TD-13.)*

### SEC-04 — Puppeteer con `--no-sandbox`
- **Categoría:** Aislamiento de proceso · **Severidad:** Media
- **Evidencia `[HECHO]`:** `report-generator.service.ts:161`: `args: ['--no-sandbox', '--disable-setuid-sandbox']`.
- **Impacto:** desactiva el sandbox de Chromium; si SEC-02/SEC-05 permiten inyectar contenido, una vulnerabilidad del motor no queda contenida.
- **Causa raíz:** patrón común en contenedores para evitar requisitos de sandbox; aceptable sólo con contención adicional.
- **Recomendación:** ejecutar el render en contenedor/worker con usuario no privilegiado y seccomp; a medio plazo restaurar sandbox. Combinar con aislamiento de TD-15.
- **Esfuerzo:** M · **Decisión:** Corregir/mitigar.

### SEC-05 — Renderizado de plantillas Handlebars (XSS en email/PDF)
- **Categoría:** Inyección de plantilla · **Severidad:** Media
- **Evidencia `[HECHO]`:** `Handlebars.compile` en `report-generator.service.ts:125` y uso extensivo en `notification.service.ts`/`smart-notifications.service.ts` con plantillas `src/templates/*.html`. Handlebars escapa por defecto, pero `{{{triple}}}`/`SafeString` no.
- **Impacto `[RIESGO]`:** si datos de vulnerabilidad (descripciones de fuentes externas) se insertan con triple-stache o SafeString, hay XSS en correo/HTML e inyección en el PDF.
- **Causa raíz:** datos externos no confiables (payloads NVD/OSV) renderizados en plantillas.
- **Recomendación:** auditar el uso de `{{{ }}}`/`SafeString` en plantillas y servicios; sanitizar HTML de fuentes externas. `[N/D]` grep dirigido pendiente en siguiente consulta.
- **Esfuerzo:** M · **Decisión:** Verificar/corregir.

### SEC-06 — Gestión de secretos y artefactos
- **Categoría:** Secretos · **Severidad:** Media
- **Evidencia `[HECHO]`:** `.env.prod` y `.env.local` **existen en el árbol de trabajo pero están gitignored** (`git check-ignore` los confirma; no aparecen en `git ls-files`) — correcto. **Sin embargo** hay un artefacto Windows rastreado: `.env.prod:Zone.Identifier` (`git ls-files` lo lista) — residuo que sugiere que un `.env.prod` real se copió desde Windows; revisar que no se haya commiteado contenido sensible en el historial `[N/D]`. Existe `reset_pwd.js` (946 B) en la raíz — script de reseteo de contraseña fuera de `scripts/`.
- **Impacto:** riesgo de fuga si el `.gitignore` cambia; `reset_pwd.js` en raíz es superficie operativa peligrosa si se despliega.
- **Recomendación:** eliminar el artefacto `Zone.Identifier` del repo; auditar historial git por secretos; mover/retirar `reset_pwd.js`; documentar gestión de secretos (hoy `.env` planos).
- **Esfuerzo:** S · **Decisión:** Corregir.

### SEC-07 — SAML/OIDC no pasan por MFA propio
- **Categoría:** Autenticación · **Severidad:** Baja-Media
- **Evidencia `[HECHO]/[INFERENCIA]`:** la rama MFA en `auth.service.ts:116-143` sólo aplica a `authProvider === 'LOCAL'`. Usuarios federados (SAML/OIDC) obtienen token sin el TOTP propio.
- **Impacto:** el segundo factor recae íntegramente en el IdP externo; si el IdP no lo impone, se pierde MFA.
- **Causa raíz:** MFA acoplado al flujo local.
- **Recomendación:** documentar/forzar contractualmente MFA en el IdP, o extender verificación. Ambos proveedores están desactivados por defecto (`AZURE_*_ENABLED=false`), así que riesgo latente.
- **Esfuerzo:** M · **Decisión:** Verificar (política) antes de habilitar SSO.

### SEC-08 — Gestión de API keys (externo)
- **Categoría:** API keys · **Severidad:** Baja (mayormente correcto)
- **Evidencia `[HECHO]`:** `ApiKeyGuard` (`external-api/guards/api-key.guard.ts`) busca por `keyPrefix` (12 chars) entre claves activas y compara con `bcrypt.compare` contra `keyHash`; respeta `expiresAt`, `isActive`, usuario activo, y **scopes** vía `@ApiKeyScopes`. Creación con `bcrypt.hash(rawKey, 10)` (`api-keys.service.ts:24`). Buen diseño.
- **Impacto/Riesgo:** `[RIESGO]` sin rate-limiting específico por key ni rotación forzada evidentes; `[THROTTLER]` `@nestjs/throttler` está en dependencias — verificar que se aplica a la API externa.
- **Recomendación:** añadir rate-limit por key y política de rotación/caducidad.
- **Esfuerzo:** S · **Decisión:** Conservar (mejorar).

### SEC-09 — Cadena de suministro
- **Categoría:** Supply chain · **Severidad:** Media
- **Evidencia `[HECHO]`:** dependencias sensibles: `puppeteer` (descarga Chromium), `openid-client`, `passport-saml`, `nodemailer`, `mysql2`. Hay `package-lock.json` (385 KB) — bien. `[N/D]` no hay evidencia de `npm audit`/SCA en CI ni de firma/verificación de artefactos.
- **Impacto:** vulnerabilidades transitivas sin monitorización; irónico para un producto de gestión de vulnerabilidades.
- **Recomendación:** integrar SCA (npm audit / dependabot) y política de actualización; fijar versión de Chromium.
- **Esfuerzo:** S-M · **Decisión:** Corregir.

### SEC-10 — Logging de datos potencialmente sensibles
- **Categoría:** Logging · **Severidad:** Baja
- **Evidencia `[HECHO]`:** `auth.service.ts:126` registra email + IP en `TEST_MFA_BYPASS_USED` (aceptable, sólo en entornos de test). `main.ts:18` habilita nivel `debug`/`verbose`. `[RIESGO]` en debug, servicios de notificación de 112/192 KB podrían loggear payloads con PII de suscriptores.
- **Recomendación:** revisar niveles de log en producción (evitar `debug`/`verbose`), verificar que no se registran secretos/PII; hoy `main.ts` deja todos los niveles activos siempre.
- **Esfuerzo:** S · **Decisión:** Verificar/corregir.

### SEC-11 — TLS y cabeceras de seguridad
- **Categoría:** Hardening HTTP · **Severidad:** Baja
- **Evidencia `[HECHO]`:** Helmet aplicado (`main.ts:36-42`) pero **HSTS y CSP sólo si `NODE_ENV === 'production'`** (`main.ts:30-34`); Swagger sirve sin CSP/HSTS siempre (`main.ts:37-40`). CORS con `credentials: true` y origins desde `CORS_ORIGIN` (`main.ts:43-52`), permite `*` si se configura así. TLS queda fuera de OCC-TVM y se termina en el proxy/ingress corporativo.
- **Impacto:** si `NODE_ENV` no es exactamente `production`, se pierde CSP/HSTS. `CORS_ORIGIN='*'` con credenciales es contradictorio (navegador lo rechaza, pero indica configuración laxa).
- **Recomendación:** garantizar `NODE_ENV=production` en prod; no permitir `CORS_ORIGIN='*'` con `credentials:true`; restringir Swagger en producción (ya condicionado por `ENABLE_SWAGGER`).
- **Esfuerzo:** S · **Decisión:** Conservar/verificar.

---

## Aspectos correctos (a conservar)
- `[HECHO]` MFA TOTP obligatorio para cuentas locales, con secreto cifrado AES-GCM y clave de 32 bytes validada (`auth.service.ts:19-49`).
- `[HECHO]` Bypass MFA de test bien contenido: bloqueado en prod, allowlist explícita, prefijo `test.`, auditado (`test-mfa-bypass.util.ts`).
- `[HECHO]` `ValidationPipe` global con `whitelist`+`forbidNonWhitelisted`+`transform` (`main.ts:62-68`) → defensa sólida contra sobre-posteo.
- `[HECHO]` Rate-limit de intentos de login (`auth.service.ts:67-76`, `LoginAttempt`) y `@nestjs/throttler` disponible.
- `[HECHO]` API keys con bcrypt + scopes + prefijo indexado (SEC-08).
- `[HECHO]` JWT valida usuario vivo en cada request (`jwt.strategy.ts:22-27`: `isActive`/`canLogin`).

## No disponible / a verificar en próxima consulta
- Uso de triple-stache/SafeString en plantillas (SEC-05).
- Origen real de URLs incrustadas en informes (SEC-02).
- Aplicación efectiva de throttler a la API externa (SEC-08).
- Historial git respecto a secretos (SEC-06).
- Cobertura de `helmet`/CSP con el `NODE_ENV` real de despliegue (SEC-11).
