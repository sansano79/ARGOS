# Plan de corrección de seguridad — ARGOS

> Basado en `docs/security/2026-11-21-auditoria-contenedores-y-aplicacion.md`. Los IDs (INF/APP/DEP) remiten a ese informe.
> Esfuerzo: **S** ≤ 1 día · **M** 2–4 días · **L** 1–2 semanas. Cada tarea se cierra con un test o evidencia verificable.

## Criterios de priorización
1. Lo que permite tomar cuentas o saltarse controles sin privilegios previos va primero.
2. Después, lo que expone secretos o datos si se compromete el host o un contenedor.
3. Por último, hardening y defensa en profundidad.

---

## FASE 0 — Urgente (antes del próximo despliegue, 1–3 días)

> **Estado 2026-11-21:** aplicadas en código 0.1–0.7, con tests (`src/auth/mfa-hardening.spec.ts`, `src/common/startup-security-check.spec.ts`). Queda pendiente 0.8, que es operativa en el servidor.
> - El estado anti-replay y de intentos de MFA se guarda en memoria (una réplica). Pasa a Redis en la tarea 1.7.
> - En producción, Swagger exige además `ENABLE_SWAGGER_IN_PRODUCTION=true`.
> - El puerto del frontend se publica en `OCC_HTTP_BIND`, por defecto `127.0.0.1`.

| # | Tarea | IDs | Esf. | Verificación |
|---|---|---|---|---|
| 0.1 | En `JwtStrategy.validate` rechazar todo payload con `purpose` y exigir `typ:'access'`. Firmar el `mfaToken` con `audience:'argos-mfa'` y el access token con `audience:'argos-api'`. Fijar `algorithms:['HS256']`, `issuer` y `audience` en la estrategia | APP-C1, APP-B8 | S | Test e2e: un `mfaToken` usado como Bearer da 401 |
| 0.2 | `mfaSetup`: rechazar si `mfaEnabled`. Guardar el secreto en campos `mfaPending*` y activarlo solo en `enroll`. Reset de MFA solo por ADMIN | APP-C2 | S | Test: usuario con MFA → `setup` da 403 |
| 0.3 | Límite de intentos MFA: 5 fallos invalidan el `mfaToken` (`jti` en una lista negra) y se guarda el último `timeStep` TOTP aceptado | APP-A2 | S | Test: el 6.º intento da 401 y repetir un código da 401 |
| 0.4 | `@Roles('ADMIN')` en `POST :id/tags`, `POST report` y `GET report/download`. Límite de `hours` ≤ 720. Corregir `@Param('filename')`. Throttle en `ai/chat` | APP-M6 | S | Tests de autorización: USER da 403 |
| 0.5 | No publicar el puerto 80 en `0.0.0.0`: `127.0.0.1:${OCC_HTTP_PORT}:8080` (o la IP del ingress) + firewall. Si no hay ingress acreditado, terminar TLS en nginx (ver 2.2) | INF-01 | S | `ss -ltnp` en el host y escaneo externo sin respuesta en :80 |
| 0.6 | Validación de configuración al arrancar (schema en `ConfigModule`). Abortar si `NODE_ENV=production` y hay: `ENABLE_SWAGGER=true`, cualquier `*_BYPASS*`, `DEV_AUTH_BYPASS`, `CORS_ORIGIN=*`, `JWT_SECRET` < 32 bytes, o `MFA_ENCRYPTION_KEY`/`DEFENDER_SECRET_KEY` vacías. Corregir los valores por defecto de `.env.example` | INF-11, APP-M9, APP-B7 | S | Test unitario del validador |
| 0.7 | Actualizar `handlebars`, `axios` y `mysql2` (parches menores, sin cambios de API) y ejecutar los tests | DEP | S | `npm audit` sin críticas en esos paquetes |
| 0.8 | Tras desplegar 0.1–0.3: **rotar `JWT_SECRET`** (invalida sesiones y `mfaToken` emitidos) y revisar en logs y `user_login_*` accesos sin MFA completado | APP-C1 | S | Registro de rotación |

---

## FASE 1 — Corto plazo (1–2 semanas)

### 1A · Secretos
| # | Tarea | IDs | Esf. |
|---|---|---|---|
| 1.1 | Migrar a **Docker secrets**: `secrets:` en compose (`file: ./secrets/*.txt`, `chmod 600`, propietario root). MySQL con `MYSQL_PASSWORD_FILE`/`MYSQL_ROOT_PASSWORD_FILE`. La API lee `*_FILE` con un loader en `ConfigModule` (JWT, MFA, Defender, BD, SMTP, Azure). Quitar `env_file` para secretos (queda solo para config no sensible) | INF-04 | M |
| 1.2 | Redis: `requirepass`/ACL en un fichero de configuración montado como secreto. Healthchecks sin credenciales en argv (`REDISCLI_AUTH`, `--defaults-extra-file`) | INF-04 | S |
| 1.3 | Separar credenciales de BD: `argos_app` (DML) para runtime y `argos_migrate` (DDL) solo para el job de migración. La contraseña root solo llega al servicio `mysql` | INF-09 | S |
| 1.4 | Cifrar la contraseña SMTP y la API key de OpenAI con `secret-crypto.util.ts` (clave `INTEGRATION_SECRET_KEY` desde un secreto). Script de migración que cifra los valores existentes. Reforzar la util: solo claves de 32 bytes (sin frase de paso) y AAD = `slug` | APP-B1, APP-B11 | M |
| 1.5 | Procedimiento documentado de **rotación** de JWT, MFA, BD, SMTP y Defender (re-cifrado con versión de clave `v2:`) | INF-04 | S |

### 1B · Autenticación y cuentas
| # | Tarea | IDs | Esf. |
|---|---|---|---|
| 1.6 | Aprobación del alta: el GET solo muestra la confirmación y un POST autenticado (ADMIN) aprueba. No reactivar usuarios existentes; si hay que hacerlo, forzar `role:'USER'` | APP-A1 | M |
| 1.7 | `@nestjs/throttler` global con store Redis (usar el Redis existente, INF-10). Límites estrictos por IP en `/auth/*` y backoff progresivo en lugar de bloqueo duro por email. Registrar la IP real (`trust proxy` correcto) | APP-M7, INF-10 | M |
| 1.8 | Escapar HTML en todas las variables de las plantillas de correo (reemplazo con función). Validar `requesterName` | APP-M3 | S |
| 1.9 | No guardar el HTML de correos con tokens (`password-reset`, `local-signup-*`) y excluirlos del reenvío. Purgar los registros existentes | APP-M4 | S |
| 1.10 | Enviar el reset siempre a `user.email`. Verificar `notificationEmail` por enlace. Uso único atómico (`updateMany({id, usedAt:null})` con `count===1`) y revocar JWT tras el reset (`passwordChangedAt` comprobado en `JwtStrategy`) | APP-M5, APP-B13 | M |
| 1.11 | `DELETE /users/:id` con `select` explícito. DTOs con `class-validator` en usuarios, portal y colector. Política de contraseña ≥ 12 caracteres | APP-B2, APP-B3 | M |

### 1C · Dependencias e imágenes
| # | Tarea | IDs | Esf. |
|---|---|---|---|
| 1.12 | Migrar `passport-saml` a `@node-saml/passport-saml` v5 y, en el mismo cambio, configurar `audience`, `validateInResponseTo:'always'` (cache en Redis) y `acceptedClockSkewMs` | DEP, APP-M1 | M |
| 1.13 | `nodemailer` 10.x y `puppeteer` 25.x (majors): revisar las APIs usadas | DEP | M |
| 1.14 | Imágenes base soportadas y fijadas por digest: `node:22-slim` (o 24), `mysql:8.4`, `nginxinc/nginx-unprivileged`, `redis:7.4-alpine`. Probar migraciones Prisma contra MySQL 8.4 con un dump restaurado | INF-05 | M |
| 1.15 | CI de seguridad: `npm audit --omit=dev --audit-level=high` (bloqueante), Trivy de imágenes (bloqueante en CRITICAL), SBOM CycloneDX, Renovate/Dependabot | INF-05, DEP | M |

---

## FASE 2 — Medio plazo (2–6 semanas)

### 2A · Cifrado
| # | Tarea | IDs | Esf. |
|---|---|---|---|
| 2.1 | **Cifrado en reposo:** cifrado de disco del host (evidencia `lsblk`/`cryptsetup status` o cifrado del volumen cloud). MySQL 8.4 con `component_keyring_file` (o KMS) y `default_table_encryption=ON`, `binlog_encryption=ON`, `innodb_redo_log_encrypt=ON`, `innodb_undo_log_encrypt=ON`, más un `ALTER TABLE … ENCRYPTION='Y'` sobre las tablas existentes. Keyring fuera del volumen de datos | INF-03 | L |
| 2.2 | **TLS externo** (si no hay ingress acreditado): nginx en 443 con TLS 1.2/1.3, cifrados modernos, HSTS, OCSP stapling, certificados como secretos y redirección 80→443 | INF-01 | M |
| 2.3 | **TLS interno:** MySQL `require_secure_transport=ON` con CA propia y `sslaccept=strict` en `DATABASE_URL`. Redis `tls-port` con `port 0`. Opcional: nginx→API por TLS | INF-02 | M |
| 2.4 | **Backups cifrados:** `db-export-prod.sh` cifra con `age`/`gpg` (clave pública en el host, privada fuera), `umask 077`, checksum y copia externa. Prueba de restauración trimestral | INF-03 | S |

### 2B · Hardening de contenedores
| # | Tarea | IDs | Esf. |
|---|---|---|---|
| 2.5 | Bloque base en cada servicio (ajustar por servicio):<br>`security_opt: ["no-new-privileges:true"]`<br>`cap_drop: [ALL]` (+ `cap_add` mínimos en mysql/redis si hacen falta)<br>`read_only: true` + `tmpfs: [/tmp, /run]` (nginx: `/var/cache/nginx`)<br>`mem_limit`, `cpus`, `pids_limit`<br>`logging: {driver: json-file, options: {max-size: 10m, max-file: "5"}}` | INF-06, INF-15 | M |
| 2.6 | Imagen API: etapa `prune` (`npm prune --omit=dev`), sin `scripts/` completos, target `migrate` separado para Prisma CLI/seed. Eliminar `db push --accept-data-loss` y la siembra implícita del entrypoint | INF-07, INF-13 | M |
| 2.7 | Aislar el render PDF: servicio `renderer` (Chromium) en una red `internal`, sin secretos ni egress, con sandbox activo (seccomp) y `setRequestInterception` que bloquee la red y `file://`. La API le envía HTML y recibe el PDF | INF-07, APP-B6 | L |
| 2.8 | nginx: cabeceras de seguridad (CSP del SPA, `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, HSTS), `server_tokens off`, `limit_req` en `/api/auth/`, `client_max_body_size 1m` (excepción para plantillas), timeouts | INF-08 | S |
| 2.9 | Control de egress: proxy de salida con allowlist (NVD, OSV, GitHub, CVE.org, Graph/Defender, SMTP) o firewall del host. El frontend, sin salida | INF-12 | M |

### 2C · Aplicación
| # | Tarea | IDs | Esf. |
|---|---|---|---|
| 2.10 | SSO: vincular por `oid`/`tid` (`externalId`). No convertir cuentas `LOCAL` sin acción de ADMIN. Usar solo el claim `email` verificado | APP-M2 | M |
| 2.11 | API keys: revocar al degradar o desactivar al usuario. Validar scopes en `update`. `every()` en el guard si procede. Throttler antes de la autenticación y límite de fallos por IP | APP-M8 | S |
| 2.12 | CSP/HSTS de la API sin depender de `NODE_ENV`. Logger por entorno. Body limit de 100 KB global con 10 MB solo en plantillas. Sin `error.message` hacia el cliente | APP-M9, APP-B10, APP-B12, INF-15 | S |
| 2.13 | `TEAM_MANAGER`: listar solo usuarios del equipo o búsqueda acotada. Allowlist de hosts para Ollama (bloquear link-local y metadata) | APP-B4, APP-B5 | S |
| 2.14 | Upgrade NestJS 10 → 11 (`express` 5, `multer`, `path-to-regexp`, `proxy-addr`) | DEP | L |
| 2.15 | Capa de autorización centralizada (política por recurso) con tests de autorización obligatorios por endpoint (continúa SEC-01) | SEC-01 | L |

---

## FASE 3 — Continuo
- **Sesión:** migrar de `localStorage` a cookie `httpOnly`+`Secure`+`SameSite=Strict` con access token corto y refresh rotatorio, y quitar el token del fragmento de la URL SSO (APP-B9).
- **Pruebas:** DAST (ZAP baseline) en CI contra staging y pentest anual.
- **Gestor de secretos:** Azure Key Vault/Vault con rotación automática (evolución de 1.1).
- **Escaneo continuo:** imágenes en el registro y alertas de nuevos CVE. ARGOS puede consumir su propio SBOM.
- **Revisión periódica:** repetir esta auditoría tras cada fase y actualizar `docs/deployment-readiness.md` con la evidencia.

## Resumen de calendario
| Fase | Contenido | Duración orientativa | Resultado |
|---|---|---|---|
| 0 | MFA, roles, exposición del puerto, validación de configuración, parches menores | 1–3 días | Sin críticos explotables |
| 1 | Secretos, autenticación, SAML, imágenes soportadas, CI de seguridad | 1–2 semanas | Sin críticas/altas en dependencias; secretos fuera del entorno |
| 2 | Cifrado en reposo e interno, TLS, hardening, aislamiento de Chromium, NestJS 11 | 2–6 semanas | Checklist de contenedores en verde |
| 3 | Sesión con cookies, DAST, vault, escaneo continuo | Continuo | Mantenimiento |
