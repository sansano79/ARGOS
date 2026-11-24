# Auditoría de seguridad — Contenedores y aplicación ARGOS

> **Fecha:** 2026-11-21 · **Rama:** `v1_0_deploy` (HEAD `bfc0f11` + cambios sin commitear del módulo Defender)
> **Tipo:** revisión estática del repositorio + `npm audit --omit=dev`. Sin pruebas dinámicas ni acceso al servidor de producción.
> **Ámbito:** `docker-compose.yml`, `docker/`, `frontend/Dockerfile.prod`, `frontend/nginx.conf`, `.env.example`, scripts de despliegue/backup, backend `src/`, dependencias.
> **Antecedente:** `docs/ctem/03-security-assessment.md` (SEC-01…SEC-11). Se indica cuándo un hallazgo coincide con uno anterior.

## 1. Resumen ejecutivo

| Severidad | Infraestructura (INF) | Aplicación (APP) | Dependencias (DEP) |
|---|---|---|---|
| Crítica | 0 | **2** | 5 paquetes |
| Alta | 4 | 2 | 29 paquetes |
| Media | 7 | 9 | 12 paquetes |
| Baja | 4 | 13 | — |

**Valoración global:** la **topología de redes es correcta**: MySQL y Redis van en redes `internal`, sin puertos publicados, y la API no se expone directamente. La API corre como usuario no root. **No cumplen buenas prácticas** los siguientes puntos:

1. **El MFA se puede saltar por completo** (APP-C1, APP-C2): con la contraseña basta para entrar con el rol del usuario, ADMIN incluido.
2. **No hay cifrado en tránsito dentro del stack ni en el propio programa.** TLS depende de un proxy externo no versionado y el puerto 80 se publica en todas las interfaces.
3. **No hay cifrado en reposo** de la BD, los volúmenes, `storage/` ni los backups.
4. **Los secretos se inyectan como variables de entorno.** Son visibles con `docker inspect`, en `/proc` y en la línea de comandos de Redis y del healthcheck de MySQL.
5. **Las imágenes base están fuera de soporte:** Node 20 y MySQL 8.0 llegaron a EOL en abril de 2026.
6. **Hay 46 vulnerabilidades en dependencias de producción** del backend: 5 críticas y 29 altas. Destacan `passport-saml` (sin parche, abandonado) y `handlebars`.

## 2. Checklist de buenas prácticas de contenedores

| Control | Estado | Evidencia |
|---|---|---|
| Redes separadas por función | ✅ Cumple | `edge_net`, `api_net`, `db_net` (internal), `cache_net` (internal) |
| BD/caché sin exposición externa | ✅ Cumple | `mysql` y `redis` sin `ports:` y solo en redes internas |
| Backend no expuesto directamente | ✅ Cumple | `api` sin `ports:`, solo accesible vía nginx (`/api/`) |
| Usuarios no root | ⚠️ Parcial | API `USER occ` ✅. El master de nginx corre como root. Chromium arranca con `--no-sandbox` |
| Cifrado externo (TLS) | ❌ No | Solo `:80` HTTP, publicado en `0.0.0.0`. TLS delegado a un ingress externo sin evidencia en el repo |
| Cifrado interno | ❌ No | API→MySQL, API→Redis y nginx→API en texto claro |
| Cifrado en reposo | ❌ No | Volúmenes `driver: local`, sin TDE en MySQL, `storage/` y backups `.sql.gz` en claro |
| Gestión de secretos | ⚠️ Parcial | `:?` obliga a definirlos y `.env*` está en `.gitignore`/`.dockerignore` ✅. Pero se inyectan por `env_file` (no Docker secrets) y aparecen en argv |
| Mínimo privilegio en BD | ❌ No | Un único usuario de BD con DDL para runtime y migraciones |
| Hardening de runtime | ❌ No | Falta `read_only`, `cap_drop`, `no-new-privileges`, límites de memoria, CPU y pids, y rotación de logs |
| Imágenes soportadas y fijadas | ❌ No | `node:20` y `mysql:8.0` en EOL. Tags flotantes sin digest |
| Imagen mínima | ⚠️ Parcial | Multi-stage ✅, pero se copian `devDependencies`, `scripts/` y Chromium al runtime |
| Healthchecks | ✅ Cumple | En los 4 servicios (con incoherencia menor, INF-14) |
| Init/PID 1 | ✅ Cumple | `dumb-init` |

## 3. Hallazgos de infraestructura (INF)

### INF-01 · Alta · Sin TLS en el perímetro del programa; puerto 80 publicado en todas las interfaces
- **Evidencia:** `docker-compose.yml` frontend `ports: "${OCC_HTTP_PORT:-80}:80"`. `nginx.conf` solo hace `listen 80`. `docs/deployment-readiness.md` delega HTTPS al "proxy/ingress corporativo". `OCC_HTTPS_PORT=443` existe en `.env.example` pero no se usa. En el commit `57e6acf` se eliminó el proxy TLS.
- **Impacto:** cualquiera con alcance de red al host puede saltarse el ingress (WAF, TLS) e ir a `http://host:80`. Credenciales, JWT y tokens de reset viajan en claro. No se puede demostrar desde el repo que el ingress exista ni que sea el único camino.
- **Corrección:**
  - Publicar solo en la interfaz del ingress (`127.0.0.1:80:8080` o la IP interna) y filtrar con firewall.
  - O terminar TLS en nginx (TLS 1.2+/1.3, certificados como secretos), con redirección 80→443 y HSTS.

### INF-02 · Media · Sin cifrado interno entre servicios
- **Evidencia:** `DATABASE_URL=mysql://…` sin `sslaccept`/`sslcert`. Redis sin `--tls-port`. `proxy_pass http://api:3000`.
- **Impacto:** las redes internas mitigan el riesgo. Aun así, un contenedor comprometido en la misma red o un host compartido puede leer credenciales y datos. Además, `mysql2 ≤3.23` permite degradar a `mysql_clear_password` (DEP).
- **Corrección:**
  - MySQL con `require_secure_transport=ON` y certificados propios, y `?sslaccept=strict` en Prisma.
  - Redis con `tls-port` y `port 0`.
  - Opcional: TLS nginx→API (o mTLS) si el host es multi-tenant.

### INF-03 · Alta · Sin cifrado en reposo
- **Evidencia:**
  - Los volúmenes `mysql_info` y `redis_data` usan `driver: local`.
  - MySQL no configura keyring ni `default_table_encryption`.
  - `./storage` es un bind mount con informes PDF y evidencias.
  - `scripts/db-export-prod.sh` genera `storage/backups/*.sql.gz` sin cifrar, con los permisos por defecto del umask.
- **Impacto:** el robo del disco, de un snapshot o de un backup expone toda la BD: usuarios, hashes, secretos MFA cifrados junto a una clave que está en `.env.prod` en el mismo host, inventario de activos y vulnerabilidades por cliente.
- **Corrección:**
  - Cifrado de disco del host (LUKS/BitLocker/volumen cloud cifrado), con evidencia.
  - MySQL con `component_keyring_file` (o KMS) y `default_table_encryption=ON`, `binlog_encryption=ON`, `innodb_redo_log_encrypt`/`undo_log_encrypt`.
  - Backups cifrados con `age`/`gpg` antes de escribirlos, `chmod 600` y copia fuera del host.
  - Dejar la clave de cifrado fuera del mismo volumen.

### INF-04 · Alta · Secretos expuestos vía variables de entorno y argv
- **Evidencia:**
  - `env_file: .env.prod` inyecta todos los secretos (JWT, MFA, BD, SMTP, Azure, Defender) en el entorno de `api`. Chromium, lanzado por Puppeteer, los hereda.
  - Redis: `redis-server --requirepass "$REDIS_PASSWORD"`, que se ve en `ps`/`docker top`.
  - Healthcheck de MySQL: `mysqladmin … -u root -p"$MYSQL_ROOT_PASSWORD"`, que pone la contraseña de **root** en argv cada 10 s.
  - Healthcheck de Redis: `redis-cli -a`.
- **Impacto:** cualquiera con acceso a `docker inspect`, al socket de Docker, a `/proc/*/environ` o a un volcado de errores obtiene todos los secretos. Un RCE en Chromium o en Node los obtiene de inmediato.
- **Corrección:**
  - Usar `secrets:` de Compose montados en `/run/secrets` (MySQL admite `MYSQL_PASSWORD_FILE`/`MYSQL_ROOT_PASSWORD_FILE`). Para la API, cargar con `*_FILE` o un loader en `ConfigModule`.
  - Redis: `requirepass` en un fichero de configuración montado como secreto, o un usuario ACL.
  - Healthchecks sin credenciales en argv (`MYSQL_PWD` desde fichero o `--defaults-extra-file`; `REDISCLI_AUTH`).
  - A medio plazo: Vault/Azure Key Vault con rotación.

### INF-05 · Alta · Imágenes base sin soporte y sin fijar
- **Evidencia:** `node:20-slim` (EOL 30-abr-2026), `mysql:8.0` (EOL abr-2026), `nginx:alpine`, `redis:7-alpine` y `node:20-alpine`, todas con tags flotantes y sin `@sha256`.
- **Impacto:** no hay parches de seguridad del runtime ni del motor de BD. Los builds no son reproducibles y aceptan cualquier cambio upstream.
- **Corrección:**
  - `node:22-slim` o `node:24-slim` (LTS), `mysql:8.4` (LTS), `nginxinc/nginx-unprivileged:<ver>`, `redis:7.4-alpine` o `valkey`.
  - Fijar por digest y actualizar con Renovate/Dependabot.
  - Escanear las imágenes con Trivy/Grype en CI. **No se escanearon los paquetes del SO en esta auditoría.**

### INF-06 · Media · Falta hardening de runtime de los contenedores
- **Evidencia:** ningún servicio declara `read_only`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `mem_limit`/`cpus`/`pids_limit`, `tmpfs` ni `logging` con rotación. `nginx:alpine` arranca el master como root.
- **Impacto:** si un contenedor se compromete, el atacante tiene más capacidades para escalar o persistir. El DoS de Puppeteer (APP-M6) o los logs sin límite pueden tumbar el host.
- **Corrección:** el bloque base por servicio está en el plan (FASE 2). En nginx, usar la imagen unprivileged escuchando en `8080`.

### INF-07 · Media · Imagen de la API sobredimensionada y Chromium sin sandbox
- **Evidencia:**
  - `npm ci` sin `--omit=dev`, y todo `node_modules` se copia al runtime.
  - `COPY scripts` copia todos los scripts.
  - El CLI `prisma` y los binarios de migración van en la imagen de ejecución.
  - Chromium se instala en la misma imagen y se lanza con `--no-sandbox --disable-setuid-sandbox` (`report-generator.service.ts:172`). Coincide con SEC-04.
- **Impacto:** mayor superficie y más CVEs heredados. Un exploit de Chromium no queda contenido y comparte proceso, red y secretos con la API.
- **Corrección:**
  - `npm prune --omit=dev` en una etapa intermedia. Imagen de migración separada (`target: migrate`).
  - Mover el render PDF a un contenedor dedicado sin secretos y sin salida a red (red `internal`), o mantener el sandbox de Chromium con un perfil seccomp adecuado.
  - Interceptar peticiones (`setRequestInterception`) y bloquear `file://` y la red.

### INF-08 · Media · Proxy nginx sin cabeceras de seguridad ni límites
- **Evidencia:** `nginx.conf` sin `server_tokens off`, CSP, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` ni HSTS. Tampoco `client_max_body_size`, `limit_req` en `/api/auth/`, ni timeouts de proxy. El frontend guarda el JWT en `localStorage` (APP-B9), así que la CSP del SPA es la principal defensa ante XSS.
- **Corrección:**
  - Cabeceras en el bloque `server`, repetidas en los `location` que usan `add_header`.
  - `limit_req_zone` para `/api/auth/` y `client_max_body_size` acorde (1 MB salvo la ruta de plantillas).
  - `proxy_read_timeout`.

### INF-09 · Media · Usuario de BD único con privilegios de propietario; credencial root disponible
- **Evidencia:** `MYSQL_USER` recibe `ALL` sobre `argos` y se usa en runtime (`DATABASE_URL`) y en migraciones (`prisma migrate deploy`). `MYSQL_ROOT_PASSWORD` vive en `.env.prod`, el mismo fichero que lee la API.
- **Impacto:** una inyección o un RCE en la API permite `DROP`/`ALTER` y leer la contraseña root.
- **Corrección:** usuario `argos_app` con `SELECT/INSERT/UPDATE/DELETE` y `argos_migrate` con DDL, usado solo por el job de migración. La contraseña root va en un secreto solo para el servicio `mysql`.

### INF-10 · Media · Redis desplegado pero sin uso
- **Evidencia:** no hay cliente Redis en `package.json` ni en `src/`. El servicio sigue levantado y la API tiene la contraseña.
- **Impacto:** superficie y secretos innecesarios. Además, los controles que necesitan estado compartido (rate limit, anti-replay del MFA, `InResponseTo` de SAML) no se están haciendo.
- **Corrección:** usarlo como store de `@nestjs/throttler`, anti-replay TOTP y caché SAML (APP-A2, M1, M7), con usuario ACL propio y sin `default`. Si no, eliminarlo.

### INF-11 · Media · Valores por defecto inseguros si `.env.example` se copia a producción
- **Evidencia:** `NODE_ENV=development`, `ENABLE_SWAGGER=true`, `TRUST_PROXY=false`. Compose fuerza `NODE_ENV=production`, pero `ENABLE_SWAGGER=true` **activa Swagger en producción** (`main.ts:73`). Los bypass de MFA y el `development-login` dependen solo de `OCC_ENV`.
- **Corrección:**
  - `.env.example` con valores seguros por defecto.
  - Validación de configuración al arrancar (Joi/zod en `ConfigModule`) que aborte si hay `NODE_ENV=production` con Swagger, bypass, `CORS_ORIGIN=*`, `JWT_SECRET` < 32 bytes o claves vacías.

### INF-12 · Baja · Salida a Internet sin control (egress)
- **Evidencia:** `api_net` y `edge_net` no son `internal`. La API necesita salir a NVD, OSV, GitHub y Defender, pero puede llegar a cualquier destino.
- **Corrección:** proxy de salida con allowlist (`HTTPS_PROXY`) o reglas de firewall del host. El frontend no necesita salida.

### INF-13 · Baja · El entrypoint aún permite `db push --accept-data-loss` y siembra automática
- **Evidencia:** `docker/entrypoint.sh` con `PRISMA_DB_PUSH_ON_START` y siembra cuando `users` está vacío. Si la consulta falla, devuelve `0` y vuelve a sembrar. Coincide con SEC-03.
- **Corrección:** eliminar la rama `db push` de la imagen de producción. Sembrar solo con un job explícito y no tratar un error de BD como "0 usuarios".

### INF-14 · Baja · Incoherencias operativas
- El healthcheck del Dockerfile usa `/api` y el de compose `/api/health`.
- `deploy.sh` usa `sleep 15` en vez de esperar a `healthy`.
- `reset_pwd.js` en la raíz crea o eleva cualquier email a ADMIN. Moverlo a `scripts/` con confirmación.
- Frontend: `npm install` en lugar de `npm ci`.

### INF-15 · Baja · Logs y depuración
- **Evidencia:** logger con `debug`/`verbose` siempre activos (`main.ts:20`) y driver `json-file` sin rotación.
- **Corrección:** nivel de log según el entorno y `logging: { driver: json-file, options: { max-size: 10m, max-file: "5" } }`.

## 4. Hallazgos de aplicación (APP)

Revisión del backend NestJS. **CONF** = código leído y ruta verificada; **PLAUS** = plausible, pendiente de prueba.

### Críticos
| ID | Hallazgo | Ubicación | Estado |
|---|---|---|---|
| **APP-C1** | El `mfaToken` (emitido solo con la contraseña) se acepta como token de acceso. Se firma con el mismo secreto y `JwtStrategy.validate` no comprueba `purpose`. **El MFA no protege nada**: una cuenta ADMIN obtiene acceso ADMIN durante 10 min, renovable | `src/auth/auth.service.ts:52-55`, `src/auth/strategies/jwt.strategy.ts:13-28` | CONF (verificado) |
| **APP-C2** | `POST /auth/mfa/setup` sobrescribe el secreto TOTP aunque el usuario ya tenga MFA. Con la contraseña, el atacante registra su propio autenticador | `src/auth/auth.service.ts:175-205` | CONF (verificado) |

### Altos
| ID | Hallazgo | Ubicación |
|---|---|---|
| APP-A1 | La aprobación del alta local es un GET de un clic (pre-fetchers de correo). Reactiva cuentas deshabilitadas **conservando el rol** y envía un enlace de reset | `auth.controller.ts:249-257`, `local-signup.service.ts:134-162` |
| APP-A2 | Sin límite de intentos ni anti-replay en `mfa/verify`/`mfa/enroll`: fuerza bruta del TOTP de 6 dígitos | `auth.service.ts:207-258` |

### Medios
| ID | Hallazgo | Ubicación |
|---|---|---|
| APP-M1 | SAML sin `audience` ni `validateInResponseTo`: reutilización o replay de aserciones | `auth/strategies/saml.strategy.ts:55-65` |
| APP-M2 (PLAUS) | SSO vincula por email y sobrescribe `role`/`authProvider` de cuentas locales: posible toma de cuenta vía claims mutables | `azure-oidc.service.ts:131-203`, `saml.strategy.ts:71-126` |
| APP-M3 | Inyección HTML en correos: `String.replace` sin escapar y `requesterName` controlado por un anónimo | `notification.service.ts:2005-2014`, `templates/local-signup-*.html` |
| APP-M4 | El HTML de reset y de aprobación (token en claro) se guarda en `notification_log` y se ve o reenvía vía API | `notification.service.ts:714-719,1493-1528` |
| APP-M5 | El reset se envía a `notificationEmail`, que el usuario cambia sin verificar (persistencia tras robar el JWT) | `password-reset.service.ts:113`, `auth.controller.ts:105` |
| APP-M6 | Endpoints sin `@Roles`: etiquetar CVEs, generar informes (DoS de Puppeteer con `hours` sin límite), descargar informes y `ai/chat` | `vulnerability-collector.controller.ts:458,617,641`, `ai.controller.ts:12` |
| APP-M7 | Sin throttling por IP en `/auth/*`. El bloqueo por email permite DoS de la víctima y la IP se guarda como `0.0.0.0` | `auth.service.ts:67-77,260-263` |
| APP-M8 | Las API keys no se revocan al degradar o desactivar al usuario. Scopes sin validar en `update`. Throttler después de la autenticación | `external-api/guards/api-key.guard.ts`, `api-keys.service.ts:93` |
| APP-M9 | CSP y HSTS solo con `NODE_ENV=production`. Swagger activable en prod. `CORS_ORIGIN=*` + `credentials` refleja cualquier origen | `main.ts:20-73` |

### Bajos
| ID | Hallazgo |
|---|---|
| APP-B1 | La contraseña SMTP y la API key de OpenAI se guardan **en claro** en la columna `api_key_encrypted` (`notification.service.ts:143,438-462`, `ai.service.ts:69`). Verificado |
| APP-B2 | `DELETE /users/:id` devuelve `passwordHash` y `mfaSecret*` (`users.service.ts:346-351`) |
| APP-B3 | Endpoints de usuarios, portal y colector con `body: any`/tipos inline: `ValidationPipe` no valida. Política de contraseña débil |
| APP-B4 | Un `TEAM_MANAGER` enumera todos los usuarios activos (`subscriber-teams.service.ts:199-211`) |
| APP-B5 | SSRF semiciega por ADMIN vía la `baseUrl` de Ollama (`ai.service.ts:39-191`) |
| APP-B6 | Puppeteer `--no-sandbox` (ver INF-07). El HTML está escapado, así que hoy es un riesgo bajo |
| APP-B7 | `development-login` (token ADMIN) y el bypass MFA dependen solo de `OCC_ENV`, no de `NODE_ENV`. Falta un fallo duro al arrancar |
| APP-B8 | JWT sin `algorithms`/`audience`/`issuer`, sin revocación ni logout, 24 h por defecto y sin longitud mínima de secreto |
| APP-B9 | El token SSO va en el fragmento de la URL y se guarda en `localStorage` (riesgo si hay XSS) |
| APP-B10 | Fuga de `error.message` en el envío de correo y en la IA |
| APP-B11 | `secret-crypto.util.ts` (nuevo): AES-256-GCM correcto. Acepta frases de paso con sal fija y no usa AAD |
| APP-B12 | Body limit de 10 MB global |
| APP-B13 | TOCTOU en el uso único del token de reset. El reset no invalida los JWT emitidos |

### Bien resuelto (mantener)
- **Contraseñas:** bcrypt con coste 12.
- **Tokens de reset y de alta:** 32 bytes guardados como SHA-256, con expiración y respuesta anti-enumeración.
- **OIDC:** PKCE S256 + `state` + `nonce`, cookies `httpOnly`/`secure`.
- **SAML:** exige respuesta y aserción firmadas.
- **Secreto MFA:** AES-256-GCM.
- **Credenciales:** sin credenciales hardcodeadas ni JWT secret por defecto.
- **API keys:** de 160 bits y guardadas con bcrypt.
- **SQL:** sin SQL raw inseguro ni `child_process`.
- **Plantillas:** Handlebars sin triple-stash.
- **Diffs de parches:** allowlist estricta.
- **Defender (nuevo):** allowlist HTTPS y secreto cifrado.
- **IDOR en equipos:** controlado con `{id, teamId}`.
- **Módulo `test-data`:** no se importa en `AppModule`.
- **`ValidationPipe`:** global con `whitelist`/`forbidNonWhitelisted`.

## 5. Dependencias (DEP)

`npm audit --omit=dev` el 2026-11-21:
- **Backend:** 46 vulnerabilidades (5 críticas, 29 altas, 12 moderadas).
- **Frontend:** 0.

| Paquete (directo) | Versión | Problema | Corrección |
|---|---|---|---|
| `passport-saml` | 3.2.4 | **Crítica:** verificación de firma SAML (node-saml). **Sin parche**, paquete abandonado. Arrastra `xml-crypto`, `@xmldom/xmldom`, `xml-encryption` y `xml2js` vulnerables | Migrar a `@node-saml/passport-saml` ≥5 |
| `handlebars` | ≤4.7.9 | **Crítica:** inyección JS y prototype pollution | Actualizar a la última 4.7.x parcheada |
| `axios` | <1.19.1 | **Alta:** bypass de SSRF con NO_PROXY y prototype pollution | Actualizar a la última 1.x |
| `mysql2` | ≤3.23.0 | **Alta:** degradación a `mysql_clear_password` y zip bomb | Actualizar a la última 3.x |
| `nodemailer` | 8.x | **Alta:** inyección SMTP/CRLF | Actualizar a 10.6.1+ (major) |
| `puppeteer` | 23.x | **Alta** (y transitivas `tar`, `basic-ftp`, `ws`, `extract-zip`) | Actualizar a 25.x |
| `@nestjs/*` | 10.x | **Alta:** `express`, `body-parser`, `multer`, `path-to-regexp`, `proxy-addr` (crítica: IP spoofing) | Migración NestJS 10 → 11 (y valorar 12) |

## 6. Limitaciones

- No se ha accedido al servidor ni al `.env.prod` real. Sin evidencia de: cifrado de disco del host, configuración del ingress TLS/WAF, firewall, permisos de `.env.prod` ni copias externas.
- No se han escaneado los paquetes del SO de las imágenes (Trivy/Grype) ni se han hecho pruebas dinámicas o de penetración.
- APP-M2 y el auto-aprobado de APP-A1 por escáneres de correo son plausibles y están pendientes de prueba contra un tenant real.
