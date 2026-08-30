# OCC-TVM — Evidencia de preparación para producción

OCC-TVM significa **Threat & Vulnerability Management**. Esta lista acompaña al despliegue y no sustituye la evidencia obtenida en el servidor.

## Contratos ya aplicados al repositorio

- El único manifiesto Compose versionado es `docker-compose.yml`; todos los scripts y ejemplos lo usan.
- MySQL y Redis quedan en redes internas; el frontend publica HTTP y reenvía `/api/` a la API interna.
- La API usa un usuario no privilegiado (`occ`) y el directorio persistente `storage/` se monta para informes y evidencias.
- `PRISMA_MIGRATE_ON_START=false` y `PRISMA_DB_PUSH_ON_START=false` son los valores de producción. Las migraciones se ejecutan explícitamente con `prisma migrate deploy` después de verificar el backup.
- HTTPS, certificados, WAF y políticas de borde se gestionan fuera de este programa mediante el proxy/ingress corporativo.
- El stack expone endpoints HTTP de salud en `/health` y `/api/health`.

## Evidencia obligatoria antes de publicar

1. Crear un dump con `./scripts/db-export-prod.sh`, registrar su ruta y `sha256sum`.
2. Restaurar ese dump en un MySQL aislado y comparar los conteos de tablas de negocio antes y después. No restaurar sobre producción para validar.
3. Copiar y proteger en el servidor `.env.prod` y el directorio de almacenamiento; no se versionan en Git.
4. Configurar y comprobar una cuenta real de Entra (OIDC o SAML) si se habilita SSO. Una configuración local no demuestra un inicio de sesión de producción.
5. Ejecutar `docker compose -f docker-compose.yml --env-file .env.prod config` y después aplicar las migraciones controladas:

   ```bash
   docker compose -f docker-compose.yml --env-file .env.prod run --rm api npx prisma migrate deploy
   ```

6. Publicar con `./deploy.sh` y adjuntar `docker compose -f docker-compose.yml --env-file .env.prod ps`.
7. Verificar desde el entorno interno `http://<host>/health` y `http://<host>/api/health`. En producción, verificar también las URLs HTTPS publicadas por el proxy/ingress externo.

## Límites de esta comprobación

El repositorio no permite acreditar por sí solo la procedencia ni la restauración de la base de datos real, el contenido histórico de `storage/`, la resolución DNS/TLS del proxy externo ni el inicio de sesión contra el tenant de Entra. Esos puntos permanecen bloqueantes hasta que exista evidencia del servidor de producción.
