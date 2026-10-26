# Test Users And MFA Bypass

## Finalidad

Este soporte crea una batería idempotente de datos de prueba para validar la gestión de usuarios, equipos suscriptores, membresías, destinatarios, suscripciones y sistemas sin tocar datos reales. También añade un bypass temporal de MFA limitado a cuentas de test explícitamente autorizadas.

## Cuentas creadas

El seed crea exclusivamente usuarios con email prefijado por `test.` y equipos con código prefijado por `test-`.

Usuarios:

- `test.admin@occ.local`
- `test.manager.it@occ.local`
- `test.manager.multi@occ.local`
- `test.manager.unassigned@occ.local`
- `test.viewer.it@occ.local`
- `test.viewer.erp@occ.local`
- `test.user.multi@occ.local`
- `test.user.unassigned@occ.local`
- `test.user.disabled@occ.local`
- `test.user.nologin@occ.local`

Equipos:

- `test-it-global`
- `test-infra`
- `test-erp`
- `test-soc`

## Matriz de pruebas

- `ADMIN` puede tener rol interno `TEAM_MANAGER` o `TEAM_VIEWER`.
- `TEAM_MANAGER` global puede tener rol interno `TEAM_MANAGER` o `TEAM_VIEWER`.
- `USER` solo puede tener rol interno `TEAM_VIEWER`.
- El seed falla si una combinación usuario-equipo no cumple esa matriz.

## Variables

Añadir en el entorno local o en el contenedor de pruebas:

```env
OCC_ENV=production
TEST_DATA_SEED_ENABLED=true
TEST_USERS_PASSWORD=ChangeMeNow123!
MFA_TEST_BYPASS_ENABLED=false
MFA_TEST_BYPASS_EMAILS=
MFA_DEV_BYPASS_ENABLED=false
```

Reglas:

- `TEST_DATA_SEED_ENABLED=true` es obligatorio para ejecutar seed o cleanup.
- `OCC_ENV` admite solo `development`, `test`, `preproduction` y `production`.
- Seed, cleanup y bypass MFA solo están permitidos con `OCC_ENV=development` o `OCC_ENV=test`.
- `TEST_USERS_PASSWORD` no se versiona y debe cumplir la longitud mínima exigida por la aplicación.
- `MFA_TEST_BYPASS_EMAILS` usa coincidencia exacta, separada por comas.
- Un `OCC_ENV` vacío o desconocido se rechaza en modo fail-closed.

## Ejecución

Preparar el entorno y ejecutar:

```bash
npm run seed:test-data
```

Dry-run sin escrituras:

```bash
npm run seed:test-data -- --dry-run
```

El script:

- valida entorno y contraseña;
- muestra un resumen sin imprimir secretos;
- hace `upsert` de equipos y usuarios;
- crea o reactiva membresías;
- crea destinatarios, suscripciones y sistemas de prueba;
- no toca usuarios que no empiecen por `test.`.
- con `--dry-run` no escribe ni modifica base de datos.

## Limpieza

La limpieza exige confirmación explícita:

```bash
npm run cleanup:test-data -- --confirm
```

Dry-run sin lecturas destructivas:

```bash
npm run cleanup:test-data -- --dry-run
```

El script:

- rechaza `OCC_ENV=preproduction`, `OCC_ENV=production`, vacío o desconocido;
- elimina solo usuarios con email `test.*`;
- elimina solo equipos con código `test-*`;
- borra destinatarios, membresías, suscripciones y sistemas asociados;
- no borra `admin@occ.local`;
- puede ejecutarse varias veces sin dejar residuos inconsistentes.
- con `--dry-run` no lee, no borra y solo informa del alcance.

## Activación del bypass MFA

Para desarrollo local, se puede activar `MFA_DEV_BYPASS_ENABLED=true`. Con `OCC_ENV=development` o `OCC_ENV=test`, el login local omitirá el desafío MFA para cualquier cuenta activa con permiso de acceso. El guard de entorno hace que el arranque falle si esta opción se habilita en preproducción o producción. El bypass no cambia el estado MFA guardado en la cuenta.

Ejemplo de activación temporal:

```env
MFA_TEST_BYPASS_ENABLED=true
MFA_TEST_BYPASS_EMAILS=test.admin@occ.local,test.manager.it@occ.local
MFA_DEV_BYPASS_ENABLED=false
```

Condiciones acumulativas para que el bypass aplique:

- `OCC_ENV=development` o `OCC_ENV=test`
- `MFA_DEV_BYPASS_ENABLED=false` para usar solo el bypass restringido a cuentas de test
- `MFA_TEST_BYPASS_ENABLED=true`
- email incluido exactamente en la allowlist
- email prefijado por `test.`
- usuario activo
- `canLogin=true`
- contraseña válida

Si se cumplen, el login local entrega token sin desafío MFA. El sistema:

- no desactiva MFA global;
- no altera la configuración MFA del usuario;
- no marca MFA como configurado;
- no devuelve secretos TOTP;
- registra `TEST_MFA_BYPASS_USED`.

Para desactivar el bypass general de desarrollo, configurar `MFA_DEV_BYPASS_ENABLED=false` y reiniciar la aplicación.

## Desactivación inmediata

Para desactivar el bypass:

```env
MFA_TEST_BYPASS_ENABLED=false
MFA_TEST_BYPASS_EMAILS=
```

Tras reiniciar la aplicación, los usuarios de test vuelven a seguir el flujo MFA normal.

## Riesgos

- No debe activarse en producción.
- No debe usarse con cuentas reales.
- La allowlist debe mantenerse mínima y explícita.
- La contraseña compartida de test debe rotarse fuera del repositorio cuando proceda.

## Prohibición en producción y preproducción

Si `OCC_ENV=preproduction`, `OCC_ENV=production`, vacío o inválido y `MFA_TEST_BYPASS_ENABLED=true`, el arranque aborta en modo fail-closed con error explícito.

## Procedimiento para LXC

1. Configurar `OCC_ENV=test`.
2. Configurar `TEST_DATA_SEED_ENABLED=true`.
3. Definir `TEST_USERS_PASSWORD` con una contraseña temporal segura.
4. Ejecutar `npm run seed:test-data` o `npm run seed:test-data -- --dry-run`.
5. Verificar login con cuentas `test.*`.
6. Activar el bypass MFA solo si la prueba lo requiere.
7. Desactivar el bypass al terminar.
8. Ejecutar `npm run cleanup:test-data -- --confirm` o `npm run cleanup:test-data -- --dry-run` al finalizar las pruebas.

## Comprobaciones posteriores

- Confirmar que no se han creado usuarios fuera de `test.*`.
- Confirmar que no existen `UserSubscription` de prueba inesperadas.
- Confirmar que las cuentas reales siguen requiriendo MFA.
- Confirmar que los logs no contienen contraseñas ni hashes.
