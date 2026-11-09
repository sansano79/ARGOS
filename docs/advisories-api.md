# API de avisos para ASTREA

Implementación local de la petición del 6 de noviembre de 2026. ARGOS aporta
contexto público, versiones y evidencia; el cliente decide la factibilidad en su
programa. Estos endpoints no reciben código, rutas ni datos internos del cliente.

## Rutas y acceso

Todas las rutas usan el prefijo habitual `/api/v1`, cabecera `X-API-Key`, scope
`vulnerabilities:read` y el límite de peticiones de la API externa.

| Método | Ruta | Resultado |
| --- | --- | --- |
| GET | `/api/v1/advisories/capabilities` | Límite 100, ecosistemas, disponibilidad de OSV y contrato |
| POST | `/api/v1/advisories/query` | Un resultado por paquete, en el mismo orden |
| GET | `/api/v1/advisories/{id}` | Aviso canónico por CVE, GHSA, PYSEC o GO |
| GET | `/api/v1/vulnerabilities/{cve}/assessment` | El mismo objeto de aviso |

Configurar `OSV_ENABLED=true` para las consultas públicas de versiones y la
resolución remota. Se conservan `OSV_BASE_URL` y `OSV_TIMEOUT_MS`. Con OSV
inhabilitado, la consulta de paquetes devuelve `not_audited/source_disabled` y
los CVE guardados siguen disponibles con sus ausencias explícitas.

```http
POST /api/v1/advisories/query
X-API-Key: <clave>
Content-Type: application/json

{"packages":[{"ecosystem":"PyPI","name":"requests","version":"2.0.0"}]}
```

```json
{"results":[{"ecosystem":"PyPI","name":"requests","version":"2.0.0","status":"audited","advisories":[]}]}
```

El ejemplo vacío solo representa una consulta satisfactoria sin avisos. Un fallo
produce `status: "not_audited"`, `reason: "upstream_unavailable"` y una lista
vacía que **no certifica ausencia de avisos**. No se devuelve el error crudo del
proveedor. La API rechaza lotes vacíos, más de 100 entradas, campos extra y rangos
en lugar de versiones exactas. Ecosistemas: PyPI, npm, Go, Maven, crates.io,
RubyGems, NuGet y Packagist. Se preservan los duplicados de la entrada.

Las consultas OSV consumen todas las páginas, con concurrencia máxima de cinco
paquetes y límites para páginas repetidas. Si falla una página, el paquete entero
queda `not_audited`. Los registros retirados no se consideran avisos vigentes.
Se agrupan los avisos con aliases compartidos y se prefiere un CVE como ID
canónico. La consulta por ID recorre aliases públicos (máximo 20) y combina los
registros con la evidencia persistida. Un 404 del proveedor se distingue de un
fallo de red: sin datos locales se responde 404 o 503, respectivamente.

Las operaciones emiten registros JSON `event=advisory_api`, con `request_id`,
fecha, identificadores públicos consultados, ID de clave y resultado. La
retención depende del sistema de logs del despliegue. No se registran la clave,
código ni errores completos del proveedor. El broker y el registro de salida de
ASTREA corresponden al lado de ASTREA.

## Objeto y procedencia

Se devuelven los campos de la petición: `advisory_id`, `aliases`, `affected`,
`vulnerable_symbols`, `affected_files`, `patch`, `weakness`, `attack`, `technique`,
`exploitation`, `detection`, `mitigations`, `references`, `provenance` y
`completeness`. Solo la consulta por paquete incluye
`version_in_affected_range`, basada en la respuesta de OSV para esa versión.

Se mantienen los valores primitivos de los ejemplos del contrato. La procedencia
por campo está en un mapa adicional **`field_provenance`**, con rutas separadas
por puntos, por ejemplo:

```json
{
  "technique": {"exploit_class":"remote", "requires_authentication":null},
  "field_provenance": {
    "technique.exploit_class": {"source":"nvd","confidence":0.75}
  }
}
```

Cada elemento de símbolos, ficheros, rangos, referencias, commits y exploits
incluye además su fuente. Los símbolos inferidos llevan confianza propia.
`null` significa desconocido. `completeness` contiene estados por sección y por
campo, por ejemplo `symbols`, `affected_range`, `technique.input_kinds`,
`technique.requires_configuration` y `detection.rules`. Una lista vacía con
estado `absent` significa que falta evidencia: **no demuestra que el riesgo, el
símbolo, el exploit o la configuración no existan**.

| Datos | Obtención |
| --- | --- |
| Rangos y versiones corregidas | Intervalos OSV separados; nunca se mezclan intervalos disjuntos ni hashes Git con versiones publicadas |
| Símbolos | `affected[].ecosystem_specific/database_specific`, imports/symbols Go, rutinas CVE.org |
| Ficheros | `programFiles` CVE.org y diffs opcionales |
| Parche | Referencias etiquetadas, commits Git OSV, PR y versiones corregidas |
| CWE y CAPEC | Datos persistidos, OSV y `impacts` CVE.org |
| Ataque | Vector CVSS 3.x primario y CVSS 4.0 adicional en `attack.cvss_v40` |
| Técnica básica | Clase remota/local de CVSS o ExploitDB; efectos e input de un subconjunto explícito de CWE |
| Explotación | KEV, EPSS y referencias/entradas ExploitDB persistidas; un PoC no implica explotación activa |
| ATT&CK, reglas y detalle adicional | Contribuciones estructuradas acreditadas; sin datos se devuelve `absent` |

No se deduce RCE solo por deserialización, ni autenticación a partir de
privilegios locales, ni una técnica ATT&CK a partir únicamente de un CVSS de red.
Un límite NVD `versionEndExcluding` se conserva como frontera de corrección con
confianza 0.7 cuando es la única evidencia; no garantiza un parche compatible con
todas las ramas. Las versiones globales de `patch.fixed_versions` pueden
pertenecer a varios paquetes: consultar también `affected` para asociarlas.

### Diffs opcionales

`ADVISORIES_PATCH_DIFF_ENABLED=true` habilita la consulta de commits públicos de
GitHub: máximo tres commits por aviso, respuesta limitada, sin redirecciones y
caché acotada de una hora. Nunca se visita una URL arbitraria de una referencia.
Se incluyen los ficheros modificados y solo se infieren funciones Python de nivel
superior que aparezcan inequívocamente en el contexto del diff. La confianza es
0.55: un símbolo tocado por el parche es una pista, no prueba de vulnerabilidad.
Los paths de un diff son relativos al repositorio; pueden requerir resolver la
raíz del paquete. No se analizan métodos sin contexto de clase ni otros lenguajes.

`patch.diff_touched_symbols` contiene objetos con `qualified_name`, `source` y
`confidence`, además de lenguaje y fichero. Si no hay símbolos de fuentes nativas,
estos también aparecen en `vulnerable_symbols` con `completeness.symbols=derived`.
Un fallo opcional queda reflejado en `provenance.patch_lookup_status`.

### Contribuciones avanzadas

Una fuente acreditada puede guardar en `VulnerabilitySourceRecord.normalizedData`
un objeto `advisory` con los campos del contrato y su `field_provenance`:

```json
{
  "advisory": {
    "detection": {
      "rules": [{"kind":"semgrep","id":"verified-rule","url":"https://github.com/org/rules/blob/main/rule.yaml"}]
    },
    "field_provenance": {
      "detection.rules": {"source":"github","confidence":0.9}
    }
  }
}
```

Se aceptan técnicas ATT&CK, resumen de disparo, requisitos de entrada,
autenticación/configuración, efectos, patrones, reglas, mitigaciones y CAPEC.
Se valida el tipo, las enumeraciones, la fuente y la confianza 0–1 de cada
campo; texto libre sin procedencia se ignora. No hay descubrimiento automático
de reglas o mapeos ATT&CK ni generación de narrativas. No se ha añadido un
endpoint de escritura de contribuciones manuales.

## Compatibilidad e ingestión

La API existente mantiene referencias con `tags` y los campos `cvssV31Vector` y
`cvssV40Vector`. Añade `affectedVersions: string[]` y conserva
`affectedProductsDetailed`. Rangos desconocidos o texto CPE como
`<log4j-core*` pasan a `null`. Se emplean comas PEP 440 para PyPI, notación de
intervalos para Maven y comparadores para los demás ecosistemas. No se realiza
un comparador universal propio: OSV determina la coincidencia de versiones.

`fixedVersions` se recupera de metadatos de paquetes, fuentes OSV y fronteras
NVD disponibles. El detalle puede enriquecerse mediante OSV si está habilitado;
los listados usan datos persistidos. El enriquecimiento OSV del colector ahora
guarda paquetes, versiones corregidas y registros de fuente completos en la misma
transacción. ExploitDB refresca los detalles de fuente incluso para CVE que ya
tenían un exploit; se conservan todas las entradas, sin truncar a cinco.

No requiere migración: reutiliza las columnas JSON y `sourceRecords`. Los datos
históricos se reparan al enriquecerse o al consultar el detalle; no se ha
modificado una base de datos durante esta implementación.

## Verificación

```sh
MFA_DEV_BYPASS_ENABLED=false npm test -- --runInBand
npm run build
npx ts-node scripts/verify-advisories-live.ts
```

El primer comando fija la variable de entorno de las pruebas, sin cambiar la
configuración ni el comportamiento de autenticación. Las pruebas heredadas de
MFA no fijan esa variable en todos sus escenarios.

Las pruebas nuevas cubren normalización, aliases, intervalos, ausencias,
procedencia, fallos de páginas, persistencia, diffs y HTTP con clave/scope reales
sobre base de datos simulada. La prueba pública utiliza el servicio local sin
base de datos y verifica Log4Shell en Log4j 2.14.1 y su ausencia en 2.17.1, además
de consultar requests 2.0.0. La ausencia de Log4Shell en 2.17.1 no significa que
esa versión carezca de otros avisos.

Verificación local del 7 de noviembre de 2026: 31 suites y 372 pruebas pasan,
compilación correcta y prueba pública OSV satisfactoria. La ejecución sin fijar
`MFA_DEV_BYPASS_ENABLED` reprodujo dos fallos heredados de entorno; con la variable
en `false`, toda la suite pasa sin cambios en autenticación.

No se ha desplegado en TITAN ni verificado una base de datos real o un servicio
publicado. La generación de mapas ATT&CK y reglas seguirá dependiendo de fuentes
acreditadas; no se presentan como datos calculados automáticamente.

Referencias de implementación: [consulta por paquete OSV](https://google.github.io/osv.dev/post-v1-query/),
[consulta por ID OSV](https://google.github.io/osv.dev/get-v1-vulns/),
[esquema OSV](https://ossf.github.io/osv-schema/).
