# API de avisos para ASTREA

Petición: implementar el documento aportado el 7 de noviembre de 2026.

## Decisiones

- Extender la API externa NestJS en `/api/v1`, con `X-API-Key`, scope
  `vulnerabilities:read`, límites y validación estricta existentes.
- OSV es la autoridad para consultar una versión en los ocho ecosistemas pedidos.
  Consultar todas las páginas; cualquier fallo produce `not_audited` y nunca un
  resultado vacío satisfactorio. Conservar orden, duplicados y errores por paquete.
- Resolver avisos y aliases con OSV y enriquecerlos con fuentes persistidas de ARGOS.
  Si OSV no responde, un CVE local sigue disponible con sus ausencias explícitas.
- Mantener valores primitivos y objetos del documento; `field_provenance` contiene
  source/confidence por ruta de campo, además de procedencia en cada elemento.
  Los campos sin evidencia son null o listas con completeness=absent.
- Extraer símbolos y ficheros de OSV y CVE.org, rangos disjuntos y versiones
  corregidas, referencias etiquetadas, CVSS 3/4 y exploits detallados.
- Resolver commits desde referencias. Lectura opcional de diffs públicos GitHub,
  acotada y sin seguir URLs arbitrarias. Inferencias conservadoras con confianza.
  ATT&CK y reglas de detección solo se expondrán si existen datos acreditados.
- Ofrecer `/vulnerabilities/:cve/assessment` con el mismo contrato y añadir
  `affectedVersions` en el API existente; rangos desconocidos pasan a null.
- Corregir el enriquecimiento OSV para conservar la contribución y su fuente.
  No requiere migración: se reutilizan sourceRecords y los JSON existentes.

## Secuencia y comprobación

1. Pruebas de normalización: ausencias, alias, intervalos, Go, CVE.org, CVSS,
   exploits y procedencia; comprobar fallo antes de implementar.
2. Cliente OSV: consulta pública por versión/ID, páginas, fallos y enriquecimiento.
3. Servicio/controladores: límites, autenticación, orden, resolución y registro.
4. Compatibilidad e ingestión: preservar referencias, arreglar rangos y OSV.
5. Pruebas de integración HTTP, suite backend y compilación. Documentar uso y
   limitaciones, distinguiendo implementación local de despliegue.

## Revisión

Casos críticos: fallo en segunda página, 404 frente a timeout, alias compartidos,
OSV retirado, rango Git frente a versión publicada, múltiples intervalos,
booleanos por defecto sin evidencia, datos crudos nunca expuestos, URLs de parche
no controladas y pérdida de metadatos de paquete durante la normalización.
