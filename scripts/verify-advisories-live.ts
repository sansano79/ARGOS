/** Read-only smoke test against public OSV; no database or client code is used. */
import { strict as assert } from "assert";
import { HttpService } from "@nestjs/axios";
import { ConfigService } from "@nestjs/config";
import { OsvCollector } from "../src/modules/vulnerability-collector/collectors/osv.collector";
import { AdvisoriesService } from "../src/modules/external-api/advisories/advisories.service";
import { PatchEvidenceService } from "../src/modules/external-api/advisories/patch-evidence.service";

async function main() {
  const http = new HttpService();
  const config = new ConfigService({
    OSV_ENABLED: "true",
    OSV_TIMEOUT_MS: 20000,
  });
  const osv = new OsvCollector(http, config);
  const prisma = {
    vulnerability: { findUnique: async () => null },
    vulnerabilitySourceRecord: { findMany: async () => [] },
  };
  const service = new AdvisoriesService(
    prisma as any,
    osv,
    new PatchEvidenceService(http, config),
  );
  const advisory = await service.getById("CVE-2021-44228");
  assert(
    advisory.patch.fixed_versions.includes("2.15.0"),
    "Log4Shell: missing released fix version",
  );
  assert(
    advisory.affected.some((a) => a.ecosystem === "Maven" && a.version_range),
    "Log4Shell: missing Maven range",
  );
  const result = await service.query([
    {
      ecosystem: "Maven",
      name: "org.apache.logging.log4j:log4j-core",
      version: "2.14.1",
    },
    {
      ecosystem: "Maven",
      name: "org.apache.logging.log4j:log4j-core",
      version: "2.17.1",
    },
    { ecosystem: "PyPI", name: "requests", version: "2.0.0" },
  ]);
  assert(
    result.results.every((r) => r.status === "audited"),
    "A public package query failed",
  );
  assert(
    result.results[0].advisories.some(
      (a) => a.advisory_id === "CVE-2021-44228",
    ),
    "Vulnerable Log4j missing Log4Shell",
  );
  assert(
    !result.results[1].advisories.some(
      (a) => a.advisory_id === "CVE-2021-44228",
    ),
    "Fixed Log4j incorrectly includes Log4Shell",
  );
  console.log(
    JSON.stringify(
      {
        advisory_id: advisory.advisory_id,
        fixed_versions: advisory.patch.fixed_versions,
        packages: result.results.map((r) => ({
          ecosystem: r.ecosystem,
          name: r.name,
          version: r.version,
          status: r.status,
          advisories: r.advisories.length,
        })),
      },
      null,
      2,
    ),
  );
}
main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
