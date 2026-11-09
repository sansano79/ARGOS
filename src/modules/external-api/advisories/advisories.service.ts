import { randomUUID } from "crypto";
import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from "@nestjs/common";
import { PrismaService } from "../../../prisma/prisma.service";
import { OsvCollector } from "../../vulnerability-collector/collectors/osv.collector";
import {
  ECOSYSTEMS,
  jsonValue,
  normalizeAdvisory,
  PublicPackage,
} from "./advisory-normalizer";
import { PatchEvidenceService } from "./patch-evidence.service";

@Injectable()
export class AdvisoriesService {
  private readonly logger = new Logger(AdvisoriesService.name);
  constructor(
    private readonly prisma: PrismaService,
    private readonly osv: OsvCollector,
    private readonly patches: PatchEvidenceService,
  ) {}

  capabilities() {
    return {
      max_packages_per_request: 100,
      ecosystems: ECOSYSTEMS,
      schema_version: "1.0",
      package_query_enabled: this.osv.isEnabled(),
      field_provenance: "JSON paths; derived fields include confidence",
      completeness_states: ["present", "derived", "absent"],
      optional_enrichment: {
        patch_diff: "GitHub commits; top-level Python functions",
        attack_techniques: "accredited source contributions",
        detection: "accredited source contributions",
      },
    };
  }

  async query(packages: PublicPackage[], apiKeyId?: number): Promise<any> {
    if (!Array.isArray(packages) || !packages.length || packages.length > 100)
      throw new BadRequestException("Provide 1 to 100 packages");
    const results: any[] = [];
    const requestId = randomUUID();
    this.audit({
      request_id: requestId,
      operation: "package_query",
      api_key_id: apiKeyId,
      packages,
    });
    // Bound outgoing concurrency while preserving the exact input order and duplicate requests.
    for (let i = 0; i < packages.length; i += 5) {
      const chunk = await Promise.all(
        packages.slice(i, i + 5).map(async (pkg) => {
          if (!(ECOSYSTEMS as readonly string[]).includes(pkg.ecosystem))
            return {
              ...pkg,
              status: "not_audited",
              reason: "unsupported_ecosystem",
              advisories: [],
            };
          try {
            const records = await this.osv.queryPackage(pkg);
            const advisories: any[] = [];
            for (const group of this.groupAliases(records)) {
              const local = await this.findLocal(
                group.flatMap((r) => [r.id, ...(r.aliases || [])]),
              );
              const normalized = normalizeAdvisory({
                osv: group,
                local,
                queriedPackage: pkg,
              });
              const patchEvidence = await this.patches.enrich(normalized);
              const advisory = normalizeAdvisory({
                osv: group,
                local,
                queriedPackage: pkg,
                patchEvidence,
              });
              advisory.provenance.patch_lookup_status = patchEvidence.status;
              advisories.push(advisory);
            }
            return { ...pkg, status: "audited", advisories };
          } catch (error) {
            return {
              ...pkg,
              status: "not_audited",
              reason:
                error.message === "OSV_DISABLED"
                  ? "source_disabled"
                  : "upstream_unavailable",
              advisories: [],
            };
          }
        }),
      );
      results.push(...chunk);
    }
    this.audit({
      request_id: requestId,
      operation: "package_query_result",
      api_key_id: apiKeyId,
      statuses: results.map((r) => r.status),
    });
    return { results };
  }

  async getById(id: string, apiKeyId?: number): Promise<any> {
    if (
      !/^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{4}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+)$/i.test(
        id,
      )
    )
      throw new BadRequestException("Unsupported advisory identifier");
    id = /^GHSA-/i.test(id)
      ? "GHSA-" + id.slice(5).toLowerCase()
      : id.toUpperCase();
    const requestId = randomUUID();
    this.audit({
      request_id: requestId,
      operation: "advisory_lookup",
      api_key_id: apiKeyId,
      advisory_id: id,
    });
    let records: any[] = [],
      lookupStatus = "complete";
    try {
      records = await this.osv.resolveAdvisory(id);
    } catch {
      lookupStatus = "upstream_unavailable";
    }
    const local = await this.findLocal([
      id,
      ...records.flatMap((r) => [r.id, ...(r.aliases || [])]),
    ]);
    if (!local && !records.length) {
      this.audit({
        request_id: requestId,
        operation: "advisory_lookup_result",
        api_key_id: apiKeyId,
        advisory_id: id,
        status: lookupStatus === "complete" ? "not_found" : lookupStatus,
      });
      if (lookupStatus !== "complete")
        throw new ServiceUnavailableException("Advisory source unavailable");
      throw new NotFoundException("Advisory not found");
    }
    const normalized = normalizeAdvisory({ local, osv: records });
    const patchEvidence = await this.patches.enrich(normalized);
    const result = normalizeAdvisory({ local, osv: records, patchEvidence });
    result.provenance.lookup_status = lookupStatus;
    result.provenance.patch_lookup_status = patchEvidence.status;
    this.audit({
      request_id: requestId,
      operation: "advisory_lookup_result",
      api_key_id: apiKeyId,
      advisory_id: id,
      status: lookupStatus,
    });
    return result;
  }

  private async findLocal(ids: string[]) {
    for (const id of ids.filter((id) => /^CVE-/.test(id))) {
      const local = await this.prisma.vulnerability.findUnique({
        where: { cveId: id },
        include: { sourceRecords: true },
      });
      if (local) return local;
    }
    for (const id of ids.filter((id) => !/^CVE-/.test(id))) {
      // Quoted JSON IDs avoid matching substrings in descriptions or unrelated IDs.
      const candidates = await this.prisma.vulnerabilitySourceRecord.findMany({
        where: {
          sourceName: "osv",
          OR: [
            { sourceRecordId: id },
            { rawPayload: { contains: JSON.stringify(id) } },
          ],
        },
        include: { vulnerability: { include: { sourceRecords: true } } },
        take: 100,
      });
      for (const source of candidates) {
        const raw = jsonValue(source.rawPayload, []);
        const records = Array.isArray(raw)
          ? raw
          : raw?.id
            ? [raw]
            : raw.records || [];
        if (
          source.sourceRecordId === id ||
          records.some((r) => r.id === id || r.aliases?.includes(id))
        )
          return source.vulnerability;
      }
      if (candidates.length === 100)
        throw new ServiceUnavailableException(
          "Local advisory lookup limit reached",
        );
    }
    return null;
  }

  private groupAliases(records: any[]): any[][] {
    const groups: { ids: Set<string>; records: any[] }[] = [];
    for (const record of records) {
      const ids = new Set<string>([record.id, ...(record.aliases || [])]);
      const matches = groups.filter((g) =>
        [...ids].some((id) => g.ids.has(id)),
      );
      const group = { ids, records: [record] };
      for (const match of matches) {
        match.ids.forEach((id) => ids.add(id));
        group.records.push(...match.records);
        groups.splice(groups.indexOf(match), 1);
      }
      groups.push(group);
    }
    return groups.map((g) => g.records);
  }

  private audit(event: Record<string, any>) {
    this.logger.log(
      JSON.stringify({
        event: "advisory_api",
        at: new Date().toISOString(),
        ...event,
      }),
    );
  }
}
