import { AdvisoriesService } from "./advisories.service";
const pkg = { ecosystem: "PyPI", name: "requests", version: "2.0.0" };
describe("AdvisoriesService", () => {
  let service: AdvisoriesService, osv: any, prisma: any;
  beforeEach(() => {
    osv = {
      isEnabled: () => true,
      queryPackage: jest.fn(),
      resolveAdvisory: jest.fn(),
    };
    prisma = {
      vulnerability: { findUnique: jest.fn().mockResolvedValue(null) },
      vulnerabilitySourceRecord: {
        findMany: jest.fn().mockResolvedValue([]),
      },
    };
    service = new AdvisoriesService(prisma, osv, {
      enrich: async () => ({ files: [], symbols: [] }),
    } as any);
  });
  it("keeps order, duplicates and per-package failure; an empty successful query is audited", async () => {
    osv.queryPackage
      .mockResolvedValueOnce([])
      .mockRejectedValueOnce(new Error("secret upstream details"))
      .mockResolvedValueOnce([]);
    const result = await service.query(
      [pkg, { ...pkg, name: "other" }, pkg],
      42,
    );
    expect(result.results.map((r) => r.status)).toEqual([
      "audited",
      "not_audited",
      "audited",
    ]);
    expect(result.results[1].reason).toBe("upstream_unavailable");
    expect(JSON.stringify(result)).not.toContain("secret");
    expect(result.results[0].advisories).toEqual([]);
  });
  it("merges aliases into one advisory and includes local enrichment", async () => {
    osv.queryPackage.mockResolvedValue([
      { id: "PYSEC-2024-1", aliases: ["CVE-2024-1000"] },
      { id: "GHSA-abcd-efgh-ijkl", aliases: ["CVE-2024-1000"] },
    ]);
    prisma.vulnerability.findUnique.mockResolvedValue({
      cveId: "CVE-2024-1000",
      isKnownExploited: true,
    });
    const result = await service.query([pkg]);
    expect(result.results[0].advisories).toHaveLength(1);
    expect(result.results[0].advisories[0].exploitation.kev).toBe(true);
  });
  it("resolves a remote alias to the canonical CVE and never emits a version decision on GET", async () => {
    osv.resolveAdvisory.mockResolvedValue([
      {
        id: "GHSA-abcd-efgh-ijkl",
        aliases: ["CVE-2024-1000"],
      },
    ]);
    const result = await service.getById("GHSA-abcd-efgh-ijkl");
    expect(result.advisory_id).toBe("CVE-2024-1000");
    expect(result).not.toHaveProperty("version_in_affected_range");
  });
  it("keeps local CVEs available on upstream failure with absent fields declared", async () => {
    osv.resolveAdvisory.mockRejectedValue(new Error("timeout"));
    prisma.vulnerability.findUnique.mockResolvedValue({
      cveId: "CVE-2024-1000",
    });
    const result = await service.getById("CVE-2024-1000");
    expect(result.advisory_id).toBe("CVE-2024-1000");
    expect(result.completeness.symbols).toBe("absent");
    expect(result.provenance.lookup_status).toBe("upstream_unavailable");
  });
  it("distinguishes not found from unavailable and rejects unsupported IDs", async () => {
    osv.resolveAdvisory.mockResolvedValue([]);
    await expect(service.getById("CVE-2024-1000")).rejects.toMatchObject({
      status: 404,
    });
    osv.resolveAdvisory.mockRejectedValue(new Error("timeout"));
    await expect(service.getById("CVE-2024-1000")).rejects.toMatchObject({
      status: 503,
    });
    await expect(service.getById("../../secret")).rejects.toMatchObject({
      status: 400,
    });
  });
  it("resolves a stored alias even if an earlier record only lists it as related", async () => {
    const id = "GHSA-abcd-efgh-ijkl";
    const unrelated = {
      rawPayload: JSON.stringify([{ id: "PYSEC-2024-2", related: [id] }]),
      vulnerability: { cveId: "CVE-2024-2000" },
    };
    const match = {
      rawPayload: JSON.stringify([{ id, aliases: ["CVE-2024-1000"] }]),
      vulnerability: { cveId: "CVE-2024-1000" },
    };
    osv.resolveAdvisory.mockResolvedValue([]);
    prisma.vulnerabilitySourceRecord.findMany = jest
      .fn()
      .mockResolvedValue([unrelated, match]);
    expect((await service.getById(id)).advisory_id).toBe("CVE-2024-1000");
  });
  it("advertises the batch limit and enforces it outside HTTP too", async () => {
    expect(service.capabilities().max_packages_per_request).toBe(100);
    await expect(service.query(Array(101).fill(pkg))).rejects.toMatchObject({
      status: 400,
    });
  });
});
