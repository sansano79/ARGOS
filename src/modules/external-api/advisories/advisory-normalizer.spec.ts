import {
  normalizeAdvisory,
  normalizeLegacyProducts,
} from "./advisory-normalizer";

const osv = {
  id: "GO-2024-0001",
  aliases: ["CVE-2024-1000", "GHSA-abcd-efgh-ijkl"],
  modified: "2026-11-05T10:00:00Z",
  affected: [
    {
      package: { ecosystem: "Go", name: "golang.org/x/net" },
      ranges: [
        {
          type: "SEMVER",
          events: [
            { introduced: "0" },
            { fixed: "1.2.0" },
            { introduced: "2.0.0" },
            { last_affected: "2.1.0" },
          ],
        },
      ],
      ecosystem_specific: {
        imports: [
          { path: "golang.org/x/net/http2", symbols: ["Server.ServeConn"] },
        ],
      },
    },
  ],
  references: [
    {
      type: "FIX",
      url: "https://github.com/golang/net/commit/abcdef1234567890",
    },
  ],
};

describe("advisory contract", () => {
  it("keeps defaults unknown when no source establishes a negative fact", () => {
    const result = normalizeAdvisory({
      local: {
        cveId: "CVE-2024-1000",
        isKnownExploited: false,
        hasPublicExploit: false,
      },
    });
    expect(result.exploitation.kev).toBeNull();
    expect(result.exploitation.public_exploit).toBeNull();
    expect(result.exploitation.maturity).toBeNull();
    expect(result.patch.patch_available).toBeNull();
    expect(result.technique.requires_authentication).toBeNull();
    expect(result.completeness.symbols).toBe("absent");
    expect(result.completeness.detection).toBe("absent");
    expect(result).not.toHaveProperty("version_in_affected_range");
  });

  it("resolves aliases, splits disjoint intervals and extracts qualified Go symbols", () => {
    const result = normalizeAdvisory({
      osv: [osv],
      queriedPackage: {
        ecosystem: "Go",
        name: "golang.org/x/net",
        version: "1.0.0",
      },
    });
    expect(result.advisory_id).toBe("CVE-2024-1000");
    expect(result.aliases).toEqual(["GHSA-abcd-efgh-ijkl", "GO-2024-0001"]);
    expect(result.version_in_affected_range).toBe(true);
    expect(result.affected).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          introduced: "0",
          fixed: "1.2.0",
          last_affected: null,
        }),
        expect.objectContaining({
          introduced: "2.0.0",
          fixed: null,
          last_affected: "2.1.0",
        }),
      ]),
    );
    expect(result.vulnerable_symbols[0]).toMatchObject({
      qualified_name: "golang.org/x/net/http2.Server.ServeConn",
      source: "osv",
      confidence: 0.95,
    });
    expect(result.patch.fixed_versions).toEqual(["1.2.0"]);
    expect(result.patch.fix_commits[0]).toMatchObject({
      repo_url: "https://github.com/golang/net",
      sha: "abcdef1234567890",
    });
    expect(result.references[0].tags).toContain("Patch");
    expect(result.field_provenance["patch.fixed_versions"]).toMatchObject({
      source: "osv",
    });
  });

  it("does not use Git hashes as fixed package versions or version ranges", () => {
    const result = normalizeAdvisory({
      osv: [
        {
          id: "GHSA-abcd-efgh-ijkl",
          affected: [
            {
              package: { ecosystem: "npm", name: "example" },
              ranges: [
                {
                  type: "GIT",
                  repo: "https://github.com/a/b",
                  events: [
                    { introduced: "a".repeat(40) },
                    { fixed: "b".repeat(40) },
                  ],
                },
              ],
            },
          ],
        },
      ],
    });
    expect(result.patch.fixed_versions).toEqual([]);
    expect(result.affected[0].version_range).toBeNull();
    expect(result.patch.fix_commits[0].sha).toBe("b".repeat(40));
  });

  it("extracts CVE.org routines/files, CAPEC and retains both CVSS vectors", () => {
    const raw = {
      containers: {
        cna: {
          affected: [
            {
              vendor: "acme",
              product: "lib",
              modules: ["mod"],
              programRoutines: [{ name: "mod.parse" }],
              programFiles: ["mod.py"],
            },
          ],
          impacts: [{ capecId: "CAPEC-586", descriptions: [] }],
        },
      },
    };
    const result = normalizeAdvisory({
      local: {
        cveId: "CVE-2024-1000",
        source: "cveorg",
        rawData: JSON.stringify(raw),
        cvssV31Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvssV40Vector:
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      },
    });
    expect(result.vulnerable_symbols[0]).toMatchObject({
      qualified_name: "mod.parse",
      source: "cve.org",
    });
    expect(result.affected_files[0].path_in_package).toBe("mod.py");
    expect(result.weakness.capec_ids).toEqual(["CAPEC-586"]);
    expect(result.attack.attack_vector).toBe("network");
    expect(result.technique.exploit_class).toBe("remote");
    expect(result.attack.cvss_v40.cvss_version).toBe("4.0");
    expect(result.technique.requires_authentication).toBe(false);
    expect(result.technique.effect).toBeNull();
  });

  it("preserves detailed exploits and does not equate public PoCs with active exploitation", () => {
    const result = normalizeAdvisory({
      local: {
        cveId: "CVE-2024-1000",
        sourceRecords: [
          {
            sourceName: "exploitdb",
            normalizedData: JSON.stringify({
              exploits: [
                {
                  id: "123",
                  type: "remote",
                  platform: "linux",
                  datePublished: "2024-04-02",
                },
              ],
            }),
          },
        ],
      },
    });
    expect(result.exploitation.exploits[0]).toMatchObject({
      id: "EDB-123",
      type: "remote",
      platform: "linux",
      published_at: "2024-04-02",
    });
    expect(result.exploitation.public_exploit).toBe(true);
    expect(result.exploitation.maturity).toBe("poc");
    expect(result.exploitation.kev).toBeNull();
  });

  it("rejects legacy CPE text and preserves valid package metadata", () => {
    const result = normalizeLegacyProducts([
      { vendor: "apache", product: "log4j", versionRange: "<log4j-core*" },
      {
        vendor: "pypi",
        product: "requests",
        ecosystem: "PyPI",
        versionRange: ">=1.0 <2.31.0",
        fixedVersions: ["2.31.0"],
      },
    ]);
    expect(result[0].versionRange).toBeNull();
    expect(result[1].versionRange).toBe(">=1.0,<2.31.0");
    expect(result[1].fixedVersions).toEqual(["2.31.0"]);
  });
});

describe("NVD range compatibility", () => {
  it("recovers nested NVD bounds, exact CPE versions and correction boundaries from persisted raw evidence", () => {
    const result = normalizeAdvisory({
      local: {
        cveId: "CVE-2021-44228",
        source: "nvd",
        rawData: JSON.stringify({
          cve: {
            configurations: [
              {
                nodes: [
                  {
                    children: [
                      {
                        cpeMatch: [
                          {
                            vulnerable: true,
                            criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                            versionStartIncluding: "2.0",
                            versionEndExcluding: "2.15.0",
                          },
                        ],
                      },
                    ],
                  },
                ],
              },
            ],
          },
        }),
      },
    });
    expect(result.affected[0]).toMatchObject({
      name: "log4j",
      version_range: ">=2.0 <2.15.0",
      source: "nvd",
    });
    expect(result.patch.fixed_versions).toContain("2.15.0");
  });
});

describe("accredited advanced enrichment", () => {
  it("exposes persisted techniques and detection rules only with field-level evidence", () => {
    const result = normalizeAdvisory({
      local: {
        cveId: "CVE-2024-1000",
        sourceRecords: [
          {
            sourceName: "manual",
            normalizedData: JSON.stringify({
              advisory: {
                technique: {
                  attack_techniques: [
                    {
                      id: "T1190",
                      name: "Exploit Public-Facing Application",
                      tactic: "initial-access",
                    },
                  ],
                  trigger_summary: "Verified trigger",
                  requires_configuration: ["debug enabled"],
                },
                detection: {
                  rules: [
                    {
                      kind: "semgrep",
                      id: "verified-rule",
                      url: "https://github.com/acme/rules/blob/main/rule.yaml",
                    },
                  ],
                },
                field_provenance: {
                  "technique.attack_techniques": {
                    source: "manual",
                    confidence: 0.9,
                  },
                  "technique.trigger_summary": {
                    source: "manual",
                    confidence: 0.9,
                  },
                  "detection.rules": { source: "github", confidence: 0.8 },
                },
              },
            }),
          },
        ],
      },
    });
    expect(result.technique.attack_techniques[0].id).toBe("T1190");
    expect(result.technique.trigger_summary).toBe("Verified trigger");
    expect(result.technique.requires_configuration).toEqual([]);
    expect(result.detection.rules[0].kind).toBe("semgrep");
    expect(result.completeness["technique.requires_configuration"]).toBe(
      "absent",
    );
    expect(result.completeness.detection).toBe("present");
  });
  it("does not infer authentication from local privileges alone", () => {
    const result = normalizeAdvisory({
      local: {
        cveId: "CVE-2024-1000",
        source: "nvd",
        cvssV31Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      },
    });
    expect(result.technique.requires_authentication).toBeNull();
  });
});

describe("patch fallback", () => {
  it("marks symbols inferred from a patch as derived and never as source-supplied symbols", () => {
    const result = normalizeAdvisory({
      local: { cveId: "CVE-2024-1000" },
      patchEvidence: {
        symbols: [
          {
            qualified_name: "lib.parse",
            source: "patch_diff",
            confidence: 0.55,
            language: "python",
            kind: "function",
          },
        ],
        files: [],
      },
    });
    expect(result.vulnerable_symbols[0]).toMatchObject({
      qualified_name: "lib.parse",
      source: "patch_diff",
      confidence: 0.55,
    });
    expect(result.completeness.symbols).toBe("derived");
  });
});
