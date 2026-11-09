/** Public advisory projection. Raw payloads never leave this module. */
export interface PublicPackage {
  ecosystem: string;
  name: string;
  version: string;
}
export type AdvisorySource =
  | "osv"
  | "nvd"
  | "cve.org"
  | "cisa_kev"
  | "epss"
  | "exploitdb"
  | "github"
  | "patch_diff"
  | "manual";
export const ECOSYSTEMS = [
  "PyPI",
  "npm",
  "Go",
  "Maven",
  "crates.io",
  "RubyGems",
  "NuGet",
  "Packagist",
] as const;
export function jsonValue(value: any, fallback: any = null): any {
  if (typeof value !== "string") return value ?? fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}
const arr = (value: any): any[] => {
  const parsed = jsonValue(value);
  return Array.isArray(parsed) ? parsed : [];
};
const unique = <T>(values: T[]): T[] => [...new Set(values)];
const objects = (values: any[]) => [
  ...new Map(values.map((v) => [JSON.stringify(v), v])).values(),
];
export function sourceName(value: any): AdvisorySource | null {
  const source = value === "cveorg" ? "cve.org" : value;
  return [
    "osv",
    "nvd",
    "cve.org",
    "cisa_kev",
    "epss",
    "exploitdb",
    "github",
    "patch_diff",
    "manual",
  ].includes(source)
    ? source
    : null;
}
const version = (v: any) =>
  typeof v === "string" && /^v?\d[0-9A-Za-z.!+_~-]*$/.test(v);

/** Only emit explicit comparable bounds; never turn CPE configuration text into a range. */
export function formatVersionRange(
  ecosystem: string | null,
  introduced: string | null,
  fixed: string | null,
  last: string | null,
  limit: string | null = null,
): string | null {
  if ([introduced, fixed, last, limit].filter(Boolean).some((v) => !version(v)))
    return null;
  const lower = introduced && introduced !== "0" ? introduced : null;
  const upper = fixed || last || limit;
  if (!lower && !upper) return null;
  if (ecosystem === "Maven")
    return `${lower ? "[" + lower : "("},${upper || ""}${last ? "]" : ")"}`;
  const bounds = [
    lower ? `>=${lower}` : null,
    upper ? `${last ? "<=" : "<"}${upper}` : null,
  ].filter(Boolean);
  return bounds.join(ecosystem === "PyPI" ? "," : " ");
}
/** Recover explicit NVD bounds, including recursively nested configurations. */
export function nvdAffectedProducts(payload: any): any[] {
  const raw = jsonValue(payload, {});
  const result: any[] = [];
  const visit = (node: any) => {
    for (const match of arr(node?.cpeMatch)) {
      const parts =
        typeof match.criteria === "string" ? match.criteria.split(":") : [];
      if (!match.vulnerable || parts.length < 6) continue;
      const bounds = [
        match.versionStartIncluding && `>=${match.versionStartIncluding}`,
        match.versionStartExcluding && `>${match.versionStartExcluding}`,
        match.versionEndIncluding && `<=${match.versionEndIncluding}`,
        match.versionEndExcluding && `<${match.versionEndExcluding}`,
      ]
        .filter(Boolean)
        .join(" ");
      result.push({
        vendor: parts[3],
        product: parts[4],
        version: version(parts[5]) ? parts[5] : null,
        versionRange: bounds || null,
        cpe: match.criteria,
        source: "nvd",
        fixedVersions: version(match.versionEndExcluding)
          ? [match.versionEndExcluding]
          : [],
      });
    }
    for (const child of [...arr(node?.nodes), ...arr(node?.children)])
      visit(child);
  };
  for (const config of arr((raw?.cve || raw)?.configurations)) visit(config);
  return normalizeLegacyProducts(result);
}

export function normalizeLegacyProducts(products: any[]): any[] {
  return products.map((p) => {
    let range: string | null = null;
    const text =
      typeof p.versionRange === "string" ? p.versionRange.trim() : "";
    const unions = text.split(/\s*\|\|\s*/);
    if (
      text &&
      unions.every((u) =>
        /^(?:(?:>=|<=|==|>|<|=)v?\d[0-9A-Za-z.!+_~-]*(?:[, ]+|$))+$/.test(u),
      )
    ) {
      range = unions
        .map((u) =>
          u
            .split(/[, ]+/)
            .filter(Boolean)
            .join(p.ecosystem === "PyPI" ? "," : " "),
        )
        .join(" || ");
      if (p.ecosystem === "PyPI" && unions.length > 1) range = null;
    } else if (
      p.ecosystem === "Maven" &&
      /^[[(](?:\d[\w.+-]*)?,(?:\d[\w.+-]*)?[)\]]$/.test(text)
    ) {
      range = text;
    } else if ((!text || text === "*") && version(p.version)) {
      range =
        p.ecosystem === "Maven"
          ? `[${p.version}]`
          : `${p.ecosystem === "PyPI" ? "==" : "="}${p.version}`;
    }
    return { ...p, versionRange: range };
  });
}

/** OSV events are ordered, disjoint intervals, never a conjunction of all events. */
export function osvAffected(records: any[]): any[] {
  const result: any[] = [];
  for (const record of records)
    for (const affected of arr(record.affected)) {
      const pkg = affected.package;
      if (!pkg?.name || !pkg.ecosystem) continue;
      const base = {
        ecosystem: pkg.ecosystem,
        name: pkg.name,
        versions: arr(affected.versions),
        source: "osv",
      };
      for (const range of arr(affected.ranges)) {
        let introduced: string | null = null;
        for (const event of arr(range.events)) {
          if (event.introduced !== undefined) introduced = event.introduced;
          if (event.fixed || event.last_affected || event.limit) {
            result.push({
              ...base,
              introduced,
              fixed: range.type === "GIT" ? null : (event.fixed ?? null),
              last_affected:
                range.type === "GIT" ? null : (event.last_affected ?? null),
              limit: range.type === "GIT" ? null : (event.limit ?? null),
              range_type: range.type,
              version_range:
                range.type === "GIT"
                  ? null
                  : formatVersionRange(
                      pkg.ecosystem,
                      introduced,
                      event.fixed,
                      event.last_affected,
                      event.limit,
                    ),
            });
            introduced = null;
          }
        }
        if (introduced !== null)
          result.push({
            ...base,
            introduced,
            fixed: null,
            last_affected: null,
            limit: null,
            range_type: range.type,
            version_range:
              range.type === "GIT"
                ? null
                : formatVersionRange(pkg.ecosystem, introduced, null, null),
          });
      }
      if (!arr(affected.ranges).length)
        result.push({
          ...base,
          introduced: null,
          fixed: null,
          last_affected: null,
          version_range: null,
        });
    }
  return objects(result);
}

export function decodeCvss(vector: any): any {
  if (typeof vector !== "string" || !/^CVSS:[34]\.\d\//.test(vector))
    return null;
  const metrics = Object.fromEntries(
    vector
      .split("/")
      .slice(1)
      .map((s) => s.split(":")),
  );
  const read = (key: string, values: Record<string, string>) =>
    values[metrics[key]] ?? null;
  return {
    cvss_version: vector.split("/")[0].slice(5),
    cvss_vector: vector,
    attack_vector: read("AV", {
      N: "network",
      A: "adjacent",
      L: "local",
      P: "physical",
    }),
    attack_complexity: read("AC", { L: "low", H: "high" }),
    privileges_required: read("PR", { N: "none", L: "low", H: "high" }),
    user_interaction: read("UI", {
      N: "none",
      R: "required",
      P: "passive",
      A: "active",
    }),
    scope: read("S", { U: "unchanged", C: "changed" }),
    attack_requirements: read("AT", { N: "none", P: "present" }),
  };
}

export interface NormalizeInput {
  local?: any;
  osv?: any[];
  queriedPackage?: PublicPackage;
  patchEvidence?: any;
}
export function normalizeAdvisory(input: NormalizeInput): any {
  const local = input.local || {};
  const sources: any[] = arr(local.sourceRecords);
  const records = objects([
    ...(input.osv || []),
    ...sources
      .filter((s) => s.sourceName === "osv")
      .flatMap((s) => {
        const raw = jsonValue(s.rawPayload);
        return Array.isArray(raw) ? raw : raw?.id ? [raw] : arr(raw?.records);
      }),
  ]).filter((r) => !r.withdrawn);
  const ids = unique(
    [local.cveId, ...records.flatMap((r) => [r.id, ...arr(r.aliases)])].filter(
      (v) => typeof v === "string",
    ),
  ).sort() as string[];
  const advisoryId =
    ids.find((id) => id.startsWith("CVE-")) || records[0]?.id || ids[0];
  const present = unique(
    [
      ...arr(local.sourcesPresent).map(sourceName),
      ...sources.map((s) => sourceName(s.sourceName)),
      sourceName(local.source),
      ...(records.length ? ["osv"] : []),
    ].filter(Boolean),
  );
  const field: Record<string, any> = {};
  const meta = (path: string, source: any, confidence?: number) => {
    if (!source) return;
    field[path] = {
      source,
      ...(confidence !== undefined ? { confidence } : {}),
    };
  };
  meta(
    "advisory_id",
    local.cveId ? sourceName(local.canonicalSource || local.source) : "osv",
  );
  if (records.length) meta("aliases", "osv");
  const payloads = sources.map((s) => ({
    source: sourceName(s.sourceName),
    raw: jsonValue(s.rawPayload),
    normalized: jsonValue(s.normalizedData, {}),
  }));
  if (local.rawData)
    payloads.push({
      source: sourceName(local.source),
      raw: jsonValue(local.rawData),
      normalized: {},
    });
  const cnas = payloads
    .filter((p) => p.source === "cve.org")
    .flatMap((p) => [p.raw?.containers?.cna, ...arr(p.raw?.containers?.adp)])
    .filter(Boolean);
  const affected = osvAffected(records);
  const nvdProducts = payloads
    .filter((p) => p.source === "nvd")
    .flatMap((p) => nvdAffectedProducts(p.raw));
  const legacy = normalizeLegacyProducts([
    ...arr(local.affectedProductsDetailed),
    ...nvdProducts,
  ]);
  if (!affected.length)
    for (const product of legacy)
      affected.push({
        ecosystem: product.ecosystem || null,
        name: product.product,
        introduced: null,
        fixed: null,
        last_affected: null,
        versions: product.version ? [product.version] : [],
        version_range: product.versionRange,
        source: sourceName(product.source),
      });
  if (affected.length)
    meta("affected", records.length ? "osv" : sourceName(local.source));

  const symbols: any[] = [],
    files: any[] = [];
  for (const record of records)
    for (const affected of arr(record.affected)) {
      const pkg = affected.package || {};
      const addSymbol = (
        name: any,
        importPath: any = null,
        kind = "function",
        language: any = null,
      ) => {
        if (typeof name !== "string" || !name.trim()) return;
        symbols.push({
          ecosystem: pkg.ecosystem,
          package: pkg.name,
          import_path: importPath,
          qualified_name:
            importPath && !name.startsWith(importPath + ".")
              ? `${importPath}.${name}`
              : name,
          kind,
          language:
            language ||
            ({
              Go: "go",
              PyPI: "python",
              Maven: "java",
              npm: "javascript",
              "crates.io": "rust",
              RubyGems: "ruby",
              NuGet: "csharp",
              Packagist: "php",
            }[pkg.ecosystem] ??
              null),
          source: "osv",
          confidence: 0.95,
        });
      };
      for (const specific of [
        affected.ecosystem_specific,
        affected.database_specific,
      ]) {
        for (const imp of arr(specific?.imports))
          for (const sym of arr(imp.symbols))
            addSymbol(
              sym,
              imp.path,
              String(sym).includes(".") ? "method" : "function",
            );
        for (const sym of arr(specific?.symbols)) {
          if (typeof sym === "string") addSymbol(sym);
          else if (
            ["function", "method", "class", "route", "config_key"].includes(
              sym?.kind,
            )
          )
            addSymbol(
              sym.qualified_name || sym.name,
              sym.import_path,
              sym.kind,
              sym.language,
            );
        }
      }
    }
  for (const cna of cnas)
    for (const product of arr(cna.affected)) {
      for (const routine of arr(product.programRoutines))
        if (routine?.name)
          symbols.push({
            ecosystem: null,
            package: product.packageName || product.product || null,
            import_path: null,
            qualified_name: routine.name,
            kind: "function",
            language: null,
            source: "cve.org",
            confidence: 0.9,
          });
      for (const path of arr(product.programFiles))
        if (typeof path === "string")
          files.push({ path_in_package: path, source: "cve.org" });
    }

  const references = objects([
    ...arr(local.references)
      .filter((r) => r?.url)
      .map((r) => ({
        url: r.url,
        tags: arr(r.tags),
        source: sourceName(r.source || local.source),
      })),
    ...records.flatMap((r) =>
      arr(r.references)
        .filter((r) => r?.url)
        .map((r) => ({
          url: r.url,
          tags: [
            r.type === "FIX"
              ? "Patch"
              : r.type === "ADVISORY"
                ? "Vendor Advisory"
                : r.type,
          ],
          source: "osv",
        })),
    ),
    ...cnas.flatMap((c) =>
      arr(c.references)
        .filter((r) => r?.url)
        .map((r) => ({ url: r.url, tags: arr(r.tags), source: "cve.org" })),
    ),
  ]);
  const commits: any[] = [],
    prs: string[] = [];
  for (const ref of references) {
    const commit =
      /^https:\/\/(github\.com|gitlab\.com)\/([^/?#]+\/[^/?#]+)\/(?:-\/)?commit\/([a-f\d]{7,40})(?:[?#].*)?$/i.exec(
        ref.url,
      );
    if (commit && ref.tags.some((t) => /^(Patch|FIX)$/i.test(t)))
      commits.push({
        repo_url: `https://${commit[1]}/${commit[2]}`,
        sha: commit[3],
        source: ref.source,
      });
    if (
      /^https:\/\/github\.com\/[^/]+\/[^/]+\/pull\/\d+/.test(ref.url) &&
      ref.tags.includes("Patch")
    )
      prs.push(ref.url);
  }
  for (const record of records)
    for (const affected of arr(record.affected))
      for (const range of arr(affected.ranges))
        if (range.type === "GIT" && range.repo) {
          for (const event of arr(range.events))
            if (/^[a-f\d]{40}$/i.test(event.fixed || ""))
              commits.push({
                repo_url: range.repo,
                sha: event.fixed,
                source: "osv",
              });
        }
  const fixed = unique(
    [
      ...arr(local.fixedVersions),
      ...legacy.flatMap((p) => arr(p.fixedVersions)),
      ...affected.map((a) => a.fixed),
    ].filter((v) => version(v)),
  ) as string[];
  const patchRef = references.find((r) => r.tags.includes("Patch"));
  const patchAvailable =
    fixed.length || commits.length || patchRef
      ? true
      : local.patchAvailable === true
        ? true
        : null;
  meta(
    "patch.fixed_versions",
    affected.some((a) => a.fixed) ? "osv" : sourceName(local.source),
    nvdProducts.some((p) => p.fixedVersions.length) && !records.length
      ? 0.7
      : undefined,
  );
  if (patchAvailable !== null)
    meta(
      "patch.patch_available",
      patchRef?.source || (records.length ? "osv" : sourceName(local.source)),
      0.95,
    );
  const patchData = input.patchEvidence || {};
  files.push(...arr(patchData.files));
  const touched = arr(patchData.symbols);
  const inferredSymbols = symbols.length === 0 && touched.length > 0;
  if (inferredSymbols)
    for (const symbol of touched) {
      const packages = affected.filter((a) => a.ecosystem === "PyPI");
      symbols.push({
        ecosystem: symbol.language === "python" ? "PyPI" : null,
        package:
          unique(packages.map((p) => p.name)).length === 1
            ? packages[0].name
            : null,
        import_path: null,
        ...symbol,
      });
    }

  const cwes = unique(
    [
      ...arr(local.cweIds),
      ...records.flatMap((r) => arr(r.database_specific?.cwe_ids)),
      ...cnas.flatMap((c) =>
        arr(c.problemTypes).flatMap((p) =>
          arr(p.descriptions).map((d) => d.cweId),
        ),
      ),
    ].filter((v) => /^CWE-\d+$/.test(v)),
  );
  const capecs = unique(
    cnas
      .flatMap((c) => arr(c.impacts).map((i) => i.capecId))
      .filter((v) => /^CAPEC-\d+$/.test(v)),
  );
  const weaknessSource =
    records.some((r) => r.database_specific?.cwe_ids?.length) &&
    !arr(local.cweIds).length
      ? "osv"
      : sourceName(local.source) || (cnas.length ? "cve.org" : null);
  if (cwes.length) meta("weakness.cwe_ids", weaknessSource);
  if (capecs.length) meta("weakness.capec_ids", "cve.org");
  const cvssCandidates = [
    ...[local.cvssV31Vector, local.cvssV40Vector].map((vector) => ({
      vector,
      source: sourceName(local.source),
    })),
    ...records.flatMap((r) =>
      [
        ...arr(r.severity),
        ...arr(r.affected).flatMap((a) => arr(a.severity)),
      ].map((s) => ({ vector: s.score, source: "osv" })),
    ),
    ...cnas.flatMap((c) =>
      arr(c.metrics).flatMap((m) =>
        [m.cvssV3_1, m.cvssV3_0, m.cvssV4_0]
          .filter(Boolean)
          .map((m) => ({ vector: m.vectorString, source: "cve.org" })),
      ),
    ),
  ];
  const v3 = cvssCandidates.find((c) => /^CVSS:3\./.test(c.vector || ""));
  const v4 = cvssCandidates.find((c) => /^CVSS:4\./.test(c.vector || ""));
  const primary = v3 || v4;
  const attack = {
    ...(decodeCvss(primary?.vector) || {
      cvss_version: null,
      cvss_vector: null,
      attack_vector: null,
      attack_complexity: null,
      privileges_required: null,
      user_interaction: null,
      scope: null,
    }),
    cvss_v40: decodeCvss(v4?.vector),
  };
  if (primary)
    for (const key of Object.keys(attack))
      if (attack[key] !== null)
        meta(
          `attack.${key}`,
          key === "cvss_v40" ? v4?.source : primary.source,
          key.startsWith("cvss") ? undefined : 1,
        );
  const exploitEntries = payloads
    .filter((p) => p.source === "exploitdb")
    .flatMap((p) => arr(p.normalized.exploits || p.normalized.entries));
  const exploitRefs = arr(local.exploitReferences);
  const exploits = objects(
    exploitEntries
      .filter((e) => /^\d+$/.test(String(e.id)))
      .map((e) => ({
        id: `EDB-${e.id}`,
        source: "exploitdb",
        type: e.type || null,
        platform: e.platform || null,
        url: `https://www.exploit-db.com/exploits/${e.id}`,
        published_at: e.datePublished || null,
      })),
  );
  const positiveRefs = exploitRefs.filter(
    (r) =>
      typeof r === "object" &&
      ["poc", "exploit", "weaponized"].includes(r.type),
  );
  const referenceSource = positiveRefs
    .map(
      (r) =>
        sourceName(r.source) ||
        (/^https:\/\/github\.com\//.test(r.url || "")
          ? "github"
          : /^https:\/\/(?:www\.)?exploit-db\.com\//.test(r.url || "")
            ? "exploitdb"
            : null),
    )
    .find(Boolean);
  const exploitSource = exploits.length
    ? "exploitdb"
    : referenceSource ||
      (local.hasPublicExploit === true
        ? present.find((s) =>
            ["exploitdb", "github", "manual"].includes(s as string),
          )
        : null);
  const publicExploit =
    exploitSource &&
    (exploits.length || positiveRefs.length || local.hasPublicExploit === true)
      ? true
      : null;
  const kev = local.isKnownExploited === true ? true : null;
  const maturity = kev
    ? "active"
    : local.exploitStatus === "weaponized" && publicExploit
      ? "weaponized"
      : publicExploit
        ? "poc"
        : publicExploit === false
          ? "none"
          : null;
  if (kev !== null) meta("exploitation.kev", "cisa_kev");
  if (local.kevDateAdded) meta("exploitation.kev_date_added", "cisa_kev");
  if (local.epssScore != null) meta("exploitation.epss", "epss");
  if (local.epssPercentile != null)
    meta("exploitation.epss_percentile", "epss");
  if (publicExploit !== null)
    meta(
      "exploitation.public_exploit",
      exploitSource,
      local.exploitConfidence ?? 0.8,
    );
  if (maturity)
    meta(
      "exploitation.maturity",
      kev ? "cisa_kev" : exploitSource,
      kev ? 1 : 0.8,
    );

  const effectByCwe: Record<string, string> = {
    "CWE-78": "rce",
    "CWE-89": "sqli",
    "CWE-918": "ssrf",
    "CWE-200": "info_leak",
    "CWE-400": "dos",
    "CWE-269": "priv_esc",
  };
  const effectCwe = cwes.find((c) => effectByCwe[c]);
  const effect = effectCwe ? effectByCwe[effectCwe] : null;
  const classEntry = exploitEntries.find((e) =>
    ["remote", "local", "webapps", "dos"].includes(e.type),
  );
  const exploitClass = classEntry
    ? classEntry.type === "webapps"
      ? "webapp"
      : classEntry.type
    : attack.attack_vector === "network"
      ? "remote"
      : attack.attack_vector === "local"
        ? "local"
        : null;
  if (effect) meta("technique.effect", weaknessSource, 0.7);
  if (exploitClass)
    meta(
      "technique.exploit_class",
      classEntry ? "exploitdb" : primary?.source,
      classEntry ? 0.9 : 0.75,
    );
  const requiresAuth =
    attack.attack_vector === "network" && attack.privileges_required === "none"
      ? false
      : null;
  if (requiresAuth !== null)
    meta("technique.requires_authentication", primary?.source, 0.65);
  const untrustedCwe = cwes.find((c) =>
    ["CWE-78", "CWE-89", "CWE-918", "CWE-502", "CWE-79"].includes(c),
  );
  if (untrustedCwe)
    meta("technique.requires_untrusted_input", weaknessSource, 0.7);
  const inputKinds = cwes.includes("CWE-502") ? ["deserialization"] : [];
  if (inputKinds.length) meta("technique.input_kinds", weaknessSource, 0.7);
  const workarounds = arr(local.workarounds).filter(
    (v) => typeof v === "string",
  );
  if (workarounds.length)
    meta("mitigations.workarounds", sourceName(local.source), 0.9);
  if (field["patch.patch_available"])
    field["mitigations.patch_available"] = field["patch.patch_available"];
  const updated = [
    local.updatedAt,
    ...records.map((r) => r.modified),
    ...sources.map((s) => s.lastSeenAt),
  ]
    .filter(Boolean)
    .map((v) => new Date(v))
    .filter((v) => !isNaN(v.getTime()));
  const result: any = {
    advisory_id: advisoryId,
    aliases: ids.filter((id) => id !== advisoryId),
    affected,
    vulnerable_symbols: objects(symbols),
    affected_files: objects(files),
    patch: {
      fix_commits: objects(commits),
      pull_requests: unique(prs),
      fixed_versions: fixed,
      patch_available: patchAvailable,
      diff_touched_symbols: touched,
    },
    weakness: {
      cwe_ids: cwes,
      cwe_names: arr(local.cweNames),
      capec_ids: capecs,
      weakness_category: local.weaknessCategory || null,
    },
    attack,
    technique: {
      attack_techniques: [],
      exploit_class: exploitClass,
      effect,
      trigger_summary: null,
      requires_untrusted_input: untrustedCwe ? true : null,
      input_kinds: inputKinds,
      requires_authentication: requiresAuth,
      requires_configuration: [],
    },
    exploitation: {
      kev,
      kev_date_added: local.kevDateAdded || null,
      epss: local.epssScore ?? null,
      epss_percentile: local.epssPercentile ?? null,
      public_exploit: publicExploit,
      maturity,
      first_seen_at: local.exploitFirstSeenAt || null,
      exploits,
      poc_urls: unique(positiveRefs.map((r) => r.url).filter(Boolean)),
    },
    detection: { code_patterns: [], rules: [] },
    mitigations: {
      workarounds,
      config_mitigation: [],
      patch_available: patchAvailable,
    },
    references,
    provenance: {
      sources_present: present,
      updated_at: updated.length
        ? new Date(Math.max(...updated.map((d) => d.getTime()))).toISOString()
        : null,
      data_confidence: local.dataConfidence ?? null,
    },
    completeness: {
      symbols: inferredSymbols
        ? "derived"
        : symbols.length
          ? "present"
          : "absent",
      affected_files: files.length ? "present" : "absent",
      affected_range: affected.some((a) => a.version_range || a.versions.length)
        ? "present"
        : "absent",
      patch: patchAvailable === null ? "absent" : "present",
      diff_touched_symbols: touched.length ? "derived" : "absent",
      weakness: cwes.length ? "present" : "absent",
      attack: primary ? "present" : "absent",
      technique:
        effect || untrustedCwe || requiresAuth !== null || exploitClass
          ? "derived"
          : "absent",
      attack_techniques: "absent",
      detection: "absent",
      mitigations: workarounds.length ? "present" : "absent",
      exploitation:
        publicExploit !== null || kev !== null || local.epssScore != null
          ? "present"
          : "absent",
    },
    field_provenance: field,
  };
  // Optional structured contributions use this same public contract. Only explicit,
  // field-level provenance can promote data into the response; free text is not parsed.
  const validators: Record<string, (v: any) => boolean> = {
    "technique.attack_techniques": (v) =>
      Array.isArray(v) &&
      v.every(
        (t) =>
          /^T\d{4}(?:\.\d{3})?$/.test(t?.id) &&
          typeof t.name === "string" &&
          typeof t.tactic === "string",
      ),
    "technique.trigger_summary": (v) => typeof v === "string" && v.length > 0,
    "technique.requires_configuration": (v) =>
      Array.isArray(v) && v.every((t) => typeof t === "string"),
    "technique.requires_authentication": (v) => typeof v === "boolean",
    "technique.requires_untrusted_input": (v) => typeof v === "boolean",
    "technique.input_kinds": (v) =>
      Array.isArray(v) &&
      v.every((t) =>
        [
          "http_param",
          "http_body",
          "file_upload",
          "deserialization",
          "env",
          "cli_arg",
        ].includes(t),
      ),
    "technique.effect": (v) =>
      ["rce", "ssrf", "sqli", "info_leak", "dos", "priv_esc"].includes(v),
    "technique.exploit_class": (v) =>
      ["remote", "local", "webapp", "dos"].includes(v),
    "detection.code_patterns": (v) =>
      Array.isArray(v) &&
      v.every(
        (t) =>
          typeof t?.language === "string" && typeof t.description === "string",
      ),
    "detection.rules": (v) =>
      Array.isArray(v) &&
      v.every(
        (t) =>
          ["semgrep", "nuclei", "codeql", "yara"].includes(t?.kind) &&
          typeof t.id === "string" &&
          /^https?:\/\//.test(t.url),
      ),
    "mitigations.workarounds": (v) =>
      Array.isArray(v) && v.every((t) => typeof t === "string"),
    "mitigations.config_mitigation": (v) =>
      Array.isArray(v) && v.every((t) => typeof t === "string"),
    "weakness.capec_ids": (v) =>
      Array.isArray(v) && v.every((t) => /^CAPEC-\d+$/.test(t)),
  };
  for (const payload of payloads) {
    if (!payload.source) continue;
    const contribution = payload.normalized?.advisory;
    if (!contribution || typeof contribution !== "object") continue;
    for (const [path, validate] of Object.entries(validators)) {
      const [section, key] = path.split(".");
      const value = contribution[section]?.[key];
      const evidence = contribution.field_provenance?.[path];
      if (
        !evidence ||
        !sourceName(evidence.source) ||
        typeof evidence.confidence !== "number" ||
        evidence.confidence < 0 ||
        evidence.confidence > 1 ||
        !validate(value)
      )
        continue;
      // Explicit contributions may replace heuristic derivations, never vice versa.
      result[section][key] = value;
      meta(path, sourceName(evidence.source), evidence.confidence);
      result.completeness[path] =
        Array.isArray(value) && !value.length ? "absent" : "present";
    }
  }
  for (const path of Object.keys(validators)) {
    if (!(path in result.completeness)) {
      const [section, key] = path.split(".");
      const value = result[section][key];
      result.completeness[path] =
        value !== null && (!Array.isArray(value) || value.length)
          ? field[path]?.confidence !== undefined
            ? "derived"
            : "present"
          : "absent";
    }
  }
  if (
    Object.keys(validators).some(
      (path) =>
        path.startsWith("technique.") &&
        result.completeness[path] === "present",
    )
  )
    result.completeness.technique = "present";
  if (result.technique.attack_techniques.length)
    result.completeness.attack_techniques = "present";
  if (result.detection.rules.length || result.detection.code_patterns.length)
    result.completeness.detection = "present";
  if (
    result.mitigations.config_mitigation.length ||
    result.mitigations.workarounds.length
  )
    result.completeness.mitigations = "present";
  if (local.weaknessCategory)
    meta("weakness.weakness_category", weaknessSource, 0.8);
  if (arr(local.cweNames).length) meta("weakness.cwe_names", weaknessSource);
  if (touched.length) meta("patch.diff_touched_symbols", "patch_diff", 0.55);
  if (symbols.length)
    meta("vulnerable_symbols", symbols[0].source, symbols[0].confidence);
  if (files.length) meta("affected_files", files[0].source);
  if (exploits.length) meta("exploitation.exploits", "exploitdb");
  if (local.exploitFirstSeenAt)
    meta("exploitation.first_seen_at", exploitSource);
  if (positiveRefs.length) meta("exploitation.poc_urls", exploitSource, 0.8);
  if (references.length) meta("references", references[0].source);
  if (commits.length) meta("patch.fix_commits", commits[0].source);
  if (prs.length) meta("patch.pull_requests", patchRef?.source);
  result.completeness["exploitation.exploits"] = exploits.length
    ? "present"
    : "absent";
  result.completeness["exploitation.poc_urls"] = positiveRefs.length
    ? "present"
    : "absent";
  result.completeness["patch.fixed_versions"] = fixed.length
    ? "present"
    : "absent";
  result.completeness["patch.fix_commits"] = commits.length
    ? "present"
    : "absent";
  result.completeness["patch.pull_requests"] = prs.length
    ? "present"
    : "absent";
  result.provenance.sources_present = unique([
    ...present,
    ...Object.values(field).map((m) => m.source),
  ]);
  if (input.queriedPackage) {
    // This flag is authoritative only after OSV's successful exact-version query.
    result.version_in_affected_range = records.length ? true : null;
    if (records.length) meta("version_in_affected_range", "osv");
  }
  return result;
}
