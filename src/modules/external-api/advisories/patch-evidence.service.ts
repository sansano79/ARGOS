import { Injectable } from "@nestjs/common";
import { HttpService } from "@nestjs/axios";
import { ConfigService } from "@nestjs/config";
import { firstValueFrom } from "rxjs";

export interface PatchEvidence {
  files: any[];
  symbols: any[];
  status: string;
}
@Injectable()
export class PatchEvidenceService {
  private readonly cache = new Map<
    string,
    { expires: number; value: PatchEvidence }
  >();
  constructor(
    private readonly http: HttpService,
    private readonly config: ConfigService,
  ) {}

  async enrich(advisory: any): Promise<PatchEvidence> {
    const result: PatchEvidence = {
      files: [],
      symbols: [],
      status: "disabled",
    };
    if (
      this.config.get<string>("ADVISORIES_PATCH_DIFF_ENABLED", "false") !==
      "true"
    )
      return result;
    result.status = "absent";
    for (const commit of (advisory.patch?.fix_commits || []).slice(0, 3)) {
      // Never fetch a reference URL directly or follow redirects.
      const repo = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)$/.exec(
        commit.repo_url || "",
      );
      if (
        !repo ||
        [repo[1], repo[2]].some((p) => p === "." || p === "..") ||
        !/^[a-f\d]{7,40}$/i.test(commit.sha)
      )
        continue;
      const url = `https://api.github.com/repos/${repo[1]}/${repo[2]}/commits/${commit.sha}`;
      let evidence = this.cache.get(url);
      if (!evidence || evidence.expires < Date.now()) {
        const value: PatchEvidence = {
          files: [],
          symbols: [],
          status: "present",
        };
        try {
          const response = await firstValueFrom(
            this.http.get(url, {
              timeout: 5000,
              maxRedirects: 0,
              maxContentLength: 2 * 1024 * 1024,
              headers: {
                Accept: "application/vnd.github+json",
                "User-Agent": "ARGOS-Advisories/1.0",
              },
            }),
          );
          if (!Array.isArray(response.data?.files))
            throw new Error("Invalid commit response");
          for (const file of response.data.files.slice(0, 100)) {
            if (
              typeof file.filename !== "string" ||
              file.filename.includes("..")
            )
              continue;
            value.files.push({
              path_in_package: file.filename,
              source: "patch_diff",
              commit_url: `https://github.com/${repo[1]}/${repo[2]}/commit/${commit.sha}`,
            });
            if (
              !file.filename.endsWith(".py") ||
              typeof file.patch !== "string"
            )
              continue;
            const module = file.filename
              .replace(/^src\//, "")
              .replace(/\.py$/, "")
              .replace(/\//g, ".");
            for (const line of file.patch.slice(0, 100000).split("\n")) {
              // Only top-level Python functions with a complete name; methods need class context we don't have.
              const match =
                /^(?:@@[^@]*@@ |[+-])(?:async )?def ([A-Za-z_]\w*)\(/.exec(
                  line,
                );
              if (match)
                value.symbols.push({
                  qualified_name: `${module}.${match[1]}`,
                  language: "python",
                  kind: "function",
                  source: "patch_diff",
                  confidence: 0.55,
                  path_in_package: file.filename,
                });
            }
          }
        } catch {
          value.status = "unavailable";
        }
        evidence = { expires: Date.now() + 3600000, value };
        if (this.cache.size >= 500)
          this.cache.delete(this.cache.keys().next().value!);
        this.cache.set(url, evidence);
      }
      result.files.push(...evidence.value.files);
      result.symbols.push(...evidence.value.symbols);
      result.status =
        evidence.value.status === "unavailable"
          ? "unavailable"
          : result.status === "unavailable"
            ? "unavailable"
            : "present";
    }
    result.symbols = [
      ...new Map(result.symbols.map((s) => [s.qualified_name, s])).values(),
    ];
    return result;
  }
}
