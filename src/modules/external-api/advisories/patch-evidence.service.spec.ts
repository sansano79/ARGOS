import { ConfigService } from "@nestjs/config";
import { of } from "rxjs";
import { PatchEvidenceService } from "./patch-evidence.service";
describe("public patch evidence", () => {
  it("only reads bounded GitHub commit APIs and marks inferred symbols", async () => {
    const http: any = {
      get: jest.fn().mockReturnValue(
        of({
          data: {
            files: [
              {
                filename: "src/lib/parser.py",
                patch:
                  "@@ -1,3 +1,3 @@ def parse(value):\n-    unsafe(value)\n+    safe(value)",
              },
            ],
          },
        }),
      ),
    };
    const service = new PatchEvidenceService(
      http,
      new ConfigService({ ADVISORIES_PATCH_DIFF_ENABLED: "true" }),
    );
    const result = await service.enrich({
      patch: {
        fix_commits: [
          { repo_url: "https://github.com/acme/lib", sha: "a".repeat(40) },
          { repo_url: "https://127.0.0.1/private", sha: "b".repeat(40) },
        ],
      },
    });
    expect(http.get).toHaveBeenCalledTimes(1);
    expect(http.get.mock.calls[0][0]).toBe(
      "https://api.github.com/repos/acme/lib/commits/" + "a".repeat(40),
    );
    expect(result.files[0]).toMatchObject({
      path_in_package: "src/lib/parser.py",
      source: "patch_diff",
    });
    expect(result.symbols[0]).toMatchObject({
      qualified_name: "lib.parser.parse",
      source: "patch_diff",
      confidence: 0.55,
    });
  });
  it("does not make requests when disabled and leaves unsupported symbols absent", async () => {
    const http: any = { get: jest.fn() };
    const service = new PatchEvidenceService(http, new ConfigService({}));
    expect(await service.enrich({ patch: { fix_commits: [] } })).toMatchObject({
      files: [],
      symbols: [],
    });
    expect(http.get).not.toHaveBeenCalled();
  });
});
