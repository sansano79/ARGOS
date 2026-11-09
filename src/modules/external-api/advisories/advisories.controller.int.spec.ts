import { INestApplication, ValidationPipe } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import { ConfigService } from "@nestjs/config";
import * as bcrypt from "bcrypt";
import { PrismaService } from "../../../prisma/prisma.service";
import { ExternalApiModule } from "../external-api.module";
import { OsvCollector } from "../../vulnerability-collector/collectors/osv.collector";

describe("Advisories HTTP contract", () => {
  let app: INestApplication, base: string, prisma: any;
  const key = "occ_test_advisory_key_123";
  const pkg = { ecosystem: "PyPI", name: "requests", version: "2.0.0" };
  beforeAll(async () => {
    prisma = {
      apiKey: {
        findMany: jest.fn().mockResolvedValue([
          {
            id: 1,
            keyHash: await bcrypt.hash(key, 4),
            scopes: '["vulnerabilities:read"]',
            user: { id: 1, isActive: true },
          },
        ]),
        update: jest.fn().mockResolvedValue({}),
      },
      vulnerability: { findUnique: jest.fn().mockResolvedValue(null) },
      vulnerabilitySourceRecord: {
        findMany: jest.fn().mockResolvedValue([]),
      },
    };
    const module = await Test.createTestingModule({
      imports: [ExternalApiModule],
    })
      .overrideProvider(PrismaService)
      .useValue(prisma)
      .overrideProvider(ConfigService)
      .useValue(new ConfigService({}))
      .overrideProvider(OsvCollector)
      .useValue({
        isEnabled: () => true,
        queryPackage: async () => [],
        resolveAdvisory: async () => [
          {
            id: "PYSEC-2024-1",
            aliases: ["CVE-2024-1000"],
          },
        ],
      })
      .compile();
    app = module.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    app.setGlobalPrefix("api");
    await app.listen(0, "127.0.0.1");
    base = await app.getUrl();
  });
  afterAll(async () => {
    await app?.close();
  });
  const request = (path: string, body?: any, apiKey: string | null = key) =>
    fetch(base + path, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { "X-API-Key": apiKey } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  it("requires an API key and read scope", async () => {
    expect(
      (await request("/api/v1/advisories/capabilities", undefined, null))
        .status,
    ).toBe(401);
    const candidates = await prisma.apiKey.findMany();
    candidates[0].scopes = '["products:read"]';
    expect((await request("/api/v1/advisories/capabilities")).status).toBe(403);
    candidates[0].scopes = '["vulnerabilities:read"]';
  });
  it("serves capabilities, queries and assessment through the actual Nest routes", async () => {
    const capabilities = await request("/api/v1/advisories/capabilities");
    expect(capabilities.status).toBe(200);
    expect((await capabilities.json()).max_packages_per_request).toBe(100);
    const query = await request("/api/v1/advisories/query", {
      packages: [pkg],
    });
    expect(query.status).toBe(200);
    expect((await query.json()).results[0]).toMatchObject({
      ...pkg,
      status: "audited",
      advisories: [],
    });
    const advisory = await request("/api/v1/advisories/PYSEC-2024-1");
    expect(advisory.status).toBe(200);
    const assessment = await request(
      "/api/v1/vulnerabilities/CVE-2024-1000/assessment",
    );
    expect(assessment.status).toBe(200);
    expect((await assessment.json()).advisory_id).toBe("CVE-2024-1000");
  });
  it("rejects extra client data, empty batches, ranges and oversized batches", async () => {
    for (const body of [
      { packages: [] },
      { packages: Array(101).fill(pkg) },
      { packages: [{ ...pkg, source_code: "private" }] },
      { packages: [pkg], client_path: "/private" },
      { packages: [{ ...pkg, version: ">=2.0" }] },
    ]) {
      expect((await request("/api/v1/advisories/query", body)).status).toBe(
        400,
      );
    }
  });
});
