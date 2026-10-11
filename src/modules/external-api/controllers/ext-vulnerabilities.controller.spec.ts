import { ExtVulnerabilitiesController } from './ext-vulnerabilities.controller';
import { ExtCoverageController } from './ext-coverage.controller';

describe('External API Controllers', () => {
  let vulnController: ExtVulnerabilitiesController;
  let coverageController: ExtCoverageController;
  let serviceMock: any;

  beforeEach(() => {
    serviceMock = {
      listVulnerabilities: jest.fn().mockResolvedValue({ data: [], meta: {} }),
      getVulnerabilityStats: jest.fn().mockResolvedValue({ total: 100 }),
      getVulnerabilityByCveId: jest.fn().mockResolvedValue({ cveId: 'CVE-2024-1000' }),
      getVulnerabilityEvidence: jest.fn().mockResolvedValue({ data: [], meta: {} }),
      getVulnerabilityChanges: jest.fn().mockResolvedValue({ data: [], meta: {} }),
      getCoverage: jest.fn().mockResolvedValue({ totalVulnerabilities: 400000 }),
    };

    vulnController = new ExtVulnerabilitiesController(serviceMock);
    coverageController = new ExtCoverageController(serviceMock);
  });

  it('delegates list queries to service', async () => {
    const q = { page: 1, limit: 20, updatedSince: '2024-01-01T00:00:00Z' };
    await vulnController.list(q as any);
    expect(serviceMock.listVulnerabilities).toHaveBeenCalledWith(q);
  });

  it('delegates getByCveId with include parameter', async () => {
    await vulnController.getByCveId('CVE-2024-1000', 'raw');
    expect(serviceMock.getVulnerabilityByCveId).toHaveBeenCalledWith('CVE-2024-1000', 'raw');
  });

  it('delegates getEvidence to service', async () => {
    await vulnController.getEvidence('CVE-2024-1000', { page: 1, limit: 10 });
    expect(serviceMock.getVulnerabilityEvidence).toHaveBeenCalledWith('CVE-2024-1000', { page: 1, limit: 10 });
  });

  it('delegates coverage endpoint to service', async () => {
    const res = await coverageController.getCoverage();
    expect(serviceMock.getCoverage).toHaveBeenCalled();
    expect(res).toEqual({ totalVulnerabilities: 400000 });
  });
});
