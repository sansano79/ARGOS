import { Controller, Get } from '@nestjs/common';

@Controller()
export class DashboardController {
  @Get()
  healthCheck() {
    return {
      service: 'OCC-TVM — Threat & Vulnerability Management',
      status: 'running',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    };
  }

  @Get('health')
  health() {
    return {
      status: 'ok',
      uptime: process.uptime(),
    };
  }
}
