import { Controller, Get } from '@nestjs/common';

@Controller()
export class DashboardController {
  @Get()
  healthCheck() {
    return {
      service: 'Servicios OCC — Vulnerability Collector',
      status: 'running',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    };
  }

  @Get('health')
  health() {
    return { status: 'ok', uptime: process.uptime() };
  }
}
