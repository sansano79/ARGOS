import { Controller, Get } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Controller()
export class DashboardController {
  constructor(private readonly configService: ConfigService) { }

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
    return {
      status: 'ok',
      uptime: process.uptime(),
      bypassAuth: this.configService.get<string>('BYPASS_AUTH') === 'true',
    };
  }
}
