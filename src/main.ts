import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import * as helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log', 'debug', 'verbose'],
  });

  // Security
  app.use(helmet.default());
  app.enableCors({
    origin: (process.env.CORS_ORIGIN || 'http://localhost:5173').split(','),
    credentials: true,
  });

  // Validation
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // API prefix
  app.setGlobalPrefix('api');

  // Swagger
  const config = new DocumentBuilder()
    .setTitle('Servicios OCC — Vulnerability Collector')
    .setDescription('API para recolección, análisis y reporte de vulnerabilidades')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  const port = process.env.APP_PORT || 3000;
  await app.listen(port);
  logger.log(`🚀 Servicios OCC API running on http://localhost:${port}`);
  logger.log(`📚 Swagger docs: http://localhost:${port}/api/docs`);
}

bootstrap();
