import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import * as helmet from 'helmet';
import { json, urlencoded } from 'express';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log', 'debug', 'verbose'],
  });

  const expressApp = app.getHttpAdapter().getInstance();
  const trustProxy = process.env.TRUST_PROXY;
  if (trustProxy && trustProxy !== 'false') {
    expressApp.set('trust proxy', trustProxy === 'true' ? 1 : trustProxy);
  }

  // Security
  app.use(helmet.default());
  const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5173')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  app.enableCors({
    origin: allowedOrigins,
    credentials: true,
  });

  // Allow larger JSON payloads (template header image can be base64 data URL)
  const bodyLimit = process.env.BODY_LIMIT || '10mb';
  app.use(json({ limit: bodyLimit }));
  app.use(urlencoded({ extended: true, limit: bodyLimit }));

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

  // Swagger (disabled by default in production)
  const enableSwagger =
    process.env.ENABLE_SWAGGER === 'true' ||
    (process.env.NODE_ENV !== 'production' && process.env.ENABLE_SWAGGER !== 'false');
  if (enableSwagger) {
    const config = new DocumentBuilder()
      .setTitle('Servicios OCC — Vulnerability Collector')
      .setDescription('API para recolección, análisis y reporte de vulnerabilidades')
      .setVersion('1.0')
      .addBearerAuth()
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/docs', app, document);
  }

  const port = process.env.APP_PORT || 3000;
  await app.listen(port);
  logger.log(`🚀 Servicios OCC API running on http://localhost:${port}`);
  if (enableSwagger) {
    logger.log(`📚 Swagger docs: http://localhost:${port}/api/docs`);
  } else {
    logger.log('📚 Swagger docs disabled');
  }
}

bootstrap();
