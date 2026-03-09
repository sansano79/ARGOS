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
  // En producción usamos Helmet completo. En desarrollo/LAN desactivamos HSTS para
  // evitar que el navegador fuerce HTTPS (lo que rompería los recursos estáticos de Swagger).
  const isProduction = process.env.NODE_ENV === 'production';
  const helmetOptions = {
    hsts: isProduction, // Solo forzar HTTPS en producción
    contentSecurityPolicy: isProduction, // CSP completa solo en producción
  };

  app.use((req, res, next) => {
    if (req.path.startsWith('/api/docs')) {
      // Para Swagger: nunca CSP ni HSTS, independientemente del entorno
      return helmet.default({ contentSecurityPolicy: false, hsts: false })(req, res, next);
    }
    return helmet.default(helmetOptions)(req, res, next);
  });
  const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173';
  const allowedOrigins = corsOrigin
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);

  app.enableCors({
    origin: corsOrigin === '*' ? true : allowedOrigins,
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

  // Swagger: debe configurarse ANTES de setGlobalPrefix para evitar conflictos de rutas
  // La ruta 'api/docs' es absoluta y no se ve afectada por el prefijo global
  const enableSwagger = process.env.ENABLE_SWAGGER === 'true' || process.env.NODE_ENV !== 'production';

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

  // API prefix (se aplica DESPUÉS de Swagger para no afectar su ruta)
  app.setGlobalPrefix('api');

  const port = process.env.API_PORT || process.env.APP_PORT || 3000;
  await app.listen(port, '0.0.0.0');
  logger.log(`🚀 Servicios OCC API running on http://0.0.0.0:${port}`);
  if (enableSwagger) {
    logger.log(`📚 Swagger docs: http://0.0.0.0:${port}/api/docs`);
  } else {
    logger.log('📚 Swagger docs disabled');
  }
}

bootstrap();
