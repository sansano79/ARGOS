#!/usr/bin/env bash
###############################################################################
#  SERVICIOS OCC — Vulnerability Collector Stack Bootstrap
#  =========================================================
#  Genera el proyecto completo: NestJS + PostgreSQL + Prisma + Docker
#  Módulo de recolección automática de vulnerabilidades cada 30 min.
#
#  Uso:
#    chmod +x bootstrap.sh
#    ./bootstrap.sh
#
#  Requisitos previos:
#    - Docker y Docker Compose v2
#    - Node.js >= 18 y npm
#    - (Opcional) NVD API Key, GitHub Token
###############################################################################

set -euo pipefail
IFS=$'\n\t'

# ─── Colores para output ─────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✔]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${CYAN}[→]${NC} $1"; }
err()  { echo -e "${RED}[✖]${NC} $1" >&2; }

PROJECT_ROOT="$(pwd)/servicios-occ-vulns"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Servicios OCC — Vulnerability Collector Stack          ║${NC}"
echo -e "${CYAN}║  NestJS + PostgreSQL + Prisma + Docker                  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── 1. Crear estructura de directorios ──────────────────────────────────────
info "Creando estructura de directorios..."

mkdir -p "$PROJECT_ROOT"
cd "$PROJECT_ROOT"

mkdir -p \
  src/auth/{guards,decorators,dto,strategies} \
  src/prisma \
  src/config \
  src/common/{filters,interceptors,pipes} \
  src/modules/vulnerability-collector/{collectors,enrichers,report/templates,dto,entities} \
  src/modules/dashboard \
  docker \
  prisma/migrations \
  storage/{reports,logs,cache} \
  scripts

log "Estructura de directorios creada"

# ─── 2. package.json ─────────────────────────────────────────────────────────
info "Generando package.json..."

cat > package.json << 'PACKAGEJSON'
{
  "name": "servicios-occ-vulns",
  "version": "1.0.0",
  "description": "Servicios OCC — Vulnerability Collector & Report Generator",
  "author": "OCC Security Team",
  "private": true,
  "license": "UNLICENSED",
  "scripts": {
    "build": "nest build",
    "format": "prettier --write \"src/**/*.ts\" \"test/**/*.ts\"",
    "start": "nest start",
    "start:dev": "nest start --watch",
    "start:debug": "nest start --debug --watch",
    "start:prod": "node dist/main",
    "lint": "eslint \"{src,apps,libs,test}/**/*.ts\" --fix",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:cov": "jest --coverage",
    "test:e2e": "jest --config ./test/jest-e2e.json",
    "prisma:generate": "prisma generate",
    "prisma:migrate": "prisma migrate dev",
    "prisma:migrate:prod": "prisma migrate deploy",
    "prisma:seed": "ts-node prisma/seed.ts",
    "prisma:studio": "prisma studio",
    "docker:up": "docker compose up -d",
    "docker:down": "docker compose down",
    "docker:logs": "docker compose logs -f",
    "setup": "npm install && npx prisma generate && npx prisma migrate dev --name init",
    "collect:manual": "ts-node scripts/manual-collect.ts"
  },
  "dependencies": {
    "@nestjs/axios": "^3.1.3",
    "@nestjs/common": "^10.4.15",
    "@nestjs/config": "^3.3.0",
    "@nestjs/core": "^10.4.15",
    "@nestjs/jwt": "^10.2.0",
    "@nestjs/passport": "^10.0.3",
    "@nestjs/platform-express": "^10.4.15",
    "@nestjs/schedule": "^4.1.2",
    "@nestjs/swagger": "^8.1.0",
    "@prisma/client": "^6.2.1",
    "axios": "^1.7.9",
    "bcrypt": "^5.1.1",
    "class-transformer": "^0.5.1",
    "class-validator": "^0.14.1",
    "handlebars": "^4.7.8",
    "helmet": "^8.0.0",
    "passport": "^0.7.0",
    "passport-jwt": "^4.0.1",
    "passport-local": "^1.0.0",
    "puppeteer": "^23.11.1",
    "reflect-metadata": "^0.2.2",
    "rxjs": "^7.8.1",
    "uuid": "^11.0.5"
  },
  "devDependencies": {
    "@nestjs/cli": "^10.4.9",
    "@nestjs/schematics": "^10.2.3",
    "@nestjs/testing": "^10.4.15",
    "@types/bcrypt": "^5.0.2",
    "@types/express": "^5.0.0",
    "@types/jest": "^29.5.14",
    "@types/node": "^22.10.5",
    "@types/passport-jwt": "^4.0.1",
    "@types/passport-local": "^1.0.38",
    "@types/uuid": "^10.0.0",
    "jest": "^29.7.0",
    "prettier": "^3.4.2",
    "prisma": "^6.2.1",
    "source-map-support": "^0.5.21",
    "ts-jest": "^29.2.5",
    "ts-loader": "^9.5.1",
    "ts-node": "^10.9.2",
    "tsconfig-paths": "^4.2.0",
    "typescript": "^5.7.3"
  },
  "jest": {
    "moduleFileExtensions": ["js", "json", "ts"],
    "rootDir": "src",
    "testRegex": ".*\\.spec\\.ts$",
    "transform": { "^.+\\.(t|j)s$": "ts-jest" },
    "collectCoverageFrom": ["**/*.(t|j)s"],
    "coverageDirectory": "../coverage",
    "testEnvironment": "node"
  }
}
PACKAGEJSON

log "package.json generado"

# ─── 3. tsconfig.json ────────────────────────────────────────────────────────
info "Generando tsconfig.json..."

cat > tsconfig.json << 'TSCONFIG'
{
  "compilerOptions": {
    "module": "commonjs",
    "declaration": true,
    "removeComments": true,
    "emitDecoratorMetadata": true,
    "experimentalDecorators": true,
    "allowSyntheticDefaultImports": true,
    "target": "ES2021",
    "sourceMap": true,
    "outDir": "./dist",
    "baseUrl": "./",
    "incremental": true,
    "skipLibCheck": true,
    "strictNullChecks": true,
    "noImplicitAny": false,
    "strictBindCallApply": false,
    "forceConsistentCasingInFileNames": false,
    "noFallthroughCasesInSwitch": false,
    "paths": {
      "@/*": ["src/*"],
      "@modules/*": ["src/modules/*"],
      "@common/*": ["src/common/*"],
      "@config/*": ["src/config/*"]
    },
    "resolveJsonModule": true,
    "esModuleInterop": true
  },
  "include": ["src/**/*", "prisma/**/*", "scripts/**/*"]
}
TSCONFIG

cat > tsconfig.build.json << 'TSBUILD'
{
  "extends": "./tsconfig.json",
  "exclude": ["node_modules", "test", "dist", "**/*spec.ts"]
}
TSBUILD

cat > nest-cli.json << 'NESTCLI'
{
  "$schema": "https://json.schemastore.org/nest-cli",
  "collection": "@nestjs/schematics",
  "sourceRoot": "src",
  "compilerOptions": {
    "deleteOutDir": true
  }
}
NESTCLI

log "TypeScript config generado"

# ─── 4. Docker Compose ───────────────────────────────────────────────────────
info "Generando Docker Compose..."

cat > docker-compose.yml << 'DOCKERCOMPOSE'
version: '3.8'

services:
  # ── PostgreSQL ──────────────────────────────────────────────
  postgres:
    image: postgres:16-alpine
    container_name: occ-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-occ_vulns}
      POSTGRES_USER: ${POSTGRES_USER:-occ_admin}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-OCC_S3cur3_P4ss!}
    ports:
      - "${POSTGRES_PORT:-5432}:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./docker/init-db.sql:/docker-entrypoint-initdb.d/01-init.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-occ_admin} -d ${POSTGRES_DB:-occ_vulns}"]
      interval: 10s
      timeout: 5s
      retries: 5

  # ── Redis (cache y colas) ───────────────────────────────────
  redis:
    image: redis:7-alpine
    container_name: occ-redis
    restart: unless-stopped
    ports:
      - "${REDIS_PORT:-6379}:6379"
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD:-OCC_R3d1s_P4ss!}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD:-OCC_R3d1s_P4ss!}", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # ── API NestJS (desarrollo) ─────────────────────────────────
  api:
    build:
      context: .
      dockerfile: docker/Dockerfile
    container_name: occ-api
    restart: unless-stopped
    environment:
      NODE_ENV: development
      DATABASE_URL: postgresql://${POSTGRES_USER:-occ_admin}:${POSTGRES_PASSWORD:-OCC_S3cur3_P4ss!}@postgres:5432/${POSTGRES_DB:-occ_vulns}?schema=public
      REDIS_URL: redis://:${REDIS_PASSWORD:-OCC_R3d1s_P4ss!}@redis:6379
      JWT_SECRET: ${JWT_SECRET:-OCC_Jwt_S3cr3t_K3y_Ch4ng3_1n_Pr0d!}
      NVD_API_KEY: ${NVD_API_KEY:-}
      GITHUB_TOKEN: ${GITHUB_TOKEN:-}
    ports:
      - "${API_PORT:-3000}:3000"
    volumes:
      - .:/app
      - /app/node_modules
      - ./storage:/app/storage
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    command: npm run start:dev

  # ── pgAdmin (opcional, para gestión BD) ─────────────────────
  pgadmin:
    image: dpage/pgadmin4:latest
    container_name: occ-pgadmin
    restart: unless-stopped
    environment:
      PGADMIN_DEFAULT_EMAIL: ${PGADMIN_EMAIL:-admin@occ.local}
      PGADMIN_DEFAULT_PASSWORD: ${PGADMIN_PASSWORD:-admin}
    ports:
      - "${PGADMIN_PORT:-5050}:80"
    depends_on:
      - postgres
    profiles:
      - tools

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local
DOCKERCOMPOSE

log "Docker Compose generado"

# ─── 5. Dockerfile ───────────────────────────────────────────────────────────
info "Generando Dockerfile..."

cat > docker/Dockerfile << 'DOCKERFILE'
FROM node:20-slim

# Puppeteer dependencies
RUN apt-get update && apt-get install -y \
    chromium \
    fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-freefont-ttf \
    libxss1 \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npx prisma generate
RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start:prod"]
DOCKERFILE

cat > docker/init-db.sql << 'INITDB'
-- Extensiones útiles
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Timezone por defecto
SET timezone = 'Europe/Madrid';
INITDB

log "Dockerfile generado"

# ─── 6. .env ─────────────────────────────────────────────────────────────────
info "Generando .env..."

cat > .env << 'DOTENV'
# ══════════════════════════════════════════════════════════════
# Servicios OCC — Vulnerability Collector
# ══════════════════════════════════════════════════════════════

# ── Aplicación ────────────────────────────────────────────────
NODE_ENV=development
APP_PORT=3000
APP_NAME="Servicios OCC - Vulnerability Collector"

# ── PostgreSQL ────────────────────────────────────────────────
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=occ_vulns
POSTGRES_USER=occ_admin
POSTGRES_PASSWORD=OCC_S3cur3_P4ss!
DATABASE_URL=postgresql://occ_admin:OCC_S3cur3_P4ss!@localhost:5432/occ_vulns?schema=public

# ── Redis ─────────────────────────────────────────────────────
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=OCC_R3d1s_P4ss!
REDIS_URL=redis://:OCC_R3d1s_P4ss!@localhost:6379

# ── JWT ───────────────────────────────────────────────────────
JWT_SECRET=OCC_Jwt_S3cr3t_K3y_Ch4ng3_1n_Pr0d!
JWT_EXPIRATION=24h

# ── NVD (NIST) API ───────────────────────────────────────────
# Obtener en: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=

# ── GitHub (mejora rate limit para búsqueda de PoCs) ─────────
GITHUB_TOKEN=

# ── Collector Settings ────────────────────────────────────────
VULN_COLLECTOR_INTERVAL_MINUTES=30
VULN_COLLECTOR_LOOKBACK_HOURS=1
VULN_COLLECTOR_EXPLOIT_CHECK_ENABLED=true
VULN_COLLECTOR_MIN_SEVERITY_FOR_EXPLOIT_CHECK=HIGH

# ── Report Settings ──────────────────────────────────────────
VULN_REPORT_DEFAULT_PERIOD_HOURS=24
VULN_REPORT_MIN_SEVERITY=MEDIUM
VULN_REPORT_OUTPUT_DIR=./storage/reports

# ── Puppeteer (PDF generation) ───────────────────────────────
PUPPETEER_EXECUTABLE_PATH=
# En Docker: /usr/bin/chromium

# ── pgAdmin (opcional) ───────────────────────────────────────
PGADMIN_EMAIL=admin@occ.local
PGADMIN_PASSWORD=admin
PGADMIN_PORT=5050
DOTENV

cp .env .env.example

log ".env generado"

# ─── 7. .gitignore ───────────────────────────────────────────────────────────
cat > .gitignore << 'GITIGNORE'
# Dependencies
node_modules/
dist/

# Environment
.env
.env.local
.env.production

# Storage
storage/reports/*.pdf
storage/logs/*.log
storage/cache/

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Testing
coverage/

# Docker
postgres_data/
redis_data/
GITIGNORE

log ".gitignore generado"

# ─── 8. Prisma Schema ────────────────────────────────────────────────────────
info "Generando Prisma schema..."

cat > prisma/schema.prisma << 'PRISMASCHEMA'
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

// ══════════════════════════════════════════════════════════════
// USUARIOS Y AUTENTICACIÓN
// ══════════════════════════════════════════════════════════════

model User {
  id              Int       @id @default(autoincrement())
  email           String    @unique
  passwordHash    String    @map("password_hash")
  name            String
  role            UserRole  @default(USER)
  isActive        Boolean   @default(true) @map("is_active")
  lastLoginAt     DateTime? @map("last_login_at")
  createdAt       DateTime  @default(now()) @map("created_at")
  updatedAt       DateTime  @updatedAt @map("updated_at")

  sessions        UserSession[]
  reports         VulnerabilityReport[]
  apiConfigs      ApiConfiguration[]
  collectorRuns   CollectorRun[]

  @@map("users")
}

enum UserRole {
  ADMIN
  USER
  VIEWER
}

model UserSession {
  id        Int      @id @default(autoincrement())
  userId    Int      @map("user_id")
  tokenHash String   @map("token_hash")
  ipAddress String?  @map("ip_address") @db.VarChar(45)
  userAgent String?  @map("user_agent")
  expiresAt DateTime @map("expires_at")
  createdAt DateTime @default(now()) @map("created_at")

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([tokenHash])
  @@index([userId])
  @@index([expiresAt])
  @@map("user_sessions")
}

model LoginAttempt {
  id          Int      @id @default(autoincrement())
  email       String
  ipAddress   String   @map("ip_address") @db.VarChar(45)
  attemptedAt DateTime @default(now()) @map("attempted_at")
  success     Boolean  @default(false)

  @@index([email, attemptedAt])
  @@index([ipAddress, attemptedAt])
  @@map("login_attempts")
}

// ══════════════════════════════════════════════════════════════
// VULNERABILIDADES
// ══════════════════════════════════════════════════════════════

model Vulnerability {
  id                 Int      @id @default(autoincrement())
  cveId              String   @unique @map("cve_id") @db.VarChar(20)

  // Descripción
  description        String?  @db.Text
  publishedAt        DateTime @map("published_at")
  lastModifiedAt     DateTime? @map("last_modified_at")

  // Scoring
  cvssV31Score       Decimal?  @map("cvss_v31_score") @db.Decimal(3, 1)
  cvssV31Vector      String?   @map("cvss_v31_vector") @db.VarChar(100)
  cvssV31Severity    String?   @map("cvss_v31_severity") @db.VarChar(20)
  epssScore          Decimal?  @map("epss_score") @db.Decimal(5, 4)
  epssPercentile     Decimal?  @map("epss_percentile") @db.Decimal(5, 4)

  // Explotación
  isKnownExploited   Boolean   @default(false) @map("is_known_exploited")
  kevDateAdded       DateTime? @map("kev_date_added")
  kevDueDate         DateTime? @map("kev_due_date")
  hasPublicExploit   Boolean   @default(false) @map("has_public_exploit")
  exploitReferences  Json      @default("[]") @map("exploit_references")

  // Software afectado
  affectedProducts   Json      @default("[]") @map("affected_products")

  // Remediación
  remediationInfo    Json      @default("{}") @map("remediation_info")

  // Metadatos
  source             String    @default("nvd") @db.VarChar(50)
  rawData            Json?     @map("raw_data")
  processingStatus   String    @default("new") @map("processing_status") @db.VarChar(20)
  firstSeenAt        DateTime  @default(now()) @map("first_seen_at")
  enrichedAt         DateTime? @map("enriched_at")

  createdAt          DateTime  @default(now()) @map("created_at")
  updatedAt          DateTime  @updatedAt @map("updated_at")

  @@index([cveId])
  @@index([cvssV31Severity])
  @@index([publishedAt(sort: Desc)])
  @@index([isKnownExploited])
  @@index([processingStatus])
  @@index([epssScore(sort: Desc)])
  @@index([firstSeenAt(sort: Desc)])
  @@map("vulnerabilities")
}

// ══════════════════════════════════════════════════════════════
// INFORMES
// ══════════════════════════════════════════════════════════════

model VulnerabilityReport {
  id             Int      @id @default(autoincrement())
  reportDate     DateTime @map("report_date")
  periodStart    DateTime @map("period_start")
  periodEnd      DateTime @map("period_end")
  totalCves      Int      @map("total_cves")
  criticalCount  Int      @default(0) @map("critical_count")
  highCount      Int      @default(0) @map("high_count")
  exploitedCount Int      @default(0) @map("exploited_count")
  filePath       String?  @map("file_path") @db.VarChar(500)
  generatedBy    Int?     @map("generated_by")

  user           User?    @relation(fields: [generatedBy], references: [id])
  createdAt      DateTime @default(now()) @map("created_at")

  @@map("vulnerability_reports")
}

// ══════════════════════════════════════════════════════════════
// COLLECTOR RUNS
// ══════════════════════════════════════════════════════════════

model CollectorRun {
  id           Int       @id @default(autoincrement())
  startedAt    DateTime  @default(now()) @map("started_at")
  finishedAt   DateTime? @map("finished_at")
  source       String    @db.VarChar(50)
  cvesFetched  Int       @default(0) @map("cves_fetched")
  cvesNew      Int       @default(0) @map("cves_new")
  cvesUpdated  Int       @default(0) @map("cves_updated")
  status       String    @db.VarChar(20)
  errorMessage String?   @map("error_message") @db.Text
  durationMs   Int?      @map("duration_ms")
  triggeredBy  Int?      @map("triggered_by")

  user         User?     @relation(fields: [triggeredBy], references: [id])

  @@index([startedAt(sort: Desc)])
  @@map("collector_runs")
}

// ══════════════════════════════════════════════════════════════
// CONFIGURACIÓN APIs EXTERNAS
// ══════════════════════════════════════════════════════════════

model ApiConfiguration {
  id                Int       @id @default(autoincrement())
  name              String    @db.VarChar(255)
  slug              String    @unique @db.VarChar(100)
  provider          String    @db.VarChar(100)
  apiKeyEncrypted   String?   @map("api_key_encrypted") @db.Text
  endpointUrl       String?   @map("endpoint_url") @db.VarChar(500)
  settings          Json      @default("{}")
  isActive          Boolean   @default(true) @map("is_active")
  lastUsedAt        DateTime? @map("last_used_at")
  createdBy         Int?      @map("created_by")

  user              User?     @relation(fields: [createdBy], references: [id])
  createdAt         DateTime  @default(now()) @map("created_at")
  updatedAt         DateTime  @updatedAt @map("updated_at")

  @@index([provider])
  @@map("api_configurations")
}
PRISMASCHEMA

log "Prisma schema generado"

# ─── 9. Prisma seed ──────────────────────────────────────────────────────────
info "Seed gestionado por prisma/seed.ts"

# ─── 10. Ahora generamos todos los ficheros TypeScript del proyecto ──────────
info "Generando código fuente NestJS..."

# === main.ts ===
cat > src/main.ts << 'MAINTS'
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
    origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
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
MAINTS

# === app.module.ts ===
cat > src/app.module.ts << 'APPMODULE'
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { VulnerabilityCollectorModule } from './modules/vulnerability-collector/vulnerability-collector.module';
import { DashboardModule } from './modules/dashboard/dashboard.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    ScheduleModule.forRoot(),
    PrismaModule,
    AuthModule,
    VulnerabilityCollectorModule,
    DashboardModule,
  ],
})
export class AppModule {}
APPMODULE

log "main.ts y app.module.ts generados"

# === Prisma Service ===
cat > src/prisma/prisma.module.ts << 'PRISMAMOD'
import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Global()
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
PRISMAMOD

cat > src/prisma/prisma.service.ts << 'PRISMASVC'
import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(PrismaService.name);

  async onModuleInit() {
    await this.$connect();
    this.logger.log('Database connected');
  }

  async onModuleDestroy() {
    await this.$disconnect();
    this.logger.log('Database disconnected');
  }
}
PRISMASVC

log "Prisma service generado"

# === Auth Module ===
cat > src/auth/auth.module.ts << 'AUTHMOD'
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';

@Module({
  imports: [
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: config.get<string>('JWT_EXPIRATION', '24h') },
      }),
    }),
  ],
  providers: [AuthService, JwtStrategy, LocalStrategy],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
AUTHMOD

cat > src/auth/auth.service.ts << 'AUTHSVC'
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    // Rate limiting check
    const recentAttempts = await this.prisma.loginAttempt.count({
      where: {
        email,
        attemptedAt: { gte: new Date(Date.now() - 15 * 60 * 1000) },
        success: false,
      },
    });

    if (recentAttempts >= 5) {
      throw new UnauthorizedException('Too many login attempts. Try again in 15 minutes.');
    }

    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user || !user.isActive) {
      await this.recordAttempt(email, false);
      return null;
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      await this.recordAttempt(email, false);
      return null;
    }

    await this.recordAttempt(email, true);
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    const { passwordHash, ...result } = user;
    return result;
  }

  async login(user: any) {
    const payload = { sub: user.id, email: user.email, role: user.role };
    return {
      access_token: this.jwtService.sign(payload),
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
    };
  }

  private async recordAttempt(email: string, success: boolean) {
    await this.prisma.loginAttempt.create({
      data: { email, ipAddress: '0.0.0.0', success },
    });
  }
}
AUTHSVC

cat > src/auth/auth.controller.ts << 'AUTHCTRL'
import { Controller, Post, UseGuards, Request, Get } from '@nestjs/common';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @Get('profile')
  getProfile(@Request() req) {
    return req.user;
  }
}
AUTHCTRL

cat > src/auth/strategies/jwt.strategy.ts << 'JWTSTRAT'
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'),
    });
  }

  async validate(payload: any) {
    return { id: payload.sub, email: payload.email, role: payload.role };
  }
}
JWTSTRAT

cat > src/auth/strategies/local.strategy.ts << 'LOCALSTRAT'
import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return user;
  }
}
LOCALSTRAT

cat > src/auth/guards/jwt-auth.guard.ts << 'JWTGUARD'
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
JWTGUARD

cat > src/auth/guards/local-auth.guard.ts << 'LOCALGUARD'
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
LOCALGUARD

cat > src/auth/guards/roles.guard.ts << 'ROLESGUARD'
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<string[]>('roles', context.getHandler());
    if (!requiredRoles) return true;

    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.includes(user.role);
  }
}
ROLESGUARD

cat > src/auth/decorators/roles.decorator.ts << 'ROLESDECO'
import { SetMetadata } from '@nestjs/common';
export const Roles = (...roles: string[]) => SetMetadata('roles', roles);
ROLESDECO

log "Auth module generado"

# === Vulnerability Collector Module ===
info "Generando módulo de recolección de vulnerabilidades..."

cat > src/modules/vulnerability-collector/vulnerability-collector.module.ts << 'VULNMOD'
import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { VulnerabilityCollectorService } from './vulnerability-collector.service';
import { VulnerabilityCollectorController } from './vulnerability-collector.controller';
import { NvdCollector } from './collectors/nvd.collector';
import { CisaKevCollector } from './collectors/cisa-kev.collector';
import { EpssCollector } from './collectors/epss.collector';
import { ExploitCheckCollector } from './collectors/exploit-check.collector';
import { ReportGeneratorService } from './report/report-generator.service';

@Module({
  imports: [
    HttpModule.register({
      timeout: 30000,
      maxRedirects: 3,
    }),
  ],
  controllers: [VulnerabilityCollectorController],
  providers: [
    VulnerabilityCollectorService,
    NvdCollector,
    CisaKevCollector,
    EpssCollector,
    ExploitCheckCollector,
    ReportGeneratorService,
  ],
  exports: [VulnerabilityCollectorService, ReportGeneratorService],
})
export class VulnerabilityCollectorModule {}
VULNMOD

# === NVD Collector ===
cat > src/modules/vulnerability-collector/collectors/nvd.collector.ts << 'NVDCOLL'
import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface ParsedVulnerability {
  cveId: string;
  description: string;
  publishedAt: Date;
  lastModifiedAt: Date;
  cvssV31Score: number | null;
  cvssV31Vector: string | null;
  cvssV31Severity: string | null;
  affectedProducts: any[];
  remediationInfo: any;
  rawData: any;
}

@Injectable()
export class NvdCollector {
  private readonly logger = new Logger(NvdCollector.name);
  private readonly baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  private readonly apiKey: string;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.apiKey = this.configService.get<string>('NVD_API_KEY', '');
  }

  async fetchRecent(hoursBack: number = 1): Promise<any[]> {
    const now = new Date();
    const since = new Date(now.getTime() - hoursBack * 60 * 60 * 1000);

    const params: Record<string, string> = {
      pubStartDate: since.toISOString(),
      pubEndDate: now.toISOString(),
      resultsPerPage: '200',
    };

    const headers: Record<string, string> = {
      'User-Agent': 'Servicios-OCC-VulnCollector/1.0',
    };
    if (this.apiKey) {
      headers['apiKey'] = this.apiKey;
    }

    const allCves: any[] = [];
    let startIndex = 0;
    let totalResults = Infinity;

    while (startIndex < totalResults) {
      try {
        const response = await firstValueFrom(
          this.httpService.get(this.baseUrl, {
            params: { ...params, startIndex: String(startIndex) },
            headers,
            timeout: 30000,
          }),
        );

        totalResults = response.data.totalResults ?? 0;
        const vulnerabilities = response.data.vulnerabilities || [];
        allCves.push(...vulnerabilities);
        startIndex += vulnerabilities.length;

        this.logger.log(`NVD: ${allCves.length}/${totalResults} CVEs fetched`);

        if (startIndex < totalResults) {
          await this.sleep(this.apiKey ? 600 : 6000);
        }
      } catch (error) {
        this.logger.error(`NVD fetch error (offset ${startIndex}): ${error.message}`);
        break;
      }
    }

    return allCves;
  }

  parseItem(item: any): ParsedVulnerability {
    const cve = item.cve;
    const cvss31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;

    return {
      cveId: cve.id,
      description:
        cve.descriptions?.find((d: any) => d.lang === 'en')?.value ||
        cve.descriptions?.[0]?.value ||
        '',
      publishedAt: new Date(cve.published),
      lastModifiedAt: new Date(cve.lastModified),
      cvssV31Score: cvss31?.baseScore ?? null,
      cvssV31Vector: cvss31?.vectorString ?? null,
      cvssV31Severity: cvss31?.baseSeverity ?? null,
      affectedProducts: this.extractAffectedProducts(cve.configurations),
      remediationInfo: this.extractRemediation(cve.references),
      rawData: item,
    };
  }

  private extractAffectedProducts(configurations?: any[]): any[] {
    if (!configurations) return [];
    const products: any[] = [];

    for (const config of configurations) {
      for (const node of config.nodes || []) {
        for (const match of node.cpeMatch || []) {
          if (!match.vulnerable) continue;
          const parts = match.criteria.split(':');
          if (parts.length >= 6) {
            products.push({
              vendor: parts[3],
              product: parts[4],
              version: parts[5] === '*' ? null : parts[5],
              versionRange: this.buildVersionRange(match),
              cpe: match.criteria,
            });
          }
        }
      }
    }

    const unique = new Map<string, any>();
    for (const p of products) {
      unique.set(`${p.vendor}:${p.product}`, p);
    }
    return Array.from(unique.values());
  }

  private buildVersionRange(match: any): string {
    const parts: string[] = [];
    if (match.versionStartIncluding) parts.push(`>=${match.versionStartIncluding}`);
    if (match.versionStartExcluding) parts.push(`>${match.versionStartExcluding}`);
    if (match.versionEndIncluding) parts.push(`<=${match.versionEndIncluding}`);
    if (match.versionEndExcluding) parts.push(`<${match.versionEndExcluding}`);
    return parts.join(' ') || '*';
  }

  private extractRemediation(references?: any[]): any {
    if (!references) return {};
    const vendorAdvisories = references
      .filter((r: any) => r.tags?.includes('Vendor Advisory') || r.tags?.includes('Patch'))
      .map((r: any) => r.url);
    const patchUrls = references
      .filter((r: any) => r.tags?.includes('Patch'))
      .map((r: any) => r.url);

    return {
      patchAvailable: patchUrls.length > 0,
      vendorAdvisories,
      patchUrls,
      allReferences: references.map((r: any) => ({ url: r.url, tags: r.tags || [] })),
    };
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
NVDCOLL

# === CISA KEV Collector ===
cat > src/modules/vulnerability-collector/collectors/cisa-kev.collector.ts << 'CISACOLL'
import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
}

@Injectable()
export class CisaKevCollector {
  private readonly logger = new Logger(CisaKevCollector.name);
  private readonly kevUrl =
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

  private kevMap = new Map<string, KevEntry>();
  private lastFetch: Date | null = null;
  private readonly cacheTtlMs = 6 * 60 * 60 * 1000; // 6 hours

  constructor(private readonly httpService: HttpService) {}

  async refreshCatalog(): Promise<void> {
    const now = new Date();
    if (this.lastFetch && now.getTime() - this.lastFetch.getTime() < this.cacheTtlMs) {
      return;
    }

    try {
      const response = await firstValueFrom(
        this.httpService.get(this.kevUrl, { timeout: 15000 }),
      );
      const entries: KevEntry[] = response.data.vulnerabilities || [];
      this.kevMap.clear();
      for (const entry of entries) {
        this.kevMap.set(entry.cveID, entry);
      }
      this.lastFetch = now;
      this.logger.log(`CISA KEV: ${this.kevMap.size} entries indexed`);
    } catch (error) {
      this.logger.error(`CISA KEV fetch error: ${error.message}`);
    }
  }

  async enrich(cveId: string): Promise<{
    isKnownExploited: boolean;
    kevDateAdded?: string;
    kevDueDate?: string;
    kevRequiredAction?: string;
    kevRansomwareUse?: boolean;
  }> {
    await this.refreshCatalog();
    const kev = this.kevMap.get(cveId);
    if (!kev) return { isKnownExploited: false };

    return {
      isKnownExploited: true,
      kevDateAdded: kev.dateAdded,
      kevDueDate: kev.dueDate,
      kevRequiredAction: kev.requiredAction,
      kevRansomwareUse: kev.knownRansomwareCampaignUse === 'Known',
    };
  }
}
CISACOLL

# === EPSS Collector ===
cat > src/modules/vulnerability-collector/collectors/epss.collector.ts << 'EPSSCOLL'
import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class EpssCollector {
  private readonly logger = new Logger(EpssCollector.name);
  private readonly baseUrl = 'https://api.first.org/data/v1/epss';

  constructor(private readonly httpService: HttpService) {}

  async fetchBatch(
    cveIds: string[],
  ): Promise<Map<string, { score: number; percentile: number }>> {
    const results = new Map<string, { score: number; percentile: number }>();
    const chunks = this.chunkArray(cveIds, 30);

    for (const chunk of chunks) {
      try {
        const response = await firstValueFrom(
          this.httpService.get(this.baseUrl, {
            params: { cve: chunk.join(',') },
            timeout: 15000,
          }),
        );

        for (const item of response.data.data || []) {
          results.set(item.cve, {
            score: parseFloat(item.epss),
            percentile: parseFloat(item.percentile),
          });
        }
        await this.sleep(1000);
      } catch (error) {
        this.logger.error(`EPSS batch error: ${error.message}`);
      }
    }

    return results;
  }

  private chunkArray<T>(arr: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < arr.length; i += size) {
      chunks.push(arr.slice(i, i + size));
    }
    return chunks;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
EPSSCOLL

# === Exploit Check Collector ===
cat > src/modules/vulnerability-collector/collectors/exploit-check.collector.ts << 'EXPLOITCOLL'
import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class ExploitCheckCollector {
  private readonly logger = new Logger(ExploitCheckCollector.name);
  private readonly githubToken: string;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.githubToken = this.configService.get<string>('GITHUB_TOKEN', '');
  }

  async check(cveId: string): Promise<{
    hasExploit: boolean;
    references: Array<{ source: string; url: string; type: string }>;
  }> {
    const references: Array<{ source: string; url: string; type: string }> = [];

    // 1. GitHub search
    try {
      const ghRefs = await this.checkGitHubPocs(cveId);
      references.push(...ghRefs);
    } catch (e) {
      this.logger.warn(`GitHub PoC check failed for ${cveId}: ${e.message}`);
    }

    // 2. nomi-sec/PoC-in-GitHub
    try {
      const nomiRefs = await this.checkNomiSec(cveId);
      references.push(...nomiRefs);
    } catch (e) {
      this.logger.warn(`nomi-sec check failed for ${cveId}: ${e.message}`);
    }

    return { hasExploit: references.length > 0, references };
  }

  private async checkGitHubPocs(cveId: string) {
    const refs: Array<{ source: string; url: string; type: string }> = [];
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github.v3+json',
    };
    if (this.githubToken) {
      headers['Authorization'] = `Bearer ${this.githubToken}`;
    }

    const response = await firstValueFrom(
      this.httpService.get('https://api.github.com/search/repositories', {
        params: { q: cveId, sort: 'updated', per_page: 5 },
        headers,
        timeout: 10000,
      }),
    );

    for (const repo of response.data.items || []) {
      const nameMatch = repo.name?.toLowerCase().includes(cveId.toLowerCase());
      const descMatch = repo.description?.toLowerCase().includes(cveId.toLowerCase());
      if (nameMatch || descMatch) {
        refs.push({ source: 'github', url: repo.html_url, type: 'poc' });
      }
    }
    return refs;
  }

  private async checkNomiSec(cveId: string) {
    const year = cveId.split('-')[1];
    const url = `https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/${year}/${cveId}.json`;

    try {
      const response = await firstValueFrom(
        this.httpService.get(url, { timeout: 5000 }),
      );
      if (Array.isArray(response.data) && response.data.length > 0) {
        return response.data.map((poc: any) => ({
          source: 'nomi-sec',
          url: poc.html_url || '',
          type: 'poc',
        }));
      }
    } catch {
      // 404 = no PoC, not an error
    }
    return [];
  }
}
EXPLOITCOLL

log "Collectors generados"

# === Orchestrator Service ===
info "Generando servicio orquestador..."

cat > src/modules/vulnerability-collector/vulnerability-collector.service.ts << 'VULNSVC'
import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import { NvdCollector, ParsedVulnerability } from './collectors/nvd.collector';
import { CisaKevCollector } from './collectors/cisa-kev.collector';
import { EpssCollector } from './collectors/epss.collector';
import { ExploitCheckCollector } from './collectors/exploit-check.collector';

@Injectable()
export class VulnerabilityCollectorService {
  private readonly logger = new Logger(VulnerabilityCollectorService.name);
  private isRunning = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly nvdCollector: NvdCollector,
    private readonly cisaKev: CisaKevCollector,
    private readonly epss: EpssCollector,
    private readonly exploitCheck: ExploitCheckCollector,
  ) {}

  /**
   * Cron: cada 30 minutos.
   */
  @Cron('0 */30 * * * *')
  async scheduledCollection(): Promise<void> {
    if (this.isRunning) {
      this.logger.warn('Previous collection still running, skipping');
      return;
    }

    this.isRunning = true;
    const startTime = Date.now();
    let runId: number | null = null;

    try {
      const run = await this.prisma.collectorRun.create({
        data: { source: 'scheduled', status: 'running' },
      });
      runId = run.id;

      const result = await this.collectAndEnrich();

      await this.prisma.collectorRun.update({
        where: { id: runId },
        data: {
          finishedAt: new Date(),
          cvesFetched: result.fetched,
          cvesNew: result.newCves,
          cvesUpdated: result.updated,
          status: 'success',
          durationMs: Date.now() - startTime,
        },
      });

      this.logger.log(
        `Collection done: ${result.newCves} new, ${result.updated} updated (${Date.now() - startTime}ms)`,
      );
    } catch (error) {
      this.logger.error(`Scheduled collection error: ${error.message}`);
      if (runId) {
        await this.prisma.collectorRun.update({
          where: { id: runId },
          data: {
            finishedAt: new Date(),
            status: 'error',
            errorMessage: error.message,
            durationMs: Date.now() - startTime,
          },
        });
      }
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Pipeline: fetch → parse → upsert → enrich (KEV + EPSS + exploits)
   */
  async collectAndEnrich(): Promise<{
    fetched: number;
    newCves: number;
    updated: number;
  }> {
    let fetched = 0;
    let newCves = 0;
    let updated = 0;

    const lookbackHours = this.configService.get<number>(
      'VULN_COLLECTOR_LOOKBACK_HOURS',
      1,
    );

    // STEP 1: Fetch from NVD
    this.logger.log('Step 1/4: Fetching from NVD...');
    const nvdItems = await this.nvdCollector.fetchRecent(lookbackHours);
    fetched = nvdItems.length;

    if (fetched === 0) {
      this.logger.log('No new CVEs from NVD');
      return { fetched: 0, newCves: 0, updated: 0 };
    }

    // STEP 2: Parse & upsert
    this.logger.log(`Step 2/4: Parsing ${fetched} CVEs...`);
    const parsedCves = nvdItems.map((item) => this.nvdCollector.parseItem(item));
    const cveIds: string[] = [];

    for (const cve of parsedCves) {
      try {
        const existing = await this.prisma.vulnerability.findUnique({
          where: { cveId: cve.cveId },
        });

        if (!existing) {
          await this.prisma.vulnerability.create({
            data: {
              cveId: cve.cveId,
              description: cve.description,
              publishedAt: cve.publishedAt,
              lastModifiedAt: cve.lastModifiedAt,
              cvssV31Score: cve.cvssV31Score,
              cvssV31Vector: cve.cvssV31Vector,
              cvssV31Severity: cve.cvssV31Severity,
              affectedProducts: cve.affectedProducts as any,
              remediationInfo: cve.remediationInfo as any,
              rawData: cve.rawData as any,
              processingStatus: 'new',
            },
          });
          newCves++;
        } else {
          await this.prisma.vulnerability.update({
            where: { cveId: cve.cveId },
            data: {
              lastModifiedAt: cve.lastModifiedAt,
              cvssV31Score: cve.cvssV31Score,
              cvssV31Vector: cve.cvssV31Vector,
              cvssV31Severity: cve.cvssV31Severity,
              affectedProducts: cve.affectedProducts as any,
              remediationInfo: cve.remediationInfo as any,
              rawData: cve.rawData as any,
            },
          });
          updated++;
        }
        cveIds.push(cve.cveId);
      } catch (err) {
        this.logger.error(`Error upserting ${cve.cveId}: ${err.message}`);
      }
    }

    // STEP 3: Enrich with CISA KEV + EPSS
    this.logger.log('Step 3/4: Enriching (CISA KEV + EPSS)...');
    for (const cveId of cveIds) {
      const kevData = await this.cisaKev.enrich(cveId);
      if (kevData.isKnownExploited) {
        await this.prisma.vulnerability.update({
          where: { cveId },
          data: {
            isKnownExploited: true,
            kevDateAdded: kevData.kevDateAdded ? new Date(kevData.kevDateAdded) : null,
            kevDueDate: kevData.kevDueDate ? new Date(kevData.kevDueDate) : null,
          },
        });
      }
    }

    const epssResults = await this.epss.fetchBatch(cveIds);
    for (const [cveId, epssData] of epssResults) {
      await this.prisma.vulnerability.update({
        where: { cveId },
        data: {
          epssScore: epssData.score,
          epssPercentile: epssData.percentile,
        },
      });
    }

    // STEP 4: Check exploits for HIGH/CRITICAL
    const exploitCheckEnabled = this.configService.get<string>(
      'VULN_COLLECTOR_EXPLOIT_CHECK_ENABLED',
      'true',
    );

    if (exploitCheckEnabled === 'true') {
      this.logger.log('Step 4/4: Checking public exploits...');
      const minSeverity = this.configService.get<string>(
        'VULN_COLLECTOR_MIN_SEVERITY_FOR_EXPLOIT_CHECK',
        'HIGH',
      );
      const severities = this.getSeveritiesAbove(minSeverity);

      const toCheck = await this.prisma.vulnerability.findMany({
        where: {
          cveId: { in: cveIds },
          cvssV31Severity: { in: severities },
        },
        select: { cveId: true },
      });

      for (const { cveId } of toCheck) {
        try {
          const exploitData = await this.exploitCheck.check(cveId);
          await this.prisma.vulnerability.update({
            where: { cveId },
            data: {
              hasPublicExploit: exploitData.hasExploit,
              exploitReferences: exploitData.references as any,
              processingStatus: 'enriched',
              enrichedAt: new Date(),
            },
          });
        } catch (err) {
          this.logger.warn(`Exploit check failed for ${cveId}: ${err.message}`);
        }
        await new Promise((r) => setTimeout(r, 2000));
      }
    }

    // Mark remaining as enriched
    await this.prisma.vulnerability.updateMany({
      where: { cveId: { in: cveIds }, processingStatus: 'new' },
      data: { processingStatus: 'enriched', enrichedAt: new Date() },
    });

    return { fetched, newCves, updated };
  }

  async manualCollection() {
    return this.collectAndEnrich();
  }

  private getSeveritiesAbove(min: string): string[] {
    const order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const idx = order.indexOf(min.toUpperCase());
    return idx >= 0 ? order.slice(idx) : order;
  }
}
VULNSVC

log "Servicio orquestador generado"

# === Report Generator ===
info "Generando generador de informes PDF..."

cat > src/modules/vulnerability-collector/report/report-generator.service.ts << 'REPORTSVC'
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../../prisma/prisma.service';
import * as Handlebars from 'handlebars';
import * as fs from 'fs/promises';
import * as path from 'path';

@Injectable()
export class ReportGeneratorService {
  private readonly logger = new Logger(ReportGeneratorService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
  ) {
    this.registerHandlebarsHelpers();
  }

  private registerHandlebarsHelpers() {
    Handlebars.registerHelper('eq', (a, b) => a === b);
    Handlebars.registerHelper('gt', (a, b) => a > b);
    Handlebars.registerHelper('formatDate', (date: Date) => {
      if (!date) return '-';
      return new Date(date).toLocaleDateString('es-ES');
    });
    Handlebars.registerHelper('formatScore', (score: any) => {
      if (score === null || score === undefined) return '-';
      return parseFloat(score).toFixed(1);
    });
    Handlebars.registerHelper('formatEpss', (score: any) => {
      if (score === null || score === undefined) return '-';
      return (parseFloat(score) * 100).toFixed(2) + '%';
    });
    Handlebars.registerHelper('severityClass', (severity: string) => {
      const map: Record<string, string> = {
        CRITICAL: 'sev-critical',
        HIGH: 'sev-high',
        MEDIUM: 'sev-medium',
        LOW: 'sev-low',
      };
      return map[severity] || '';
    });
    Handlebars.registerHelper('truncate', (str: string, len: number) => {
      if (!str) return '';
      return str.length > len ? str.substring(0, len) + '...' : str;
    });
  }

  async generateReport(options: {
    periodHours?: number;
    minSeverity?: string;
    onlyExploited?: boolean;
    generatedBy?: number;
  }): Promise<{ filePath: string; summary: any }> {
    const periodHours = options.periodHours || 24;
    const since = new Date(Date.now() - periodHours * 60 * 60 * 1000);
    const now = new Date();

    // Build query
    const whereClause: any = {
      firstSeenAt: { gte: since },
      processingStatus: 'enriched',
    };

    if (options.minSeverity) {
      whereClause.cvssV31Severity = { in: this.getSeveritiesAbove(options.minSeverity) };
    }

    if (options.onlyExploited) {
      whereClause.OR = [
        { isKnownExploited: true },
        { hasPublicExploit: true },
      ];
    }

    const vulnerabilities = await this.prisma.vulnerability.findMany({
      where: whereClause,
      orderBy: [
        { isKnownExploited: 'desc' },
        { cvssV31Score: 'desc' },
        { epssScore: 'desc' },
      ],
    });

    // Summary
    const summary = {
      period: { from: since.toISOString(), to: now.toISOString(), hours: periodHours },
      total: vulnerabilities.length,
      bySeverity: {
        critical: vulnerabilities.filter((v) => v.cvssV31Severity === 'CRITICAL').length,
        high: vulnerabilities.filter((v) => v.cvssV31Severity === 'HIGH').length,
        medium: vulnerabilities.filter((v) => v.cvssV31Severity === 'MEDIUM').length,
        low: vulnerabilities.filter((v) => v.cvssV31Severity === 'LOW').length,
      },
      exploited: vulnerabilities.filter((v) => v.isKnownExploited).length,
      withPublicExploit: vulnerabilities.filter((v) => v.hasPublicExploit).length,
      requireImmediateAction: vulnerabilities.filter(
        (v) =>
          v.isKnownExploited ||
          (v.cvssV31Severity === 'CRITICAL' && v.hasPublicExploit),
      ).length,
    };

    // Categorize
    const categorized = {
      immediate: vulnerabilities.filter(
        (v) =>
          v.isKnownExploited ||
          (v.cvssV31Severity === 'CRITICAL' && v.hasPublicExploit),
      ),
      critical: vulnerabilities.filter(
        (v) =>
          v.cvssV31Severity === 'CRITICAL' &&
          !v.isKnownExploited &&
          !v.hasPublicExploit,
      ),
      high: vulnerabilities.filter((v) => v.cvssV31Severity === 'HIGH'),
      medium: vulnerabilities.filter((v) => v.cvssV31Severity === 'MEDIUM'),
      low: vulnerabilities.filter((v) => v.cvssV31Severity === 'LOW'),
    };

    // Render HTML
    const templatePath = path.join(__dirname, 'templates', 'vuln-report.template.hbs');
    const templateSource = await fs.readFile(templatePath, 'utf-8');
    const template = Handlebars.compile(templateSource);

    const html = template({
      reportDate: now.toLocaleDateString('es-ES', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      }),
      reportTime: now.toLocaleTimeString('es-ES'),
      summary,
      categorized,
      generatedAt: now.toISOString(),
    });

    // Generate PDF
    const filename = `vuln-report_${now.toISOString().slice(0, 10)}_${Date.now()}.pdf`;
    const outputDir = this.configService.get<string>(
      'VULN_REPORT_OUTPUT_DIR',
      './storage/reports',
    );
    await fs.mkdir(outputDir, { recursive: true });
    const filePath = path.join(outputDir, filename);

    // Use Puppeteer for PDF
    let puppeteer: any;
    try {
      puppeteer = require('puppeteer');
    } catch {
      this.logger.error('Puppeteer not available, saving HTML instead');
      const htmlPath = filePath.replace('.pdf', '.html');
      await fs.writeFile(htmlPath, html, 'utf-8');
      return { filePath: htmlPath, summary };
    }

    const browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
      executablePath: this.configService.get<string>('PUPPETEER_EXECUTABLE_PATH') || undefined,
    });

    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    await page.pdf({
      path: filePath,
      format: 'A4',
      margin: { top: '20mm', right: '15mm', bottom: '20mm', left: '15mm' },
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: `<div style="font-size:9px;width:100%;text-align:center;color:#666;">
        Servicios OCC — Informe de Vulnerabilidades — CONFIDENCIAL</div>`,
      footerTemplate: `<div style="font-size:9px;width:100%;display:flex;justify-content:space-between;padding:0 20mm;color:#666;">
        <span>Generado: ${now.toLocaleString('es-ES')}</span>
        <span>Pág. <span class="pageNumber"></span>/<span class="totalPages"></span></span></div>`,
    });
    await browser.close();

    // Record report
    await this.prisma.vulnerabilityReport.create({
      data: {
        reportDate: now,
        periodStart: since,
        periodEnd: now,
        totalCves: summary.total,
        criticalCount: summary.bySeverity.critical,
        highCount: summary.bySeverity.high,
        exploitedCount: summary.exploited,
        filePath,
        generatedBy: options.generatedBy || null,
      },
    });

    this.logger.log(`Report generated: ${filePath} (${summary.total} CVEs)`);
    return { filePath, summary };
  }

  private getSeveritiesAbove(min: string): string[] {
    const order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const idx = order.indexOf(min.toUpperCase());
    return idx >= 0 ? order.slice(idx) : order;
  }
}
REPORTSVC

log "Report generator generado"

# === Report Template (Handlebars) ===
info "Generando plantilla de informe PDF..."

cat > src/modules/vulnerability-collector/report/templates/vuln-report.template.hbs << 'HBSTEMPLATE'
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<style>
  @page { margin: 0; }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; color: #333; line-height: 1.5; font-size: 11px; margin: 0; padding: 20px; }

  .cover { page-break-after: always; min-height: 90vh; display: flex; flex-direction: column; justify-content: center; padding: 60px; background: linear-gradient(135deg, #1A1A1A 0%, #333 100%); color: white; margin: -20px; margin-bottom: 20px; }
  .cover-logo { width: 56px; height: 56px; background: #E30613; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 22px; font-weight: bold; color: white; margin-bottom: 40px; }
  .cover h1 { font-size: 34px; margin: 0 0 8px 0; }
  .cover h2 { font-size: 18px; font-weight: 300; color: #999; margin: 0 0 40px 0; }
  .cover .meta { color: #888; font-size: 13px; line-height: 2; }
  .confidential { margin-top: 50px; padding: 10px 20px; border: 2px solid #E30613; display: inline-block; color: #E30613; font-weight: 600; text-transform: uppercase; letter-spacing: 2px; font-size: 12px; }

  h2 { color: #1A1A1A; border-bottom: 2px solid #E30613; padding-bottom: 8px; margin-top: 30px; font-size: 18px; }
  h3 { color: #444; margin-top: 16px; font-size: 14px; }

  .summary-grid { display: flex; gap: 12px; margin: 20px 0; flex-wrap: wrap; }
  .summary-card { flex: 1; min-width: 120px; padding: 16px; border-radius: 8px; text-align: center; }
  .summary-card .number { font-size: 30px; font-weight: 700; }
  .summary-card .label { font-size: 10px; color: #666; margin-top: 4px; }
  .card-critical { background: #FDE8E8; color: #C62828; }
  .card-high { background: #FFF3E0; color: #E65100; }
  .card-medium { background: #FFF8E1; color: #F57F17; }
  .card-low { background: #E8F5E9; color: #2E7D32; }
  .card-exploited { background: #FCE4EC; color: #B71C1C; border: 2px solid #B71C1C; }

  .action-required { background: #B71C1C; color: white; padding: 14px 20px; border-radius: 8px; margin: 16px 0; font-weight: 600; font-size: 13px; }

  table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 9px; }
  th { background: #F5F5F5; padding: 8px 6px; text-align: left; font-size: 8px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #E0E0E0; }
  td { padding: 8px 6px; border-bottom: 1px solid #EEE; vertical-align: top; }
  tr:nth-child(even) { background: #FAFAFA; }
  tr.row-exploited { background: #FDE8E8 !important; }

  .sev-badge { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 8px; font-weight: 600; text-transform: uppercase; color: white; }
  .sev-critical { background: #C62828; }
  .sev-high { background: #E65100; }
  .sev-medium { background: #F57F17; }
  .sev-low { background: #2E7D32; }

  .exploit-yes { color: #B71C1C; font-weight: 700; }
  .exploit-no { color: #999; }

  .vuln-block { page-break-inside: avoid; border: 1px solid #E0E0E0; border-radius: 8px; padding: 14px; margin: 10px 0; }
  .vuln-block.exploited { border-left: 4px solid #B71C1C; }
  .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .vuln-cve { font-size: 14px; font-weight: 700; color: #1A1A1A; }
  .vuln-desc { color: #555; font-size: 10px; margin: 6px 0; }
  .product-tag { display: inline-block; background: #E3F2FD; color: #1565C0; padding: 1px 6px; border-radius: 3px; font-size: 8px; margin: 1px 2px; }
  .remediation-box { background: #E8F5E9; border-left: 3px solid #4CAF50; padding: 8px 10px; margin-top: 8px; font-size: 10px; }
  .remediation-box.no-patch { background: #FFF3E0; border-left-color: #FF9800; }

  .footer-note { margin-top: 30px; padding-top: 10px; border-top: 1px solid #E0E0E0; font-size: 8px; color: #999; text-align: center; }
</style>
</head>
<body>

<!-- COVER -->
<div class="cover">
  <div class="cover-logo">OCC</div>
  <h1>Informe de Vulnerabilidades</h1>
  <h2>Boletín de Seguridad — Servicios OCC</h2>
  <div class="meta">
    <p>Fecha: {{reportDate}}</p>
    <p>Hora de generación: {{reportTime}}</p>
    <p>Periodo analizado: {{summary.period.hours}} horas</p>
    <p>Total CVEs procesados: {{summary.total}}</p>
  </div>
  <div class="confidential">Confidencial — Uso Interno</div>
</div>

<!-- EXECUTIVE SUMMARY -->
<h2>1. Resumen Ejecutivo</h2>

<div class="summary-grid">
  <div class="summary-card card-critical">
    <div class="number">{{summary.bySeverity.critical}}</div>
    <div class="label">Críticas</div>
  </div>
  <div class="summary-card card-high">
    <div class="number">{{summary.bySeverity.high}}</div>
    <div class="label">Altas</div>
  </div>
  <div class="summary-card card-medium">
    <div class="number">{{summary.bySeverity.medium}}</div>
    <div class="label">Medias</div>
  </div>
  <div class="summary-card card-low">
    <div class="number">{{summary.bySeverity.low}}</div>
    <div class="label">Bajas</div>
  </div>
  <div class="summary-card card-exploited">
    <div class="number">{{summary.exploited}}</div>
    <div class="label">Explotación Activa</div>
  </div>
</div>

{{#if (gt summary.requireImmediateAction 0)}}
<div class="action-required">
  ⚠ {{summary.requireImmediateAction}} vulnerabilidad(es) requieren acción INMEDIATA — explotación activa o CVSS crítico con exploit público
</div>
{{/if}}

<!-- IMMEDIATE ACTION -->
{{#if categorized.immediate.length}}
<h2>2. Acción Inmediata Requerida</h2>
<p style="color:#B71C1C;font-weight:600;font-size:11px;">
  Las siguientes vulnerabilidades están siendo explotadas activamente. Parcheo prioritario obligatorio.
</p>

{{#each categorized.immediate}}
<div class="vuln-block exploited">
  <div class="vuln-header">
    <span class="vuln-cve">{{this.cveId}}</span>
    <span>
      <span class="sev-badge sev-critical">CVSS {{formatScore this.cvssV31Score}}</span>
      {{#if this.isKnownExploited}}
      <span class="sev-badge" style="background:#B71C1C;margin-left:4px;">🔴 EXPLOTACIÓN ACTIVA</span>
      {{/if}}
    </span>
  </div>
  <div class="vuln-desc">{{truncate this.description 300}}</div>
  <div>
    <strong style="font-size:9px;">Software afectado:</strong>
    {{#each this.affectedProducts}}
    <span class="product-tag">{{this.vendor}} / {{this.product}} {{this.versionRange}}</span>
    {{/each}}
  </div>
  {{#if this.epssScore}}
  <p style="font-size:10px;margin:4px 0;"><strong>EPSS:</strong> {{formatEpss this.epssScore}} (probabilidad explotación 30 días)</p>
  {{/if}}
  {{#if this.remediationInfo.patchAvailable}}
  <div class="remediation-box">
    <strong>Remediación:</strong> Parche disponible.
    {{#each this.remediationInfo.vendorAdvisories}}
    <br>→ {{this}}
    {{/each}}
  </div>
  {{else}}
  <div class="remediation-box no-patch">
    <strong>Remediación:</strong> Sin parche oficial. Aplicar workarounds / mitigaciones temporales.
  </div>
  {{/if}}
</div>
{{/each}}
{{/if}}

<!-- FULL TABLE -->
<h2>{{#if categorized.immediate.length}}3{{else}}2{{/if}}. Listado Completo de Vulnerabilidades</h2>

<table>
  <thead>
    <tr>
      <th style="width:12%">CVE</th>
      <th style="width:6%">CVSS</th>
      <th style="width:8%">Severidad</th>
      <th style="width:7%">EPSS</th>
      <th style="width:6%">KEV</th>
      <th style="width:6%">Exploit</th>
      <th style="width:30%">Productos Afectados</th>
      <th style="width:6%">Parche</th>
      <th style="width:19%">Remediación</th>
    </tr>
  </thead>
  <tbody>
    {{#each categorized.immediate}}
    <tr class="row-exploited">
      <td><strong>{{this.cveId}}</strong></td>
      <td>{{formatScore this.cvssV31Score}}</td>
      <td><span class="sev-badge {{severityClass this.cvssV31Severity}}">{{this.cvssV31Severity}}</span></td>
      <td>{{formatEpss this.epssScore}}</td>
      <td class="exploit-yes">SÍ</td>
      <td>{{#if this.hasPublicExploit}}<span class="exploit-yes">SÍ</span>{{else}}<span class="exploit-no">No</span>{{/if}}</td>
      <td>{{#each this.affectedProducts}}<span class="product-tag">{{this.vendor}}/{{this.product}}</span>{{/each}}</td>
      <td>{{#if this.remediationInfo.patchAvailable}}✅{{else}}❌{{/if}}</td>
      <td style="font-size:8px;">{{#if this.remediationInfo.patchAvailable}}Aplicar parche{{else}}Mitigar{{/if}}</td>
    </tr>
    {{/each}}
    {{#each categorized.critical}}
    <tr>
      <td><strong>{{this.cveId}}</strong></td>
      <td>{{formatScore this.cvssV31Score}}</td>
      <td><span class="sev-badge sev-critical">CRITICAL</span></td>
      <td>{{formatEpss this.epssScore}}</td>
      <td><span class="exploit-no">No</span></td>
      <td>{{#if this.hasPublicExploit}}<span class="exploit-yes">SÍ</span>{{else}}<span class="exploit-no">No</span>{{/if}}</td>
      <td>{{#each this.affectedProducts}}<span class="product-tag">{{this.vendor}}/{{this.product}}</span>{{/each}}</td>
      <td>{{#if this.remediationInfo.patchAvailable}}✅{{else}}❌{{/if}}</td>
      <td style="font-size:8px;">{{#if this.remediationInfo.patchAvailable}}Aplicar parche{{else}}Pendiente{{/if}}</td>
    </tr>
    {{/each}}
    {{#each categorized.high}}
    <tr>
      <td>{{this.cveId}}</td>
      <td>{{formatScore this.cvssV31Score}}</td>
      <td><span class="sev-badge sev-high">HIGH</span></td>
      <td>{{formatEpss this.epssScore}}</td>
      <td>{{#if this.isKnownExploited}}<span class="exploit-yes">SÍ</span>{{else}}<span class="exploit-no">No</span>{{/if}}</td>
      <td>{{#if this.hasPublicExploit}}<span class="exploit-yes">SÍ</span>{{else}}<span class="exploit-no">No</span>{{/if}}</td>
      <td>{{#each this.affectedProducts}}<span class="product-tag">{{this.vendor}}/{{this.product}}</span>{{/each}}</td>
      <td>{{#if this.remediationInfo.patchAvailable}}✅{{else}}❌{{/if}}</td>
      <td style="font-size:8px;">{{#if this.remediationInfo.patchAvailable}}Aplicar parche{{else}}Pendiente{{/if}}</td>
    </tr>
    {{/each}}
    {{#each categorized.medium}}
    <tr>
      <td>{{this.cveId}}</td>
      <td>{{formatScore this.cvssV31Score}}</td>
      <td><span class="sev-badge sev-medium">MEDIUM</span></td>
      <td>{{formatEpss this.epssScore}}</td>
      <td><span class="exploit-no">No</span></td>
      <td>{{#if this.hasPublicExploit}}<span class="exploit-yes">SÍ</span>{{else}}<span class="exploit-no">No</span>{{/if}}</td>
      <td>{{#each this.affectedProducts}}<span class="product-tag">{{this.vendor}}/{{this.product}}</span>{{/each}}</td>
      <td>{{#if this.remediationInfo.patchAvailable}}✅{{else}}❌{{/if}}</td>
      <td style="font-size:8px;">{{#if this.remediationInfo.patchAvailable}}Programar{{else}}Evaluar{{/if}}</td>
    </tr>
    {{/each}}
    {{#each categorized.low}}
    <tr>
      <td>{{this.cveId}}</td>
      <td>{{formatScore this.cvssV31Score}}</td>
      <td><span class="sev-badge sev-low">LOW</span></td>
      <td>{{formatEpss this.epssScore}}</td>
      <td><span class="exploit-no">No</span></td>
      <td><span class="exploit-no">No</span></td>
      <td>{{#each this.affectedProducts}}<span class="product-tag">{{this.vendor}}/{{this.product}}</span>{{/each}}</td>
      <td>{{#if this.remediationInfo.patchAvailable}}✅{{else}}❌{{/if}}</td>
      <td style="font-size:8px;">Siguiente ciclo</td>
    </tr>
    {{/each}}
  </tbody>
</table>

<!-- FOOTER -->
<div class="footer-note">
  Informe generado automáticamente por Servicios OCC — {{generatedAt}}<br>
  Fuentes: NVD (NIST), CISA KEV, FIRST EPSS, GitHub PoC Database<br>
  Clasificación: CONFIDENCIAL — Uso Interno
</div>

</body>
</html>
HBSTEMPLATE

log "Plantilla de informe generada"

# === Controller ===
info "Generando controlador API..."

cat > src/modules/vulnerability-collector/vulnerability-collector.controller.ts << 'VULNCTRL'
import {
  Controller, Get, Post, Query, UseGuards, Request, Res,
  StreamableFile, Header,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';
import { VulnerabilityCollectorService } from './vulnerability-collector.service';
import { ReportGeneratorService } from './report/report-generator.service';
import { PrismaService } from '../../prisma/prisma.service';

@ApiTags('Vulnerabilities')
@ApiBearerAuth()
@Controller('vulnerabilities')
@UseGuards(JwtAuthGuard)
export class VulnerabilityCollectorController {
  constructor(
    private readonly collector: VulnerabilityCollectorService,
    private readonly reportGenerator: ReportGeneratorService,
    private readonly prisma: PrismaService,
  ) {}

  @Get()
  @ApiQuery({ name: 'severity', required: false })
  @ApiQuery({ name: 'exploited', required: false })
  @ApiQuery({ name: 'hours', required: false })
  @ApiQuery({ name: 'page', required: false })
  @ApiQuery({ name: 'limit', required: false })
  async list(
    @Query('severity') severity?: string,
    @Query('exploited') exploited?: string,
    @Query('hours') hours?: string,
    @Query('page') page?: string,
    @Query('limit') limit?: string,
  ) {
    const where: any = {};
    const take = Math.min(parseInt(limit || '50'), 200);
    const skip = (parseInt(page || '1') - 1) * take;

    if (severity) where.cvssV31Severity = severity.toUpperCase();
    if (exploited === 'true') where.isKnownExploited = true;
    if (hours) {
      where.firstSeenAt = { gte: new Date(Date.now() - parseInt(hours) * 3600000) };
    }

    const [data, total] = await Promise.all([
      this.prisma.vulnerability.findMany({
        where,
        orderBy: [{ isKnownExploited: 'desc' }, { cvssV31Score: 'desc' }],
        take,
        skip,
        select: {
          id: true, cveId: true, description: true,
          cvssV31Score: true, cvssV31Severity: true, cvssV31Vector: true,
          epssScore: true, epssPercentile: true,
          isKnownExploited: true, hasPublicExploit: true, exploitReferences: true,
          affectedProducts: true, remediationInfo: true,
          publishedAt: true, firstSeenAt: true, enrichedAt: true,
        },
      }),
      this.prisma.vulnerability.count({ where }),
    ]);

    return { data, total, page: parseInt(page || '1'), limit: take };
  }

  @Post('collect')
  @UseGuards(RolesGuard)
  @Roles('ADMIN')
  async triggerCollection(@Request() req) {
    const result = await this.collector.manualCollection();
    return { message: 'Collection completed', ...result };
  }

  @Post('report')
  @ApiQuery({ name: 'hours', required: false })
  @ApiQuery({ name: 'minSeverity', required: false })
  @ApiQuery({ name: 'onlyExploited', required: false })
  async generateReport(
    @Request() req,
    @Query('hours') hours?: string,
    @Query('minSeverity') minSeverity?: string,
    @Query('onlyExploited') onlyExploited?: string,
  ) {
    const result = await this.reportGenerator.generateReport({
      periodHours: parseInt(hours || '24'),
      minSeverity: minSeverity || 'MEDIUM',
      onlyExploited: onlyExploited === 'true',
      generatedBy: req.user?.id,
    });

    return {
      message: 'Report generated',
      downloadUrl: `/api/vulnerabilities/report/download/${path.basename(result.filePath)}`,
      summary: result.summary,
    };
  }

  @Get('report/download/:filename')
  async downloadReport(
    @Query('filename') filename: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<StreamableFile> {
    const filePath = path.join(
      process.cwd(),
      'storage',
      'reports',
      path.basename(filename),
    );

    if (!fs.existsSync(filePath)) {
      res.status(404).json({ message: 'Report not found' });
      return;
    }

    const file = fs.createReadStream(filePath);
    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${path.basename(filePath)}"`,
    });
    return new StreamableFile(file);
  }

  @Get('dashboard')
  async dashboard() {
    const last24h = new Date(Date.now() - 24 * 3600000);
    const last7d = new Date(Date.now() - 7 * 24 * 3600000);

    const [todayByS, weekByS, topExploited, lastRun, totalAll] = await Promise.all([
      this.prisma.vulnerability.groupBy({
        by: ['cvssV31Severity'],
        where: { firstSeenAt: { gte: last24h } },
        _count: true,
      }),
      this.prisma.vulnerability.groupBy({
        by: ['cvssV31Severity'],
        where: { firstSeenAt: { gte: last7d } },
        _count: true,
      }),
      this.prisma.vulnerability.findMany({
        where: { isKnownExploited: true },
        orderBy: { firstSeenAt: 'desc' },
        take: 10,
        select: {
          cveId: true, cvssV31Score: true, cvssV31Severity: true,
          affectedProducts: true, firstSeenAt: true, epssScore: true,
        },
      }),
      this.prisma.collectorRun.findFirst({
        orderBy: { startedAt: 'desc' },
      }),
      this.prisma.vulnerability.count(),
    ]);

    return { today: todayByS, week: weekByS, topExploited, lastRun, totalAll };
  }

  @Get('reports')
  async listReports(
    @Query('page') page?: string,
    @Query('limit') limit?: string,
  ) {
    const take = Math.min(parseInt(limit || '20'), 100);
    const skip = (parseInt(page || '1') - 1) * take;

    const [data, total] = await Promise.all([
      this.prisma.vulnerabilityReport.findMany({
        orderBy: { createdAt: 'desc' },
        take,
        skip,
        include: { user: { select: { name: true, email: true } } },
      }),
      this.prisma.vulnerabilityReport.count(),
    ]);

    return { data, total };
  }

  @Get('runs')
  async listRuns(@Query('limit') limit?: string) {
    const take = Math.min(parseInt(limit || '20'), 100);
    return this.prisma.collectorRun.findMany({
      orderBy: { startedAt: 'desc' },
      take,
    });
  }
}
VULNCTRL

log "Controlador API generado"

# === Dashboard Module (minimal) ===
cat > src/modules/dashboard/dashboard.module.ts << 'DASHMOD'
import { Module } from '@nestjs/common';
import { DashboardController } from './dashboard.controller';

@Module({
  controllers: [DashboardController],
})
export class DashboardModule {}
DASHMOD

cat > src/modules/dashboard/dashboard.controller.ts << 'DASHCTRL'
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
DASHCTRL

log "Dashboard module generado"

# === Manual collection script ===
cat > scripts/manual-collect.ts << 'MANUALCOLLECT'
/**
 * Script para lanzar una recolección manual desde CLI.
 * Uso: npx ts-node scripts/manual-collect.ts
 */
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { VulnerabilityCollectorService } from '../src/modules/vulnerability-collector/vulnerability-collector.service';

async function main() {
  console.log('🚀 Starting manual vulnerability collection...\n');
  
  const app = await NestFactory.createApplicationContext(AppModule);
  const collector = app.get(VulnerabilityCollectorService);

  try {
    const result = await collector.manualCollection();
    console.log('\n✅ Collection completed:');
    console.log(`   CVEs fetched: ${result.fetched}`);
    console.log(`   New CVEs:     ${result.newCves}`);
    console.log(`   Updated:      ${result.updated}`);
  } catch (error) {
    console.error('❌ Collection failed:', error.message);
  } finally {
    await app.close();
  }
}

main();
MANUALCOLLECT

# === README ===
info "Generando README..."

cat > README.md << 'README'
# Servicios OCC — Vulnerability Collector

Sistema automatizado de recolección, análisis y reporte de vulnerabilidades para la Oficina de Ciberseguridad.

## Stack Tecnológico

| Componente | Tecnología |
|-----------|------------|
| Backend | NestJS + TypeScript |
| Base de datos | PostgreSQL 16 |
| ORM | Prisma |
| Cache | Redis 7 |
| PDF | Puppeteer + Handlebars |
| Contenedores | Docker Compose |
| Scheduler | @nestjs/schedule (Cron) |

## Fuentes de Datos

- **NVD (NIST)**: CVEs, CVSS scores, CPE (software afectado)
- **CISA KEV**: Vulnerabilidades con explotación activa confirmada
- **FIRST EPSS**: Probabilidad de explotación en 30 días
- **GitHub / nomi-sec**: Exploits públicos (PoC)

## Inicio Rápido

```bash
# 1. Levantar infraestructura
docker compose up -d postgres redis

# 2. Instalar dependencias
npm install

# 3. Generar cliente Prisma + migrar BD
npx prisma generate
npx prisma migrate dev --name init

# 4. Seed (usuarios y config iniciales)
npx prisma db seed

# 5. Arrancar API
npm run start:dev
```

O con Docker completo:
```bash
docker compose up -d
```

## Configuración

Copiar `.env.example` → `.env` y configurar:

- `NVD_API_KEY`: Obtener en https://nvd.nist.gov/developers/request-an-api-key
- `GITHUB_TOKEN`: Token personal de GitHub (mejora rate limit)
- `JWT_SECRET`: Cambiar obligatoriamente en producción
- `POSTGRES_PASSWORD`: Cambiar en producción

## API Endpoints

| Método | Endpoint | Descripción |
|--------|---------|-------------|
| POST | `/api/auth/login` | Login (email + password) |
| GET | `/api/auth/profile` | Perfil usuario autenticado |
| GET | `/api/vulnerabilities` | Listar vulnerabilidades (filtros: severity, exploited, hours) |
| POST | `/api/vulnerabilities/collect` | Disparo manual de recolección (admin) |
| POST | `/api/vulnerabilities/report` | Generar informe PDF |
| GET | `/api/vulnerabilities/dashboard` | Datos para dashboard |
| GET | `/api/vulnerabilities/reports` | Historial de informes |
| GET | `/api/vulnerabilities/runs` | Historial de ejecuciones del collector |
| GET | `/api/docs` | Swagger UI |

## Usuarios

En producción, no se deben usar credenciales por defecto. Provisiona usuarios mediante SSO (Azure SAML) o crea cuentas locales con MFA.

## Funcionamiento del Collector

Cada 30 minutos (configurable):

1. **NVD API** → Descarga CVEs publicados en la última hora
2. **Parse CPE** → Extrae vendor, producto, versiones afectadas
3. **CISA KEV** → Flag si la vulnerabilidad tiene explotación activa
4. **EPSS** → Probabilidad de explotación en 30 días
5. **Exploit Check** → Busca PoCs en GitHub (solo HIGH/CRITICAL)
6. **Persist** → Upsert en PostgreSQL con todos los datos enriquecidos

## Generación de Informes

```bash
# Via API
curl -X POST "http://localhost:3000/api/vulnerabilities/report?hours=24&minSeverity=HIGH" \
  -H "Authorization: Bearer <token>"

# Via CLI
npx ts-node scripts/manual-collect.ts
```

El PDF incluye:
- Portada con branding SEIDOR/OCC
- Resumen ejecutivo con métricas
- Sección de acción inmediata (CVEs con explotación activa)
- Tabla completa con CVSS, EPSS, exploit status, productos y remediación
- Clasificación CONFIDENCIAL

## Estructura del Proyecto

```
src/
├── auth/                          # Autenticación JWT
├── prisma/                        # Prisma service
├── modules/
│   ├── vulnerability-collector/
│   │   ├── collectors/            # NVD, CISA KEV, EPSS, Exploit Check
│   │   ├── report/                # Generador PDF + plantilla Handlebars
│   │   ├── vulnerability-collector.service.ts   # Orquestador + Cron
│   │   └── vulnerability-collector.controller.ts # API REST
│   └── dashboard/                 # Health check
├── app.module.ts
└── main.ts
```
README

log "README generado"

# ─── Final summary ───────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ Proyecto generado correctamente                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Directorio: ${PROJECT_ROOT}${NC}"
echo ""
echo "Para arrancar:"
echo ""
echo "  cd ${PROJECT_ROOT}"
echo ""
echo "  # Opción A: Docker completo"
echo "  docker compose up -d"
echo ""
echo "  # Opción B: Solo BD + app local"
echo "  docker compose up -d postgres redis"
echo "  npm install"
echo "  npx prisma generate"
echo "  npx prisma migrate dev --name init"
echo "  npx prisma db seed"
echo "  npm run start:dev"
echo ""
echo "  # API disponible en: http://localhost:3000"
echo "  # Swagger docs:      http://localhost:3000/api/docs"
echo ""
echo -e "${YELLOW}⚠ Configurar NVD_API_KEY en .env para mejor rate limit${NC}"
echo -e "${YELLOW}⚠ Cambiar passwords y JWT_SECRET antes de producción${NC}"
echo ""
