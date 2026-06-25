##############################################
# STAGE 1 — Build
##############################################
FROM node:20-slim AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install --legacy-peer-deps

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

COPY prisma ./prisma
RUN npx prisma generate

COPY . .
RUN npm run build
RUN npx tsc scripts/seed-test-data.ts scripts/cleanup-test-data.ts --target ES2020 --module commonjs --lib es2020 --skipLibCheck --esModuleInterop --resolveJsonModule --outDir dist --rootDir . --declaration false

# Compile seed.ts to seed.js for database seeding
RUN npx tsc prisma/seed.ts --target ES2020 --module commonjs --lib es2020 --skipLibCheck --esModuleInterop --resolveJsonModule --outDir prisma --declaration false

# NestJS with rootDir includes compiles to dist/src/
# Verify it exists
RUN ls dist/src/main.js
RUN ls dist/scripts/seed-test-data.js dist/scripts/cleanup-test-data.js

##############################################
# STAGE 2 — Production runtime
##############################################
FROM node:20-slim

RUN apt-get update && apt-get install -y \
  chromium \
  fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-freefont-ttf \
  libxss1 \
  openssl \
  dumb-init \
  --no-install-recommends \
  && rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
ENV NODE_ENV=production

RUN groupadd -r occ && useradd -r -g occ -m occ

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/package.json ./

# Copy HBS templates for PDF reports (runtime reference uses __dirname)
COPY --from=builder /app/src/modules/vulnerability-collector/report/templates ./dist/src/modules/vulnerability-collector/report/templates

# Copy email notification templates
COPY --from=builder /app/src/templates ./dist/src/templates

COPY docker/entrypoint.sh ./entrypoint.sh

RUN sed -i 's/\r$//' entrypoint.sh \
  && mkdir -p storage/reports storage/logs storage/cache data \
  && chown -R occ:occ /app \
  && chmod +x entrypoint.sh

USER occ

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=40s \
  CMD node -e "require('http').get('http://localhost:3000/api', (r) => { process.exit(r.statusCode < 500 ? 0 : 1) }).on('error', () => process.exit(1))"

ENTRYPOINT ["dumb-init", "--"]
CMD ["./entrypoint.sh"]
