FROM node:20-slim

# Dependencias de Puppeteer y herramientas base
RUN apt-get update && apt-get install -y \
    chromium \
    fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-freefont-ttf \
    libxss1 \
    dumb-init \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

WORKDIR /app

COPY package*.json ./
RUN npm install --legacy-peer-deps

COPY . .

# --- CORRECCIÓN DE BINARIOS Y PERMISOS ---
# 1. Aseguramos que el script sea ejecutable
# 2. Corregimos los finales de línea (CRLF -> LF) por si estás en Windows
RUN chmod +x docker/entrypoint.sh && \
    sed -i 's/\r$//' docker/entrypoint.sh

RUN npx prisma generate
RUN npm run build

EXPOSE 3000

# Usamos dumb-init para gestionar procesos y apuntamos a la ruta correcta del script
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["docker/entrypoint.sh"]
