#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Genera certificado SSL autofirmado para Servicios OCC
# ═══════════════════════════════════════════════════════════

CERT_DIR="./docker/ssl"
DAYS=365
DOMAIN="${OCC_DOMAIN:-occ.local}"

mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
    echo "✅ Certificados SSL ya existen en $CERT_DIR"
    echo "   Para regenerar, elimina $CERT_DIR/server.* y ejecuta de nuevo"
    exit 0
fi

echo "🔐 Generando certificado SSL autofirmado para: $DOMAIN"
echo "   Validez: $DAYS días"

openssl req -x509 -nodes -days $DAYS \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -subj "/C=ES/ST=Madrid/L=Madrid/O=SEIDOR/OU=OCC/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:$DOMAIN,DNS:*.${DOMAIN},DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

if [ $? -eq 0 ]; then
    chmod 644 "$CERT_DIR/server.crt"
    chmod 600 "$CERT_DIR/server.key"
    echo "✅ Certificado generado:"
    echo "   📄 Cert: $CERT_DIR/server.crt"
    echo "   🔑 Key:  $CERT_DIR/server.key"
    echo ""
    echo "⚠️  NOTA: Es un certificado autofirmado."
    echo "   Los navegadores mostrarán advertencia de seguridad."
    echo "   Para producción con dominio público, usar Let's Encrypt."
else
    echo "❌ Error generando certificado"
    exit 1
fi
