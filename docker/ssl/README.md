# TLS material

No private key or environment-specific certificate may be committed to this repository.

For local development, generate a new self-signed certificate from the repository root:

```bash
OCC_DOMAIN=occ.local ./scripts/generate-ssl.sh
```

This creates the ignored files:

```text
docker/ssl/server.crt
docker/ssl/server.key
```

For production, provision the certificate and private key through the deployment platform or a secrets manager, mount them read-only at runtime, and rotate them according to the organisation's certificate policy.

Any key previously committed to Git must be treated as compromised and must not be reused.
