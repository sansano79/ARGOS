import * as crypto from 'crypto';

/**
 * Cifrado AES-256-GCM para secretos de integraciones guardados en BD.
 * Formato: `v1:<iv b64>:<tag b64>:<ciphertext b64>`.
 */
const PREFIX = 'v1';

export class SecretKeyMissingError extends Error {
  constructor(envName: string) {
    super(`${envName} no está configurada: no se puede cifrar ni descifrar el secreto`);
  }
}

export function resolveSecretKey(raw: string | undefined | null): Buffer | null {
  const value = String(raw || '').trim();
  if (!value) return null;
  if (/^[0-9a-f]{64}$/i.test(value)) return Buffer.from(value, 'hex');
  const b64 = Buffer.from(value, 'base64');
  if (b64.length === 32 && /^[A-Za-z0-9+/]+={0,2}$/.test(value)) return b64;
  // Frase de paso: se deriva una clave de 32 bytes.
  return crypto.scryptSync(value, 'argos-integration-secret-v1', 32);
}

export function isEncryptedSecret(value: string | null | undefined): boolean {
  return typeof value === 'string' && value.startsWith(`${PREFIX}:`) && value.split(':').length === 4;
}

export function encryptSecret(plain: string, key: Buffer): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [PREFIX, iv.toString('base64'), tag.toString('base64'), enc.toString('base64')].join(':');
}

export function decryptSecret(payload: string, key: Buffer): string {
  if (!isEncryptedSecret(payload)) throw new Error('Formato de secreto cifrado no válido');
  const [, ivB64, tagB64, encB64] = payload.split(':');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(encB64, 'base64')), decipher.final()]).toString('utf8');
}
