import crypto from 'crypto';
import env from 'dotenv';
env.config();

const secretKey = process.env.ENCRYPTION_SECRET;

if (!secretKey || secretKey.length !== 32) {
  throw new Error('❌ ENCRYPTION_SECRET must be exactly 32 characters long.');
}

const algorithm = 'aes-256-cbc';

export function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(secretKey), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

export function decrypt(text) {
  const [ivHex, encrypted] = text.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(secretKey), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
