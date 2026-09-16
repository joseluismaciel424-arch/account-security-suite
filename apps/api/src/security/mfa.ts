import crypto from 'crypto';

const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const encryptionKey = () => {
  const value = process.env.MFA_ENCRYPTION_KEY;
  if (!value || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error('MFA_ENCRYPTION_KEY must be a 32-byte hexadecimal key.');
  }
  return Buffer.from(value, 'hex');
};

export const generateMfaSecret = () => {
  const bytes = crypto.randomBytes(20);
  let bits = '';
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');

  let result = '';
  for (let index = 0; index < bits.length; index += 5) {
    const value = Number.parseInt(bits.slice(index, index + 5).padEnd(5, '0'), 2);
    result += BASE32_ALPHABET[value];
  }
  return result;
};

const decodeBase32 = (value: string) => {
  const normalized = value.replace(/=+$/g, '').replace(/\s+/g, '').toUpperCase();
  let bits = '';

  for (const character of normalized) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index < 0) throw new Error('Invalid TOTP secret.');
    bits += index.toString(2).padStart(5, '0');
  }

  const bytes: number[] = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }

  return Buffer.from(bytes);
};

const codeForCounter = (secret: string, counter: number) => {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', decodeBase32(secret)).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
};

export const verifyTotpCode = (secret: string, code: string) => {
  if (!secret || !/^[0-9]{6}$/.test(code.trim())) return false;
  const counter = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
  return [-1, 0, 1].some((offset) => {
    const token = codeForCounter(secret, counter + offset);
    return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(code.trim()));
  });
};

export const encryptMfaSecret = (secret: string) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${ciphertext.toString('hex')}`;
};

export const decryptMfaSecret = (payload: string) => {
  const [ivHex, tagHex, ciphertextHex] = payload.split(':');
  if (!ivHex || !tagHex || !ciphertextHex) throw new Error('Invalid encrypted MFA secret.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertextHex, 'hex')), decipher.final()]).toString('utf8');
};

export const generateRecoveryCodes = (count = 10) =>
  Array.from({ length: count }, () => crypto.randomBytes(4).toString('hex').toUpperCase());
