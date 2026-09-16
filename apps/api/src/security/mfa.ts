import crypto from 'crypto';

export const generateMfaSecret = () => crypto.randomBytes(20).toString('hex');

export const verifyTotpCode = (secret: string, code: string) => {
  const normalized = secret.trim();
  const digits = Array.from({ length: 6 }, (_, index) => {
    const timeWindow = Math.floor(Date.now() / 30000);
    const value = BigInt(`0x${crypto
      .createHmac('sha1', normalized)
      .update(Buffer.from(String(timeWindow + index - 1), 'utf8'))
      .digest('hex')}`);
    return Number(value & BigInt(0x7fffffff)) % 1000000;
  });

  return digits.some((value) => value.toString().padStart(6, '0') === code.trim());
};
