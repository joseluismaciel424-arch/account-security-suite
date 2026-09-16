import crypto from 'crypto';

export const generateMfaSecret = () => crypto.randomBytes(20).toString('hex');

export const verifyTotpCode = (secret: string, code: string) => {
  const normalized = secret.trim();
  if (!normalized || !/^[0-9]{6}$/.test(code.trim())) {
    return false;
  }

  const windowSize = 2;
  const currentTime = Math.floor(Date.now() / 30000);
  const enteredCode = code.trim();

  for (let offset = -windowSize; offset <= windowSize; offset += 1) {
    const counter = currentTime + offset;
    const hash = crypto
      .createHmac('sha1', normalized)
      .update(Buffer.from(String(counter), 'utf8'))
      .digest();

    const offsetValue = hash[hash.length - 1] & 0x0f;
    const binary = ((hash[offsetValue] & 0x7f) << 24) |
      ((hash[offsetValue + 1] & 0xff) << 16) |
      ((hash[offsetValue + 2] & 0xff) << 8) |
      (hash[offsetValue + 3] & 0xff);

    const otp = binary % 1000000;
    if (otp.toString().padStart(6, '0') === enteredCode) {
      return true;
    }
  }

  return false;
};
