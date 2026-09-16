import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.MFA_ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

const { decryptMfaSecret, encryptMfaSecret, generateMfaSecret, generateTotpCode, verifyTotpCode } = await import('../security/mfa.js');

test('generates a Base32 secret and validates the current TOTP', () => {
  const secret = generateMfaSecret();
  const code = generateTotpCode(secret);
  assert.match(secret, /^[A-Z2-7]+$/);
  assert.match(code, /^\d{6}$/);
  assert.equal(verifyTotpCode(secret, code), true);
  assert.equal(verifyTotpCode(secret, '000000'), false);
});

test('accepts only the adjacent TOTP time window', () => {
  const secret = 'JBSWY3DPEHPK3PXP';
  const timestamp = 1_700_000_000_000;
  const code = generateTotpCode(secret, timestamp);
  assert.equal(verifyTotpCode(secret, code, timestamp), true);
  assert.equal(verifyTotpCode(secret, code, timestamp + 120_000), false);
});

test('encrypts and decrypts the TOTP secret', () => {
  const secret = generateMfaSecret();
  const encrypted = encryptMfaSecret(secret);
  assert.notEqual(encrypted, secret);
  assert.equal(decryptMfaSecret(encrypted), secret);
});
