import { Router } from 'express';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';
import { hashRecoveryCode, verifyRecoveryCode } from '../security/auth';
import { decryptMfaSecret, encryptMfaSecret, generateMfaSecret, generateRecoveryCodes, verifyTotpCode } from '../security/mfa';

export const mfaRouter = Router();
mfaRouter.use(requireAuth);

mfaRouter.post('/setup', async (req, res) => {
  const secret = generateMfaSecret();
  await pool.query(
    'UPDATE users SET mfa_secret_encrypted = $1, mfa_enabled = false, mfa_failed_attempts = 0, mfa_locked_until = NULL, updated_at = NOW() WHERE id = $2',
    [encryptMfaSecret(secret), req.user!.id],
  );

  return res.json({
    secret,
    otpAuthUrl: `otpauth://totp/AccountSecuritySuite:${req.user!.id}?secret=${secret}&issuer=AccountSecuritySuite`,
    message: 'Store the secret securely and confirm a valid TOTP code.',
  });
});

mfaRouter.post('/enable', async (req, res) => {
  const code = String(req.body?.code ?? '');
  const userResult = await pool.query('SELECT mfa_secret_encrypted FROM users WHERE id = $1', [req.user!.id]);
  if (!userResult.rowCount || !userResult.rows[0].mfa_secret_encrypted) {
    return res.status(400).json({ message: 'MFA setup is not pending.' });
  }

  const secret = decryptMfaSecret(userResult.rows[0].mfa_secret_encrypted);
  if (!verifyTotpCode(secret, code)) {
    return res.status(400).json({ message: 'Invalid MFA code.' });
  }

  const recoveryCodes = generateRecoveryCodes();
  const hashes = await Promise.all(recoveryCodes.map((item) => hashRecoveryCode(item)));
  await pool.query(
    'UPDATE users SET mfa_enabled = true, recovery_codes_hashes = $1::jsonb, mfa_failed_attempts = 0, mfa_locked_until = NULL, updated_at = NOW() WHERE id = $2',
    [JSON.stringify(hashes), req.user!.id],
  );

  return res.json({ enabled: true, recoveryCodes, message: 'MFA is active. Save the recovery codes securely.' });
});

mfaRouter.post('/disable', async (req, res) => {
  const code = String(req.body?.code ?? '');
  const userResult = await pool.query('SELECT mfa_secret_encrypted FROM users WHERE id = $1', [req.user!.id]);
  if (!userResult.rowCount || !userResult.rows[0].mfa_secret_encrypted) {
    return res.status(400).json({ message: 'MFA is not configured.' });
  }

  const secret = decryptMfaSecret(userResult.rows[0].mfa_secret_encrypted);
  if (!verifyTotpCode(secret, code)) {
    return res.status(400).json({ message: 'Invalid MFA code.' });
  }

  await pool.query(
    'UPDATE users SET mfa_enabled = false, mfa_secret_encrypted = NULL, recovery_codes_hashes = \'[]\'::jsonb, updated_at = NOW() WHERE id = $1',
    [req.user!.id],
  );

  return res.json({ disabled: true });
});

mfaRouter.post('/recovery/verify', async (req, res) => {
  const code = String(req.body?.code ?? '');
  const result = await pool.query('SELECT recovery_codes_hashes FROM users WHERE id = $1', [req.user!.id]);
  if (!result.rowCount) return res.status(404).json({ message: 'User not found.' });

  const hashes = Array.isArray(result.rows[0].recovery_codes_hashes) ? result.rows[0].recovery_codes_hashes : [];
  for (const hash of hashes) {
    if (await verifyRecoveryCode(code, hash)) {
      return res.json({ valid: true, message: 'Recovery code accepted.' });
    }
  }

  return res.status(401).json({ valid: false, message: 'Invalid recovery code.' });
});
