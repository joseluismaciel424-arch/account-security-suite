import { Router } from 'express';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';
import { hashRecoveryCode } from '../security/auth';
import { encryptMfaSecret, generateMfaSecret, generateRecoveryCodes, verifyTotpCode, decryptMfaSecret } from '../security/mfa';

export const mfaRouter = Router();
mfaRouter.use(requireAuth);

mfaRouter.post('/setup', async (req, res) => {
  const secret = generateMfaSecret();
  await pool.query('UPDATE users SET mfa_secret_encrypted = $1, mfa_enabled = false, updated_at = NOW() WHERE id = $2', [encryptMfaSecret(secret), req.user!.id]);
  return res.json({ secret, otpAuthUrl: `otpauth://totp/AccountSecuritySuite:${req.user!.id}?secret=${secret}&issuer=AccountSecuritySuite`, message: 'Registra el secreto en tu autenticador y confirma un código.' });
});

mfaRouter.post('/enable', async (req, res) => {
  const code = String(req.body?.code ?? '');
  const result = await pool.query('SELECT mfa_secret_encrypted FROM users WHERE id = $1', [req.user!.id]);
  if (!result.rowCount || !result.rows[0].mfa_secret_encrypted) return res.status(400).json({ message: 'MFA setup is not pending.' });
  if (!verifyTotpCode(decryptMfaSecret(result.rows[0].mfa_secret_encrypted), code)) return res.status(400).json({ message: 'Invalid MFA code.' });

  const recoveryCodes = generateRecoveryCodes();
  const hashes = await Promise.all(recoveryCodes.map(hashRecoveryCode));
  await pool.query('UPDATE users SET mfa_enabled = true, recovery_codes_hashes = $1::jsonb, mfa_failed_attempts = 0, mfa_locked_until = NULL, updated_at = NOW() WHERE id = $2', [JSON.stringify(hashes), req.user!.id]);
  return res.json({ enabled: true, recoveryCodes, message: 'MFA enabled. Store recovery codes securely; they will not be shown again.' });
});

mfaRouter.post('/disable', async (req, res) => {
  const code = String(req.body?.code ?? '');
  const result = await pool.query('SELECT mfa_secret_encrypted FROM users WHERE id = $1', [req.user!.id]);
  if (!result.rowCount || !result.rows[0].mfa_secret_encrypted) return res.status(400).json({ message: 'MFA is not configured.' });
  if (!verifyTotpCode(decryptMfaSecret(result.rows[0].mfa_secret_encrypted), code)) return res.status(400).json({ message: 'Invalid MFA code.' });
  await pool.query('UPDATE users SET mfa_enabled = false, mfa_secret_encrypted = NULL, recovery_codes_hashes = \'[]\'::jsonb, updated_at = NOW() WHERE id = $1', [req.user!.id]);
  return res.json({ disabled: true });
});
