import { Router } from 'express';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';
import { hashRecoveryCode, verifyRecoveryCode } from '../security/auth';
import { decryptMfaSecret, encryptMfaSecret, generateMfaSecret, generateRecoveryCodes, verifyTotpCode } from '../security/mfa';
import { recordSecurityEvent } from '../security/events';

export const mfaRouter = Router();
mfaRouter.use(requireAuth);

mfaRouter.post('/setup', async (req, res) => {
  try {
    const secret = generateMfaSecret();
    await pool.query('UPDATE users SET mfa_secret_encrypted=$1,mfa_enabled=false,mfa_failed_attempts=0,mfa_locked_until=NULL,updated_at=NOW() WHERE id=$2', [encryptMfaSecret(secret), req.user!.id]);
    await recordSecurityEvent({ userId: req.user!.id, type: 'mfa-setup-started', req });
    return res.json({ secret, otpAuthUrl: `otpauth://totp/AccountSecuritySuite:${req.user!.id}?secret=${secret}&issuer=AccountSecuritySuite` });
  } catch { return res.status(500).json({ message: 'Unable to initialize MFA setup.' }); }
});

mfaRouter.post('/enable', async (req, res) => {
  try {
    const result = await pool.query('SELECT mfa_secret_encrypted FROM users WHERE id=$1', [req.user!.id]);
    if (!result.rowCount || !result.rows[0].mfa_secret_encrypted) return res.status(400).json({ message: 'MFA setup is not pending.' });
    if (!verifyTotpCode(decryptMfaSecret(result.rows[0].mfa_secret_encrypted), String(req.body?.code ?? ''))) return res.status(400).json({ message: 'Invalid MFA code.' });
    const recoveryCodes = generateRecoveryCodes(); const hashes = await Promise.all(recoveryCodes.map(hashRecoveryCode));
    await pool.query('UPDATE users SET mfa_enabled=true,recovery_codes_hashes=$1::jsonb,mfa_failed_attempts=0,mfa_locked_until=NULL,updated_at=NOW() WHERE id=$2', [JSON.stringify(hashes), req.user!.id]);
    await recordSecurityEvent({ userId: req.user!.id, type: 'mfa-enabled', req });
    return res.json({ enabled: true, recoveryCodes });
  } catch { return res.status(500).json({ message: 'Unable to enable MFA.' }); }
});

mfaRouter.post('/disable', async (req, res) => {
  try {
    const result = await pool.query('SELECT mfa_secret_encrypted FROM users WHERE id=$1', [req.user!.id]);
    if (!result.rowCount || !result.rows[0].mfa_secret_encrypted || !verifyTotpCode(decryptMfaSecret(result.rows[0].mfa_secret_encrypted), String(req.body?.code ?? ''))) return res.status(400).json({ message: 'Invalid MFA code.' });
    await pool.query("UPDATE users SET mfa_enabled=false,mfa_secret_encrypted=NULL,recovery_codes_hashes='[]'::jsonb,updated_at=NOW() WHERE id=$1", [req.user!.id]);
    await recordSecurityEvent({ userId: req.user!.id, type: 'mfa-disabled', req });
    return res.json({ disabled: true });
  } catch { return res.status(500).json({ message: 'Unable to disable MFA.' }); }
});

mfaRouter.post('/recovery/verify', async (req, res) => {
  const result = await pool.query('SELECT recovery_codes_hashes FROM users WHERE id=$1', [req.user!.id]);
  const hashes = Array.isArray(result.rows[0]?.recovery_codes_hashes) ? result.rows[0].recovery_codes_hashes : [];
  for (let index = 0; index < hashes.length; index += 1) if (await verifyRecoveryCode(String(req.body?.code ?? ''), hashes[index])) {
    await pool.query('UPDATE users SET recovery_codes_hashes=$1::jsonb WHERE id=$2', [JSON.stringify(hashes.filter((_hash: string, i: number) => i !== index)), req.user!.id]);
    await recordSecurityEvent({ userId: req.user!.id, type: 'recovery-code-used', req });
    return res.json({ valid: true, remainingCodes: hashes.length - 1 });
  }
  return res.status(401).json({ valid: false, message: 'Invalid or already-used recovery code.' });
});
