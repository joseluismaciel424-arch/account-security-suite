import { Router } from 'express';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';
import { hashRecoveryCode, verifyRecoveryCode } from '../security/auth';
import { decryptMfaSecret, encryptMfaSecret, generateMfaSecret, generateRecoveryCodes, verifyTotpCode } from '../security/mfa';

export const mfaRouter = Router();
mfaRouter.use(requireAuth);

mfaRouter.post('/setup', async (req, res) => {
  try {
    const secret = generateMfaSecret();
    const result = await pool.query(
      `UPDATE users SET mfa_secret_encrypted = $1, mfa_enabled = false,
       mfa_failed_attempts = 0, mfa_locked_until = NULL, updated_at = NOW()
       WHERE id = $2 RETURNING id`,
      [encryptMfaSecret(secret), req.user!.id],
    );

    if (!result.rowCount) return res.status(404).json({ message: 'User not found.' });

    return res.json({
      secret,
      otpAuthUrl: `otpauth://totp/AccountSecuritySuite:${req.user!.id}?secret=${secret}&issuer=AccountSecuritySuite`,
      message: 'Add this account to your authenticator and confirm a six-digit code.',
    });
  } catch (error) {
    console.error('MFA setup error:', error);
    return res.status(500).json({ message: 'Unable to initialize MFA setup.' });
  }
});

mfaRouter.post('/enable', async (req, res) => {
  const code = String(req.body?.code ?? '').trim();

  try {
    const result = await pool.query('SELECT mfa_secret_encrypted FROM users WHERE id = $1', [req.user!.id]);
    if (!result.rowCount || !result.rows[0].mfa_secret_encrypted) {
      return res.status(400).json({ message: 'MFA setup is not pending.' });
    }

    if (!verifyTotpCode(decryptMfaSecret(result.rows[0].mfa_secret_encrypted), code)) {
      return res.status(400).json({ message: 'Invalid MFA code.' });
    }

    const recoveryCodes = generateRecoveryCodes();
    const hashes = await Promise.all(recoveryCodes.map(hashRecoveryCode));
    await pool.query(
      `UPDATE users SET mfa_enabled = true, recovery_codes_hashes = $1::jsonb,
       mfa_failed_attempts = 0, mfa_locked_until = NULL, updated_at = NOW()
       WHERE id = $2`,
      [JSON.stringify(hashes), req.user!.id],
    );

    return res.json({
      enabled: true,
      recoveryCodes,
      message: 'MFA enabled. Save these recovery codes; they will not be shown again.',
    });
  } catch (error) {
    console.error('MFA enable error:', error);
    return res.status(500).json({ message: 'Unable to enable MFA.' });
  }
});

mfaRouter.post('/disable', async (req, res) => {
  const code = String(req.body?.code ?? '').trim();

  try {
    const result = await pool.query('SELECT mfa_secret_encrypted FROM users WHERE id = $1', [req.user!.id]);
    if (!result.rowCount || !result.rows[0].mfa_secret_encrypted) {
      return res.status(400).json({ message: 'MFA is not configured.' });
    }

    if (!verifyTotpCode(decryptMfaSecret(result.rows[0].mfa_secret_encrypted), code)) {
      return res.status(400).json({ message: 'Invalid MFA code.' });
    }

    await pool.query(
      `UPDATE users SET mfa_enabled = false, mfa_secret_encrypted = NULL,
       recovery_codes_hashes = '[]'::jsonb, updated_at = NOW() WHERE id = $1`,
      [req.user!.id],
    );

    return res.json({ disabled: true });
  } catch (error) {
    console.error('MFA disable error:', error);
    return res.status(500).json({ message: 'Unable to disable MFA.' });
  }
});

mfaRouter.post('/recovery/verify', async (req, res) => {
  const code = String(req.body?.code ?? '').trim();
  const result = await pool.query('SELECT recovery_codes_hashes FROM users WHERE id = $1', [req.user!.id]);
  if (!result.rowCount) return res.status(404).json({ message: 'User not found.' });

  const hashes = Array.isArray(result.rows[0].recovery_codes_hashes) ? result.rows[0].recovery_codes_hashes : [];
  for (let index = 0; index < hashes.length; index += 1) {
    if (await verifyRecoveryCode(code, hashes[index])) {
      const remaining = hashes.filter((_hash: string, hashIndex: number) => hashIndex !== index);
      await pool.query('UPDATE users SET recovery_codes_hashes = $1::jsonb WHERE id = $2', [JSON.stringify(remaining), req.user!.id]);
      return res.json({ valid: true, remainingCodes: remaining.length });
    }
  }

  return res.status(401).json({ valid: false, message: 'Invalid or already-used recovery code.' });
});
