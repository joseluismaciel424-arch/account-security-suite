import { Router } from 'express';
import { pool } from '../db';
import { generateMfaSecret, verifyTotpCode } from '../security/mfa';

export const mfaRouter = Router();

mfaRouter.post('/setup', async (req, res) => {
  const userId = req.body?.userId;

  if (!userId) {
    return res.status(400).json({ message: 'User ID is required.' });
  }

  const user = await pool.query('SELECT id FROM users WHERE id = $1', [userId]);
  if (!user.rowCount || user.rowCount === 0) {
    return res.status(404).json({ message: 'User not found.' });
  }

  const secret = generateMfaSecret();

  await pool.query(
    `UPDATE users SET mfa_secret = $1, mfa_enabled = true, updated_at = NOW() WHERE id = $2`,
    [secret, userId],
  );

  return res.status(200).json({
    secret,
    otpAuthUrl: `otpauth://totp/AccountSecuritySuite:${userId}?secret=${secret}&issuer=AccountSecuritySuite`,
    message: 'MFA setup initialized. Store this secret securely and validate the TOTP code.',
  });
});

mfaRouter.post('/verify', async (req, res) => {
  const { userId, code } = req.body ?? {};

  if (!userId || !code) {
    return res.status(400).json({ message: 'User ID and code are required.' });
  }

  const userResult = await pool.query(
    'SELECT id, mfa_secret, mfa_enabled FROM users WHERE id = $1',
    [userId],
  );

  if (!userResult.rowCount || userResult.rowCount === 0) {
    return res.status(404).json({ message: 'User not found.' });
  }

  const user = userResult.rows[0];

  if (!user.mfa_enabled || !user.mfa_secret) {
    return res.status(400).json({ message: 'MFA is not configured for this user.' });
  }

  const valid = verifyTotpCode(user.mfa_secret, String(code));

  if (!valid) {
    return res.status(400).json({ valid: false, message: 'Invalid MFA code.' });
  }

  return res.status(200).json({
    valid: true,
    message: 'MFA verification successful.',
  });
});
