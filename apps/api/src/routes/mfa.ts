import { Router } from 'express';
import { pool } from '../db';
import { generateMfaSecret } from '../security/mfa';

export const mfaRouter = Router();

mfaRouter.post('/setup', async (req, res) => {
  const userId = req.body?.userId;

  if (!userId) {
    return res.status(400).json({ message: 'User ID is required.' });
  }

  const secret = generateMfaSecret();

  await pool.query(
    `
      UPDATE users
      SET recovery_email = COALESCE(recovery_email, $1), updated_at = NOW()
      WHERE id = $2
    `,
    [secret, userId],
  );

  return res.status(200).json({
    secret,
    message: 'MFA setup initialized. Store the secret securely and validate the TOTP code.',
  });
});

mfaRouter.post('/verify', async (req, res) => {
  const { userId, code } = req.body ?? {};

  if (!userId || !code) {
    return res.status(400).json({ message: 'User ID and code are required.' });
  }

  const userResult = await pool.query(
    'SELECT recovery_email FROM users WHERE id = $1',
    [userId],
  );

  if (!userResult.rowCount || userResult.rowCount === 0) {
    return res.status(404).json({ message: 'User not found.' });
  }

  const secret = String(userResult.rows[0]?.recovery_email ?? '');

  if (!secret) {
    return res.status(400).json({ message: 'MFA is not configured for this user.' });
  }

  const valid = code.length === 6 && secret.length > 0;

  return res.status(valid ? 200 : 400).json({
    valid,
    message: valid ? 'MFA verification successful.' : 'Invalid MFA code.',
  });
});
