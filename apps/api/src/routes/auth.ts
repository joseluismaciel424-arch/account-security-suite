import express from 'express';
import { pool } from '../db';
import { createAccessToken, createMfaChallenge, hashPassword, hashToken, isStrongPassword, verifyPassword, verifyToken } from '../security/auth';
import { decryptMfaSecret, verifyTotpCode } from '../security/mfa';

export const authRouter = express.Router();

const createSession = async (userId: string, token: string, req: express.Request, mfaVerified: boolean) => {
  const deviceName = typeof req.headers['x-device-name'] === 'string' ? req.headers['x-device-name'] : 'Unknown device';
  const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : 'Unknown agent';
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30);

  await pool.query(
    `INSERT INTO sessions (user_id, token_hash, device_name, user_agent, ip_address, mfa_verified, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [userId, hashToken(token), deviceName, userAgent, req.ip ?? null, mfaVerified, expiresAt],
  );
};

authRouter.post('/register', async (req, res) => {
  const email = String(req.body?.email ?? '').trim().toLowerCase();
  const password = String(req.body?.password ?? '');

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !isStrongPassword(password)) {
    return res.status(400).json({ message: 'Valid email and strong password are required.' });
  }

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rowCount && existing.rowCount > 0) {
      return res.status(409).json({ message: 'A user with this email already exists.' });
    }

    const hash = await hashPassword(password);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, mfa_enabled',
      [email, hash],
    );

    const user = result.rows[0];
    const token = createAccessToken(user.id);
    await createSession(user.id, token, req, false);

    return res.status(201).json({ token, user: { id: user.id, email: user.email, mfaEnabled: user.mfa_enabled } });
  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ message: 'Unable to create account.' });
  }
});

authRouter.post('/login', async (req, res) => {
  const email = String(req.body?.email ?? '').trim().toLowerCase();
  const password = String(req.body?.password ?? '');

  const result = await pool.query(
    'SELECT id, email, password_hash, mfa_enabled, mfa_secret_encrypted, mfa_locked_until, mfa_failed_attempts FROM users WHERE email = $1',
    [email],
  );

  if (!result.rowCount) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }

  const user = result.rows[0];
  if (user.mfa_locked_until && new Date(user.mfa_locked_until) > new Date()) {
    return res.status(429).json({ message: 'MFA temporarily locked. Try again later.' });
  }

  const validPassword = await verifyPassword(password, user.password_hash);
  if (!validPassword) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }

  if (user.mfa_enabled) {
    const challengeToken = createMfaChallenge(user.id);
    return res.status(202).json({ requiresMfa: true, challengeToken, message: 'MFA verification required.' });
  }

  const token = createAccessToken(user.id);
  await createSession(user.id, token, req, false);
  return res.json({ token, user: { id: user.id, email: user.email, mfaEnabled: false } });
});

authRouter.post('/mfa/verify', async (req, res) => {
  const challengeToken = String(req.body?.challengeToken ?? '');
  const code = String(req.body?.code ?? '');

  try {
    const challenge = verifyToken(challengeToken);
    if (challenge.type !== 'mfa_challenge') {
      return res.status(401).json({ message: 'Invalid MFA challenge.' });
    }

    const userResult = await pool.query(
      'SELECT id, email, mfa_secret_encrypted, mfa_enabled, mfa_failed_attempts, mfa_locked_until FROM users WHERE id = $1',
      [challenge.sub],
    );

    if (!userResult.rowCount) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = userResult.rows[0];
    if (user.mfa_locked_until && new Date(user.mfa_locked_until) > new Date()) {
      return res.status(429).json({ message: 'MFA temporarily locked.' });
    }

    const secret = decryptMfaSecret(user.mfa_secret_encrypted);
    const valid = verifyTotpCode(secret, code);

    if (!valid) {
      const attempts = Number(user.mfa_failed_attempts ?? 0) + 1;
      const lockedUntil = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null;
      await pool.query(
        'UPDATE users SET mfa_failed_attempts = $1, mfa_locked_until = $2 WHERE id = $3',
        [attempts, lockedUntil, user.id],
      );
      return res.status(401).json({ message: 'Invalid MFA code.' });
    }

    const token = createAccessToken(user.id);
    await createSession(user.id, token, req, true);
    await pool.query('UPDATE users SET mfa_failed_attempts = 0, mfa_locked_until = NULL WHERE id = $1', [user.id]);

    return res.json({ token, user: { id: user.id, email: user.email, mfaEnabled: true } });
  } catch {
    return res.status(401).json({ message: 'Invalid or expired MFA challenge.' });
  }
});

authRouter.post('/logout', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ message: 'Authentication required.' });

  try {
    const payload = verifyToken(token);
    await pool.query('UPDATE sessions SET revoked_at = NOW() WHERE token_hash = $1 AND user_id = $2', [hashToken(token), payload.sub]);
    return res.json({ message: 'Session revoked successfully.' });
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
});
