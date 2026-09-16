import express from 'express';
import { pool } from '../db';
import { createAccessToken, hashPassword, hashToken, isStrongPassword, verifyPassword } from '../security/auth';

export type AuthUser = {
  id: string;
  email: string;
  password_hash: string;
  mfa_enabled: boolean;
  mfa_secret: string | null;
  recovery_email: string | null;
  created_at: string;
  updated_at: string;
};

export const authRouter = express.Router();

const createSession = async ({
  userId,
  token,
  req,
}: {
  userId: string;
  token: string;
  req: { ip?: string; headers: Record<string, string | string[] | undefined> };
}) => {
  const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : 'Unknown device';
  const deviceName = typeof req.headers['x-device-name'] === 'string' ? req.headers['x-device-name'] : 'Unknown device';
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30);

  await pool.query(
    `INSERT INTO sessions (user_id, token_hash, device_name, user_agent, ip_address, mfa_verified, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [userId, hashToken(token), deviceName, userAgent, req.ip ?? null, false, expiresAt],
  );
};

authRouter.post('/register', async (req, res) => {
  const email = String(req.body?.email ?? '').trim().toLowerCase();
  const password = String(req.body?.password ?? '');

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ message: 'Invalid email format.' });
  }

  if (!isStrongPassword(password)) {
    return res.status(400).json({
      message: 'Password must be at least 12 characters, include uppercase, lowercase, a number, and a symbol.',
    });
  }

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rowCount && existing.rowCount > 0) {
      return res.status(409).json({ message: 'A user with this email already exists.' });
    }

    const passwordHash = await hashPassword(password);
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, mfa_enabled, mfa_secret, recovery_email, created_at, updated_at)
       VALUES ($1, $2, false, NULL, NULL, NOW(), NOW())
       RETURNING id, email, mfa_enabled, mfa_secret, recovery_email, created_at, updated_at`,
      [email, passwordHash],
    );

    const user = result.rows[0] as AuthUser;
    const token = createAccessToken(user.id);
    await createSession({ userId: user.id, token, req });

    return res.status(201).json({
      token,
      user: {
        id: user.id,
        email: user.email,
        mfaEnabled: user.mfa_enabled,
        createdAt: user.created_at,
      },
    });
  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ message: 'Unable to create the user account.' });
  }
});

authRouter.post('/login', async (req, res) => {
  const email = String(req.body?.email ?? '').trim().toLowerCase();
  const password = String(req.body?.password ?? '');

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const result = await pool.query(
      'SELECT id, email, password_hash, mfa_enabled, mfa_secret, recovery_email FROM users WHERE email = $1',
      [email],
    );

    if (!result.rowCount || result.rowCount === 0) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const user = result.rows[0] as AuthUser;
    const valid = await verifyPassword(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    if (user.mfa_enabled) {
      return res.status(202).json({
        requiresMfa: true,
        message: 'MFA verification required for this account.',
        userId: user.id,
      });
    }

    const token = createAccessToken(user.id);
    await createSession({ userId: user.id, token, req });

    return res.status(200).json({
      token,
      requiresMfa: false,
      user: {
        id: user.id,
        email: user.email,
        mfaEnabled: user.mfa_enabled,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ message: 'Unable to sign in.' });
  }
});

authRouter.post('/mfa/verify', async (req, res) => {
  const { userId, code } = req.body ?? {};

  if (!userId || !code) {
    return res.status(400).json({ message: 'User ID and MFA code are required.' });
  }

  try {
    const result = await pool.query(
      'SELECT id, email, mfa_enabled, mfa_secret FROM users WHERE id = $1',
      [userId],
    );

    if (!result.rowCount || result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = result.rows[0] as AuthUser;
    if (!user.mfa_enabled || !user.mfa_secret) {
      return res.status(400).json({ message: 'MFA is not configured for this user.' });
    }

    if (String(code).trim().length !== 6) {
      return res.status(400).json({ message: 'MFA code must be six digits.' });
    }

    const token = createAccessToken(user.id);
    await createSession({ userId: user.id, token, req });

    return res.status(200).json({
      token,
      requiresMfa: false,
      user: { id: user.id, email: user.email, mfaEnabled: true },
    });
  } catch (error) {
    console.error('MFA verification error:', error);
    return res.status(500).json({ message: 'Unable to verify MFA code.' });
  }
});
