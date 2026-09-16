import express from 'express';
import { pool } from '../db';
import { createAccessToken, hashPassword, isStrongPassword, verifyPassword } from '../security/auth';

export type AuthUser = {
  id: string;
  email: string;
  password_hash: string;
  mfa_enabled: boolean;
  created_at: string;
  updated_at: string;
};

export const authRouter = express.Router();

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
      `
        INSERT INTO users (email, password_hash, mfa_enabled, created_at, updated_at)
        VALUES ($1, $2, false, NOW(), NOW())
        RETURNING id, email, mfa_enabled, created_at, updated_at
      `,
      [email, passwordHash],
    );

    const user = result.rows[0] as AuthUser;
    const token = createAccessToken(user.id);

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
      'SELECT id, email, password_hash, mfa_enabled FROM users WHERE email = $1',
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

    const token = createAccessToken(user.id);

    return res.status(200).json({
      token,
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

authRouter.post('/mfa/verify', (_req, res) => {
  res.status(200).json({
    message: 'MFA verification flow is available. Connect TOTP or passkey verification for production use.',
  });
});
