import express from 'express';
import { pool } from '../db';
import { createAccessToken, createMfaChallenge, hashPassword, hashToken, isStrongPassword, verifyPassword, verifyToken } from '../security/auth';
import { decryptMfaSecret, verifyTotpCode } from '../security/mfa';
import { isNewDevice, recordSecurityEvent } from '../security/events';

export const authRouter = express.Router();
const createSession = async (userId: string, token: string, req: express.Request, mfaVerified: boolean) => {
  await pool.query('INSERT INTO sessions (user_id,token_hash,device_name,user_agent,ip_address,mfa_verified,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)', [userId, hashToken(token), typeof req.headers['x-device-name'] === 'string' ? req.headers['x-device-name'] : 'Unknown device', typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : 'Unknown agent', req.ip ?? null, mfaVerified, new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)]);
};

authRouter.post('/register', async (req, res) => {
  const email = String(req.body?.email ?? '').trim().toLowerCase(); const password = String(req.body?.password ?? '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !isStrongPassword(password)) return res.status(400).json({ message: 'Valid email and strong password are required.' });
  try { const result = await pool.query('INSERT INTO users (email,password_hash) VALUES ($1,$2) RETURNING id,email,mfa_enabled', [email, await hashPassword(password)]); const user = result.rows[0]; const token = createAccessToken(user.id); await createSession(user.id, token, req, false); return res.status(201).json({ token, user: { id: user.id, email: user.email, mfaEnabled: user.mfa_enabled } }); } catch { return res.status(409).json({ message: 'Unable to create account.' }); }
});

authRouter.post('/login', async (req, res) => {
  const email = String(req.body?.email ?? '').trim().toLowerCase(); const password = String(req.body?.password ?? '');
  const result = await pool.query('SELECT id,email,password_hash,mfa_enabled,mfa_locked_until FROM users WHERE email=$1', [email]);
  if (!result.rowCount) return res.status(401).json({ message: 'Invalid email or password.' });
  const user = result.rows[0];
  if (!(await verifyPassword(password, user.password_hash))) { await recordSecurityEvent({ userId: user.id, type: 'login-failed', req }); return res.status(401).json({ message: 'Invalid email or password.' }); }
  if (user.mfa_enabled) return res.status(202).json({ requiresMfa: true, challengeToken: createMfaChallenge(user.id) });
  const token = createAccessToken(user.id); await createSession(user.id, token, req, false);
  if (await isNewDevice(user.id, req)) await recordSecurityEvent({ userId: user.id, type: 'new-device-signin', req });
  return res.json({ token, user: { id: user.id, email: user.email, mfaEnabled: false } });
});

authRouter.post('/mfa/verify', async (req, res) => {
  try {
    const challenge = verifyToken(String(req.body?.challengeToken ?? ''));
    if (challenge.type !== 'mfa_challenge') return res.status(401).json({ message: 'Invalid MFA challenge.' });
    const result = await pool.query('SELECT id,email,mfa_secret_encrypted,mfa_enabled,mfa_failed_attempts,mfa_locked_until FROM users WHERE id=$1', [challenge.sub]);
    if (!result.rowCount || !result.rows[0].mfa_enabled || !result.rows[0].mfa_secret_encrypted) return res.status(401).json({ message: 'Invalid MFA challenge.' });
    const user = result.rows[0];
    if (user.mfa_locked_until && new Date(user.mfa_locked_until) > new Date()) return res.status(429).json({ message: 'MFA temporarily locked.' });
    const valid = verifyTotpCode(decryptMfaSecret(user.mfa_secret_encrypted), String(req.body?.code ?? ''));
    if (!valid) { const attempts = Number(user.mfa_failed_attempts ?? 0) + 1; const lockUntil = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null; await pool.query('UPDATE users SET mfa_failed_attempts=$1,mfa_locked_until=$2 WHERE id=$3', [attempts, lockUntil, user.id]); await recordSecurityEvent({ userId: user.id, type: attempts >= 5 ? 'mfa-locked' : 'mfa-failed', req, metadata: { attempts } }); return res.status(attempts >= 5 ? 429 : 401).json({ message: attempts >= 5 ? 'MFA temporarily locked.' : 'Invalid MFA code.' }); }
    await pool.query('UPDATE users SET mfa_failed_attempts=0,mfa_locked_until=NULL WHERE id=$1', [user.id]); const token = createAccessToken(user.id); await createSession(user.id, token, req, true); await recordSecurityEvent({ userId: user.id, type: 'mfa-verified', req });
    return res.json({ token, user: { id: user.id, email: user.email, mfaEnabled: true } });
  } catch { return res.status(401).json({ message: 'Invalid or expired MFA challenge.' }); }
});

authRouter.post('/logout', async (req, res) => { const token = req.headers.authorization?.replace('Bearer ', '').trim(); if (!token) return res.status(401).json({ message: 'Authentication required.' }); try { const payload = verifyToken(token); await pool.query('UPDATE sessions SET revoked_at=NOW() WHERE token_hash=$1 AND user_id=$2', [hashToken(token), payload.sub]); return res.json({ message: 'Logged out successfully.' }); } catch { return res.status(401).json({ message: 'Invalid token.' }); } });
