import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET must be configured.');

export const hashToken = (token: string) => crypto.createHash('sha256').update(token).digest('hex');
export const hashPassword = async (password: string) => bcrypt.hash(password, 12);
export const verifyPassword = async (password: string, hash: string) => bcrypt.compare(password, hash);
export const hashRecoveryCode = async (code: string) => bcrypt.hash(code, 12);
export const verifyRecoveryCode = async (code: string, hash: string) => bcrypt.compare(code, hash);

export const isStrongPassword = (password: string) =>
  password.length >= 12 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password);

export const createAccessToken = (userId: string) => jwt.sign({ sub: userId, type: 'access' }, JWT_SECRET, { expiresIn: '1h' });
export const createMfaChallenge = (userId: string) => jwt.sign({ sub: userId, type: 'mfa_challenge' }, JWT_SECRET, { expiresIn: '5m' });
export const verifyToken = (token: string) => jwt.verify(token, JWT_SECRET) as { sub: string; type: string };
