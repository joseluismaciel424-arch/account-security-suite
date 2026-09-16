import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET ?? 'dev-secret-change-me';

export const isStrongPassword = (password: string) => {
  if (password.length < 12) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  if (!/[^A-Za-z0-9]/.test(password)) return false;
  return true;
};

export const hashPassword = async (password: string) =>
  bcrypt.hash(password, 12);

export const verifyPassword = async (password: string, hash: string) =>
  bcrypt.compare(password, hash);

export const createAccessToken = (userId: string) =>
  jwt.sign({ sub: userId, type: 'access' }, JWT_SECRET, { expiresIn: '1h' });

export const verifyToken = (token: string) =>
  jwt.verify(token, JWT_SECRET) as { sub: string; type: string };
