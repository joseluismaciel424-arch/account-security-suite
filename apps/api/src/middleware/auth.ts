import type { Request, Response, NextFunction } from 'express';
import { pool } from '../db';
import { hashToken, verifyToken } from '../security/auth';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
      };
    }
  }
}

export const requireAuth = async (req: Request, res: Response, next: NextFunction) => {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authentication required.' });
  }

  const token = authorization.replace('Bearer ', '').trim();

  try {
    const payload = verifyToken(token);
    const tokenHash = hashToken(token);
    const sessionResult = await pool.query(
      `SELECT user_id FROM sessions
       WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()`,
      [tokenHash],
    );

    if (!sessionResult.rowCount || sessionResult.rowCount === 0) {
      return res.status(401).json({ message: 'Invalid or expired session.' });
    }

    await pool.query(
      `UPDATE sessions SET last_seen_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL`,
      [tokenHash],
    );

    req.user = { id: String(sessionResult.rows[0].user_id) };
    return next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
};
