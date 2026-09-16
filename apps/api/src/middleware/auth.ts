import type { Request, Response, NextFunction } from 'express';
import { pool } from '../db';
import { hashToken, verifyToken } from '../security/auth';

declare global { namespace Express { interface Request { user?: { id: string }; } } }

export const requireAuth = async (req: Request, res: Response, next: NextFunction) => {
  const authorization = req.headers.authorization;
  if (!authorization?.startsWith('Bearer ')) return res.status(401).json({ message: 'Authentication required.' });
  try {
    const token = authorization.slice(7).trim();
    const payload = verifyToken(token);
    if (payload.type !== 'access' || !payload.sub) return res.status(401).json({ message: 'Invalid access token.' });
    const result = await pool.query(
      `SELECT s.user_id FROM sessions s JOIN users u ON u.id=s.user_id
       WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>NOW()
       AND (u.mfa_enabled=false OR s.mfa_verified=true)`,
      [hashToken(token)],
    );
    if (!result.rowCount) return res.status(401).json({ message: 'Invalid or incomplete session.' });
    await pool.query('UPDATE sessions SET last_seen_at=NOW() WHERE token_hash=$1 AND revoked_at IS NULL', [hashToken(token)]);
    req.user = { id: String(result.rows[0].user_id) };
    return next();
  } catch { return res.status(401).json({ message: 'Invalid or expired token.' }); }
};
