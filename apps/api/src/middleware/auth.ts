import type { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../security/auth';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
      };
    }
  }
}

export const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authentication required.' });
  }

  const token = authorization.replace('Bearer ', '').trim();

  try {
    const payload = verifyToken(token);
    req.user = { id: payload.sub };
    return next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
};
