import type { Request, Response, NextFunction } from 'express';

export const requireAuth = (_req: Request, _res: Response, next: NextFunction) => {
  next();
};
