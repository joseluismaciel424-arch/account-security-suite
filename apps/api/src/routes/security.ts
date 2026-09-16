import { Router } from 'express';

export const securityRouter = Router();

securityRouter.get('/summary', (_req, res) => {
  res.status(200).json({
    level: 'high',
    status: 'secure',
    score: 91,
    factors: [
      'MFA enabled',
      'Session monitoring active',
      'Recovery email checks active',
      'Breach monitoring enabled'
    ]
  });
});
