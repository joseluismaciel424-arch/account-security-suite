import express from 'express';
import { authRouter } from './routes/auth';
import { mfaRouter } from './routes/mfa';
import { securityRouter } from './routes/security';
import { requireAuth } from './middleware/auth';
import { initDatabase } from './db';

const app = express();

app.use(express.json());
app.use('/api/v1/auth', authRouter);
app.use('/api/v1/mfa', requireAuth, mfaRouter);
app.use('/api/v1/security', requireAuth, securityRouter);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

initDatabase().then(() => {
  app.listen(4000, () => console.log('API running on http://localhost:4000'));
});
