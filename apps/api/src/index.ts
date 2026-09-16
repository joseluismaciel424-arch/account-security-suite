import express from 'express';
import { authRouter } from './routes/auth';
import { requireAuth } from './middleware/auth';
import { securityRouter } from './routes/security';

const app = express();

app.use(express.json());
app.use('/api/v1/auth', authRouter);
app.use('/api/v1/security', requireAuth, securityRouter);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', app: 'Account Security Suite' });
});

app.listen(4000, () => {
  console.log('API running on http://localhost:4000');
});
