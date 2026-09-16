import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import helmet from 'helmet';
import { initDatabase } from './db';
import { requireAuth } from './middleware/auth';
import { authRouter } from './routes/auth';
import { mfaRouter } from './routes/mfa';
import { securityRouter } from './routes/security';

dotenv.config();

const app = express();
const port = Number(process.env.PORT ?? 4000);

app.use(helmet());
app.use(cors({ origin: process.env.WEB_ORIGIN ?? 'http://localhost:3000' }));
app.use(express.json());
app.use('/api/v1/auth', authRouter);
app.use('/api/v1/mfa', requireAuth, mfaRouter);
app.use('/api/v1/security', requireAuth, securityRouter);

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

initDatabase()
  .then(() => app.listen(port, () => console.log(`API running on http://localhost:${port}`)))
  .catch((error) => {
    console.error('Database initialization failed:', error);
    process.exit(1);
  });
