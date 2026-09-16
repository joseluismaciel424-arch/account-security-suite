import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import { API_HEALTH_MESSAGE, APP_NAME } from '@account-security-suite/shared';

dotenv.config();

const app = express();
const port = Number(process.env.PORT ?? 4000);

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

app.get('/health', (_req, res) => {
  res.json({
    app: APP_NAME,
    status: 'ok',
    message: API_HEALTH_MESSAGE,
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/v1/security-summary', (_req, res) => {
  res.json({
    user: 'demo-user',
    securityScore: 91,
    risks: [
      {
        id: 'risk-1',
        level: 'medium',
        title: '2-factor authentication pending on one account',
      }
    ],
    accounts: [
      {
        id: 'gmail',
        provider: 'Google',
        status: 'secure',
        lastCheckedAt: new Date().toISOString(),
      },
      {
        id: 'github',
        provider: 'GitHub',
        status: 'needs-attention',
        lastCheckedAt: new Date().toISOString(),
      }
    ]
  });
});

app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});
