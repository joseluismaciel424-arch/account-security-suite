import express from 'express';

export type AuthUser = {
  id: string;
  email: string;
  passwordHash: string;
  mfaEnabled: boolean;
  createdAt: string;
  updatedAt: string;
};

export const authRouter = express.Router();

authRouter.post('/register', (_req, res) => {
  res.status(201).json({ message: 'Registration flow ready. Connect a real database and user persistence here.' });
});

authRouter.post('/login', (_req, res) => {
  res.status(200).json({ message: 'Login flow ready. Connect a real auth service and JWT issuance here.' });
});

authRouter.post('/mfa/verify', (_req, res) => {
  res.status(200).json({ message: 'MFA flow ready. Connect a TOTP or passkey verification provider here.' });
});
