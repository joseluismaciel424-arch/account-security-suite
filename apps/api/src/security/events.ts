import type { Request } from 'express';
import { pool } from '../db';

const definitions: Record<string, { severity: 'low' | 'medium' | 'high' | 'critical'; title: string; description: string }> = {
  'login-failed': { severity: 'medium', title: 'Failed sign-in attempt', description: 'Invalid credentials were submitted.' },
  'mfa-failed': { severity: 'high', title: 'Invalid MFA code', description: 'An invalid MFA code was submitted.' },
  'mfa-locked': { severity: 'critical', title: 'MFA temporarily locked', description: 'MFA was locked after repeated invalid codes.' },
  'mfa-verified': { severity: 'low', title: 'MFA verification successful', description: 'A sign-in completed with a valid MFA code.' },
  'mfa-enabled': { severity: 'low', title: 'MFA enabled', description: 'MFA was enabled for the account.' },
  'mfa-disabled': { severity: 'critical', title: 'MFA disabled', description: 'MFA was disabled for the account.' },
  'recovery-code-used': { severity: 'high', title: 'Recovery code used', description: 'A recovery code was consumed.' },
  'new-device-signin': { severity: 'medium', title: 'New device sign-in', description: 'A new device signed in to the account.' },
};

export const recordSecurityEvent = async ({ userId, type, req, metadata = {} }: { userId: string; type: string; req?: Pick<Request, 'ip' | 'headers'>; metadata?: Record<string, unknown> }) => {
  const definition = definitions[type] ?? { severity: 'medium' as const, title: 'Security event', description: 'A security-related action occurred.' };
  await pool.query(
    `INSERT INTO security_events (user_id,event_type,severity,title,description,metadata,ip_address,user_agent)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`,
    [userId, type, definition.severity, definition.title, definition.description, JSON.stringify(metadata), req?.ip ?? null, typeof req?.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null],
  );
};

export const isNewDevice = async (userId: string, req: Pick<Request, 'ip' | 'headers'>) => {
  const agent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null;
  const result = await pool.query('SELECT 1 FROM sessions WHERE user_id=$1 AND user_agent=$2 AND ip_address=$3 LIMIT 1', [userId, agent, req.ip ?? null]);
  return result.rowCount === 0;
};
