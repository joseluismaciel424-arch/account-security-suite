import type { Request } from 'express';
import { pool } from '../db';

export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical';

const EVENT_DEFINITIONS: Record<string, { severity: SecuritySeverity; title: string; description: string }> = {
  'login-failed': { severity: 'medium', title: 'Failed sign-in attempt', description: 'A sign-in attempt used invalid credentials.' },
  'mfa-failed': { severity: 'high', title: 'Invalid MFA code', description: 'An invalid MFA code was submitted during sign-in.' },
  'mfa-locked': { severity: 'critical', title: 'MFA temporarily locked', description: 'MFA verification was locked after repeated failed attempts.' },
  'mfa-verified': { severity: 'low', title: 'MFA verification successful', description: 'A sign-in was completed with a valid MFA code.' },
  'mfa-enabled': { severity: 'low', title: 'MFA enabled', description: 'Multi-factor authentication was enabled for the account.' },
  'mfa-disabled': { severity: 'critical', title: 'MFA disabled', description: 'Multi-factor authentication was disabled for the account.' },
  'recovery-code-used': { severity: 'high', title: 'Recovery code used', description: 'A recovery code was used to access the account.' },
  'new-device-signin': { severity: 'medium', title: 'New device sign-in detected', description: 'A new device or browser signed in to the account.' },
};

export const recordSecurityEvent = async ({
  userId,
  type,
  req,
  metadata = {},
  severity,
  title,
  description,
}: {
  userId: string;
  type: string;
  req?: Pick<Request, 'ip' | 'headers'>;
  metadata?: Record<string, unknown>;
  severity?: SecuritySeverity;
  title?: string;
  description?: string;
}) => {
  const definition = EVENT_DEFINITIONS[type];
  await pool.query(
    `INSERT INTO security_events
      (user_id, event_type, severity, title, description, metadata, ip_address, user_agent)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
    [
      userId,
      type,
      severity ?? definition?.severity ?? 'medium',
      title ?? definition?.title ?? 'Security event',
      description ?? definition?.description ?? 'A security-related action occurred.',
      JSON.stringify(metadata),
      req?.ip ?? null,
      typeof req?.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null,
    ],
  );
};

export const isNewDevice = async (userId: string, req: Pick<Request, 'ip' | 'headers'>) => {
  const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null;
  const result = await pool.query(
    `SELECT 1 FROM sessions WHERE user_id = $1 AND user_agent = $2 AND ip_address = $3 LIMIT 1`,
    [userId, userAgent, req.ip ?? null],
  );
  return result.rowCount === 0;
};
