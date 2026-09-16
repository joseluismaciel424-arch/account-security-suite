import { pool } from '../db';

export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical';

export type SecurityCondition = {
  type: string;
  severity: SecuritySeverity;
  title: string;
  description: string;
  metadata?: Record<string, unknown>;
};

export const evaluateLoginConditions = ({
  userAgent,
  ipAddress,
  isNewDevice,
  mfaEnabled,
  hasRecoveryEmail,
}: {
  userAgent?: string;
  ipAddress?: string;
  isNewDevice: boolean;
  mfaEnabled: boolean;
  hasRecoveryEmail: boolean;
}): SecurityCondition[] => {
  const conditions: SecurityCondition[] = [];

  if (isNewDevice) {
    conditions.push({
      type: 'new-device-signin',
      severity: 'medium',
      title: 'New device sign-in detected',
      description: 'This sign-in came from a device or browser we have not seen before.',
      metadata: {
        userAgent: userAgent ?? 'unknown',
        ipAddress: ipAddress ?? 'unknown',
      },
    });
  }

  if (!mfaEnabled) {
    conditions.push({
      type: 'mfa-not-enabled',
      severity: 'high',
      title: 'MFA is not enabled',
      description: 'This account is still missing multi-factor authentication protection.',
    });
  }

  if (!hasRecoveryEmail) {
    conditions.push({
      type: 'recovery-email-missing',
      severity: 'medium',
      title: 'Recovery email missing',
      description: 'Add a recovery email to make account recovery safer.',
    });
  }

  return conditions;
};

export const evaluateRiskSummary = (conditions: SecurityCondition[]) => {
  const severities: SecuritySeverity[] = conditions.map((condition) => condition.severity);

  if (severities.includes('critical')) return 'critical';
  if (severities.includes('high')) return 'high';
  if (severities.includes('medium')) return 'medium';
  return 'low';
};

export const recordConditionsForUser = async ({
  userId,
  conditions,
  req,
}: {
  userId: string;
  conditions: SecurityCondition[];
  req: { ip?: string; headers: Record<string, string | string[] | undefined> };
}) => {
  for (const condition of conditions) {
    await pool.query(
      `
        INSERT INTO security_events (
          user_id,
          event_type,
          severity,
          title,
          description,
          metadata,
          ip_address,
          user_agent
        ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
      `,
      [
        userId,
        condition.type,
        condition.severity,
        condition.title,
        condition.description,
        JSON.stringify(condition.metadata ?? {}),
        req.ip ?? null,
        typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null,
      ],
    );
  }
};
