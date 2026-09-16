import { pool } from '../db';

export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical';

export type CreateSecurityEventInput = {
  userId: string;
  eventType: string;
  severity: SecuritySeverity;
  title: string;
  description: string;
  metadata?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
};

export const recordSecurityEvent = async (event: CreateSecurityEventInput) => {
  const result = await pool.query(
    `
      INSERT INTO security_events
        (user_id, event_type, severity, title, description, metadata, ip_address, user_agent)
      VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
      RETURNING id, user_id, event_type, severity, title, description, metadata,
                ip_address, user_agent, created_at, resolved, resolved_at
    `,
    [
      event.userId,
      event.eventType,
      event.severity,
      event.title,
      event.description,
      JSON.stringify(event.metadata ?? {}),
      event.ipAddress ?? null,
      event.userAgent ?? null,
    ],
  );

  return result.rows[0];
};
