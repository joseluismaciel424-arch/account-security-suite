import { Router } from 'express';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';

export const securityRouter = Router();
securityRouter.use(requireAuth);

securityRouter.get('/summary', async (req, res) => {
  try {
    const [userResult, eventsResult, sessionsResult] = await Promise.all([
      pool.query('SELECT mfa_enabled, recovery_email FROM users WHERE id=$1', [req.user!.id]),
      pool.query('SELECT id,event_type,severity,title,description,metadata,created_at,resolved FROM security_events WHERE user_id=$1 ORDER BY created_at DESC LIMIT 25', [req.user!.id]),
      pool.query('SELECT id,device_name,user_agent,ip_address,mfa_verified,last_seen_at FROM sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>NOW() ORDER BY last_seen_at DESC', [req.user!.id]),
    ]);
    const user = userResult.rows[0] ?? {}; const events = eventsResult.rows; const sessions = sessionsResult.rows;
    const unresolved = events.filter((event) => !event.resolved); const critical = unresolved.some((event) => event.severity === 'critical'); const high = unresolved.some((event) => event.severity === 'high');
    return res.json({ status: critical ? 'critical' : high || unresolved.length ? 'needs-attention' : 'secure', score: Math.max(0, 100 - unresolved.length * 12 - (user.mfa_enabled ? 0 : 16)), mfaEnabled: Boolean(user.mfa_enabled), recoveryEmailConfigured: Boolean(user.recovery_email), unresolvedEventCount: unresolved.length, activeSessionCount: sessions.length, events, sessions });
  } catch { return res.status(500).json({ message: 'Unable to load security summary.' }); }
});

securityRouter.get('/events', async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 25, 1), 100);
  const result = await pool.query('SELECT id,event_type,severity,title,description,metadata,ip_address,user_agent,created_at,resolved,resolved_at FROM security_events WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2', [req.user!.id, limit]);
  return res.json({ events: result.rows });
});

securityRouter.post('/events/:eventId/resolve', async (req, res) => {
  const result = await pool.query('UPDATE security_events SET resolved=true,resolved_at=NOW() WHERE id=$1 AND user_id=$2 RETURNING id,resolved,resolved_at', [req.params.eventId, req.user!.id]);
  if (!result.rowCount) return res.status(404).json({ message: 'Security event not found.' });
  return res.json({ event: result.rows[0] });
});
