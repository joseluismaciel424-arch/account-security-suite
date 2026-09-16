import { Router } from 'express';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';

export const securityRouter = Router();
securityRouter.use(requireAuth);

securityRouter.get('/summary', async (req, res) => {
  try {
    const userId = req.user!.id;

    const [userResult, eventsResult, sessionsResult] = await Promise.all([
      pool.query(
        'SELECT mfa_enabled, recovery_email FROM users WHERE id = $1',
        [userId],
      ),
      pool.query(
        `SELECT id, event_type, severity, title, description, metadata, created_at, resolved
         FROM security_events WHERE user_id = $1 ORDER BY created_at DESC LIMIT 25`,
        [userId],
      ),
      pool.query(
        `SELECT id, device_name, user_agent, ip_address, mfa_verified, last_seen_at
         FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
         ORDER BY last_seen_at DESC`,
        [userId],
      ),
    ]);

    const user = userResult.rows[0] ?? { mfa_enabled: false, recovery_email: null };
    const events = eventsResult.rows;
    const sessions = sessionsResult.rows;
    const unresolvedCount = events.filter((event) => !event.resolved).length;
    const criticalCount = events.filter((event) => event.severity === 'critical').length;
    const highCount = events.filter((event) => event.severity === 'high').length;

    const score = Math.max(0, 100 - unresolvedCount * 12 - (user.mfa_enabled ? 0 : 16) - (user.recovery_email ? 0 : 8));
    const status = criticalCount > 0 ? 'critical' : highCount > 0 ? 'needs-attention' : unresolvedCount > 0 ? 'needs-attention' : 'secure';

    return res.json({
      status,
      score,
      mfaEnabled: Boolean(user.mfa_enabled),
      recoveryEmailConfigured: Boolean(user.recovery_email),
      unresolvedEventCount: unresolvedCount,
      activeSessionCount: sessions.length,
      events,
      sessions,
    });
  } catch (error) {
    console.error('Security summary error:', error);
    return res.status(500).json({ message: 'Unable to load security summary.' });
  }
});

securityRouter.get('/events', async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 25, 1), 100);
    const result = await pool.query(
      `SELECT id, event_type, severity, title, description, metadata, created_at, resolved
       FROM security_events WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [req.user!.id, limit],
    );
    return res.json({ events: result.rows });
  } catch (error) {
    console.error('Security events error:', error);
    return res.status(500).json({ message: 'Unable to load security events.' });
  }
});

securityRouter.post('/events/:eventId/resolve', async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE security_events SET resolved = true, resolved_at = NOW()
       WHERE id = $1 AND user_id = $2 RETURNING id, resolved, resolved_at`,
      [req.params.eventId, req.user!.id],
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: 'Security event not found.' });
    }

    return res.json({ event: result.rows[0] });
  } catch (error) {
    console.error('Resolve event error:', error);
    return res.status(500).json({ message: 'Unable to resolve security event.' });
  }
});
