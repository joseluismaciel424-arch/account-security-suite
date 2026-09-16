import { Router } from 'express';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';

export const securityRouter = Router();
securityRouter.use(requireAuth);

securityRouter.get('/summary', async (req, res) => {
  try {
    const [events, sessions] = await Promise.all([
      pool.query(
        `SELECT id, event_type, severity, title, description, metadata, created_at, resolved
         FROM security_events
         WHERE user_id = $1 AND resolved = false
         ORDER BY created_at DESC LIMIT 25`,
        [req.user!.id],
      ),
      pool.query(
        `SELECT id, device_name, user_agent, ip_address, mfa_verified, created_at, last_seen_at, expires_at
         FROM sessions
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
         ORDER BY last_seen_at DESC`,
        [req.user!.id],
      ),
    ]);

    const criticalCount = events.rows.filter((event) => event.severity === 'critical').length;
    const highCount = events.rows.filter((event) => event.severity === 'high').length;

    return res.json({
      status: criticalCount > 0 ? 'critical' : highCount > 0 ? 'needs-attention' : 'secure',
      unresolvedEventCount: events.rowCount ?? 0,
      activeSessionCount: sessions.rowCount ?? 0,
      events: events.rows,
      sessions: sessions.rows,
    });
  } catch (error) {
    console.error('Security summary error:', error);
    return res.status(500).json({ message: 'Unable to load security summary.' });
  }
});

securityRouter.get('/events', async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 25, 1), 100);

  try {
    const result = await pool.query(
      `SELECT id, event_type, severity, title, description, metadata, ip_address,
              user_agent, created_at, resolved, resolved_at
       FROM security_events
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
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
      `UPDATE security_events
       SET resolved = true, resolved_at = NOW()
       WHERE id = $1 AND user_id = $2
       RETURNING id, resolved, resolved_at`,
      [req.params.eventId, req.user!.id],
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: 'Security event not found.' });
    }

    return res.json({ event: result.rows[0] });
  } catch (error) {
    console.error('Resolve security event error:', error);
    return res.status(500).json({ message: 'Unable to resolve security event.' });
  }
});
