'use client';

import { useCallback, useEffect, useState } from 'react';
import { APP_NAME } from '@account-security-suite/shared';

type SecurityEvent = {
  id: string;
  event_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  created_at: string;
  resolved: boolean;
};

type SecuritySummary = {
  status: 'secure' | 'needs-attention' | 'critical';
  score: number;
  mfaEnabled: boolean;
  recoveryEmailConfigured: boolean;
  unresolvedEventCount: number;
  activeSessionCount: number;
  events: SecurityEvent[];
  sessions: Array<{
    id: string;
    device_name: string | null;
    user_agent: string | null;
    ip_address: string | null;
    mfa_verified: boolean;
    last_seen_at: string;
  }>;
};

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

export default function HomePage() {
  const [summary, setSummary] = useState<SecuritySummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadSummary = useCallback(async () => {
    const token = window.localStorage.getItem('accessToken');
    if (!token) {
      setError('Inicia sesión para consultar el estado de seguridad de tu cuenta.');
      setLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/v1/security/summary`, {
        headers: { Authorization: `Bearer ${token}` },
        cache: 'no-store',
      });

      if (response.status === 401) {
        window.localStorage.removeItem('accessToken');
        throw new Error('La sesión ha expirado. Vuelve a iniciar sesión.');
      }
      if (!response.ok) throw new Error('No se pudo cargar el resumen de seguridad.');

      setSummary(await response.json());
      setError(null);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Error de conexión.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSummary();
  }, [loadSummary]);

  const resolveEvent = async (eventId: string) => {
    const token = window.localStorage.getItem('accessToken');
    if (!token) return;

    await fetch(`${API_URL}/api/v1/security/events/${eventId}/resolve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    await loadSummary();
  };

  return (
    <main className="dashboard-shell">
      <div className="dashboard-container">
        <header className="dashboard-header">
          <div>
            <p className="eyebrow">Protection dashboard</p>
            <h1>{APP_NAME}</h1>
            <p className="muted">Condiciones, eventos y sesiones de tu cuenta.</p>
          </div>
          <button className="secondary-button" onClick={() => void loadSummary()}>Actualizar</button>
        </header>

        {loading && <div className="panel">Cargando resumen de seguridad…</div>}
        {error && <div className="panel error-panel">{error}</div>}

        {summary && (
          <>
            <section className="metric-grid">
              <Metric label="Estado" value={summary.status} />
              <Metric label="Puntuación" value={`${summary.score}/100`} />
              <Metric label="Eventos pendientes" value={String(summary.unresolvedEventCount)} />
              <Metric label="Sesiones activas" value={String(summary.activeSessionCount)} />
            </section>

            <section className="content-grid">
              <div className="panel">
                <h2>Factores de seguridad</h2>
                <div className="factor-list">
                  <Factor label="MFA" enabled={summary.mfaEnabled} />
                  <Factor label="Correo de recuperación" enabled={summary.recoveryEmailConfigured} />
                  <Factor label="Monitoreo de sesiones" enabled={summary.activeSessionCount > 0} />
                </div>
              </div>

              <div className="panel">
                <h2>Eventos recientes</h2>
                {summary.events.length === 0 ? (
                  <p className="muted">No hay eventos pendientes.</p>
                ) : (
                  <div className="event-list">
                    {summary.events.map((event) => (
                      <article className="event" key={event.id}>
                        <div>
                          <strong>{event.title}</strong>
                          <p>{event.description}</p>
                          <small>{new Date(event.created_at).toLocaleString()}</small>
                        </div>
                        <div className="event-actions">
                          <span className={`severity ${event.severity}`}>{event.severity}</span>
                          <button className="link-button" onClick={() => void resolveEvent(event.id)}>Marcar revisado</button>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </div>
            </section>

            <section className="panel">
              <h2>Sesiones activas</h2>
              {summary.sessions.length === 0 ? <p className="muted">No hay sesiones activas.</p> : (
                <div className="session-list">
                  {summary.sessions.map((session) => (
                    <div className="session" key={session.id}>
                      <strong>{session.device_name || 'Dispositivo sin nombre'}</strong>
                      <span>{session.ip_address || 'IP no disponible'} · Última actividad {new Date(session.last_seen_at).toLocaleString()}</span>
                      <span className={session.mfa_verified ? 'ok' : 'warning'}>{session.mfa_verified ? 'MFA verificado' : 'MFA no verificado'}</span>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </>
        )}
      </div>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong></div>;
}

function Factor({ label, enabled }: { label: string; enabled: boolean }) {
  return <div className="factor"><span>{label}</span><span className={enabled ? 'ok' : 'warning'}>{enabled ? 'Activo' : 'Pendiente'}</span></div>;
}
