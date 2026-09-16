'use client';

import { APP_NAME } from '@account-security-suite/shared';
import { useCallback, useEffect, useState } from 'react';

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
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [authLoading, setAuthLoading] = useState(false);

  const loadSummary = useCallback(async () => {
    const token = window.localStorage.getItem('accessToken');
    if (!token) {
      setSummary(null);
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
        setSummary(null);
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

  const handleLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setAuthLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Device-Name': 'Web browser' },
        body: JSON.stringify({ email, password }),
      });
      const payload = await response.json();

      if (!response.ok && response.status !== 202) {
        throw new Error(payload.message ?? 'No se pudo iniciar sesión.');
      }

      if (payload.requiresMfa && payload.challengeToken) {
        setChallengeToken(payload.challengeToken);
        setMfaCode('');
        return;
      }

      if (!payload.token) throw new Error('La respuesta de autenticación no contiene una sesión válida.');
      window.localStorage.setItem('accessToken', payload.token);
      await loadSummary();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Error al iniciar sesión.');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleMfaVerification = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!challengeToken) return;

    setAuthLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_URL}/api/v1/auth/mfa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Device-Name': 'Web browser' },
        body: JSON.stringify({ challengeToken, code: mfaCode }),
      });
      const payload = await response.json();

      if (!response.ok) throw new Error(payload.message ?? 'No se pudo verificar el código MFA.');
      if (!payload.token) throw new Error('La verificación MFA no devolvió una sesión válida.');

      window.localStorage.setItem('accessToken', payload.token);
      setChallengeToken(null);
      setMfaCode('');
      await loadSummary();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Error al verificar MFA.');
    } finally {
      setAuthLoading(false);
    }
  };

  const cancelMfa = () => {
    setChallengeToken(null);
    setMfaCode('');
    setError(null);
  };

  const handleLogout = async () => {
    const token = window.localStorage.getItem('accessToken');
    if (!token) {
      setSummary(null);
      return;
    }

    try {
      await fetch(`${API_URL}/api/v1/auth/logout`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
    } finally {
      window.localStorage.removeItem('accessToken');
      setSummary(null);
      setError(null);
      setLoading(false);
    }
  };

  const resolveEvent = async (eventId: string) => {
    const token = window.localStorage.getItem('accessToken');
    if (!token) return;

    await fetch(`${API_URL}/api/v1/security/events/${eventId}/resolve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    await loadSummary();
  };

  if (!summary && !loading) {
    return (
      <main className="auth-shell">
        <div className="auth-card">
          <p className="eyebrow">Protection dashboard</p>
          <h1>{APP_NAME}</h1>
          {challengeToken ? (
            <>
              <h2>Verificación MFA</h2>
              <p className="muted">Introduce el código de seis dígitos de tu aplicación autenticadora.</p>
              <form onSubmit={handleMfaVerification} className="auth-form">
                <label htmlFor="mfa-code">Código temporal</label>
                <input
                  id="mfa-code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(event) => setMfaCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  required
                  autoFocus
                />
                {error && <div className="error-panel">{error}</div>}
                <button type="submit" disabled={authLoading || mfaCode.length !== 6}>
                  {authLoading ? 'Verificando…' : 'Verificar código'}
                </button>
                <button type="button" className="link-button" onClick={cancelMfa}>Volver al inicio de sesión</button>
              </form>
            </>
          ) : (
            <>
              <p className="muted">Inicia sesión para ver el estado de seguridad de tu cuenta.</p>
              <form onSubmit={handleLogin} className="auth-form">
                <label htmlFor="email">Correo electrónico</label>
                <input id="email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="correo@ejemplo.com" autoComplete="email" required />
                <label htmlFor="password">Contraseña</label>
                <input id="password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Contraseña" autoComplete="current-password" required />
                {error && <div className="error-panel">{error}</div>}
                <button type="submit" disabled={authLoading}>
                  {authLoading ? 'Entrando…' : 'Iniciar sesión'}
                </button>
              </form>
            </>
          )}
        </div>
      </main>
    );
  }

  return (
    <main className="dashboard-shell">
      <div className="dashboard-container">
        <header className="dashboard-header">
          <div>
            <p className="eyebrow">Protection dashboard</p>
            <h1>{APP_NAME}</h1>
            <p className="muted">Condiciones, eventos y sesiones de tu cuenta.</p>
          </div>
          <div className="header-actions">
            <button className="secondary-button" onClick={() => void loadSummary()}>Actualizar</button>
            <button className="secondary-button danger" onClick={handleLogout}>Cerrar sesión</button>
          </div>
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
                {summary.events.length === 0 ? <p className="muted">No hay eventos pendientes.</p> : (
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
