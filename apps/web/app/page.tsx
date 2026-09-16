'use client';

import { APP_NAME } from '@account-security-suite/shared';
import { useCallback, useEffect, useState } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

type SecuritySummary = {
  status: string;
  score: number;
  mfaEnabled: boolean;
  recoveryEmailConfigured: boolean;
  unresolvedEventCount: number;
  activeSessionCount: number;
  events: Array<{ id: string; title: string; description: string; severity: string; created_at: string }>;
  sessions: Array<{ id: string; device_name: string | null; ip_address: string | null; mfa_verified: boolean; last_seen_at: string }>;
};

type MfaSetup = { secret: string; otpAuthUrl: string };

export default function HomePage() {
  const [summary, setSummary] = useState<SecuritySummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authLoading, setAuthLoading] = useState(false);
  const [mfaSetup, setMfaSetup] = useState<MfaSetup | null>(null);
  const [setupCode, setSetupCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [disableCode, setDisableCode] = useState('');

  const token = () => window.localStorage.getItem('accessToken');

  const loadSummary = useCallback(async () => {
    const accessToken = token();
    if (!accessToken) { setSummary(null); setLoading(false); return; }

    try {
      const response = await fetch(`${API_URL}/api/v1/security/summary`, {
        headers: { Authorization: `Bearer ${accessToken}` }, cache: 'no-store',
      });
      if (response.status === 401) {
        window.localStorage.removeItem('accessToken');
        throw new Error('La sesión ha expirado.');
      }
      if (!response.ok) throw new Error('No se pudo cargar el resumen de seguridad.');
      setSummary(await response.json());
      setError(null);
    } catch (requestError) {
      setSummary(null);
      setError(requestError instanceof Error ? requestError.message : 'Error de conexión.');
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void loadSummary(); }, [loadSummary]);

  const request = async (path: string, options: RequestInit = {}) => {
    const accessToken = token();
    if (!accessToken) throw new Error('La sesión ha expirado.');
    const response = await fetch(`${API_URL}${path}`, {
      ...options,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}`, ...(options.headers ?? {}) },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.message ?? 'La operación no se pudo completar.');
    return payload;
  };

  const handleLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setAuthLoading(true); setError(null);
    try {
      const response = await fetch(`${API_URL}/api/v1/auth/login`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.message ?? 'No se pudo iniciar sesión.');
      if (payload.requiresMfa) throw new Error('Completa la verificación MFA desde el flujo de acceso.');
      window.localStorage.setItem('accessToken', payload.token);
      await loadSummary();
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'Error al iniciar sesión.'); }
    finally { setAuthLoading(false); }
  };

  const startMfaSetup = async () => {
    try { setError(null); setMfaSetup(await request('/api/v1/mfa/setup', { method: 'POST' })); }
    catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'No se pudo iniciar MFA.'); }
  };

  const enableMfa = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setAuthLoading(true); setError(null);
    try {
      const payload = await request('/api/v1/mfa/enable', { method: 'POST', body: JSON.stringify({ code: setupCode }) });
      setRecoveryCodes(payload.recoveryCodes ?? []); setMfaSetup(null); setSetupCode(''); await loadSummary();
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'No se pudo activar MFA.'); }
    finally { setAuthLoading(false); }
  };

  const disableMfa = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setAuthLoading(true); setError(null);
    try {
      await request('/api/v1/mfa/disable', { method: 'POST', body: JSON.stringify({ code: disableCode }) });
      setDisableCode(''); setRecoveryCodes([]); await loadSummary();
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'No se pudo desactivar MFA.'); }
    finally { setAuthLoading(false); }
  };

  const logout = async () => {
    try { await request('/api/v1/auth/logout', { method: 'POST' }); } catch { /* token is removed locally below */ }
    window.localStorage.removeItem('accessToken'); setSummary(null); setLoading(false); setMfaSetup(null); setRecoveryCodes([]);
  };

  if (!summary && !loading) return (
    <main className="auth-shell"><div className="auth-card">
      <p className="eyebrow">Protection dashboard</p><h1>{APP_NAME}</h1>
      <p className="muted">Inicia sesión para administrar la seguridad de tu cuenta.</p>
      <form onSubmit={handleLogin} className="auth-form">
        <label htmlFor="email">Correo electrónico</label><input id="email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
        <label htmlFor="password">Contraseña</label><input id="password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} required />
        {error && <div className="error-panel">{error}</div>}
        <button type="submit" disabled={authLoading}>{authLoading ? 'Entrando…' : 'Iniciar sesión'}</button>
      </form>
    </div></main>
  );

  return <main className="dashboard-shell"><div className="dashboard-container">
    <header className="dashboard-header"><div><p className="eyebrow">Protection dashboard</p><h1>{APP_NAME}</h1><p className="muted">Seguridad y configuración de tu cuenta.</p></div><div className="header-actions"><button className="secondary-button" onClick={() => void loadSummary()}>Actualizar</button><button className="danger-button" onClick={() => void logout()}>Cerrar sesión</button></div></header>
    {error && <div className="panel error-panel">{error}</div>}
    {summary && <>
      <section className="metric-grid"><Metric label="Estado" value={summary.status} /><Metric label="Puntuación" value={`${summary.score}/100`} /><Metric label="Eventos pendientes" value={String(summary.unresolvedEventCount)} /><Metric label="Sesiones activas" value={String(summary.activeSessionCount)} /></section>
      <section className="content-grid">
        <div className="panel"><h2>Seguridad de la cuenta</h2><p className="muted">Administra el segundo factor desde tu perfil.</p><div className="security-status"><strong>MFA</strong><span className={summary.mfaEnabled ? 'ok' : 'warning'}>{summary.mfaEnabled ? 'Activo' : 'No configurado'}</span></div>
          {!summary.mfaEnabled && !mfaSetup && <button onClick={() => void startMfaSetup()}>Configurar MFA</button>}
          {mfaSetup && <div className="mfa-setup"><p>Escanea el enlace con tu aplicación autenticadora o copia el secreto.</p><code>{mfaSetup.secret}</code><a href={mfaSetup.otpAuthUrl}>Abrir en autenticador</a><form onSubmit={enableMfa} className="auth-form"><label htmlFor="setup-code">Código de confirmación</label><input id="setup-code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} value={setupCode} onChange={(event) => setSetupCode(event.target.value.replace(/\D/g, ''))} required /><button type="submit" disabled={authLoading || setupCode.length !== 6}>{authLoading ? 'Activando…' : 'Activar MFA'}</button></form></div>}
          {summary.mfaEnabled && <form onSubmit={disableMfa} className="auth-form"><label htmlFor="disable-code">Código TOTP para desactivar</label><input id="disable-code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} value={disableCode} onChange={(event) => setDisableCode(event.target.value.replace(/\D/g, ''))} required /><button className="danger-button" type="submit" disabled={authLoading || disableCode.length !== 6}>Desactivar MFA</button></form>}
        </div>
        <div className="panel"><h2>Sesiones activas</h2>{summary.sessions.map((session) => <div className="session" key={session.id}><strong>{session.device_name || 'Dispositivo'}</strong><span>{session.ip_address || 'IP no disponible'}</span><span className={session.mfa_verified ? 'ok' : 'warning'}>{session.mfa_verified ? 'MFA verificado' : 'MFA no verificado'}</span></div>)}</div>
      </section>
      {recoveryCodes.length > 0 && <section className="panel recovery-panel"><h2>Códigos de recuperación</h2><p>Guárdalos ahora. Por seguridad, no se volverán a mostrar.</p><div className="recovery-codes">{recoveryCodes.map((code) => <code key={code}>{code}</code>)}</div><button onClick={() => setRecoveryCodes([])}>Ya los guardé</button></section>}
      <section className="panel"><h2>Eventos de seguridad</h2>{summary.events.length === 0 ? <p className="muted">No hay eventos.</p> : summary.events.map((event) => <div className="event" key={event.id}><strong>{event.title}</strong><span className={event.severity === 'critical' || event.severity === 'high' ? 'warning' : 'ok'}>{event.severity}</span><small>{new Date(event.created_at).toLocaleString()}</small></div>)}</section>
    </>}
  </div></main>;
}

function Metric({ label, value }: { label: string; value: string }) { return <div className="metric"><span>{label}</span><strong>{value}</strong></div>; }
