import { APP_NAME } from '@account-security-suite/shared';

const summary = [
  { label: 'Security score', value: '91/100' },
  { label: 'Accounts monitored', value: '12' },
  { label: 'Alerts', value: '3 pending' },
  { label: 'MFA enabled', value: '10/12' },
];

const accounts = [
  { name: 'Google', status: 'Secure', risk: 'Low', lastSeen: '2 min ago' },
  { name: 'GitHub', status: 'Needs attention', risk: 'Medium', lastSeen: '15 min ago' },
  { name: 'Microsoft', status: 'Secure', risk: 'Low', lastSeen: '1 hour ago' },
];

export default function HomePage() {
  return (
    <main style={{ padding: '2rem', fontFamily: 'sans-serif', background: '#0b1020', color: '#e5eefb', minHeight: '100vh' }}>
      <div style={{ maxWidth: 1100, margin: '0 auto' }}>
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
          <div>
            <p style={{ margin: 0, color: '#8ab4f8', textTransform: 'uppercase', letterSpacing: '0.12em', fontSize: 12 }}>Protection dashboard</p>
            <h1 style={{ margin: '0.4rem 0 0', fontSize: '2.5rem' }}>{APP_NAME}</h1>
          </div>
          <button style={{ background: '#1d4ed8', color: 'white', border: 'none', borderRadius: 8, padding: '0.8rem 1.2rem', fontWeight: 600 }}>
            Review security
          </button>
        </header>

        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
          {summary.map((item) => (
            <div key={item.label} style={{ background: '#101827', border: '1px solid #1f2a3d', borderRadius: 14, padding: '1rem' }}>
              <div style={{ fontSize: 12, color: '#9fb4d1' }}>{item.label}</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 700, marginTop: '0.6rem' }}>{item.value}</div>
            </div>
          ))}
        </section>

        <section style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem' }}>
          <div style={{ background: '#101827', border: '1px solid #1f2a3d', borderRadius: 14, padding: '1rem' }}>
            <h2 style={{ marginTop: 0 }}>Accounts monitored</h2>
            <div style={{ display: 'grid', gap: '0.8rem' }}>
              {accounts.map((account) => (
                <div key={account.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #243047', paddingBottom: '0.7rem' }}>
                  <div>
                    <div style={{ fontWeight: 700 }}>{account.name}</div>
                    <div style={{ color: '#9fb4d1', fontSize: 12 }}>Last seen {account.lastSeen}</div>
                  </div>
                  <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
                    <span style={{ color: account.risk === 'Medium' ? '#fbbf24' : '#4ade80', fontWeight: 600 }}>{account.risk}</span>
                    <span style={{ background: '#15263d', borderRadius: 999, padding: '0.4rem 0.75rem', color: '#d9e7ff', fontSize: 12 }}>{account.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ background: '#101827', border: '1px solid #1f2a3d', borderRadius: 14, padding: '1rem' }}>
            <h2 style={{ marginTop: 0 }}>Security alerts</h2>
            <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'grid', gap: '0.8rem' }}>
              <li style={{ background: '#142033', borderRadius: 10, padding: '0.8rem' }}><strong>New sign-in</strong><br />Detected from a new device on GitHub</li>
              <li style={{ background: '#142033', borderRadius: 10, padding: '0.8rem' }}><strong>Recovery update</strong><br />One account has an unverified recovery email</li>
              <li style={{ background: '#142033', borderRadius: 10, padding: '0.8rem' }}><strong>Breached email</strong><br />Your email was found in a public leak database</li>
            </ul>
          </div>
        </section>
      </div>
    </main>
  );
}
