import dotenv from 'dotenv';
import { Pool } from 'pg';

dotenv.config();

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL must be configured.');
}

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : undefined,
});

export const initDatabase = async () => {
  await pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      mfa_enabled BOOLEAN NOT NULL DEFAULT false,
      mfa_secret TEXT,
      recovery_email TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT false');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS security_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      ip_address INET,
      user_agent TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      resolved BOOLEAN NOT NULL DEFAULT false,
      resolved_at TIMESTAMPTZ
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      device_name TEXT,
      user_agent TEXT,
      ip_address INET,
      mfa_verified BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      revoked_at TIMESTAMPTZ
    );
  `);

  await pool.query('ALTER TABLE security_events ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT \'{}\'::jsonb');
  await pool.query('ALTER TABLE security_events ADD COLUMN IF NOT EXISTS ip_address INET');
  await pool.query('ALTER TABLE security_events ADD COLUMN IF NOT EXISTS user_agent TEXT');
  await pool.query('ALTER TABLE security_events ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ');
  await pool.query('ALTER TABLE sessions ADD COLUMN IF NOT EXISTS mfa_verified BOOLEAN NOT NULL DEFAULT false');
  await pool.query('ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()');
  await pool.query('ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ');

  await pool.query('CREATE INDEX IF NOT EXISTS security_events_user_created_idx ON security_events (user_id, created_at DESC)');
  await pool.query('CREATE INDEX IF NOT EXISTS security_events_unresolved_idx ON security_events (user_id, resolved, created_at DESC)');
  await pool.query('CREATE INDEX IF NOT EXISTS sessions_user_active_idx ON sessions (user_id, revoked_at, expires_at)');
};
