# Account Security Suite

A real-world security monitoring platform for users who want to keep an eye on their accounts, detect suspicious activity, and act quickly when something is off.

## Overview

This project is structured as a monorepo with:

- `apps/web` — the user dashboard
- `apps/api` — the backend API and business logic
- `apps/worker` — background monitoring jobs
- `apps/mobile` — future mobile client
- `packages/shared` — shared types and constants
- `infra` — Docker and deployment configuration

## MVP goals

- Secure authentication with MFA support
- Dashboard with account health status
- Detection of suspicious login attempts
- Alerts for password changes, recovery changes, and new devices
- Account connection management
- Activity timeline and security risk indicators

## Stack

- Frontend: Next.js + TypeScript + Tailwind
- Backend: NestJS + TypeScript
- Database: PostgreSQL
- Cache/queue: Redis
- Notifications: email + push-ready infrastructure

## Getting started

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the database and Redis:
   ```bash
   docker compose up -d postgres redis
   ```

3. Start the API:
   ```bash
   npm run dev --workspace @account-security-suite/api
   ```

4. Start the web dashboard:
   ```bash
   npm run dev --workspace @account-security-suite/web
   ```

## Security principles

- Never store user passwords in plain text.
- Use OAuth or official provider APIs when available.
- Enforce MFA and passkeys where possible.
- Keep tokens encrypted at rest.
- Treat every activity event as auditable.

## Roadmap

- Phase 1: authentication, dashboard, alerting
- Phase 2: provider integrations (Google, Microsoft, GitHub)
- Phase 3: breach monitoring and anomaly detection
- Phase 4: mobile push notifications
- Phase 5: production hardening and deployment

## License

MIT
