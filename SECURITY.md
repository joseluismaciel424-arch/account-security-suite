# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues. Contact the repository owner privately through GitHub.

## Secrets policy

- Never commit passwords, OAuth client secrets, API keys, JWT secrets, database credentials, or private keys.
- Use `.env` locally and GitHub Actions Secrets or the deployment provider's secret manager in hosted environments.
- Rotate any secret immediately if it is accidentally exposed.
- Use least-privilege OAuth scopes and encrypt tokens at rest.
