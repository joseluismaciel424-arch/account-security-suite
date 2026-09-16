# Private repository checklist

Repository owners must complete these settings in GitHub:

- Set repository visibility to **Private**.
- Enable secret scanning and push protection when available.
- Require two-factor authentication for maintainers.
- Protect `main`: require pull requests, status checks, and no force pushes.
- Store deployment credentials only in GitHub Actions Secrets or an external secret manager.
- Review collaborators and OAuth applications regularly.
- Never use real account credentials in local development or test fixtures.

The application must never request or store a user's primary account password. Use official OAuth flows and minimum required scopes.
