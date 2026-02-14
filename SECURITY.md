# Security Policy

## Supported Versions

This repository currently supports the `main` branch.

## Reporting a Vulnerability

If you identify a security issue, do not open a public issue with exploit details.

Report privately with:
- A clear description
- Reproduction steps
- Impact assessment
- Suggested fix (if available)

If the repository owner has configured GitHub private vulnerability reporting, use that channel first.

## Secrets and Credentials

Never commit:
- Real Oracle tenant URLs tied to private environments
- Usernames/passwords
- Access tokens
- Session IDs or cookies

Use environment variables and local `.venv` runtime configuration only.
