# Contributing Guide

Thanks for contributing.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run locally:

```bash
python3 oracle_migration_server.py
```

## Coding Guidelines
- Keep backend responses explicit and safe (avoid raw unhandled exceptions).
- Validate required request payload fields before processing.
- Keep UI text translatable (use language dictionary keys).
- Do not add real tenant/customer data in placeholders, docs, or examples.

## Pull Request Checklist
- [ ] Feature works in both light and dark themes.
- [ ] UI labels are available in EN, PT-BR, and ES.
- [ ] No secrets or real credentials committed.
- [ ] Basic manual flow tested (test connection, export/import paths).
- [ ] README updated when behavior changes.

## Branching
- Use short topic branches, for example:
  - `feature/i18n-theme-toggle`
  - `fix/export-processid-diagnostics`

## Commit Messages
Use clear imperative messages:
- `Add language switcher and theme toggle`
- `Improve export ProcessId fallback diagnostics`
- `Document setup and troubleshooting`
