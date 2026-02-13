# OracleFusionRolesMigration

Web-based solution to export and import Oracle Fusion roles between environments using FSM and SCIM APIs.

## Highlights
- End-to-end migration flow:
  - `Export only`
  - `Export + Import`
  - `Import only`
- Built-in diagnostics for FSM, ESS, and ERP integration checks.
- Multilingual UI with flag switcher:
  - English (`EN`)
  - Portuguese (Brazil) (`PT-BR`)
  - Spanish (`ES`)
- Light/Dark theme toggle (sun/moon button).
- Safe fake placeholders by default (no real tenant data in UI hints).

## Project Structure
- `oracle_migration_server.py`: Flask backend and Oracle API proxy endpoints.
- `oracle_migration_gui.html`: Single-page frontend UI.
- `oracle_fusion_role_migration.py`: CLI migration utility.
- `guia_migracao_roles_oracle_fusion.md`: Original migration notes.

## Requirements
- Python 3.10+
- Oracle Fusion credentials with required permissions
- Python packages:
  - `flask`
  - `flask-cors`
  - `requests`

Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the Web App

```bash
cd /Users/Ale/Documents/oracle_fusion_roles_migration
python3 oracle_migration_server.py
```

Open:
- `http://127.0.0.1:5050`

Custom port:

```bash
PORT=5051 python3 oracle_migration_server.py
```

## Run the CLI Tool

```bash
python3 oracle_fusion_role_migration.py --help
```

Examples:

```bash
python3 oracle_fusion_role_migration.py discover --env dev
python3 oracle_fusion_role_migration.py export --env dev --offering financials
python3 oracle_fusion_role_migration.py import --env uat --file oracle_roles_export_dev_20260212.zip
```

## Backend API Endpoints
- `POST /api/test-connection`
- `POST /api/validate-access`
- `POST /api/export`
- `POST /api/export-status`
- `POST /api/download`
- `POST /api/import`
- `POST /api/import-status`
- `POST /api/list-roles`
- `POST /api/debug-ess`
- `POST /api/debug-version`

## Required Oracle Roles (Typical)
For FSM export/import operations, users usually need:
- `ORA_ASM_FUNCTIONAL_SETUPS_USER_ABSTRACT` (Export Import Functional Setups User)

Recommended for richer diagnostics:
- `ORA_FND_IT_SECURITY_MANAGER_JOB` (IT Security Manager)

Without required permissions, export can return success status for object creation but no usable `ProcessId`.

## Troubleshooting
- `Failed to fetch` in browser:
  - Ensure backend is running.
  - Open UI from backend URL (`http://127.0.0.1:5050`) instead of `file://`.
- `ProcessId not found`:
  - Validate permissions.
  - Use built-in **Diagnose** action and inspect log attempts.
- Port already in use:
  - Run with another port using `PORT=...`.

## Security Notes
- Do not commit real credentials or tenant URLs.
- The UI now ships with fake placeholders only.
- Prefer environment variables for runtime credentials.

## Contributing
See `CONTRIBUTING.md`.

## License
This project is licensed under the MIT License. See `LICENSE`.
