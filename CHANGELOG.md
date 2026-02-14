# Changelog

## 2026-02-13
- Renamed solution branding to `OracleFusionRolesMigration`.
- Added top UI panel listing minimum required roles.
- Added pre-flight access validation endpoint: `POST /api/validate-access`.
- Added automatic access checks before export/import starts, with blocking reasons and missing role details.
- Set default UI language to English.
- Replaced the migration guide with an English version:
  - `oracle_fusion_roles_migration_guide.md`
- Added repository governance files:
  - `SECURITY.md`
  - `CODE_OF_CONDUCT.md`
  - `.github` issue and PR templates
- Added multilingual UI support with language switcher:
  - English
  - Portuguese (Brazil)
  - Spanish
- Added light/dark theme toggle with persistent preference.
- Replaced environment placeholders with fake/safe sample values.
- Improved frontend message localization across status, logs, and diagnostics.
- Improved backend robustness for API payload validation and export diagnostics.
- Added project documentation for Git onboarding in English.
