# Oracle Fusion Roles Migration Guide (DEV -> UAT)

This guide describes practical, production-friendly approaches to migrate custom roles between Oracle Fusion environments.

## Migration Options

| Method | Complexity | Automation | Best Use Case |
|---|---|---|---|
| FSM CSV Export/Import (UI) | Low | Manual | One-time migrations |
| FSM REST API | Medium | High | Repeatable migrations, CI/CD |
| Configuration Set Migration (CSM) | High | Partial | Broad configuration transport |

## Prerequisites

### Minimum Required Role

- `ORA_ASM_FUNCTIONAL_SETUPS_USER_ABSTRACT` (`Export Import Functional Setups User`)

### Recommended Role

- `ORA_FND_IT_SECURITY_MANAGER_JOB` (`IT Security Manager`) for better SCIM-based diagnostics

### Technical Requirements

- Source and target pods should be on compatible releases
- Sandbox changes should be published before export
- Python 3.10+ for CLI workflow

## Method 1: FSM CSV Export/Import (UI)

### What Is Exported

Typical role package includes:

- `ORA_ASE_FUNCTIONAL_SECURITY_CUSTOM_ROLES.csv`
- `ORA_ASE_FUNCTIONAL_SECURITY_CUSTOM_ROLE_HIERARCHY.csv`
- `ORA_ASE_FUNCTIONAL_SECURITY_CUSTOM_ROLE_PRIVILEGE_MEMBERSHIP.csv`

### Export Steps (Source)

1. Open `Navigator > My Enterprise > Setup and Maintenance`
2. Search `Manage Job Roles` under `Users and Security`
3. Select `Actions > Export to CSV File`
4. Select target roles and run export
5. Download the generated ZIP

### Import Steps (Target)

1. Open `Navigator > My Enterprise > Setup and Maintenance`
2. Go to `Manage Job Roles` under `Users and Security`
3. Select `Actions > Import from CSV File`
4. Upload ZIP from source
5. Run scheduled process `Import Users and Roles into Application Security`
6. Validate imported roles in Security Console

## Method 2: FSM REST API

Use this method for automation.

### Core Endpoints

```http
GET /fscmRestApi/resources/11.13.18.05/setupOfferings
GET /fscmRestApi/resources/11.13.18.05/setupOfferings/{OfferingCode}/child/functionalAreas
POST /fscmRestApi/resources/11.13.18.05/setupOfferingCSVExports
GET /fscmRestApi/resources/11.13.18.05/setupOfferingCSVExports/{OfferingCode}/child/SetupOfferingCSVExportProcess/{ProcessId}
POST /fscmRestApi/resources/11.13.18.05/setupOfferingCSVImports
GET /hcmRestApi/scim/Roles?count=200&startIndex=1
```

### Authentication

```http
Authorization: Basic <base64(username:password)>
```

### CLI Quick Start

```bash
export ORACLE_DEV_URL="https://your-dev-pod.fa.us2.oraclecloud.com"
export ORACLE_DEV_USER="service_user"
export ORACLE_DEV_PASS="secret"

export ORACLE_UAT_URL="https://your-uat-pod.fa.us2.oraclecloud.com"
export ORACLE_UAT_USER="service_user"
export ORACLE_UAT_PASS="secret"

python oracle_fusion_role_migration.py discover --env dev
python oracle_fusion_role_migration.py export --env dev --offering financials
python oracle_fusion_role_migration.py import --env uat --file oracle_roles_export_dev_YYYYMMDD.zip
python oracle_fusion_role_migration.py migrate --source dev --target uat --offering financials
```

## Method 3: Configuration Set Migration (CSM)

Use CSM when you need to move broader configuration bundles, not only roles.

### Known Limitation

Some security changes made outside supported migration paths may need manual recreation in target.

## Best Practices

1. Export a backup from target before import
2. Validate in test/staging before UAT/production
3. Keep environments stable during migration
4. Always run post-import security sync
5. Validate final access with test users

## Troubleshooting

### HTTP 403 on FSM endpoints

Check required role assignment:

- `ORA_ASM_FUNCTIONAL_SETUPS_USER_ABSTRACT`

### Export returns no `ProcessId`

Usually permissions or endpoint behavior mismatch. Run diagnostics and review access roles.

### Imported roles are not visible

Run `Import Users and Roles into Application Security` and wait for completion.

## References

- Oracle Docs: Export and Import of Custom Roles
- Oracle Docs: SCIM Roles API
- Oracle Docs: Roles Required for Import and Export Management
