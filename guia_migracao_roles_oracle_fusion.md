# Guia Completo: Migração de Roles do Oracle Fusion Cloud (DEV → UAT)

## Visão Geral

A migração de custom roles entre ambientes Oracle Fusion Cloud (por exemplo, DEV para UAT) pode ser feita por três métodos principais. Este guia cobre todos eles em detalhe.

| Método | Complexidade | Automação | Quando usar |
|--------|-------------|-----------|-------------|
| FSM CSV Export/Import (UI) | Baixa | Manual | Migrações pontuais |
| FSM REST API | Média | Total | CI/CD, migrações frequentes |
| Configuration Set Migration (CSM) | Alta | Parcial | Migração ampla (não só roles) |

---

## Pré-requisitos

### Roles necessárias no usuário que executa a migração

O usuário que vai executar a exportação e importação precisa ter as seguintes roles atribuídas:

- **Export Import Functional Setups User** (`ORA_ASM_FUNCTIONAL_SETUPS_USER_ABSTRACT`) — necessária para submeter processos de export/import via API ou UI
- **IT Security Manager** (`ORA_FND_IT_SECURITY_MANAGER_JOB`) — necessária para acessar a SCIM REST API e o Security Console
- Role de administrador do módulo correspondente (ex: Application Administrator para Financials)

### Requisitos técnicos

- Ambientes DEV e UAT devem estar na **mesma release** do Oracle Fusion Cloud
- Patches standard e one-off devem ser os mesmos em ambos ambientes
- Todas as configurações feitas em sandboxes devem estar **publicadas** antes da exportação
- Python 3.8+ com a biblioteca `requests` instalada (para o script de automação)

---

## Método 1: FSM CSV Export/Import (via Interface Web)

Este é o método mais simples e recomendado para migrações pontuais.

### O que é exportado

Quando você exporta roles pela área Users and Security, o ZIP gerado contém três arquivos CSV:

- `ORA_ASE_FUNCTIONAL_SECURITY_CUSTOM_ROLES.csv` — informações básicas de cada role customizada (nome, código, descrição)
- `ORA_ASE_FUNCTIONAL_SECURITY_CUSTOM_ROLE_HIERARCHY.csv` — hierarquia das roles (quais duty roles e data roles estão contidas em cada job role)
- `ORA_ASE_FUNCTIONAL_SECURITY_CUSTOM_ROLE_PRIVILEGE_MEMBERSHIP.csv` — mapeamento de function security privileges para cada role

**Importante:** Listas de usuários ou informações sobre usuários específicos nunca fazem parte deste processo de export/import.

### Passos para Exportar (Ambiente DEV)

1. Acesse **Navigator > My Enterprise > Setup and Maintenance**
2. Na barra de busca, procure por **Manage Job Roles** na functional area **Users and Security**
3. Na tabela de tasks, selecione **Columns > View > Actions** para tornar visíveis as ações aplicáveis
4. No menu **Actions** correspondente, selecione **Export to CSV File**
5. Selecione as roles que precisam ser migradas e clique em **Apply**
6. Após selecionar todas as roles desejadas, clique em **Save and Close**
7. Clique em **Download File** para baixar o arquivo ZIP
8. Salve o arquivo ZIP em um local acessível

### Passos para Importar (Ambiente UAT)

1. Acesse o ambiente UAT: **Navigator > My Enterprise > Setup and Maintenance**
2. Navegue até **Manage Job Roles** na functional area **Users and Security**
3. No menu **Actions**, selecione **Import from CSV File**
4. Faça upload do arquivo ZIP exportado do DEV
5. Aguarde o processo de importação concluir
6. Execute o scheduled process **Import Users and Roles into Application Security**:
   - Navegue para **Users and Security**
   - Clique em **Import Users and Roles into Application Security**
   - Clique em **Submit**
7. Verifique as roles importadas na **Security Console**

### Agendar sincronização recorrente

Recomenda-se agendar o processo "Import Users and Roles into Application Security" para execução diária:

1. Na tela do scheduled process, clique em **Advanced**
2. Vá para a aba **Schedule**
3. Defina Run como **Using a schedule**
4. Defina Frequency como **Daily**, Days Between Runs como **1**
5. Configure as datas/horários de início e fim

---

## Método 2: FSM REST API (Automação)

Use este método para automatizar a migração com scripts ou pipelines CI/CD. O script Python fornecido (`oracle_fusion_role_migration.py`) implementa este método.

### Endpoints REST API

#### Descobrir Offerings disponíveis

```
GET /fscmRestApi/resources/11.13.18.05/setupOfferings
```

#### Descobrir Functional Areas de um Offering

```
GET /fscmRestApi/resources/11.13.18.05/setupOfferings/{OfferingCode}/child/functionalAreas
```

#### Iniciar Exportação

```
POST /fscmRestApi/resources/11.13.18.05/setupOfferingCSVExports
Content-Type: application/vnd.oracle.adf.resourceitem+json

{
  "OfferingCode": "FIN_FSCM_OFFERING",
  "FunctionalAreaCode": "ORA_ASE_USERS_AND_SECURITY"
}
```

Resposta inclui o `ProcessId` para acompanhar o processo.

#### Verificar Status da Exportação

```
GET /fscmRestApi/resources/11.13.18.05/setupOfferingCSVExports/{OfferingCode}/child/SetupOfferingCSVExportProcess/{ProcessId}
```

#### Baixar o Arquivo Exportado

```
GET /fscmRestApi/resources/11.13.18.05/setupOfferingCSVExports/{OfferingCode}/child/SetupOfferingCSVExportProcess/{ProcessId}/child/SetupOfferingCSVExportProcessResult/{ProcessId}/enclosure/FileContent
```

#### Iniciar Importação

```
POST /fscmRestApi/resources/11.13.18.05/setupOfferingCSVImports
Content-Type: application/vnd.oracle.adf.resourceitem+json

{
  "OfferingCode": "FIN_FSCM_OFFERING",
  "FunctionalAreaCode": "ORA_ASE_USERS_AND_SECURITY",
  "FileContent": "<base64_encoded_zip>",
  "FileName": "exported_roles.zip",
  "ContentType": "application/zip"
}
```

#### Listar Roles (SCIM API)

```
GET /hcmRestApi/scim/Roles?count=200&startIndex=1
Authorization: Basic <base64(user:pass)>
```

### Autenticação

Todas as APIs suportam **Basic Authentication over SSL**. O formato do header é:

```
Authorization: Basic <base64(username:password)>
```

### Usando o Script de Automação

#### Configuração inicial

Configure as variáveis de ambiente com as credenciais:

```bash
# Ambiente DEV
export ORACLE_DEV_URL="https://your-dev-pod.fa.us2.oraclecloud.com"
export ORACLE_DEV_USER="admin_user"
export ORACLE_DEV_PASS="admin_password"

# Ambiente UAT
export ORACLE_UAT_URL="https://your-uat-pod.fa.us2.oraclecloud.com"
export ORACLE_UAT_USER="admin_user"
export ORACLE_UAT_PASS="admin_password"
```

#### Comandos disponíveis

```bash
# Instalar dependência
pip install requests

# Descobrir offerings e functional areas
python oracle_fusion_role_migration.py discover --env dev
python oracle_fusion_role_migration.py discover --env dev --offering-code FIN_FSCM_OFFERING

# Exportar roles do DEV
python oracle_fusion_role_migration.py export --env dev --offering financials

# Importar roles no UAT
python oracle_fusion_role_migration.py import --env uat --file oracle_roles_export_dev_20260212.zip --offering financials

# Migração completa (exporta do DEV e importa no UAT automaticamente)
python oracle_fusion_role_migration.py migrate --source dev --target uat --offering financials

# Listar todas as roles
python oracle_fusion_role_migration.py list-roles --env dev --all

# Verificar se uma role específica existe
python oracle_fusion_role_migration.py verify --env uat --role-name "Custom Finance Manager"

# Verificar status de um processo
python oracle_fusion_role_migration.py status --env dev --process-id 300100068271744
```

---

## Método 3: Configuration Set Migration (CSM)

O CSM é um framework mais amplo para migrar todas as customizações entre ambientes Oracle Fusion (não apenas roles). Use quando precisar migrar roles junto com outras configurações.

### Limitações importantes do CSM para roles

- Enterprise roles, novas duty roles e mudanças de hierarquia feitas diretamente no Oracle Authorization Policy Manager (APM) **não são migradas** pelo CSM
- Se você fez alterações de segurança fora do Application Composer no ambiente fonte, precisará recriar manualmente essas alterações no ambiente destino antes de usar o CSM

### Como usar o CSM

1. Acesse **Navigator > Tools > Customization Migration**
2. No ambiente de origem (DEV), crie um novo Configuration Set
3. Selecione os objetos de segurança que deseja migrar
4. Exporte o Configuration Set
5. No ambiente de destino (UAT), importe o Configuration Set
6. Aplique o migration set importado

### CSM via REST API

```
# Verificar modo de migração
GET /fscmUI/applcoreApi/v2/csm/mode/migration

# Aplicar migration set importado
POST /fscmUI/applcoreApi/v2/csm/apply/{csId}
```

---

## Boas Práticas

1. **Sempre faça backup antes de importar** — Exporte as roles atuais do UAT antes de importar as novas do DEV

2. **Teste em ambiente intermediário** — Se possível, importe primeiro em um ambiente de teste antes do UAT

3. **Não altere configurações durante a exportação** — O processo de exportação deve ser feito com o ambiente estável

4. **Verifique a segurança funcional** — Certifique-se de que os function security privileges associados às roles existem tanto no ambiente de origem quanto no de destino

5. **Execute o scheduled process após importar** — Sempre execute "Import Users and Roles into Application Security" após a importação para sincronizar os dados

6. **Documente as roles migradas** — Mantenha um registro de quais roles foram migradas, quando e por quem

7. **Valide com um usuário de teste** — Após a migração, teste o acesso com um usuário atribuído às roles migradas para confirmar que as permissões estão corretas

---

## Troubleshooting

### Erro 403 na API

Verifique se o usuário tem a role `ORA_ASM_FUNCTIONAL_SETUPS_USER_ABSTRACT` atribuída.

### Roles não aparecem após importação

Execute o scheduled process "Import Users and Roles into Application Security" e aguarde sua conclusão.

### Hierarquia de roles diferente após importação

Verifique se as duty roles e privileges referenciados nas roles customizadas existem no ambiente de destino. Roles standard (ORA_*) devem estar presentes por padrão, mas roles customizadas dependentes precisam ser migradas primeiro.

### Processo de exportação/importação em status PENDING por muito tempo

Verifique se não há outros processos concorrentes rodando no ambiente. O tempo máximo esperado é de 30 minutos para exportações normais.

---

## Referências

- [Oracle Docs - Export and Import of Custom Roles](https://docs.oracle.com/en/cloud/saas/applications-common/25d/faser/export-and-import-of-custom-roles.html)
- [Oracle Docs - Export and Import of Custom Roles, Role Hierarchies, and Privilege Assignments](https://docs.oracle.com/en/cloud/saas/sales/oscus/export-and-import-of-custom-roles-role-hierarchies-and-role-to.html)
- [Oracle Docs - Automate Export and Import of CSV File Packages](https://docs.oracle.com/en/cloud/saas/applications-common/25c/oafsm/automate-export-and-import-of-csv-file-packages.html)
- [Oracle Docs - REST API: Setup Offering CSV Exports](https://docs.oracle.com/en/cloud/saas/applications-common/23d/farca/Offering_CSV_Export.html)
- [Oracle Docs - SCIM Roles API](https://docs.oracle.com/en/cloud/saas/applications-common/25b/farca/op-hcmrestapi-scim-roles-get.html)
- [Oracle Docs - Export and Import of Security Setup Data](https://docs.oracle.com/en/cloud/saas/applications-common/21c/faser/export-and-import-of-security-setup-data.html)
- [Oracle Docs - Roles Required for Import and Export Management](https://docs.oracle.com/en/cloud/saas/sales/fasqa/roles-required-for-import-and-export-management.html)
- [Oracle A-Team - CI/CD Using CSM REST APIs](https://www.ateam-oracle.com/post/cicd-using-csm-rest-apis-for-sandbox-migration)
- [Jade Global - Migrating Security Roles from One POD to Another](https://www.jadeglobal.com/themes/custom/jade_subtheme/pdf/oracle-cloud-security-migrating-security-roles-from-one-pod-to-another-whitepaper.pdf)
