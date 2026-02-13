#!/usr/bin/env python3
"""
Oracle Fusion Cloud - Migração de Roles entre Ambientes (DEV → UAT)
====================================================================

Este script automatiza o processo de exportação e importação de custom roles,
role hierarchies e privilege-to-role assignments entre ambientes Oracle Fusion Cloud
usando as REST APIs do Functional Setup Manager (FSM).

Métodos suportados:
  1. FSM CSV Export/Import via REST API (setupOfferingCSVExports / setupOfferingCSVImports)
  2. SCIM REST API para listar e verificar roles

Pré-requisitos:
  - Python 3.8+
  - Biblioteca 'requests' (pip install requests)
  - Usuário com role "Export Import Functional Setups User" (ORA_ASM_FUNCTIONAL_SETUPS_USER_ABSTRACT)
  - Usuário com role "IT Security Manager" (ORA_FND_IT_SECURITY_MANAGER_JOB) para SCIM API
  - Ambientes DEV e UAT devem estar na mesma release

Uso:
  # Exportar roles do DEV
  python oracle_fusion_role_migration.py export --env dev

  # Importar roles no UAT
  python oracle_fusion_role_migration.py import --env uat --file exported_roles.zip

  # Listar roles customizadas (SCIM API)
  python oracle_fusion_role_migration.py list-roles --env dev

  # Fluxo completo: exportar do DEV e importar no UAT
  python oracle_fusion_role_migration.py migrate --source dev --target uat

  # Verificar status de um processo
  python oracle_fusion_role_migration.py status --env dev --process-id 300100068271744

Autor: Gerado para Alê - Virttus
Data: Fevereiro 2026
"""

import argparse
import base64
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    print("ERRO: Biblioteca 'requests' não encontrada.")
    print("Instale com: pip install requests")
    sys.exit(1)


# ============================================================================
# CONFIGURAÇÃO DOS AMBIENTES
# ============================================================================
# Edite as configurações abaixo com os dados dos seus ambientes Oracle Fusion.
# Você também pode definir variáveis de ambiente para não expor credenciais.
#
# Variáveis de ambiente aceitas:
#   ORACLE_DEV_URL, ORACLE_DEV_USER, ORACLE_DEV_PASS
#   ORACLE_UAT_URL, ORACLE_UAT_USER, ORACLE_UAT_PASS
# ============================================================================

ENVIRONMENTS = {
    "dev": {
        "name": "Desenvolvimento (DEV)",
        "base_url": os.environ.get(
            "ORACLE_DEV_URL",
            "https://YOUR-DEV-POD.fa.DATACENTER.oraclecloud.com"
        ),
        "username": os.environ.get("ORACLE_DEV_USER", ""),
        "password": os.environ.get("ORACLE_DEV_PASS", ""),
    },
    "uat": {
        "name": "Homologação (UAT)",
        "base_url": os.environ.get(
            "ORACLE_UAT_URL",
            "https://YOUR-UAT-POD.fa.DATACENTER.oraclecloud.com"
        ),
        "username": os.environ.get("ORACLE_UAT_USER", ""),
        "password": os.environ.get("ORACLE_UAT_PASS", ""),
    },
}

# ============================================================================
# CÓDIGOS DE OFFERING E FUNCTIONAL AREA
# ============================================================================
# Estes códigos identificam a área "Users and Security" em cada offering.
# Descomente/ajuste conforme o seu módulo Oracle Fusion.
#
# Para descobrir o código correto do seu ambiente, use:
#   GET /fscmRestApi/resources/11.13.18.05/setupOfferings
#   GET /fscmRestApi/resources/11.13.18.05/setupOfferings/{code}/child/functionalAreas
# ============================================================================

OFFERING_CONFIGS = {
    "financials": {
        "offering_code": "FIN_FSCM_OFFERING",
        "functional_area_code": "ORA_ASE_USERS_AND_SECURITY",
        "description": "Financials - Users and Security",
    },
    "hcm": {
        "offering_code": "PER_WKF_DEV",
        "functional_area_code": "ORA_ASE_USERS_AND_SECURITY",
        "description": "HCM / Workforce Deployment - Users and Security",
    },
    "sales": {
        "offering_code": "ZBS_SALES",
        "functional_area_code": "ORA_ASE_USERS_AND_SECURITY",
        "description": "Sales - Users and Security",
    },
    "scm": {
        "offering_code": "SCM_OFFERING",
        "functional_area_code": "ORA_ASE_USERS_AND_SECURITY",
        "description": "SCM - Users and Security",
    },
}

# Configuração padrão (altere conforme necessário)
DEFAULT_OFFERING = "financials"

# REST API version
API_VERSION = "11.13.18.05"

# Tempo máximo de espera para processos (em segundos)
MAX_WAIT_TIME = 1800  # 30 minutos
POLL_INTERVAL = 15    # Verificar a cada 15 segundos


# ============================================================================
# CLASSE PRINCIPAL
# ============================================================================

class OracleFusionRoleMigration:
    """Classe para gerenciar a migração de roles entre ambientes Oracle Fusion."""

    def __init__(self, env_key: str, offering_key: str = DEFAULT_OFFERING):
        if env_key not in ENVIRONMENTS:
            raise ValueError(
                f"Ambiente '{env_key}' não configurado. "
                f"Opções: {', '.join(ENVIRONMENTS.keys())}"
            )
        if offering_key not in OFFERING_CONFIGS:
            raise ValueError(
                f"Offering '{offering_key}' não configurado. "
                f"Opções: {', '.join(OFFERING_CONFIGS.keys())}"
            )

        self.env = ENVIRONMENTS[env_key]
        self.env_key = env_key
        self.offering = OFFERING_CONFIGS[offering_key]
        self.base_url = self.env["base_url"].rstrip("/")
        self.auth = HTTPBasicAuth(self.env["username"], self.env["password"])

        # Endpoints
        self.fsm_base = f"{self.base_url}/fscmRestApi/resources/{API_VERSION}"
        self.scim_base = f"{self.base_url}/hcmRestApi/scim"

        self._validate_config()

    def _validate_config(self):
        """Valida se as configurações básicas estão preenchidas."""
        if not self.env["username"] or not self.env["password"]:
            print(f"\n{'='*60}")
            print(f"  CONFIGURAÇÃO NECESSÁRIA - Ambiente: {self.env['name']}")
            print(f"{'='*60}")
            print(f"  Defina as credenciais via variáveis de ambiente:")
            env_prefix = self.env_key.upper()
            print(f"    export ORACLE_{env_prefix}_URL='https://pod.fa.dc.oraclecloud.com'")
            print(f"    export ORACLE_{env_prefix}_USER='seu_usuario'")
            print(f"    export ORACLE_{env_prefix}_PASS='sua_senha'")
            print(f"  Ou edite a seção ENVIRONMENTS neste script.")
            print(f"{'='*60}\n")
            raise SystemExit(1)

        if "YOUR-" in self.base_url:
            print(f"\n  ERRO: URL do ambiente '{self.env_key}' não configurada.")
            print(f"  Edite ENVIRONMENTS ou defina ORACLE_{self.env_key.upper()}_URL\n")
            raise SystemExit(1)

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Faz uma requisição HTTP com tratamento de erros."""
        headers = kwargs.pop("headers", {})
        headers.setdefault("Content-Type", "application/vnd.oracle.adf.resourceitem+json")
        headers.setdefault("Accept", "application/json")

        try:
            response = requests.request(
                method, url, auth=self.auth, headers=headers,
                timeout=120, **kwargs
            )
            if response.status_code >= 400:
                print(f"\n  ERRO HTTP {response.status_code}: {url}")
                try:
                    error_detail = response.json()
                    print(f"  Detalhes: {json.dumps(error_detail, indent=2, ensure_ascii=False)}")
                except Exception:
                    print(f"  Resposta: {response.text[:500]}")
                response.raise_for_status()
            return response
        except requests.exceptions.ConnectionError:
            print(f"\n  ERRO: Não foi possível conectar a {self.base_url}")
            print(f"  Verifique a URL e sua conectividade de rede.")
            raise
        except requests.exceptions.Timeout:
            print(f"\n  ERRO: Timeout na requisição para {url}")
            raise

    # ========================================================================
    # 1. DESCOBERTA - Listar Offerings e Functional Areas
    # ========================================================================

    def discover_offerings(self) -> list:
        """
        Lista todos os offerings disponíveis no ambiente.
        Útil para descobrir o código correto do offering.

        GET /fscmRestApi/resources/{version}/setupOfferings
        """
        print(f"\n  Descobrindo offerings no ambiente {self.env['name']}...")
        url = f"{self.fsm_base}/setupOfferings"
        response = self._request("GET", url)
        data = response.json()

        offerings = []
        for item in data.get("items", []):
            offering = {
                "code": item.get("OfferingCode", ""),
                "name": item.get("Name", ""),
                "enabled": item.get("EnabledFlag", False),
            }
            offerings.append(offering)

        print(f"  Encontrados {len(offerings)} offerings.\n")
        for o in offerings:
            status = "ATIVO" if o["enabled"] else "inativo"
            print(f"    [{status}] {o['code']} - {o['name']}")

        return offerings

    def discover_functional_areas(self, offering_code: str) -> list:
        """
        Lista as functional areas de um offering específico.

        GET /fscmRestApi/resources/{version}/setupOfferings/{code}/child/functionalAreas
        """
        print(f"\n  Descobrindo functional areas para '{offering_code}'...")
        url = f"{self.fsm_base}/setupOfferings/{offering_code}/child/functionalAreas"
        response = self._request("GET", url)
        data = response.json()

        areas = []
        for item in data.get("items", []):
            area = {
                "code": item.get("FunctionalAreaCode", ""),
                "name": item.get("Name", ""),
            }
            areas.append(area)

        print(f"  Encontradas {len(areas)} functional areas.\n")
        for a in areas:
            print(f"    {a['code']} - {a['name']}")

        return areas

    # ========================================================================
    # 2. EXPORTAÇÃO DE ROLES VIA FSM REST API
    # ========================================================================

    def export_roles(self, output_dir: str = ".") -> str:
        """
        Exporta custom roles do ambiente usando o FSM REST API.

        Fluxo:
          1. POST setupOfferingCSVExports - Inicia o processo de exportação
          2. GET (poll) - Aguarda conclusão do processo
          3. GET (download) - Baixa o ZIP com os CSVs

        Retorna o caminho do arquivo ZIP exportado.
        """
        offering_code = self.offering["offering_code"]
        fa_code = self.offering["functional_area_code"]

        print(f"\n{'='*60}")
        print(f"  EXPORTAÇÃO DE ROLES")
        print(f"  Ambiente: {self.env['name']}")
        print(f"  Offering: {self.offering['description']}")
        print(f"  Offering Code: {offering_code}")
        print(f"  Functional Area: {fa_code}")
        print(f"{'='*60}\n")

        # ----- Passo 1: Iniciar exportação -----
        print("  [1/3] Iniciando processo de exportação...")
        export_url = f"{self.fsm_base}/setupOfferingCSVExports"
        payload = {
            "OfferingCode": offering_code,
            "FunctionalAreaCode": fa_code,
            "SetupOfferingCSVExportProcess": [{"OfferingCode": offering_code}],
        }

        response = self._request("POST", export_url, json=payload)
        result = response.json()

        # Extrair ProcessId
        process_id = None
        export_processes = result.get("SetupOfferingCSVExportProcess", [])
        if export_processes:
            process_id = export_processes[0].get("ProcessId")

        if not process_id:
            # Tentar extrair de outra estrutura de resposta
            process_id = result.get("ProcessId")

        # Follow child link to SetupOfferingCSVExportProcess collection
        if not process_id and "links" in result:
            child_href = None
            for link in result.get("links", []):
                if link.get("name") == "SetupOfferingCSVExportProcess" and link.get("rel") == "child":
                    child_href = link.get("href", "")
                    break
            if child_href:
                print(f"  ProcessId nao encontrado inline. Consultando child link...")
                try:
                    child_resp = self._request("GET", child_href)
                    child_data = child_resp.json()
                    child_items = child_data.get("items", [])
                    if child_items and isinstance(child_items, list):
                        for item in child_items:
                            pid = item.get("ProcessId") or item.get("processId")
                            if pid:
                                process_id = pid
                                break
                    if not process_id:
                        process_id = child_data.get("ProcessId") or child_data.get("processId")
                except Exception as child_err:
                    print(f"  Erro ao consultar child link: {child_err}")

        if not process_id:
            print(f"  ERRO: Não foi possível obter o ProcessId da resposta.")
            print(f"  Resposta completa: {json.dumps(result, indent=2)}")
            raise RuntimeError("ProcessId não encontrado na resposta de exportação")

        print(f"  Process ID: {process_id}")

        # ----- Passo 2: Aguardar conclusão -----
        print(f"\n  [2/3] Aguardando conclusão do processo...")
        completed = self._wait_for_process(offering_code, process_id, "export")

        if not completed:
            raise RuntimeError(
                f"Processo de exportação não concluído dentro de "
                f"{MAX_WAIT_TIME}s. Process ID: {process_id}"
            )

        # ----- Passo 3: Baixar o arquivo ZIP -----
        print(f"\n  [3/3] Baixando arquivo de exportação...")
        download_url = (
            f"{self.fsm_base}/setupOfferingCSVExports/{offering_code}"
            f"/child/SetupOfferingCSVExportProcess/{process_id}"
            f"/child/SetupOfferingCSVExportProcessResult/{process_id}"
            f"/enclosure/FileContent"
        )

        response = self._request("GET", download_url, headers={"Accept": "*/*"})

        # O conteúdo pode vir como base64 ou binário direto
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(
            output_dir,
            f"oracle_roles_export_{self.env_key}_{timestamp}.zip"
        )

        content_type = response.headers.get("Content-Type", "")
        if "json" in content_type:
            # Resposta é base64 encoded dentro de JSON
            data = response.json()
            file_content = data.get("FileContent", data.get("fileContent", ""))
            if file_content:
                with open(output_file, "wb") as f:
                    f.write(base64.b64decode(file_content))
            else:
                print("  AVISO: Conteúdo do arquivo vazio na resposta JSON.")
                print(f"  Chaves disponíveis: {list(data.keys())}")
                with open(output_file, "wb") as f:
                    f.write(response.content)
        else:
            with open(output_file, "wb") as f:
                f.write(response.content)

        file_size = os.path.getsize(output_file)
        print(f"\n  Exportação concluída com sucesso!")
        print(f"  Arquivo: {output_file}")
        print(f"  Tamanho: {file_size:,} bytes")

        return output_file

    def _wait_for_process(
        self, offering_code: str, process_id: int, process_type: str
    ) -> bool:
        """Aguarda a conclusão de um processo de exportação/importação."""
        if process_type == "export":
            status_url = (
                f"{self.fsm_base}/setupOfferingCSVExports/{offering_code}"
                f"/child/SetupOfferingCSVExportProcess/{process_id}"
            )
        else:
            status_url = (
                f"{self.fsm_base}/setupOfferingCSVImports/{offering_code}"
                f"/child/SetupOfferingCSVImportProcess/{process_id}"
            )

        elapsed = 0
        while elapsed < MAX_WAIT_TIME:
            try:
                response = self._request("GET", status_url)
                result = response.json()

                # Verificar se o processo foi concluído
                completed = result.get("CompletedFlag", result.get("Completed", False))
                status = result.get("Status", result.get("ProcessStatus", "UNKNOWN"))

                if completed or status in ("COMPLETED", "SUCCEEDED", "SUCCESS"):
                    print(f"\r  Status: CONCLUÍDO (tempo: {elapsed}s)        ")
                    return True
                elif status in ("FAILED", "ERROR", "CANCELLED"):
                    error_msg = result.get("ErrorMessage", result.get("StatusDetail", ""))
                    print(f"\r  Status: FALHOU - {error_msg}        ")
                    return False
                else:
                    print(
                        f"\r  Status: {status} (aguardando... {elapsed}s/{MAX_WAIT_TIME}s)",
                        end="", flush=True
                    )
            except requests.exceptions.HTTPError:
                print(f"\r  Aguardando processo iniciar... ({elapsed}s)", end="", flush=True)

            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL

        print(f"\n  TIMEOUT: Processo não concluiu em {MAX_WAIT_TIME}s")
        return False

    # ========================================================================
    # 3. IMPORTAÇÃO DE ROLES VIA FSM REST API
    # ========================================================================

    def import_roles(self, zip_file_path: str) -> bool:
        """
        Importa custom roles no ambiente a partir de um arquivo ZIP exportado.

        Fluxo:
          1. POST setupOfferingCSVImports - Envia o ZIP e inicia a importação
          2. GET (poll) - Aguarda conclusão do processo
          3. Executa "Import Users and Roles into Application Security" (manual)

        Retorna True se a importação foi bem-sucedida.
        """
        if not os.path.exists(zip_file_path):
            raise FileNotFoundError(f"Arquivo não encontrado: {zip_file_path}")

        offering_code = self.offering["offering_code"]
        fa_code = self.offering["functional_area_code"]

        print(f"\n{'='*60}")
        print(f"  IMPORTAÇÃO DE ROLES")
        print(f"  Ambiente: {self.env['name']}")
        print(f"  Offering: {self.offering['description']}")
        print(f"  Arquivo: {zip_file_path}")
        print(f"{'='*60}\n")

        # ----- Passo 1: Upload e início da importação -----
        print("  [1/2] Enviando arquivo e iniciando importação...")

        # Ler o arquivo e converter para base64
        with open(zip_file_path, "rb") as f:
            file_content = base64.b64encode(f.read()).decode("utf-8")

        import_url = f"{self.fsm_base}/setupOfferingCSVImports"
        payload = {
            "OfferingCode": offering_code,
            "FunctionalAreaCode": fa_code,
            "FileContent": file_content,
            "FileName": os.path.basename(zip_file_path),
            "ContentType": "application/zip",
        }

        response = self._request("POST", import_url, json=payload)
        result = response.json()

        # Extrair ProcessId
        process_id = None
        import_processes = result.get("SetupOfferingCSVImportProcess", [])
        if import_processes:
            process_id = import_processes[0].get("ProcessId")
        if not process_id:
            process_id = result.get("ProcessId")

        if not process_id:
            print(f"  ERRO: Não foi possível obter o ProcessId.")
            print(f"  Resposta: {json.dumps(result, indent=2)}")
            raise RuntimeError("ProcessId não encontrado na resposta de importação")

        print(f"  Process ID: {process_id}")

        # ----- Passo 2: Aguardar conclusão -----
        print(f"\n  [2/2] Aguardando conclusão da importação...")
        completed = self._wait_for_process(offering_code, process_id, "import")

        if completed:
            print(f"\n  Importação concluída com sucesso!")
            print(f"\n  {'='*50}")
            print(f"  AÇÃO MANUAL NECESSÁRIA:")
            print(f"  {'='*50}")
            print(f"  Após a importação, execute o scheduled process:")
            print(f"  'Import Users and Roles into Application Security'")
            print(f"  ")
            print(f"  Navegação no Oracle Fusion:")
            print(f"    Navigator > My Enterprise > Setup and Maintenance")
            print(f"    > Users and Security")
            print(f"    > Import Users and Roles into Application Security")
            print(f"  {'='*50}")
            return True
        else:
            print(f"\n  FALHA na importação. Verifique os logs no ambiente.")
            return False

    # ========================================================================
    # 4. SCIM API - Listar e Verificar Roles
    # ========================================================================

    def list_roles(self, filter_custom: bool = True, max_count: int = 200) -> list:
        """
        Lista roles usando a SCIM REST API.

        GET /hcmRestApi/scim/Roles

        Parâmetros:
          filter_custom: Se True, tenta filtrar apenas roles customizadas
          max_count: Número máximo de roles a retornar
        """
        print(f"\n{'='*60}")
        print(f"  LISTAGEM DE ROLES (SCIM API)")
        print(f"  Ambiente: {self.env['name']}")
        print(f"{'='*60}\n")

        url = f"{self.scim_base}/Roles"
        params = {
            "count": max_count,
            "startIndex": 1,
        }

        if filter_custom:
            # Filtrar roles que começam com prefixo customizado
            # Roles customizadas geralmente têm prefixo diferente de ORA_
            params["filter"] = 'category eq "ORA_DEFAULT"'

        response = self._request("GET", url, params=params)
        data = response.json()

        resources = data.get("Resources", data.get("resources", []))
        total = data.get("totalResults", len(resources))

        print(f"  Total de roles encontradas: {total}")
        print(f"  Exibindo: {len(resources)}\n")

        roles = []
        for r in resources:
            role = {
                "id": r.get("id", ""),
                "name": r.get("name", r.get("displayName", "")),
                "displayName": r.get("displayName", ""),
                "description": r.get("description", ""),
                "category": r.get("category", ""),
            }
            roles.append(role)
            print(f"    {role['name']}")
            if role["description"]:
                print(f"      {role['description'][:80]}")

        return roles

    def verify_role_exists(self, role_name: str) -> bool:
        """Verifica se uma role específica existe no ambiente via SCIM API."""
        print(f"  Verificando role '{role_name}'...")
        url = f"{self.scim_base}/Roles"
        params = {
            "filter": f'displayName eq "{role_name}"',
            "count": 1,
        }

        try:
            response = self._request("GET", url, params=params)
            data = response.json()
            resources = data.get("Resources", data.get("resources", []))
            exists = len(resources) > 0
            print(f"    -> {'Encontrada' if exists else 'NÃO encontrada'}")
            return exists
        except Exception as e:
            print(f"    -> Erro ao verificar: {e}")
            return False

    # ========================================================================
    # 5. VERIFICAÇÃO DE STATUS
    # ========================================================================

    def check_process_status(self, process_id: int) -> dict:
        """Verifica o status de um processo de exportação/importação."""
        offering_code = self.offering["offering_code"]

        print(f"\n  Verificando status do processo {process_id}...")

        # Tentar como exportação primeiro
        for process_type, resource in [
            ("Exportação", "setupOfferingCSVExports"),
            ("Importação", "setupOfferingCSVImports"),
        ]:
            child_name = resource.replace("setupOffering", "SetupOffering")
            child_name = child_name.replace("Exports", "ExportProcess")
            child_name = child_name.replace("Imports", "ImportProcess")

            url = (
                f"{self.fsm_base}/{resource}/{offering_code}"
                f"/child/{child_name}/{process_id}"
            )
            try:
                response = self._request("GET", url)
                result = response.json()
                print(f"  Tipo: {process_type}")
                print(f"  Status: {result.get('Status', result.get('ProcessStatus', 'N/A'))}")
                print(f"  Concluído: {result.get('CompletedFlag', 'N/A')}")
                return result
            except requests.exceptions.HTTPError:
                continue

        print(f"  Processo {process_id} não encontrado.")
        return {}

    # ========================================================================
    # 6. MIGRAÇÃO COMPLETA (DEV → UAT)
    # ========================================================================

    @staticmethod
    def migrate(source_env: str, target_env: str, offering: str = DEFAULT_OFFERING):
        """
        Executa o fluxo completo de migração:
          1. Exporta roles do ambiente de origem
          2. Importa roles no ambiente de destino
          3. Fornece instruções para passos manuais
        """
        print(f"\n{'#'*60}")
        print(f"  MIGRAÇÃO COMPLETA DE ROLES")
        print(f"  Origem: {source_env.upper()} → Destino: {target_env.upper()}")
        print(f"{'#'*60}")

        # Exportar
        source = OracleFusionRoleMigration(source_env, offering)
        export_file = source.export_roles(output_dir=".")

        # Importar
        target = OracleFusionRoleMigration(target_env, offering)
        success = target.import_roles(export_file)

        if success:
            print(f"\n{'#'*60}")
            print(f"  MIGRAÇÃO CONCLUÍDA COM SUCESSO!")
            print(f"{'#'*60}")
            print(f"\n  Arquivo exportado preservado em: {export_file}")
            print(f"\n  PRÓXIMOS PASSOS:")
            print(f"  1. Acesse o ambiente {target_env.upper()}")
            print(f"  2. Execute: 'Import Users and Roles into Application Security'")
            print(f"     Navigator > Setup and Maintenance > Users and Security")
            print(f"  3. Verifique as roles na Security Console")
            print(f"  4. Teste as permissões com um usuário de teste")
        else:
            print(f"\n  MIGRAÇÃO FALHOU. Verifique os erros acima.")

        return success


# ============================================================================
# CLI - Interface de Linha de Comando
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Oracle Fusion Cloud - Migração de Roles entre Ambientes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Descobrir offerings disponíveis
  %(prog)s discover --env dev

  # Descobrir functional areas de um offering
  %(prog)s discover --env dev --offering-code FIN_FSCM_OFFERING

  # Exportar roles do DEV
  %(prog)s export --env dev --offering financials

  # Importar roles no UAT
  %(prog)s import --env uat --file oracle_roles_export_dev_20260212.zip

  # Migração completa DEV → UAT
  %(prog)s migrate --source dev --target uat

  # Listar roles via SCIM API
  %(prog)s list-roles --env dev

  # Verificar status de um processo
  %(prog)s status --env dev --process-id 300100068271744
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Comando a executar")

    # -- discover --
    p_discover = subparsers.add_parser("discover", help="Descobrir offerings e functional areas")
    p_discover.add_argument("--env", required=True, choices=ENVIRONMENTS.keys())
    p_discover.add_argument("--offering-code", help="Código do offering para listar functional areas")

    # -- export --
    p_export = subparsers.add_parser("export", help="Exportar roles de um ambiente")
    p_export.add_argument("--env", required=True, choices=ENVIRONMENTS.keys())
    p_export.add_argument("--offering", default=DEFAULT_OFFERING, choices=OFFERING_CONFIGS.keys())
    p_export.add_argument("--output-dir", default=".", help="Diretório para salvar o arquivo")

    # -- import --
    p_import = subparsers.add_parser("import", help="Importar roles em um ambiente")
    p_import.add_argument("--env", required=True, choices=ENVIRONMENTS.keys())
    p_import.add_argument("--file", required=True, help="Arquivo ZIP exportado")
    p_import.add_argument("--offering", default=DEFAULT_OFFERING, choices=OFFERING_CONFIGS.keys())

    # -- migrate --
    p_migrate = subparsers.add_parser("migrate", help="Migração completa entre ambientes")
    p_migrate.add_argument("--source", required=True, choices=ENVIRONMENTS.keys())
    p_migrate.add_argument("--target", required=True, choices=ENVIRONMENTS.keys())
    p_migrate.add_argument("--offering", default=DEFAULT_OFFERING, choices=OFFERING_CONFIGS.keys())

    # -- list-roles --
    p_list = subparsers.add_parser("list-roles", help="Listar roles via SCIM API")
    p_list.add_argument("--env", required=True, choices=ENVIRONMENTS.keys())
    p_list.add_argument("--all", action="store_true", help="Listar todas as roles (não apenas custom)")
    p_list.add_argument("--count", type=int, default=200, help="Máximo de roles a retornar")

    # -- verify --
    p_verify = subparsers.add_parser("verify", help="Verificar se uma role existe")
    p_verify.add_argument("--env", required=True, choices=ENVIRONMENTS.keys())
    p_verify.add_argument("--role-name", required=True, help="Nome da role a verificar")

    # -- status --
    p_status = subparsers.add_parser("status", help="Verificar status de um processo")
    p_status.add_argument("--env", required=True, choices=ENVIRONMENTS.keys())
    p_status.add_argument("--process-id", type=int, required=True)
    p_status.add_argument("--offering", default=DEFAULT_OFFERING, choices=OFFERING_CONFIGS.keys())

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == "discover":
            client = OracleFusionRoleMigration(args.env)
            if args.offering_code:
                client.discover_functional_areas(args.offering_code)
            else:
                client.discover_offerings()

        elif args.command == "export":
            client = OracleFusionRoleMigration(args.env, args.offering)
            client.export_roles(output_dir=args.output_dir)

        elif args.command == "import":
            client = OracleFusionRoleMigration(args.env, args.offering)
            client.import_roles(args.file)

        elif args.command == "migrate":
            if args.source == args.target:
                print("ERRO: Origem e destino devem ser ambientes diferentes.")
                return
            OracleFusionRoleMigration.migrate(args.source, args.target, args.offering)

        elif args.command == "list-roles":
            client = OracleFusionRoleMigration(args.env)
            client.list_roles(filter_custom=not args.all, max_count=args.count)

        elif args.command == "verify":
            client = OracleFusionRoleMigration(args.env)
            client.verify_role_exists(args.role_name)

        elif args.command == "status":
            client = OracleFusionRoleMigration(args.env, args.offering)
            client.check_process_status(args.process_id)

    except KeyboardInterrupt:
        print("\n\n  Operação cancelada pelo usuário.")
    except Exception as e:
        print(f"\n  ERRO: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
