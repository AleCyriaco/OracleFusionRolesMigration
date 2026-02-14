#!/usr/bin/env python3
"""
OracleFusionRolesMigration - Backend Server
===========================================

Uso:
  pip install flask requests flask-cors
  python3 oracle_migration_server.py

  Depois acesse: http://localhost:5050

Autor: Gerado para Alê - Virttus
"""

import base64
import json
import os
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    from flask import Flask, request, jsonify, send_file, send_from_directory
    from flask_cors import CORS
except ImportError:
    print("Dependencias necessarias nao encontradas.")
    print("Instale com: pip install flask requests flask-cors")
    sys.exit(1)

import requests as http_requests
from requests.auth import HTTPBasicAuth

# ============================================================
# App Setup
# ============================================================
app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app)

EXPORT_CACHE_DIR = tempfile.mkdtemp(prefix="oracle_migration_")

# API versions to try (most common first)
API_VERSIONS = [
    "11.13.18.05",
    "11.13.18.06",
    "11.13.18.04",
    "11.13.18.03",
    "latest",
]

# Cache detected API version per base_url to avoid re-detecting
_api_version_cache = {}

# Minimal roles required for this solution to work reliably.
REQUIRED_ACCESS_ROLES = [
    {
        "code": "ORA_ASM_APPLICATION_IMPLEMENTATION_CONSULTANT_JOB",
        "name": "Application Implementation Consultant",
        "alternativeCodes": [
            "ORA_ASM_FUNCTIONAL_SETUPS_USER_ABSTRACT",
            "ORA_ASM_APPLICATION_IMPLEMENTATION_MANAGER_JOB",
            "ORA_ASM_APPLICATION_IMPLEMENTATION_ADMINISTRATOR_JOB",
        ],
        "aliases": [
            "application implementation consultant",
            "application implementation manager",
            "application implementation administrator",
            "export import functional setups user",
            "functional setups user",
        ],
        "requiredFor": ["export", "import", "full"],
    },
]

OPTIONAL_ACCESS_ROLES = [
    {
        "code": "ORA_FND_IT_SECURITY_MANAGER_JOB",
        "name": "IT Security Manager",
        "aliases": ["it security manager"],
        "reason": "Enables SCIM role introspection for richer permission validation.",
    }
]


def get_payload(required_fields=None):
    """
    Parse and validate JSON payload.
    When authType=sso, replaces username/password requirements with tokenUrl/clientId/clientSecret.
    Returns (data, error_response) where error_response is a Flask response tuple or None.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, (jsonify({"error": "Corpo JSON invalido ou ausente"}), 400)

    if required_fields:
        auth_type = data.get("authType", "basic")
        fields = list(required_fields)
        if auth_type == "sso":
            # Replace username/password with cookies field
            for f in ("username", "password"):
                if f in fields:
                    fields.remove(f)
            if "cookies" not in fields:
                fields.append("cookies")
        missing = [field for field in fields if not data.get(field)]
        if missing:
            return None, (
                jsonify({"error": f"Campos obrigatorios ausentes: {', '.join(missing)}"}),
                400,
            )

    # Sanitize URL: strip path/query to just scheme://host
    if data.get("url"):
        parsed = urlparse(data["url"])
        data["url"] = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")

    return data, None


# ============================================================
# Serve Frontend
# ============================================================
@app.route("/")
def index():
    return send_file("oracle_migration_gui.html")


def resolve_auth(data):
    """
    Resolve auth credentials from request payload.
    For authType=sso: returns session cookies captured from browser SSO login.
    For authType=basic (default): returns username/password as-is.
    Returns dict with keys: username, password, token, cookies.
    """
    auth_type = data.get("authType", "basic")
    if auth_type == "sso":
        return {"token": None, "username": None, "password": None, "cookies": data.get("cookies", "")}
    return {"token": None, "username": data["username"], "password": data["password"], "cookies": None}


# ============================================================
# Helper: CSRF token cache for cookie-based sessions
# ============================================================
_csrf_token_cache = {}  # base_url -> csrf_token


def _fetch_csrf_token(base_url, cookies):
    """Fetch CSRF token required for POST/PUT/DELETE with session cookies."""
    cached = _csrf_token_cache.get(base_url)
    if cached:
        return cached
    url = f"{base_url.rstrip('/')}/fscmRestApi/resources/latest"
    headers = {
        "Cookie": cookies,
        "Accept": "application/json",
    }
    try:
        resp = http_requests.get(url, headers=headers, timeout=30, verify=True)
        # Oracle returns the CSRF token in the response header
        csrf = resp.headers.get("X-ORACLE-DMS-ECID") or resp.headers.get("X-Oracle-Csrf-Token")
        if not csrf:
            # Fallback: try a HEAD request with Fetch header
            headers["X-CSRF-Token"] = "Fetch"
            resp2 = http_requests.head(url, headers=headers, timeout=30, verify=True)
            csrf = resp2.headers.get("X-CSRF-Token") or resp2.headers.get("X-Oracle-Csrf-Token")
        if csrf:
            _csrf_token_cache[base_url] = csrf
        return csrf
    except Exception as e:
        print(f"[WARN] Failed to fetch CSRF token: {e}", flush=True)
        return None


# ============================================================
# Helper: Make Oracle API call
# ============================================================
def oracle_request(method, base_url, path, username=None, password=None, token=None, cookies=None, **kwargs):
    """Proxy request to Oracle Fusion Cloud REST API."""
    url = f"{base_url.rstrip('/')}{path}"
    headers = kwargs.pop("headers", {})
    headers.setdefault("Content-Type", "application/vnd.oracle.adf.resourceitem+json")
    headers.setdefault("Accept", "application/json")

    auth = None
    if cookies:
        headers["Cookie"] = cookies
        # Oracle REST API requires CSRF token for mutating requests with session cookies
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            csrf = _fetch_csrf_token(base_url, cookies)
            if csrf:
                headers["X-CSRF-Token"] = csrf
                headers["X-Oracle-Csrf-Token"] = csrf
    elif token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        auth = HTTPBasicAuth(username, password)

    resp = http_requests.request(
        method, url, auth=auth, headers=headers, timeout=120,
        verify=True, **kwargs
    )
    return resp


def detect_api_version(base_url, username=None, password=None, token=None, cookies=None):
    """
    Auto-detecta a versão correta da REST API tentando múltiplas versões.
    Retorna a primeira que responde com 200.
    """
    base_url = base_url.rstrip("/")

    # Check cache
    if base_url in _api_version_cache:
        return _api_version_cache[base_url]

    for version in API_VERSIONS:
        try:
            path = f"/fscmRestApi/resources/{version}/setupOfferings?limit=1&onlyData=true"
            resp = oracle_request("GET", base_url, path, username, password, token=token, cookies=cookies)
            if resp.status_code == 200:
                _api_version_cache[base_url] = version
                return version
            # 401/403 means the endpoint exists but auth failed - still a valid version
            if resp.status_code in (401, 403):
                _api_version_cache[base_url] = version
                return version
        except Exception:
            continue

    # Fallback: try describe endpoint
    for version in API_VERSIONS:
        try:
            path = f"/fscmRestApi/resources/{version}/describe"
            resp = oracle_request("GET", base_url, path, username, password, token=token, cookies=cookies)
            if resp.status_code in (200, 401, 403):
                _api_version_cache[base_url] = version
                return version
        except Exception:
            continue

    return API_VERSIONS[0]  # Default fallback


def get_api_version(base_url, username=None, password=None, token=None, cookies=None):
    """Get cached or detect API version."""
    return detect_api_version(base_url, username, password, token=token, cookies=cookies)


def _to_positive_int(value):
    """Convert value to positive int when possible."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        iv = int(value)
        return iv if iv > 0 else None
    if isinstance(value, str):
        txt = value.strip()
        if txt.isdigit():
            iv = int(txt)
            return iv if iv > 0 else None
    return None


def _deep_find_process_id(obj, depth=0):
    """Recursively search for a ProcessId-like field in a nested dict/list."""
    if depth > 5:
        return None
    if isinstance(obj, dict):
        for key, val in obj.items():
            k = key.lower()
            if ("process" in k or "request" in k or "job" in k) and "id" in k:
                pid = _to_positive_int(val)
                if pid:
                    return pid
            if k in ("reqstid", "requestid", "req_id", "essrequestid", "loadrequestid"):
                pid = _to_positive_int(val)
                if pid:
                    return pid
            # Recurse into nested dicts/lists
            found = _deep_find_process_id(val, depth + 1)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _deep_find_process_id(item, depth + 1)
            if found:
                return found
    return None


def _normalize_user_roles(scim_payload):
    """Extract role display strings from SCIM user payload."""
    resources = scim_payload.get("Resources", scim_payload.get("resources", []))
    if not resources:
        return []

    roles = resources[0].get("roles", [])
    out = []
    for role in roles:
        if isinstance(role, dict):
            candidates = [
                role.get("display"),
                role.get("value"),
                role.get("name"),
                role.get("code"),
            ]
            display = next((str(x) for x in candidates if x), "")
            if not display:
                display = json.dumps(role, ensure_ascii=False)
            out.append(display)
        elif role is not None:
            out.append(str(role))
    return out


def _role_matches(role_text, role_spec):
    txt = (role_text or "").lower()
    checks = [role_spec.get("code", ""), role_spec.get("name", "")]
    checks.extend(role_spec.get("aliases", []))
    checks.extend(role_spec.get("alternativeCodes", []))
    for token in checks:
        token = str(token).lower().strip()
        if token and token in txt:
            return True
    return False


def _check_required_roles(detected_roles, mode):
    """Return missing required roles for the selected operation mode."""
    missing = []
    for spec in REQUIRED_ACCESS_ROLES:
        if mode not in spec.get("requiredFor", []):
            continue
        if not any(_role_matches(role, spec) for role in detected_roles):
            missing.append({
                "code": spec["code"],
                "name": spec["name"],
                "requiredFor": spec["requiredFor"],
            })
    return missing


# ============================================================
# API: Test Connection
# ============================================================
@app.route("/api/test-connection", methods=["POST"])
def test_connection():
    """
    Testa a conexão com um ambiente Oracle Fusion.
    Tenta múltiplos endpoints para garantir que o pod está acessível.
    """
    data, err = get_payload(["url", "username", "password"])
    if err:
        return err

    url = data["url"].rstrip("/")
    try:
        creds = resolve_auth(data)
    except Exception as e:
        return jsonify({"error": f"Falha na autenticacao SSO/OAuth2: {str(e)[:300]}"}), 401
    username = creds["username"]
    password = creds["password"]
    token = creds["token"]
    cookies = creds["cookies"]

    # Ensure https
    if not url.startswith("http"):
        url = "https://" + url

    # List of endpoints to try (from most specific to most generic)
    test_endpoints = [
        # FSM REST API (multiple versions)
        ("/fscmRestApi/resources/{v}/setupOfferings?limit=1&onlyData=true", "FSM REST API"),
        # SCIM API
        ("/hcmRestApi/scim/Roles?count=1", "SCIM API"),
        # Generic ADF describe
        ("/fscmRestApi/resources/{v}/describe", "FSM Describe"),
        # Simple connectivity test
        ("/fscmRestApi/resources/latest/setupOfferings?limit=1", "FSM Latest"),
    ]

    last_error = ""
    detected_version = None

    for path_template, endpoint_name in test_endpoints:
        for version in API_VERSIONS:
            path = path_template.replace("{v}", version)
            try:
                resp = oracle_request("GET", url, path, username, password, token=token, cookies=cookies)

                if resp.status_code == 200:
                    detected_version = version
                    _api_version_cache[url] = version
                    warning = None
                    if endpoint_name == "SCIM API":
                        warning = (
                            "SCIM respondeu, mas a API FSM (setupOfferings/setupOfferingCSVExports) "
                            "nao foi validada. Exportacao pode falhar por permissao."
                        )
                    return jsonify({
                        "status": "ok",
                        "message": f"Conexao OK via {endpoint_name} (API v{version})",
                        "apiVersion": version,
                        "endpoint": endpoint_name,
                        "warning": warning
                    })
                elif resp.status_code == 401:
                    return jsonify({
                        "error": "Credenciais invalidas (HTTP 401). Verifique usuario e senha."
                    }), 401
                elif resp.status_code == 403:
                    # 403 means auth worked but user lacks permission - connection IS valid
                    detected_version = version
                    _api_version_cache[url] = version
                    return jsonify({
                        "status": "ok",
                        "message": f"Conexao OK via {endpoint_name} (API v{version}) - Nota: usuario pode precisar de roles adicionais",
                        "apiVersion": version,
                        "endpoint": endpoint_name,
                        "warning": "Usuario autenticado mas pode nao ter todas as permissoes necessarias (HTTP 403)"
                    })
                elif resp.status_code == 404:
                    last_error = f"{endpoint_name} v{version}: endpoint nao encontrado (404)"
                    continue  # Try next version/endpoint
                else:
                    last_error = f"{endpoint_name} v{version}: HTTP {resp.status_code}"
                    continue
            except http_requests.exceptions.SSLError as e:
                return jsonify({"error": f"Erro SSL ao conectar: {str(e)[:150]}"}), 502
            except http_requests.exceptions.ConnectionError:
                return jsonify({"error": f"Nao foi possivel conectar a {url}. Verifique a URL e sua rede."}), 502
            except http_requests.exceptions.Timeout:
                return jsonify({"error": "Timeout na conexao. O servidor pode estar lento ou inacessivel."}), 504
            except Exception as e:
                last_error = str(e)
                continue

        # If we get here for non-versioned endpoints, no need to try all versions
        if "{v}" not in path_template:
            break

    # Nothing worked
    return jsonify({
        "error": f"Nenhum endpoint REST respondeu. Ultimo erro: {last_error}. "
                 f"Verifique se a URL esta correta e se o pod esta ativo."
    }), 404


# ============================================================
# API: Validate Access and Required Roles
# ============================================================
@app.route("/api/validate-access", methods=["POST"])
def validate_access():
    """
    Validate if the user has the minimum access required for the selected operation mode.
    It checks:
      1) FSM endpoint reachability/permissions
      2) SCIM user roles (when available)
    """
    data, err = get_payload(["url", "username", "password"])
    if err:
        return err

    url = data["url"].rstrip("/")
    try:
        creds = resolve_auth(data)
    except Exception as e:
        return jsonify({"error": f"Falha na autenticacao SSO/OAuth2: {str(e)[:300]}"}), 401
    username = creds["username"]
    password = creds["password"]
    token = creds["token"]
    cookies = creds["cookies"]
    mode = str(data.get("mode", "export")).lower()
    if mode not in ("export", "import", "full"):
        mode = "export"
    offering_code = data.get("offeringCode", "FIN_FSCM_OFFERING")

    if not url.startswith("http"):
        url = "https://" + url

    checks = {}
    warnings = []
    blocking_reasons = []
    detected_roles = []
    missing_roles = []

    def run_get_check(key, path):
        try:
            resp = oracle_request("GET", url, path, username, password, token=token, cookies=cookies)
            checks[key] = {"status": resp.status_code, "ok": resp.status_code == 200, "path": path}
            return resp
        except Exception as ex:
            checks[key] = {"status": "ERROR", "ok": False, "path": path, "error": str(ex)[:300]}
            return None

    try:
        api_version = get_api_version(url, username, password, token=token, cookies=cookies)
    except Exception as ex:
        return jsonify({
            "status": "blocked",
            "canProceed": False,
            "message": "Nao foi possivel detectar a versao da API.",
            "blockingReasons": [str(ex)],
            "requiredRoles": [
                {"code": r["code"], "name": r["name"]}
                for r in REQUIRED_ACCESS_ROLES if mode in r.get("requiredFor", [])
            ],
            "optionalRoles": [
                {"code": r["code"], "name": r["name"], "reason": r["reason"]}
                for r in OPTIONAL_ACCESS_ROLES
            ],
        }), 200

    # Core setup check
    setup_path = f"/fscmRestApi/resources/{api_version}/setupOfferings?limit=1&onlyData=true"
    setup_resp = run_get_check("setupOfferings", setup_path)
    if setup_resp is not None:
        if setup_resp.status_code == 401:
            blocking_reasons.append("Credenciais invalidas para API FSM (HTTP 401).")
        elif setup_resp.status_code == 403:
            blocking_reasons.append("Usuario autenticado sem permissao FSM basica (HTTP 403).")

    if mode in ("export", "full"):
        exp_path = f"/fscmRestApi/resources/{api_version}/setupOfferingCSVExports/{offering_code}"
        exp_resp = run_get_check("csvExportResource", exp_path)
        if exp_resp is not None:
            if exp_resp.status_code == 403:
                blocking_reasons.append(
                    "Sem permissao para recurso FSM de exportacao (setupOfferingCSVExports)."
                )
            elif exp_resp.status_code == 404:
                warnings.append(
                    f"Offering '{offering_code}' nao encontrado para exportacao (HTTP 404)."
                )

    if mode in ("import", "full"):
        imp_path = f"/fscmRestApi/resources/{api_version}/setupOfferingCSVImports/{offering_code}"
        imp_resp = run_get_check("csvImportResource", imp_path)
        if imp_resp is not None:
            if imp_resp.status_code == 403:
                blocking_reasons.append(
                    "Sem permissao para recurso FSM de importacao (setupOfferingCSVImports)."
                )
            elif imp_resp.status_code == 404:
                warnings.append(
                    f"Offering '{offering_code}' nao encontrado para importacao (HTTP 404)."
                )

    # Try role introspection via SCIM (skip user filter in SSO mode since username may be unavailable)
    if username:
        scim_path = f"/hcmRestApi/scim/Users?filter=userName eq \"{username}\"&attributes=roles&count=1"
    else:
        scim_path = "/hcmRestApi/scim/Users?attributes=roles&count=1"
    scim_resp = run_get_check("scimUserRoles", scim_path)
    if scim_resp is not None and scim_resp.status_code == 200:
        try:
            detected_roles = _normalize_user_roles(scim_resp.json())
        except Exception as ex:
            warnings.append(f"Falha ao interpretar roles via SCIM: {str(ex)[:150]}")
    elif scim_resp is not None:
        warnings.append(
            f"Nao foi possivel ler roles via SCIM (HTTP {scim_resp.status_code}). "
            "Validacao de roles foi limitada a permissao de endpoint."
        )
    else:
        warnings.append(
            "Nao foi possivel consultar SCIM para listar roles do usuario."
        )

    if detected_roles:
        missing_roles = _check_required_roles(detected_roles, mode)
        if missing_roles:
            blocking_reasons.append(
                "Usuario sem todas as roles minimas obrigatorias para esta operacao."
            )

    can_proceed = len(blocking_reasons) == 0
    required_roles = [
        {"code": r["code"], "name": r["name"]}
        for r in REQUIRED_ACCESS_ROLES if mode in r.get("requiredFor", [])
    ]
    optional_roles = [
        {"code": r["code"], "name": r["name"], "reason": r["reason"]}
        for r in OPTIONAL_ACCESS_ROLES
    ]

    if can_proceed:
        message = "Acessos minimos validados. Operacao pode prosseguir."
    else:
        message = "Validacao bloqueou a execucao. Ajuste as roles/permissoes antes de continuar."

    return jsonify({
        "status": "ok" if can_proceed else "blocked",
        "canProceed": can_proceed,
        "message": message,
        "mode": mode,
        "offeringCode": offering_code,
        "apiVersion": api_version,
        "requiredRoles": required_roles,
        "optionalRoles": optional_roles,
        "detectedRoles": detected_roles[:80],
        "missingRoles": missing_roles,
        "checks": checks,
        "warnings": warnings,
        "blockingReasons": blocking_reasons,
    })


# ============================================================
# API: Export Roles
# ============================================================
@app.route("/api/export", methods=["POST"])
def export_roles():
    """
    Inicia o processo de exportação de roles via FSM REST API.
    Auto-detecta a versão da API.
    """
    data, err = get_payload(["url", "username", "password", "offeringCode", "faCode"])
    if err:
        return err

    url = data["url"].rstrip("/")
    try:
        creds = resolve_auth(data)
    except Exception as e:
        return jsonify({"error": f"Falha na autenticacao SSO/OAuth2: {str(e)[:300]}"}), 401
    username = creds["username"]
    password = creds["password"]
    token = creds["token"]
    cookies = creds["cookies"]
    offering_code = data["offeringCode"]
    fa_code = data["faCode"]

    try:
        api_version = get_api_version(url, username, password, token=token, cookies=cookies)
        process_id = None
        attempt_errors = []
        child_collection_path = None

        # ══════════════════════════════════════════════════════════
        # METHOD 1 (PRIMARY): FSM REST API - setupOfferingCSVExports
        # Per Oracle docs, POST must include SetupOfferingCSVExportProcess
        # array to trigger the export and get ProcessId inline.
        # ══════════════════════════════════════════════════════════
        print(f"\n[EXPORT] Method 1 (FSM): POST setupOfferingCSVExports with child array...", flush=True)
        path = f"/fscmRestApi/resources/{api_version}/setupOfferingCSVExports"

        # The critical fix: include SetupOfferingCSVExportProcess array in POST body
        fa_candidates = []
        for candidate in [
            fa_code,
            "ORA_ASE_USERS_AND_SECURITY",
            "ORA_ASE_APPLICATION_SECURITY",
            None,  # fallback sem FA explícita
        ]:
            if candidate not in fa_candidates:
                fa_candidates.append(candidate)

        resp = None
        raw_text = ""
        for idx, fa_candidate in enumerate(fa_candidates, start=1):
            payload = {
                "OfferingCode": offering_code,
                "SetupOfferingCSVExportProcess": [
                    {
                        "OfferingCode": offering_code,
                    }
                ],
            }
            if fa_candidate:
                payload["FunctionalAreaCode"] = fa_candidate

            print(f"[EXPORT] POST attempt {idx}/{len(fa_candidates)} {url}{path}", flush=True)
            print(f"[EXPORT] Payload: {json.dumps(payload)}", flush=True)

            resp = oracle_request("POST", url, path, username, password, token=token, cookies=cookies, json=payload)
            print(f"[EXPORT] HTTP {resp.status_code}", flush=True)
            raw_text = resp.text[:3000]
            print(f"[EXPORT] Response:\n{raw_text}", flush=True)
            print(f"[EXPORT] Response Headers: {dict(resp.headers)}", flush=True)

            if resp.status_code in (401, 403):
                return jsonify({
                    "error": (
                        "Sem permissao para exportar via FSM REST API "
                        f"(HTTP {resp.status_code})."
                    ),
                    "hint": (
                        "Adicione ao usuario a role ORA_ASM_APPLICATION_IMPLEMENTATION_CONSULTANT_JOB "
                        "(Application Implementation Consultant)."
                    ),
                    "apiVersion": api_version,
                    "path": path,
                    "responseText": raw_text,
                }), 403

            attempt_errors.append({
                "attempt": idx,
                "faCode": fa_candidate or "(none)",
                "status": resp.status_code,
                "response": raw_text[:500],
            })

            if resp.status_code < 400:
                break

        if resp and resp.status_code < 400:
            result = resp.json()

            # Pattern A: ProcessId inline in SetupOfferingCSVExportProcess array
            export_procs = result.get("SetupOfferingCSVExportProcess", [])
            if export_procs and isinstance(export_procs, list):
                for proc in export_procs:
                    pid = proc.get("ProcessId") or proc.get("processId")
                    if pid:
                        process_id = int(pid)
                        print(f"[EXPORT] ✓ ProcessId from inline array: {process_id}", flush=True)
                        break

            # Pattern B: ProcessId at top level
            if not process_id:
                pid = (
                    result.get("ProcessId")
                    or result.get("processId")
                    or result.get("RequestId")
                    or result.get("requestId")
                    or result.get("ReqstId")
                    or result.get("ESSRequestId")
                    or result.get("LoadRequestId")
                )
                if pid:
                    process_id = int(pid)
                    print(f"[EXPORT] ✓ ProcessId from top level: {process_id}", flush=True)

            # Pattern B2: ProcessId in HTTP Location header
            if not process_id:
                location = resp.headers.get("Location", "")
                if location:
                    for part in reversed(location.rstrip("/").split("/")):
                        if part.isdigit():
                            process_id = int(part)
                            print(f"[EXPORT] ✓ ProcessId from POST Location header: {process_id}", flush=True)
                            break

            # Pattern C: Deep search in response
            if not process_id:
                pid = _deep_find_process_id(result)
                if pid:
                    process_id = pid
                    print(f"[EXPORT] ✓ ProcessId from deep search: {process_id}", flush=True)

            # Pattern D: Follow child links from response
            if not process_id:
                links = result.get("links", [])
                for link in links:
                    rel = link.get("rel", "")
                    href = link.get("href", "")
                    if "SetupOfferingCSVExportProcess" in href and not child_collection_path:
                        parsed = urlparse(href)
                        child_collection_path = parsed.path
                        if parsed.query:
                            child_collection_path += f"?{parsed.query}"
                    if "SetupOfferingCSVExportProcess" in href or "child" in rel:
                        print(f"[EXPORT] Following child link: {href}", flush=True)
                        try:
                            parsed = urlparse(href)
                            child_resp = oracle_request("GET", url, parsed.path, username, password, token=token, cookies=cookies)
                            if child_resp.status_code == 200:
                                child_data = child_resp.json()
                                items = child_data.get("items", [])
                                print(f"[EXPORT] Child link returned {len(items)} items", flush=True)
                                for item in reversed(items):
                                    pid = item.get("ProcessId") or item.get("processId")
                                    if pid:
                                        process_id = int(pid)
                                        print(f"[EXPORT] ✓ ProcessId from child link: {process_id}", flush=True)
                                        break
                        except Exception as le:
                            print(f"[EXPORT] Child link error: {le}", flush=True)
                    if process_id:
                        break

        # If POST didn't return ProcessId, try polling the child collection
        if not process_id and resp.status_code < 400:
            child_path = child_collection_path or (
                f"/fscmRestApi/resources/{api_version}"
                f"/setupOfferingCSVExports/{offering_code}"
                f"/child/SetupOfferingCSVExportProcess"
            )
            print(f"[EXPORT] Polling child collection for ProcessId...", flush=True)
            for attempt in range(1, 6):
                wait_secs = attempt * 5
                if attempt > 1:
                    print(f"[EXPORT] Waiting {wait_secs}s before poll {attempt}...", flush=True)
                    time.sleep(wait_secs)
                try:
                    cr = oracle_request("GET", url, child_path, username, password, token=token, cookies=cookies)
                    if cr.status_code == 200:
                        cd = cr.json()
                        items = cd.get("items", [])
                        print(f"[EXPORT] Poll {attempt}: {len(items)} items", flush=True)
                        attempt_errors.append({
                            "attempt": f"poll-{attempt}",
                            "faCode": fa_code,
                            "status": cr.status_code,
                            "response": json.dumps({"items": len(items)})[:500],
                        })
                        for item in reversed(items):
                            pid = (
                                item.get("ProcessId")
                                or item.get("processId")
                                or item.get("RequestId")
                                or item.get("requestId")
                                or item.get("ReqstId")
                                or item.get("ESSRequestId")
                            )
                            if pid:
                                process_id = int(pid)
                                print(f"[EXPORT] ✓ ProcessId from poll: {process_id}", flush=True)
                                break
                        if process_id:
                            break
                    else:
                        attempt_errors.append({
                            "attempt": f"poll-{attempt}",
                            "faCode": fa_code,
                            "status": cr.status_code,
                            "response": cr.text[:500],
                        })
                except Exception as pe:
                    print(f"[EXPORT] Poll error: {pe}", flush=True)
                    attempt_errors.append({
                        "attempt": f"poll-{attempt}",
                        "faCode": fa_code,
                        "status": "EXCEPTION",
                        "response": str(pe)[:500],
                    })

        # ══════════════════════════════════════════════════════════
        # METHOD 2 (FALLBACK): POST directly to child endpoint
        # Some Oracle versions require separate child POST
        # ══════════════════════════════════════════════════════════
        if not process_id:
            print(f"\n[EXPORT] Method 2: POST directly to child endpoint...", flush=True)
            child_path = child_collection_path or (
                f"/fscmRestApi/resources/{api_version}"
                f"/setupOfferingCSVExports/{offering_code}"
                f"/child/SetupOfferingCSVExportProcess"
            )
            child_payload = {
                "OfferingCode": offering_code,
                "FunctionalAreaCode": fa_code,
            }
            print(f"[EXPORT] POST {child_path}", flush=True)
            try:
                proc_resp = oracle_request(
                    "POST", url, child_path, username, password, token=token, cookies=cookies,
                    json=child_payload,
                    headers={
                        "Content-Type": "application/vnd.oracle.adf.resourceitem+json",
                        "Accept": "application/json",
                        "REST-Framework-Version": "4",
                        "Prefer": "return=representation",
                    },
                )
                print(f"[EXPORT] Child POST HTTP {proc_resp.status_code}", flush=True)
                print(f"[EXPORT] Child POST Headers: {dict(proc_resp.headers)}", flush=True)
                print(f"[EXPORT] Child POST Body: {proc_resp.text[:2000]}", flush=True)
                attempt_errors.append({
                    "attempt": "child-post-1",
                    "faCode": fa_code,
                    "status": proc_resp.status_code,
                    "response": proc_resp.text[:500],
                })

                if proc_resp.status_code >= 400:
                    fallback_payload = {"OfferingCode": offering_code}
                    print(f"[EXPORT] Child POST retry without FunctionalAreaCode", flush=True)
                    proc_resp = oracle_request(
                        "POST", url, child_path, username, password, token=token, cookies=cookies,
                        json=fallback_payload,
                        headers={
                            "Content-Type": "application/vnd.oracle.adf.resourceitem+json",
                            "Accept": "application/json",
                            "REST-Framework-Version": "4",
                            "Prefer": "return=representation",
                        },
                    )
                    print(f"[EXPORT] Child POST retry HTTP {proc_resp.status_code}", flush=True)
                    print(f"[EXPORT] Child POST retry body: {proc_resp.text[:2000]}", flush=True)
                    attempt_errors.append({
                        "attempt": "child-post-2",
                        "faCode": "(none)",
                        "status": proc_resp.status_code,
                        "response": proc_resp.text[:500],
                    })

                if proc_resp.status_code < 400:
                    # Check body
                    try:
                        pr = proc_resp.json()
                        pid = pr.get("ProcessId") or pr.get("processId")
                        if pid:
                            process_id = int(pid)
                            print(f"[EXPORT] ✓ ProcessId from child POST body: {process_id}", flush=True)
                        if not process_id:
                            process_id = _deep_find_process_id(pr)
                            if process_id:
                                print(f"[EXPORT] ✓ ProcessId from child POST deep search: {process_id}", flush=True)
                    except Exception:
                        pass

                    # Check Location header
                    if not process_id:
                        location = proc_resp.headers.get("Location", "")
                        if location:
                            for part in reversed(location.rstrip("/").split("/")):
                                if part.isdigit():
                                    process_id = int(part)
                                    print(f"[EXPORT] ✓ ProcessId from Location: {process_id}", flush=True)
                                    break

                    # Poll again after child POST
                    if not process_id:
                        print(f"[EXPORT] Polling after child POST...", flush=True)
                        for attempt in range(1, 4):
                            time.sleep(10)
                            try:
                                cr = oracle_request("GET", url, child_path, username, password, token=token, cookies=cookies)
                                if cr.status_code == 200:
                                    cd = cr.json()
                                    items = cd.get("items", [])
                                    print(f"[EXPORT] Post-child poll {attempt}: {len(items)} items", flush=True)
                                    for item in reversed(items):
                                        pid = item.get("ProcessId") or item.get("processId")
                                        if pid:
                                            process_id = int(pid)
                                            print(f"[EXPORT] ✓ ProcessId from post-child poll: {process_id}", flush=True)
                                            break
                                    if process_id:
                                        break
                            except Exception:
                                pass
            except Exception as ce:
                print(f"[EXPORT] Child POST error: {ce}", flush=True)
                attempt_errors.append({
                    "attempt": "child-post-exception",
                    "faCode": fa_code,
                    "status": "EXCEPTION",
                    "response": str(ce)[:500],
                })

        # ══════════════════════════════════════════════════════════
        # METHOD 3: Search recent ESS jobs for export-related ones
        # ══════════════════════════════════════════════════════════
        if not process_id:
            print(f"\n[EXPORT] Method 3: Searching recent ESS jobs...", flush=True)
            ess_hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
            try:
                er = oracle_request(
                    "GET", url, "/ess/rest/scheduler/v1/requests", username, password,
                    token=token, cookies=cookies, headers=ess_hdrs,
                )
                print(f"[EXPORT] ESS list HTTP {er.status_code}", flush=True)
                if er.status_code == 200:
                    ed = er.json()
                    ess_items = ed.get("items", [])
                    print(f"[EXPORT] ESS has {len(ess_items)} jobs. Checking details...", flush=True)
                    for item in ess_items[:15]:
                        rid = item.get("requestId")
                        if not rid:
                            continue
                        try:
                            detail_resp = oracle_request(
                                "GET", url,
                                f"/ess/rest/scheduler/v1/requests/{rid}?fields=@full",
                                username, password, token=token, cookies=cookies, headers=ess_hdrs,
                            )
                            if detail_resp.status_code == 200:
                                detail = detail_resp.json()
                                jname = str(detail.get("jobDefinitionName", "")).lower()
                                desc = str(detail.get("description", "")).lower()
                                app_name = str(detail.get("application", "")).lower()
                                print(f"[EXPORT] ESS job {rid}: name={jname}, app={app_name}, desc={desc[:60]}, state={detail.get('state')}", flush=True)
                                if any(kw in jname for kw in ["export", "csv", "setup", "fndexport"]) or \
                                   any(kw in desc for kw in ["export", "csv", offering_code.lower()]) or \
                                   any(kw in app_name for kw in ["setup", "asm"]):
                                    process_id = int(rid)
                                    print(f"[EXPORT] ✓ Found export-related ESS job: {process_id}", flush=True)
                                    break
                        except Exception as de:
                            print(f"[EXPORT] ESS detail error for {rid}: {de}", flush=True)
            except Exception as e:
                print(f"[EXPORT] ESS search error: {e}", flush=True)

        if not process_id:
            return jsonify({
                "error": "ProcessId nao encontrado. O usuario pode nao ter a role ORA_ASM_APPLICATION_IMPLEMENTATION_CONSULTANT_JOB (Application Implementation Consultant).",
                "hint": "Verifique se o usuario tem permissao de Export Import Functional Setups User.",
                "apiVersion": api_version,
                "attempts": attempt_errors,
            }), 500

        return jsonify({
            "processId": process_id,
            "offeringCode": offering_code,
            "apiVersion": api_version,
            "status": "SUBMITTED",
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: Debug - Diagnose ESS and FSM
# ============================================================
@app.route("/api/debug-ess", methods=["POST"])
def debug_ess():
    """Diagnostica o ambiente Oracle: ESS jobs, permissoes, e FSM export."""
    data, err = get_payload(["url", "username", "password"])
    if err:
        return err

    url = data["url"].rstrip("/")
    try:
        creds = resolve_auth(data)
    except Exception as e:
        return jsonify({"error": f"Falha na autenticacao SSO/OAuth2: {str(e)[:300]}"}), 401
    username = creds["username"]
    password = creds["password"]
    token = creds["token"]
    cookies = creds["cookies"]
    offering_code = data.get("offeringCode", "FIN_FSCM_OFFERING")
    fa_code = data.get("faCode", "ORA_ASE_USERS_AND_SECURITY")
    results = {}

    ess_hdrs = {"Content-Type": "application/json", "Accept": "application/json"}

    # 1) Get one ESS job with full details
    try:
        r = oracle_request("GET", url, "/ess/rest/scheduler/v1/requests", username, password, token=token, cookies=cookies, headers=ess_hdrs)
        if r.status_code == 200:
            items = r.json().get("items", [])
            results["ess_job_count"] = len(items)
            if items:
                rid = items[0].get("requestId")
                # Get full detail of first job
                dr = oracle_request("GET", url, f"/ess/rest/scheduler/v1/requests/{rid}", username, password, token=token, cookies=cookies, headers=ess_hdrs)
                results["ess_sample_job_full"] = dr.json() if dr.status_code == 200 else f"HTTP {dr.status_code}"
                # Also try ?fields=@full
                dr2 = oracle_request("GET", url, f"/ess/rest/scheduler/v1/requests/{rid}?fields=@full", username, password, token=token, cookies=cookies, headers=ess_hdrs)
                results["ess_sample_job_fields_full"] = dr2.json() if dr2.status_code == 200 else f"HTTP {dr2.status_code}: {dr2.text[:500]}"
    except Exception as e:
        results["ess_error"] = str(e)

    # 2) Check user roles/permissions via SCIM
    try:
        scim_filter = f"?filter=userName eq \"{username}\"&attributes=roles" if username else "?attributes=roles&count=1"
        r = oracle_request("GET", url, f"/hcmRestApi/scim/Users{scim_filter}", username, password, token=token, cookies=cookies)
        if r.status_code == 200:
            user_data = r.json()
            resources = user_data.get("Resources", [])
            if resources:
                roles = resources[0].get("roles", [])
                results["user_role_count"] = len(roles)
                # Check for the specific required role
                setup_roles = [r for r in roles if "setup" in str(r).lower() or "export" in str(r).lower() or "asm" in str(r).lower()]
                results["user_setup_related_roles"] = setup_roles[:10]
    except Exception as e:
        results["scim_error"] = str(e)

    # 3) Check what the FSM GET returns for this offering
    api_version = get_api_version(url, username, password, token=token, cookies=cookies)
    try:
        r = oracle_request("GET", url, f"/fscmRestApi/resources/{api_version}/setupOfferingCSVExports/{offering_code}", username, password, token=token, cookies=cookies)
        results["fsm_get_status"] = r.status_code
        results["fsm_get_body"] = r.json() if r.status_code == 200 else r.text[:1000]
    except Exception as e:
        results["fsm_error"] = str(e)

    # 4) Try SOAP-like erpintegrations for export
    try:
        erp_path = "/fscmRestApi/resources/11.13.18.05/erpintegrations"
        erp_payload = {
            "OperationName": "exportBulkData",
            "DocumentContent": "NONE",
            "ContentType": "zip",
            "ParameterList": f"{offering_code},{fa_code}"
        }
        r = oracle_request("POST", url, erp_path, username, password, token=token, cookies=cookies, json=erp_payload)
        results["erp_integration_status"] = r.status_code
        results["erp_integration_body"] = r.json() if r.status_code < 400 else r.text[:1000]
    except Exception as e:
        results["erp_integration_error"] = str(e)

    print(f"\n[DEBUG-ESS] Results:\n{json.dumps(results, indent=2, default=str)[:5000]}", flush=True)
    return jsonify(results)


# ============================================================
# API: Export Status
# ============================================================
@app.route("/api/export-status", methods=["POST"])
def export_status():
    """Verifica o status de um processo de exportação."""
    data, err = get_payload(["url", "username", "password", "offeringCode", "processId"])
    if err:
        return err

    url = data["url"].rstrip("/")
    try:
        creds = resolve_auth(data)
    except Exception as e:
        return jsonify({"error": f"Falha na autenticacao SSO/OAuth2: {str(e)[:300]}"}), 401
    username = creds["username"]
    password = creds["password"]
    token = creds["token"]
    cookies = creds["cookies"]
    offering_code = data["offeringCode"]
    process_id = data["processId"]

    try:
        api_version = get_api_version(url, username, password, token=token, cookies=cookies)
        path = (
            f"/fscmRestApi/resources/{api_version}"
            f"/setupOfferingCSVExports/{offering_code}"
            f"/child/SetupOfferingCSVExportProcess/{process_id}"
        )

        resp = oracle_request("GET", url, path, username, password, token=token, cookies=cookies)

        if resp.status_code >= 400:
            return jsonify({
                "completed": False,
                "failed": False,
                "status": "CHECKING",
                "error": f"HTTP {resp.status_code}"
            })

        result = resp.json()
        completed_flag = result.get("CompletedFlag", result.get("Completed", False))
        status = result.get("Status", result.get("ProcessStatus", "UNKNOWN"))
        failed = status in ("FAILED", "ERROR", "CANCELLED")

        return jsonify({
            "completed": bool(completed_flag) or status in ("COMPLETED", "SUCCEEDED", "SUCCESS"),
            "failed": failed,
            "status": status,
            "rolesCount": result.get("RolesCount", 0),
            "error": result.get("ErrorMessage", "") if failed else "",
            "raw": result
        })

    except Exception as e:
        return jsonify({
            "completed": False,
            "failed": False,
            "status": "ERROR",
            "error": str(e)
        })


# ============================================================
# API: Download Export
# ============================================================
@app.route("/api/download", methods=["POST"])
def download_export():
    """Baixa o arquivo ZIP exportado."""
    data, err = get_payload(["url", "username", "password", "offeringCode", "processId"])
    if err:
        return err

    url = data["url"].rstrip("/")
    try:
        creds = resolve_auth(data)
    except Exception as e:
        return jsonify({"error": f"Falha na autenticacao SSO/OAuth2: {str(e)[:300]}"}), 401
    username = creds["username"]
    password = creds["password"]
    token = creds["token"]
    cookies = creds["cookies"]
    offering_code = data["offeringCode"]
    process_id = data["processId"]

    try:
        api_version = get_api_version(url, username, password, token=token, cookies=cookies)
        path = (
            f"/fscmRestApi/resources/{api_version}"
            f"/setupOfferingCSVExports/{offering_code}"
            f"/child/SetupOfferingCSVExportProcess/{process_id}"
            f"/child/SetupOfferingCSVExportProcessResult/{process_id}"
            f"/enclosure/FileContent"
        )

        resp = oracle_request(
            "GET", url, path, username, password, token=token, cookies=cookies,
            headers={"Accept": "*/*"}
        )

        if resp.status_code >= 400:
            return jsonify({"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}), resp.status_code

        # Determine content
        content_type = resp.headers.get("Content-Type", "")
        if "json" in content_type:
            result = resp.json()
            file_content_b64 = result.get("FileContent", result.get("fileContent", ""))
            if file_content_b64:
                file_bytes = base64.b64decode(file_content_b64)
            else:
                file_bytes = resp.content
        else:
            file_bytes = resp.content

        # Save to cache for full migration
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"oracle_roles_export_{timestamp}.zip"
        cache_path = os.path.join(EXPORT_CACHE_DIR, file_name)
        with open(cache_path, "wb") as f:
            f.write(file_bytes)

        file_size_str = f"{len(file_bytes):,} bytes"

        return jsonify({
            "fileName": file_name,
            "fileSize": file_size_str,
            "filePath": cache_path,
            "fileContent": base64.b64encode(file_bytes).decode()
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: Import Roles
# ============================================================
@app.route("/api/import", methods=["POST"])
def import_roles():
    """Importa roles no ambiente de destino."""
    data, err = get_payload(["url", "username", "password", "offeringCode", "faCode"])
    if err:
        return err

    url = data["url"].rstrip("/")
    try:
        creds = resolve_auth(data)
    except Exception as e:
        return jsonify({"error": f"Falha na autenticacao SSO/OAuth2: {str(e)[:300]}"}), 401
    username = creds["username"]
    password = creds["password"]
    token = creds["token"]
    cookies = creds["cookies"]
    offering_code = data["offeringCode"]
    fa_code = data["faCode"]
    use_exported = data.get("useExportedFile", False)
    file_content = data.get("fileContent")
    file_name = data.get("fileName", "roles.zip")

    try:
        # Get file content
        if use_exported:
            cache_files = sorted(Path(EXPORT_CACHE_DIR).glob("*.zip"), reverse=True)
            if not cache_files:
                return jsonify({"error": "Nenhum arquivo exportado encontrado no cache"}), 404
            with open(cache_files[0], "rb") as f:
                file_content = base64.b64encode(f.read()).decode()
            file_name = cache_files[0].name
        elif not file_content:
            return jsonify({"error": "Conteudo do arquivo nao fornecido"}), 400

        api_version = get_api_version(url, username, password, token=token, cookies=cookies)
        path = f"/fscmRestApi/resources/{api_version}/setupOfferingCSVImports"
        payload = {
            "OfferingCode": offering_code,
            "FunctionalAreaCode": fa_code,
            "FileContent": file_content,
            "FileName": file_name,
            "ContentType": "application/zip",
        }

        resp = oracle_request("POST", url, path, username, password, token=token, cookies=cookies, json=payload)

        if resp.status_code >= 400:
            error_detail = ""
            try:
                error_detail = resp.json()
            except Exception:
                error_detail = resp.text[:500]
            return jsonify({
                "error": f"Falha ao iniciar importacao (HTTP {resp.status_code})",
                "detail": error_detail
            }), resp.status_code

        result = resp.json()

        process_id = None
        import_procs = result.get("SetupOfferingCSVImportProcess", [])
        if import_procs and isinstance(import_procs, list):
            process_id = import_procs[0].get("ProcessId")
        if not process_id:
            process_id = result.get("ProcessId")

        if not process_id:
            return jsonify({
                "error": "ProcessId nao encontrado na resposta de importacao",
                "response": result
            }), 500

        return jsonify({
            "processId": process_id,
            "status": "SUBMITTED"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: Import Status
# ============================================================
@app.route("/api/import-status", methods=["POST"])
def import_status():
    """Verifica o status de um processo de importação."""
    data, err = get_payload(["url", "username", "password", "offeringCode", "processId"])
    if err:
        return err

    url = data["url"].rstrip("/")
    try:
        creds = resolve_auth(data)
    except Exception as e:
        return jsonify({"error": f"Falha na autenticacao SSO/OAuth2: {str(e)[:300]}"}), 401
    username = creds["username"]
    password = creds["password"]
    token = creds["token"]
    cookies = creds["cookies"]
    offering_code = data["offeringCode"]
    process_id = data["processId"]

    try:
        api_version = get_api_version(url, username, password, token=token, cookies=cookies)
        path = (
            f"/fscmRestApi/resources/{api_version}"
            f"/setupOfferingCSVImports/{offering_code}"
            f"/child/SetupOfferingCSVImportProcess/{process_id}"
        )

        resp = oracle_request("GET", url, path, username, password, token=token, cookies=cookies)

        if resp.status_code >= 400:
            return jsonify({
                "completed": False,
                "failed": False,
                "status": "CHECKING",
                "error": f"HTTP {resp.status_code}"
            })

        result = resp.json()
        completed_flag = result.get("CompletedFlag", result.get("Completed", False))
        status = result.get("Status", result.get("ProcessStatus", "UNKNOWN"))
        failed = status in ("FAILED", "ERROR", "CANCELLED")

        return jsonify({
            "completed": bool(completed_flag) or status in ("COMPLETED", "SUCCEEDED", "SUCCESS"),
            "failed": failed,
            "status": status,
            "error": result.get("ErrorMessage", "") if failed else ""
        })

    except Exception as e:
        return jsonify({
            "completed": False,
            "failed": False,
            "status": "ERROR",
            "error": str(e)
        })


# ============================================================
# API: List Roles (SCIM)
# ============================================================
@app.route("/api/list-roles", methods=["POST"])
def list_roles():
    """Lista roles via SCIM REST API."""
    data, err = get_payload(["url", "username", "password"])
    if err:
        return err

    url = data["url"].rstrip("/")
    try:
        creds = resolve_auth(data)
    except Exception as e:
        return jsonify({"error": f"Falha na autenticacao SSO/OAuth2: {str(e)[:300]}"}), 401
    username = creds["username"]
    password = creds["password"]
    token = creds["token"]
    cookies = creds["cookies"]
    count = data.get("count", 100)

    try:
        path = f"/hcmRestApi/scim/Roles?count={count}&startIndex=1"
        resp = oracle_request("GET", url, path, username, password, token=token, cookies=cookies)

        if resp.status_code >= 400:
            return jsonify({"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}), resp.status_code

        result = resp.json()
        resources = result.get("Resources", result.get("resources", []))
        total = result.get("totalResults", len(resources))

        roles = []
        for r in resources:
            roles.append({
                "id": r.get("id", ""),
                "name": r.get("name", r.get("displayName", "")),
                "displayName": r.get("displayName", ""),
                "description": r.get("description", ""),
                "category": r.get("category", ""),
            })

        return jsonify({
            "total": total,
            "count": len(roles),
            "roles": roles
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: Debug - show detected version
# ============================================================
@app.route("/api/debug-version", methods=["POST"])
def debug_version():
    """Detecta e retorna a versão da API para debug."""
    data, err = get_payload(["url", "username", "password"])
    if err:
        return err

    url = data["url"].rstrip("/")
    try:
        creds = resolve_auth(data)
    except Exception as e:
        return jsonify({"error": f"Falha na autenticacao SSO/OAuth2: {str(e)[:300]}"}), 401
    username = creds["username"]
    password = creds["password"]
    token = creds["token"]
    cookies = creds["cookies"]

    results = []
    for version in API_VERSIONS:
        try:
            path = f"/fscmRestApi/resources/{version}/setupOfferings?limit=1&onlyData=true"
            resp = oracle_request("GET", url, path, username, password, token=token, cookies=cookies)
            results.append({
                "version": version,
                "status": resp.status_code,
                "ok": resp.status_code in (200, 401, 403)
            })
        except Exception as e:
            results.append({
                "version": version,
                "status": "ERROR",
                "error": str(e)
            })

    detected = get_api_version(url, username, password, token=token, cookies=cookies)
    return jsonify({
        "detectedVersion": detected,
        "allResults": results
    })


# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 5050))
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  OracleFusionRolesMigration - Backend Server                 ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  GUI:      http://localhost:{PORT}                            ║
║  API:      http://localhost:{PORT}/api/                       ║
║  Cache:    {EXPORT_CACHE_DIR:<45}║
║                                                              ║
║  Pressione Ctrl+C para encerrar                              ║
╚══════════════════════════════════════════════════════════════╝
""")
    app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
