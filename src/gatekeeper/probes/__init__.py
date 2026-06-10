"""Infrastructure audit probes — deployment-level checks for AI API gateways.

Each probe checks one specific misconfiguration that real-world deployments
commonly miss. These are NOT model-level tests (jailbreak, prompt injection).
Those are garak/augustus territory. We test what THEY don't test:
docker-compose, CORS, secrets in env/ci, model ACLs, rate limiting.

Complementary to:
  - garak / augustus → model-level red-teaming
  - promptfoo → code-level data flow (prompt → LLM → dangerous sink)
  - gatekeeper → deployment-level infra audit (this tool)
"""

import re
import os
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class AuditFinding:
    id: str
    name: str
    category: str      # secrets, access, network, config, deployment
    severity: str       # critical, high, medium, low, info
    passed: bool        # True = secure, False = vulnerability found
    description: str
    detail: str = ""
    fix: str = ""


# ============================================================
# Helpers
# ============================================================

def _file_exists(project_dir: str, name: str) -> bool:
    return os.path.isfile(os.path.join(project_dir, name))


def _read_file(project_dir: str, name: str) -> str:
    path = os.path.join(project_dir, name)
    if not os.path.isfile(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _is_env_gitignored(project_dir: str) -> bool:
    """Check if .env is in .gitignore (the bare minimum)."""
    content = _read_file(project_dir, ".gitignore")
    return ".env" in content


# ============================================================
# Category 1: Secrets Management
# ============================================================

def check_secrets_hardcoded_keys(project_dir: str) -> AuditFinding:
    """Scan for real API keys in non-.env config files.

    .env is expected to hold keys (as long as it's gitignored).
    This probe focuses on keys in config.yaml / docker-compose.yml
    that should use ${ENV_VAR} references instead.
    """
    # Files that should NOT contain real keys (should use env var references)
    managed_files = ["config.yaml", "config.yml", "docker-compose.yml",
                     "docker-compose.yaml"]
    # Patterns for real-looking API keys
    real_key_patterns = [
        r'sk-[a-zA-Z0-9]{15,60}',                # OpenAI/DeepSeek style
        r'api_key\s*[:=]\s*["\'][a-zA-Z0-9\-_]{20,}["\']',  # literal key values
        r'password\s*[:=]\s*["\'](?!\$\{|\$)[^"\'$]{4,}["\']',  # plaintext pwd (not env ref)
    ]

    findings = []
    for fname in managed_files:
        content = _read_file(project_dir, fname)
        if not content:
            continue
        for pat in real_key_patterns:
            matches = re.findall(pat, content, re.IGNORECASE)
            for m in matches[:2]:
                masked = m[:8] + "***" + m[-4:] if len(m) > 14 else "***"
                findings.append(f"  {fname}: {masked}")

    if findings:
        return AuditFinding(
            id="SEC-001",
            name="Hardcoded Secrets in Managed Config Files",
            category="secrets",
            severity="critical",
            passed=False,
            description=f"{len(findings)} real API keys found in config files (should use env vars)",
            detail="\n".join(findings[:5]),
            fix="Replace hardcoded keys with env var references:\n"
                "  api_key: ${DEEPSEEK_API_KEY}\n"
                "Use .env for local values, but NEVER commit .env to git.",
        )

    # Now check .env separately — warn if keys found AND .env isn't gitignored
    env_content = _read_file(project_dir, ".env")
    if env_content and not _is_env_gitignored(project_dir):
        key_count = len(re.findall(r'sk-[a-zA-Z0-9]{15,60}', env_content))
        key_count += len(re.findall(r'api_key\s*[:=]\s*["\'][a-zA-Z0-9\-_]{15,}["\']',
                                    env_content, re.IGNORECASE))
        if key_count > 0:
            return AuditFinding(
                id="SEC-001",
                name="Secrets in .env — NOT Git-Ignored",
                category="secrets",
                severity="critical",
                passed=False,
                description=f".env contains {key_count} keys but .gitignore doesn't protect it",
                detail=".env has real API keys and is NOT in .gitignore",
                fix="1. Add .env to .gitignore IMMEDIATELY\n"
                    "2. Rotate any keys that may have been committed\n"
                    "3. Run: git rm --cached .env",
            )

    return AuditFinding(
        id="SEC-001", name="Secrets Management", category="secrets",
        severity="critical", passed=True,
        description="No hardcoded secrets in managed config files",
    )


def check_secrets_env_leak(project_dir: str) -> AuditFinding:
    """Check if .env and its variants are protected from git."""
    gitignore_path = os.path.join(project_dir, ".gitignore")

    if not os.path.isfile(gitignore_path):
        has_env = _file_exists(project_dir, ".env")
        if has_env:
            return AuditFinding(
                id="SEC-002",
                name=".gitignore Missing — Secrets May Leak",
                category="secrets",
                severity="critical",
                passed=False,
                description=".env exists but no .gitignore file found",
                fix="Create .gitignore with:\n  .env\n  .env.*\n  !.env.example",
            )
        return AuditFinding(
            id="SEC-002", name="No .gitignore Found", category="secrets",
            severity="info", passed=True,
            description="No .env or .gitignore found — likely not a project directory",
        )

    content = _read_file(project_dir, ".gitignore")
    has_dotenv = ".env" in content
    has_env_wildcard = ".env.*" in content or "*.env" in content

    if not has_dotenv:
        return AuditFinding(
            id="SEC-002",
            name=".env NOT in .gitignore",
            category="secrets",
            severity="critical",
            passed=False,
            description=".env files may be committed to git",
            detail="'.env' not found in .gitignore",
            fix="Add to .gitignore:\n  .env\n  .env.*\n  !.env.example",
        )

    if not has_env_wildcard:
        return AuditFinding(
            id="SEC-002",
            name=".env Variants Not Protected",
            category="secrets",
            severity="medium",
            passed=False,
            description=".env is gitignored, but .env.local / .env.production variants are not",
            detail="Missing: .env.* or *.env patterns in .gitignore",
            fix="Also add to .gitignore:\n  .env.*\n  *.env\n  !.env.example",
        )

    return AuditFinding(
        id="SEC-002", name=".gitignore Protects Secrets", category="secrets",
        severity="critical", passed=True,
        description="All .env patterns properly excluded from git",
    )


def check_secrets_default_keys(project_dir: str) -> AuditFinding:
    """Check for default/example API keys in non-documentation config files.

    .env.example is EXCLUDED — it's documentation, placeholder keys there are normal.
    """
    default_keys = [
        "sk-test", "sk-your-", "YOUR_API_KEY", "your-api-key",
        "changeme", "replace-me", "placeholder",
        "sk-xxxxxxxx", "sk-12345678", "sk-demo",
    ]
    # Exclude .env.example — it's documentation
    config_files = ["config.yaml", "config.yml", "docker-compose.yml"]

    found = []
    for fname in config_files:
        content = _read_file(project_dir, fname)
        if not content:
            continue
        lowered = content.lower()
        for dk in default_keys:
            if dk.lower() in lowered:
                found.append(f"  {fname}: contains '{dk}'")

    if found:
        return AuditFinding(
            id="SEC-003",
            name="Default/Example API Keys in Active Config",
            category="secrets",
            severity="high",
            passed=False,
            description=f"{len(found)} default or placeholder keys found in active config files",
            detail="\n".join(found),
            fix="Replace placeholder keys with ${ENV_VAR} references.\n"
                "Placeholder keys in .env.example are fine (documentation).\n"
                "Placeholder keys in config.yaml are NOT fine (they get used at runtime).",
        )
    return AuditFinding(
        id="SEC-003", name="No Default Keys in Active Config", category="secrets",
        severity="high", passed=True,
        description="No placeholder or default API keys in active config files",
    )


# ============================================================
# Category 2: Access Control
# ============================================================

def check_access_cors(endpoint: str, api_key: str) -> AuditFinding:
    """Check if CORS is properly restricted."""
    try:
        import urllib.request
        req = urllib.request.Request(
            f"{endpoint}/models",
            headers={"Authorization": f"Bearer {api_key}"},
            method="OPTIONS",
        )
        resp = urllib.request.urlopen(req, timeout=5)
        cors_header = resp.headers.get("Access-Control-Allow-Origin", "")
        if cors_header == "*":
            return AuditFinding(
                id="ACC-001",
                name="CORS: Wildcard Origin (*)",
                category="access",
                severity="high",
                passed=False,
                description="Any website can call your API from a browser",
                detail="Access-Control-Allow-Origin: *",
                fix="Restrict to your frontend origin:\n"
                    "  Access-Control-Allow-Origin: https://your-app.com",
            )
        return AuditFinding(
            id="ACC-001", name="CORS Config", category="access",
            severity="high", passed=True,
            description=f"CORS restricted: {cors_header or '(not set — secure)'}",
        )
    except Exception as e:
        return AuditFinding(
            id="ACC-001", name="CORS Config", category="access",
            severity="info", passed=True,
            description=f"Cannot verify CORS (endpoint unreachable): {e}",
        )


def check_access_no_auth(endpoint: str) -> AuditFinding:
    """Check if the API accepts requests without authentication."""
    try:
        import urllib.request
        req = urllib.request.Request(f"{endpoint}/models", method="GET")
        resp = urllib.request.urlopen(req, timeout=5)
        if resp.status == 200:
            return AuditFinding(
                id="ACC-002",
                name="API Accepts Unauthenticated Requests",
                category="access",
                severity="critical",
                passed=False,
                description="Endpoint responds without any API key",
                detail=f"GET /models returned {resp.status} with no Authorization header",
                fix="Require Authorization header on all routes.\n"
                    "In LiteLLM: set LITELLM_MASTER_KEY and require_auth=true",
            )
    except Exception:
        pass
    return AuditFinding(
        id="ACC-002", name="Auth Required", category="access",
        severity="critical", passed=True,
        description="Endpoint requires authentication",
    )


def check_access_model_permissions(endpoint: str, api_key: str) -> AuditFinding:
    """Check if all models are accessible without per-model key restrictions."""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key, base_url=endpoint)
        models = client.models.list()
        model_ids = [m.id for m in models.data]

        callable_models = []
        for mid in model_ids[:5]:
            try:
                client.chat.completions.create(
                    model=mid,
                    messages=[{"role": "user", "content": "ping"}],
                    max_tokens=1,
                )
                callable_models.append(mid)
            except Exception:
                pass

        if len(callable_models) >= 3:
            return AuditFinding(
                id="ACC-003",
                name="No Per-Model Access Control",
                category="access",
                severity="medium",
                passed=False,
                description=f"All {len(callable_models)} tested models accessible with one key",
                detail="Models: " + ", ".join(callable_models),
                fix="Set per-model access with model-specific keys.\n"
                    "Separate cheap models from expensive ones (cost control).",
            )
    except Exception:
        pass
    return AuditFinding(
        id="ACC-003", name="Model Access Control", category="access",
        severity="medium", passed=True,
        description="Per-model access control in place or could not verify",
    )


# ============================================================
# Category 3: Network Security
# ============================================================

def check_network_https(endpoint: str) -> AuditFinding:
    """Check if the API endpoint uses HTTPS."""
    parsed = urlparse(endpoint)
    if parsed.scheme == "https":
        return AuditFinding(
            id="NET-001", name="HTTPS Enforced", category="network",
            severity="high", passed=True,
            description="API endpoint uses HTTPS",
        )
    if parsed.hostname in ("localhost", "127.0.0.1"):
        return AuditFinding(
            id="NET-001", name="HTTP on Localhost", category="network",
            severity="info", passed=True,
            description="HTTP acceptable for localhost development",
        )
    return AuditFinding(
        id="NET-001",
        name="No HTTPS — Plain HTTP in Production",
        category="network",
        severity="critical",
        passed=False,
        description=f"Endpoint uses plain HTTP: {endpoint}",
        detail="All API traffic visible to network observers",
        fix="Put Nginx + Let's Encrypt in front:\n"
            "  certbot --nginx -d api.your-domain.com",
    )


def check_network_exposed_admin(endpoint: str, api_key: str) -> AuditFinding:
    """Check if admin/management routes are publicly accessible."""
    admin_paths = ["/admin", "/ui", "/dashboard", "/metrics"]
    try:
        import urllib.request
        for path in admin_paths:
            try:
                req = urllib.request.Request(
                    f"{endpoint.rstrip('/v1')}{path}",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                resp = urllib.request.urlopen(req, timeout=3)
                if resp.status == 200:
                    return AuditFinding(
                        id="NET-002",
                        name=f"Admin Route Exposed: {path}",
                        category="network",
                        severity="high",
                        passed=False,
                        description=f"Management interface {path} is publicly reachable",
                        detail=f"GET {path} returned {resp.status}",
                        fix=f"Restrict {path} to internal network:\n"
                            "  nginx: allow 10.0.0.0/8; deny all;",
                    )
            except Exception:
                continue
    except Exception:
        pass
    return AuditFinding(
        id="NET-002", name="Admin Routes Protected", category="network",
        severity="high", passed=True,
        description="No admin routes exposed on public endpoint",
    )


def check_network_ports(docker_compose_path: str) -> AuditFinding:
    """Check for ports exposed to public network in docker-compose."""
    if not os.path.isfile(docker_compose_path):
        return AuditFinding(
            id="NET-003", name="Port Exposure", category="network",
            severity="info", passed=True,
            description="No docker-compose.yml found to check",
        )

    content = _read_file(os.path.dirname(docker_compose_path),
                         os.path.basename(docker_compose_path))

    # Find port mappings: "HOST:CONTAINER" or "IP:HOST:CONTAINER"
    # Formats: "4000:4000", "127.0.0.1:4000:4000", "${VAR:-4000}:4000"
    # Strategy: extract quoted strings containing colons and digits,
    # split from the RIGHT at the last colon to get container port.
    port_strings = re.findall(r'"([^"]*:\d+)"', content)

    dangerous = []
    safe = 0
    for port_str in port_strings:
        # Split at last colon — rightmost part is container port
        last_colon = port_str.rfind(":")
        if last_colon == -1:
            continue
        host_part = port_str[:last_colon]
        cont_port = port_str[last_colon + 1:]

        if not cont_port.isdigit():
            continue

        # Now classify based on what host_part looks like
        if host_part.startswith("127.0.0.1"):
            safe += 1
        elif host_part.startswith("localhost"):
            safe += 1
        elif host_part.startswith("0.0.0.0"):
            dangerous.append(f"0.0.0.0 -> {cont_port} (all interfaces)")
        elif "$" in host_part:
            # Env var — if prefixed with 127.0.0.1, it's safe
            if "127.0.0.1" in host_part.split(":")[0]:
                safe += 1
            else:
                dangerous.append(f"env var '{host_part}' -> {cont_port}")
        elif host_part.isdigit():
            # "4000:4000" format — no IP, defaults to 0.0.0.0
            dangerous.append(f"0.0.0.0:{host_part} -> {cont_port}")
        else:
            # Something else — flag for review
            dangerous.append(f"{host_part} -> {cont_port}")

    if re.search(r'0\.0\.0\.0:\d+', content):
        dangerous.append("binds to 0.0.0.0 (all network interfaces)")

    if dangerous:
        return AuditFinding(
            id="NET-003",
            name="Ports Exposed to Public Network",
            category="network",
            severity="high",
            passed=False,
            description=f"Docker exposes ports to public interfaces",
            detail="\n".join(f"  - {d}" for d in dangerous),
            fix="Bind internal services to 127.0.0.1:\n"
                '  ports:\n    - "127.0.0.1:4000:4000"',
        )

    return AuditFinding(
        id="NET-003", name="Port Exposure", category="network",
        severity="high", passed=True,
        description=f"All {safe} port(s) bound to localhost — safe",
    )


# ============================================================
# Category 4: Configuration
# ============================================================

def check_config_rate_limiting(project_dir: str) -> AuditFinding:
    """Check if rate limiting is configured anywhere in the stack.

    Searches: config.yaml, .env, docker-compose.yml, nginx configs.
    If not found, notes that external proxy-level limiting may exist.
    """
    # Search all relevant config files
    search_files = []
    for fname in ["config.yaml", "config.yml", ".env",
                  "docker-compose.yml", "nginx.conf",
                  "nginx/sites-enabled/default", "Caddyfile"]:
        if _file_exists(project_dir, fname):
            search_files.append(fname)

    rate_limit_keywords = [
        "rate_limit", "rpm_limit", "rps_limit",
        "rpm", "rps", "requests_per", "throttle",
        "limit_req", "limit_req_zone",   # nginx
        "rate {",                         # Caddy
    ]

    for fname in search_files:
        content = _read_file(project_dir, fname)
        if any(kw in content.lower() for kw in rate_limit_keywords):
            return AuditFinding(
                id="CFG-001", name="Rate Limiting Configured", category="config",
                severity="high", passed=True,
                description=f"Rate limiting found in {fname}",
            )

    # Not found — but might be on external proxy
    has_router = any(
        kw in (_read_file(project_dir, "config.yaml") +
               _read_file(project_dir, "config.yml")).lower()
        for kw in ["router_settings", "rpm", "cooldown"]
    )

    return AuditFinding(
        id="CFG-001",
        name="No Rate Limiting in Project Config",
        category="config",
        severity="high",
        passed=False,
        description="No rate limiting found in project files",
        detail=("If rate limiting is configured on an external proxy (Nginx, Cloudflare),\n"
                "add a note or config file so CI/audit tools can verify it."),
        fix="Option A (LiteLLM):\n"
            "  general_settings:\n"
            "    rpm_limit: 500\n"
            "    rpm_limit_per_key: 100\n"
            "Option B (Nginx):\n"
            "  limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\n"
            "  limit_req zone=api burst=20;",
    )


def check_config_resource_limits(docker_compose_path: str) -> AuditFinding:
    """Check if Docker resource limits are set."""
    if not os.path.isfile(docker_compose_path):
        return AuditFinding(
            id="CFG-002", name="Resource Limits", category="config",
            severity="info", passed=True,
            description="No docker-compose.yml found to check",
        )

    content = _read_file(os.path.dirname(docker_compose_path),
                         os.path.basename(docker_compose_path))

    has_limits = any(kw in content for kw in
                     ["mem_limit", "deploy:", "resources:"])

    if not has_limits:
        return AuditFinding(
            id="CFG-002",
            name="No Container Resource Limits",
            category="config",
            severity="medium",
            passed=False,
            description="Containers can consume unlimited host memory",
            fix="Add resource limits to each service:\n"
                "  deploy:\n"
                "    resources:\n"
                "      limits:\n"
                "        memory: 512M",
        )
    return AuditFinding(
        id="CFG-002", name="Resource Limits Configured", category="config",
        severity="medium", passed=True,
        description="Container resource limits found",
    )


# ============================================================
# Category 5: Deployment Security
# ============================================================

def check_deploy_root_user(docker_compose_path: str) -> AuditFinding:
    """Check if containers run as root.

    Mitigations that count:
    - Explicit user: "1000:1000" or similar
    - security_opt: no-new-privileges:true (partial defense)
    - cap_drop: [ALL] (drops all capabilities)
    """
    if not os.path.isfile(docker_compose_path):
        return AuditFinding(
            id="DEP-001", name="Root User Check", category="deployment",
            severity="info", passed=True,
            description="No docker-compose.yml found to check",
        )

    content = _read_file(os.path.dirname(docker_compose_path),
                         os.path.basename(docker_compose_path))

    has_explicit_user = bool(re.search(r'^\s+user\s*:\s*["\']?\d+:\d+', content,
                                       re.MULTILINE))
    has_no_new_privs = "no-new-privileges" in content
    has_cap_drop_all = "cap_drop:" in content and "ALL" in content

    if has_explicit_user:
        return AuditFinding(
            id="DEP-001", name="Non-Root User Configured", category="deployment",
            severity="high", passed=True,
            description="Explicit non-root user set in docker-compose",
        )

    if has_no_new_privs or has_cap_drop_all:
        mitigations = []
        if has_no_new_privs:
            mitigations.append("security_opt: no-new-privileges (blocks privilege escalation)")
        if has_cap_drop_all:
            mitigations.append("cap_drop: ALL (drops all capabilities)")
        return AuditFinding(
            id="DEP-001",
            name="Running as Root — Partial Mitigations Present",
            category="deployment",
            severity="medium",
            passed=False,
            description="Containers run as root but have partial hardening",
            detail="Mitigations: " + ", ".join(mitigations),
            fix="For stronger defense, add:\n  user: \"1000:1000\"",
        )

    return AuditFinding(
        id="DEP-001",
        name="Containers Run as Root — No Mitigations",
        category="deployment",
        severity="high",
        passed=False,
        description="No non-root user, no-privileges, or capability dropping configured",
        detail="Running as root means container escape = host root compromise",
        fix="Add to each service:\n"
            '  user: "1000:1000"\n'
            "  security_opt:\n"
            '    - "no-new-privileges:true"',
    )


def check_deploy_privileged(docker_compose_path: str) -> AuditFinding:
    """Check for privileged containers (full host access)."""
    if not os.path.isfile(docker_compose_path):
        return AuditFinding(
            id="DEP-002", name="Privileged Mode", category="deployment",
            severity="critical", passed=True,
            description="No docker-compose.yml found to check",
        )

    content = _read_file(os.path.dirname(docker_compose_path),
                         os.path.basename(docker_compose_path))

    if "privileged: true" in content:
        return AuditFinding(
            id="DEP-002",
            name="Privileged Container Detected",
            category="deployment",
            severity="critical",
            passed=False,
            description="Container has full host access via privileged mode",
            fix="Remove 'privileged: true'. Use specific capabilities instead:\n"
                "  cap_add: [NET_ADMIN]  # only what you need",
        )
    return AuditFinding(
        id="DEP-002", name="No Privileged Mode", category="deployment",
        severity="critical", passed=True,
        description="No containers in privileged mode",
    )


def check_deploy_readonly_rootfs(docker_compose_path: str) -> AuditFinding:
    """Check if containers use read-only root filesystem."""
    if not os.path.isfile(docker_compose_path):
        return AuditFinding(
            id="DEP-003", name="Read-Only Filesystem", category="deployment",
            severity="info", passed=True,
            description="No docker-compose.yml found to check",
        )

    content = _read_file(os.path.dirname(docker_compose_path),
                         os.path.basename(docker_compose_path))

    if "read_only: true" in content:
        return AuditFinding(
            id="DEP-003", name="Read-Only Root Filesystem", category="deployment",
            severity="medium", passed=True,
            description="Read-only root filesystem configured",
        )
    return AuditFinding(
        id="DEP-003",
        name="Writable Root Filesystem",
        category="deployment",
        severity="low",
        passed=False,
        description="Containers have writable root filesystem",
        detail="Increases attack surface if container is compromised",
        fix="Add: read_only: true (with tmpfs for /tmp if needed)",
    )


# ============================================================
# Probe registry
# ============================================================

# File-based probes (no network needed)
FILE_PROBES = [
    check_secrets_hardcoded_keys,
    check_secrets_env_leak,
    check_secrets_default_keys,
    check_network_ports,
    check_config_rate_limiting,
    check_config_resource_limits,
    check_deploy_root_user,
    check_deploy_privileged,
    check_deploy_readonly_rootfs,
]

# Network-based probes (need endpoint + API key)
NETWORK_PROBES = [
    check_access_cors,
    check_access_no_auth,
    check_access_model_permissions,
    check_network_https,
    check_network_exposed_admin,
]

FILE_PROBE_COUNT = len(FILE_PROBES)
NETWORK_PROBE_COUNT = len(NETWORK_PROBES)
TOTAL_PROBES = FILE_PROBE_COUNT + NETWORK_PROBE_COUNT
