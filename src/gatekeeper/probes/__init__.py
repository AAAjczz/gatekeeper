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
    # New: built-in risk explanation — no AI needed
    risk_what: str = ""   # plain-language: what could actually happen
    effort: str = ""       # 5min / 15min / 30min / 1hr / requires_planning


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
    """Check if .env is in .gitignore (line-by-line match, not substring)."""
    content = _read_file(project_dir, ".gitignore")
    if not content:
        return False
    for line in content.splitlines():
        stripped = line.strip()
        # Skip comments and empty lines
        if stripped.startswith("#") or not stripped:
            continue
        if stripped == ".env":
            return True
    return False


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
    # .env.example included: if real keys leak here, they get committed to git
    managed_files = ["config.yaml", "config.yml", "docker-compose.yml",
                     "docker-compose.yaml", ".env.example"]
    # Patterns for real-looking API keys
    # Exclude obvious placeholder prefixes
    real_key_patterns = [
        r'sk-(?!your-|example|placeholder|xxx|demo|test-|generate|random|changeme|replace)[a-zA-Z0-9\-_]{15,100}',
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
                masked = m[:3] + "***" + m[-3:] if len(m) > 10 else "***"
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
            risk_what="Anyone who can see your config file (teammates, logs, backups, "
                      "or attackers who gain read access) gets full access to your "
                      "AI provider account. They can run up charges, steal data, "
                      "or get your account banned for abuse.",
            effort="5min",
        )

    # Now check .env separately — warn if keys found AND .env isn't gitignored
    env_content = _read_file(project_dir, ".env")
    if env_content and not _is_env_gitignored(project_dir):
        key_count = len(re.findall(r'sk-[a-zA-Z0-9]{15,60}', env_content))
        key_count += len(re.findall(r'api_key\s*[:=]\s*["\'][a-zA-Z0-9\-_]{15,}["\']',
                                    env_content, re.IGNORECASE))
        if key_count > 0:
            return AuditFinding(
                id="SEC-001B",
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
    lines = [l.strip() for l in content.splitlines()
             if l.strip() and not l.strip().startswith("#")]
    has_dotenv = any(l == ".env" for l in lines)
    has_env_wildcard = any(l in (".env.*", "*.env") for l in lines)

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
            risk_what="One accidental 'git add .' and your API keys are permanently "
                      "in git history. Deleting the file later won't help — the keys "
                      "stay in old commits forever. Anyone who clones your repo "
                      "gets your keys.",
            effort="1min",
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
        import urllib.error

        # CORS preflight should work without auth — try without first
        for headers in [
            {"Origin": "https://gatekeeper.test"},
            {"Origin": "https://gatekeeper.test", "Authorization": f"Bearer {api_key}"},
        ]:
            try:
                req = urllib.request.Request(
                    f"{endpoint}/models", headers=headers, method="OPTIONS",
                )
                resp = urllib.request.urlopen(req, timeout=5)
                break  # success
            except urllib.error.HTTPError:
                continue  # try with auth next
        else:
            return AuditFinding(
                id="ACC-001", name="CORS Config", category="access",
                severity="info", passed=True,
                description="OPTIONS rejected — CORS preflight blocked (secure)",
            )

        cors_origin = resp.headers.get("Access-Control-Allow-Origin", "")
        cors_creds = resp.headers.get("Access-Control-Allow-Credentials", "")

        if cors_origin == "*" and cors_creds.lower() == "true":
            return AuditFinding(
                id="ACC-001",
                name="CORS: Wildcard Origin + Credentials",
                category="access",
                severity="critical",
                passed=False,
                description="Any website can make authenticated requests from a browser",
                detail="Access-Control-Allow-Origin: * with Allow-Credentials: true",
                fix="Never use wildcard origin with credentials. Restrict to your origin:\n"
                    "  Access-Control-Allow-Origin: https://your-app.com\n"
                    "  Access-Control-Allow-Credentials: true",
            )

        if cors_origin == "*":
            return AuditFinding(
                id="ACC-001",
                name="CORS: Wildcard Origin (*)",
                category="access",
                severity="critical",
                passed=False,
                description="Any website can call your API from a browser",
                detail="Access-Control-Allow-Origin: *",
                fix="Restrict to your frontend origin:\n"
                    "  Access-Control-Allow-Origin: https://your-app.com",
            )
        return AuditFinding(
            id="ACC-001", name="CORS Config", category="access",
            severity="critical", passed=True,
            description=f"CORS restricted: {cors_origin or '(not set — secure)'}",
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
        import urllib.error
        req = urllib.request.Request(f"{endpoint}/models", method="GET")
        try:
            resp = urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            # 401/403 = auth required (good). Other codes = unclear.
            if e.code in (401, 403):
                return AuditFinding(
                    id="ACC-002", name="Auth Required", category="access",
                    severity="critical", passed=True,
                    description=f"Endpoint correctly rejects unauthenticated requests (HTTP {e.code})",
                )
            return AuditFinding(
                id="ACC-002", name="Auth Check Inconclusive", category="access",
                severity="medium", passed=False,
                description=f"Endpoint returned HTTP {e.code} without auth — unexpected, not conclusive",
                detail=f"HTTP {e.code} is not 401/403. Could be a redirect, rate-limit, or misconfiguration.",
                fix="Verify manually that auth is enforced across all API routes.",
            )

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

        # Non-200, non-401/403 — ambiguous
        return AuditFinding(
            id="ACC-002", name="Auth Check Inconclusive", category="access",
            severity="medium", passed=False,
            description=f"Endpoint returned HTTP {resp.status} without auth — not conclusive",
            detail=f"HTTP {resp.status} — could be a redirect, rate-limit, or auth bypass.",
            fix="Verify manually that auth is enforced across all API routes.",
        )
    except Exception:
        return AuditFinding(
            id="ACC-002", name="Auth Check Failed", category="access",
            severity="info", passed=True,
            description="Could not verify authentication (endpoint unreachable)",
        )


def check_access_model_permissions(endpoint: str, api_key: str) -> AuditFinding:
    """Check if all models are accessible without per-model key restrictions."""
    try:
        from openai import OpenAI
    except ImportError:
        return AuditFinding(
            id="ACC-003", name="Model Access Control", category="access",
            severity="info", passed=True,
            description="Skipped — 'openai' package not installed (pip install openai)",
        )

    try:
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
    except Exception as e:
        return AuditFinding(
            id="ACC-003", name="Model Access Control", category="access",
            severity="info", passed=True,
            description=f"Could not verify model permissions: {e}",
        )
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
                    f"{endpoint.removesuffix('/v1')}{path}",
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
    # Also handle unquoted: 4000:4000 (valid YAML)
    # Strategy: extract quoted AND unquoted port strings containing colons and digits,
    # split from the RIGHT at the last colon to get container port.
    port_strings = re.findall(r'(?:"([^"]*:\d+)")|(?:^\s*- (\d+:\d+))', content, re.MULTILINE)
    # Flatten: tuples from two capture groups
    flat = []
    for t in port_strings:
        flat.append(t[0] or t[1])
    port_strings = flat

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
            severity="info", passed=True,
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


def check_deploy_image_pinning(docker_compose_path: str) -> AuditFinding:
    """Check if Docker images use specific tags (not :latest)."""
    if not os.path.isfile(docker_compose_path):
        return AuditFinding(
            id="DEP-004", name="Image Pinning", category="deployment",
            severity="info", passed=True,
            description="No docker-compose.yml found to check",
        )

    content = _read_file(os.path.dirname(docker_compose_path),
                         os.path.basename(docker_compose_path))

    # Find all image references
    images = re.findall(r'image:\s*["\']?(\S+)["\']?', content)
    latest_images = [img for img in images
                     if img.endswith(":latest") or (":" not in img and "/" in img)]

    if latest_images:
        return AuditFinding(
            id="DEP-004",
            name="Unpinned Docker Images (:latest)",
            category="deployment",
            severity="medium",
            passed=False,
            description=f"{len(latest_images)} image(s) use floating tags — can break silently",
            detail="Images: " + ", ".join(latest_images[:5]),
            fix="Pin images to specific SHA or version tags:\n"
                "  image: litellm:1.75.0  # not :latest\n"
                "Consider using Dependabot or Renovate for automated updates.",
        )
    return AuditFinding(
        id="DEP-004", name="Images Pinned", category="deployment",
        severity="medium", passed=True,
        description="All Docker images use specific version tags",
    )


def check_deploy_healthcheck(docker_compose_path: str) -> AuditFinding:
    """Check if containers have health checks configured."""
    if not os.path.isfile(docker_compose_path):
        return AuditFinding(
            id="DEP-005", name="Healthcheck", category="deployment",
            severity="info", passed=True,
            description="No docker-compose.yml found to check",
        )

    content = _read_file(os.path.dirname(docker_compose_path),
                         os.path.basename(docker_compose_path))

    # Count services and services with healthcheck
    services = re.findall(r'^\s{2,}(\w+):', content, re.MULTILINE)
    services_with_hc = set()

    # Find healthcheck blocks and associate with nearest service above
    # Simpler: check how many "healthcheck:" appear
    hc_count = len(re.findall(r'healthcheck\s*:', content))

    if hc_count == 0:
        return AuditFinding(
            id="DEP-005",
            name="No Health Checks Configured",
            category="deployment",
            severity="medium",
            passed=False,
            description="No containers have health checks — downtime undetected",
            fix="Add healthcheck to each service:\n"
                "  healthcheck:\n"
                "    test: [\"CMD\", \"curl\", \"-f\", \"http://localhost:4000/health\"]\n"
                "    interval: 30s\n"
                "    retries: 3",
        )
    return AuditFinding(
        id="DEP-005", name="Health Checks Configured", category="deployment",
        severity="medium", passed=True,
        description=f"{hc_count} healthcheck(s) found",
    )


def check_deploy_restart_policy(docker_compose_path: str) -> AuditFinding:
    """Check if restart policy is set for all services."""
    if not os.path.isfile(docker_compose_path):
        return AuditFinding(
            id="DEP-006", name="Restart Policy", category="deployment",
            severity="info", passed=True,
            description="No docker-compose.yml found to check",
        )

    content = _read_file(os.path.dirname(docker_compose_path),
                         os.path.basename(docker_compose_path))

    # Count services (top-level under 'services:' — indent of 2 spaces)
    services = re.findall(r'^  (\w+):', content, re.MULTILINE)
    # Filter out known non-service keys
    service_names = [s for s in services if s not in
                     ("environment", "volumes", "ports", "networks",
                      "deploy", "healthcheck", "depends_on", "build",
                      "security_opt", "command", "labels", "secrets",
                      "configs", "cap_add", "cap_drop", "dns", "entrypoint",
                      "extra_hosts", "logging", "tmpfs", "ulimits")]
    # Count restart policies
    restart_count = len(re.findall(r'restart\s*:', content))

    if restart_count < len(service_names):
        return AuditFinding(
            id="DEP-006",
            name="Missing Restart Policy",
            category="deployment",
            severity="medium",
            passed=False,
            description=f"Only {restart_count}/{len(service_names)} services have restart policy",
            fix="Add to each service:\n"
                "  restart: unless-stopped",
        )
    return AuditFinding(
        id="DEP-006", name="Restart Policy Set", category="deployment",
        severity="medium", passed=True,
        description=f"All {len(service_names)} services have restart policies",
    )


def check_config_debug_mode(project_dir: str) -> AuditFinding:
    """Check if debug/verbose mode is disabled in production config."""
    debug_indicators = [
        (r'set_verbose\s*:\s*true', "LiteLLM verbose mode enabled"),
        (r'debug\s*:\s*true', "debug mode enabled"),
        (r'LOG_LEVEL\s*=\s*["\']?(debug|trace)', "debug log level"),
        (r'DEBUG\s*=\s*["\']?true', "DEBUG flag set"),
        (r'NODE_ENV\s*=\s*["\']?development', "Node.js in development mode"),
    ]

    found = []
    for fname in ["config.yaml", "config.yml", ".env", "docker-compose.yml"]:
        content = _read_file(project_dir, fname)
        if not content:
            continue
        for pattern, label in debug_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                found.append(f"  {fname}: {label}")

    if found:
        return AuditFinding(
            id="CFG-003",
            name="Debug/Verbose Mode in Config",
            category="config",
            severity="high",
            passed=False,
            description=f"{len(found)} debug/verbose settings found — leaks info in production",
            detail="\n".join(found[:5]),
            fix="Disable in production:\n"
                "  LiteLLM: set_verbose: false\n"
                "  .env: LOG_LEVEL=warn or error",
        )
    return AuditFinding(
        id="CFG-003", name="Debug Mode Disabled", category="config",
        severity="high", passed=True,
        description="No debug/verbose settings detected in production config",
    )


def check_secrets_key_strength(project_dir: str) -> AuditFinding:
    """Check if API master key meets minimum complexity requirements.

    Checks .env AND config.yaml for master keys.
    """
    # Collect content from all relevant files
    sources = {}
    for fname in [".env", "config.yaml", "config.yml"]:
        content = _read_file(project_dir, fname)
        if content:
            sources[fname] = content

    if not sources:
        return AuditFinding(
            id="SEC-004", name="API Key Strength", category="secrets",
            severity="info", passed=True,
            description="No .env or config files found to check",
        )

    # Find master key across all sources
    # Skip env var references like os.environ/X, ${X}, $X
    key_match = None
    source_file = "?"
    for fname, content in sources.items():
        for m in re.finditer(
            r'(?:MASTER_KEY|LITELLM_MASTER_KEY|API_KEY)\s*[=:]\s*["\']?(\S+)["\']?',
            content, re.IGNORECASE,
        ):
            val = m.group(1).strip('"\'')
            # Skip env var references — these are not the actual key
            if val.startswith("os.environ") or val.startswith("${") or val.startswith("$"):
                continue
            key_match = m
            source_file = fname
            break
        if key_match:
            break
    if not key_match:
        return AuditFinding(
            id="SEC-004", name="API Key Strength", category="secrets",
            severity="medium", passed=True,
            description="No master key found in .env or config files",
        )

    key = key_match.group(1)
    if len(key) < 32:
        return AuditFinding(
            id="SEC-004",
            name="Weak API Master Key",
            category="secrets",
            severity="high",
            passed=False,
            description=f"Master key in {source_file} is only {len(key)} chars — brute-forceable",
            detail=f"File: {source_file}, key length: {len(key)} (minimum recommended: 32)",
            fix="Generate a strong key:\n"
                "  openssl rand -hex 32\n"
                "Or use a password manager to generate a 64-char random string.",
        )
    return AuditFinding(
        id="SEC-004", name="API Key Strength", category="secrets",
        severity="high", passed=True,
        description=f"Master key in {source_file}: {len(key)} chars — adequate",
    )


def check_access_security_headers(endpoint: str) -> AuditFinding:
    """Check for security-related HTTP headers on the API endpoint."""
    security_headers = {
        "Strict-Transport-Security": "HSTS (prevents SSL stripping)",
        "X-Content-Type-Options": "MIME sniffing protection",
        "X-Frame-Options": "Clickjacking protection",
        "Content-Security-Policy": "XSS protection",
        "X-XSS-Protection": "Legacy XSS protection",
    }
    try:
        import urllib.request
        req = urllib.request.Request(f"{endpoint}/models", method="GET")
        resp = urllib.request.urlopen(req, timeout=5)

        missing = []
        for header, description in security_headers.items():
            if header not in resp.headers:
                missing.append(f"  {header}: {description}")

        if len(missing) >= 3:
            return AuditFinding(
                id="ACC-004",
                name="Missing Security Headers",
                category="access",
                severity="medium",
                passed=False,
                description=f"{len(missing)}/{len(security_headers)} security headers missing",
                detail="\n".join(missing),
                fix="Add to Nginx config:\n"
                    "  add_header Strict-Transport-Security \"max-age=31536000\" always;\n"
                    "  add_header X-Content-Type-Options \"nosniff\" always;\n"
                    "  add_header X-Frame-Options \"DENY\" always;",
            )
        return AuditFinding(
            id="ACC-004", name="Security Headers", category="access",
            severity="medium", passed=True,
            description=f"Only {len(missing)}/{len(security_headers)} headers missing",
        )
    except Exception as e:
        return AuditFinding(
            id="ACC-004", name="Security Headers", category="access",
            severity="info", passed=True,
            description=f"Cannot verify headers (endpoint unreachable): {e}",
        )


def check_deploy_docker_socket(docker_compose_path: str) -> AuditFinding:
    """Check if Docker socket is mounted into containers (container escape risk)."""
    if not os.path.isfile(docker_compose_path):
        return AuditFinding(
            id="DEP-007", name="Docker Socket Exposure", category="deployment",
            severity="info", passed=True,
            description="No docker-compose.yml found to check",
        )

    content = _read_file(os.path.dirname(docker_compose_path),
                         os.path.basename(docker_compose_path))

    # Check for docker socket mount
    socket_patterns = [
        r'/var/run/docker\.sock',
        r'/run/docker\.sock',
    ]
    for pat in socket_patterns:
        if pat in content:
            return AuditFinding(
                id="DEP-007",
                name="Docker Socket Mounted in Container",
                category="deployment",
                severity="critical",
                passed=False,
                description="Container can access host Docker daemon — trivial escape to root",
                detail=f"Found: {pat} mounted as volume",
                fix="NEVER mount docker.sock unless absolutely required.\n"
                    "If needed for healthchecks, use docker-exec or HTTP health endpoints instead.",
            )
    return AuditFinding(
        id="DEP-007", name="Docker Socket Not Exposed", category="deployment",
        severity="critical", passed=True,
        description="Docker socket not mounted in containers",
    )


def check_network_tls_cert(endpoint: str) -> AuditFinding:
    """Check TLS certificate validity across related domains.

    Multi-CDN services (DeepSeek, OpenAI, etc.) often deploy different
    certificates on different edge nodes. This probe scans the primary
    endpoint AND related domains to catch inconsistencies.
    """
    import ssl
    import socket
    from datetime import datetime, timezone

    parsed = urlparse(endpoint)
    if parsed.scheme != "https":
        return AuditFinding(
            id="NET-004", name="TLS Certificate", category="network",
            severity="info", passed=True,
            description="Non-HTTPS endpoint — certificate check skipped",
        )

    hostname = parsed.hostname or ""
    port = parsed.port or 443

    # Build related domain list for multi-CDN coverage
    # e.g. api.deepseek.com → also check deepseek.com, deepseek.ai
    domains_to_check = {hostname}
    parts = hostname.split(".")
    if len(parts) >= 2:
        base = parts[-2]  # "deepseek"
        tld = parts[-1]   # "com"
        # Add sibling TLDs
        for alt_tld in [".com", ".ai", ".cn", ".io"]:
            if alt_tld != f".{tld}":
                domains_to_check.add(f"{base}{alt_tld}")
        # Add www and api variants
        if hostname.startswith("api."):
            domains_to_check.add(hostname.replace("api.", "", 1))
        else:
            domains_to_check.add(f"api.{hostname}")

    certs_by_domain = {}

    for domain in list(domains_to_check):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        continue
                    not_after = datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    cn = subject.get("commonName", "?")
                    issuer_name = issuer.get("organizationName", "?")
                    days_left = (not_after - datetime.now(timezone.utc)).days

                    certs_by_domain[domain] = {
                        "cn": cn,
                        "issuer": issuer_name,
                        "not_after": not_after.strftime("%Y-%m-%d"),
                        "not_after_utc": not_after.isoformat(),
                        "days_left": days_left,
                    }
        except (ssl.SSLError, ssl.CertificateError):
            certs_by_domain[domain] = {"cn": "?", "error": "certificate validation failed"}
        except (socket.timeout, socket.gaierror, OSError):
            continue  # domain not reachable — skip silently

    if not certs_by_domain:
        return AuditFinding(
            id="NET-004", name="TLS Certificate", category="network",
            severity="info", passed=True,
            description=f"No TLS certificates reachable for {hostname} or related domains",
        )

    # Analyze results
    primary = certs_by_domain.get(hostname, {})
    distinct_certs = set(
        (d["cn"], d.get("issuer", "?"), d.get("not_after", "?"))
        for d in certs_by_domain.values() if "cn" in d
    )
    min_days = min(
        (d["days_left"] for d in certs_by_domain.values() if "days_left" in d),
        default=999,
    )

    # Build detail
    lines = []
    for domain, info in certs_by_domain.items():
        if "error" in info:
            lines.append(f"  {domain}: {info['error']}")
        else:
            lines.append(
                f"  {domain} → CN={info['cn']}, issuer={info['issuer']}, "
                f"expires={info['not_after']} ({info['days_left']}d)"
            )

    # Decide verdict
    if len(distinct_certs) > 1 and min_days < 60:
        # Multi-CDN with expiring certs — the most interesting finding
        return AuditFinding(
            id="NET-004",
            name="Multi-CDN Certificate Inconsistency",
            category="network",
            severity="high",
            passed=False,
            description=f"{len(distinct_certs)} different certificates across "
                        f"{len(certs_by_domain)} domains — earliest expires in {min_days}d",
            detail="Different CDN nodes return different certificates:\n"
                   + "\n".join(lines)
                   + "\n\nNot necessarily a vulnerability — common in multi-CDN setups. "
                   "But the inconsistency risks partial outages if one certificate expires "
                   "before others are renewed.",
            fix="Ensure all CDN edge certificates are renewed before the earliest expiry. "
                "Use UTC for all expiration tracking to avoid timezone confusion.",
        )

    if min_days <= 0:
        return AuditFinding(
            id="NET-004",
            name="TLS Certificate EXPIRED",
            category="network",
            severity="critical",
            passed=False,
            description=f"Certificate expired — found across {len(certs_by_domain)} domain(s)",
            detail="\n".join(lines),
            fix="Renew immediately: certbot renew --force-renewal",
        )

    if min_days <= 30:
        return AuditFinding(
            id="NET-004",
            name="TLS Certificate Expiring Soon (<30d)",
            category="network",
            severity="high",
            passed=False,
            description=f"Earliest expiry in {min_days} days",
            detail="\n".join(lines),
            fix="Renew before expiry.",
        )

    if len(distinct_certs) > 1:
        return AuditFinding(
            id="NET-004",
            name="Multiple Certificates Detected — All Valid",
            category="network",
            severity="info",
            passed=True,
            description=f"{len(distinct_certs)} certificates across "
                        f"{len(certs_by_domain)} domains, earliest in {min_days}d",
            detail="\n".join(lines),
        )

    return AuditFinding(
        id="NET-004",
        name="TLS Certificate Valid",
        category="network",
        severity="info",
        passed=True,
        description=f"Certificate valid for {min_days} days",
        detail="\n".join(lines),
    )


def check_secrets_key_rotation(project_dir: str) -> AuditFinding:
    """Check for key rotation documentation or automation."""
    # Look for rotation hints: scripts, docs, comments
    rotation_keywords = [
        "key rotation", "rotate keys", "key rotation policy",
        "ROTATION", "rotating keys", "rotation schedule",
    ]

    search_files = [".env", ".env.example", "README.md", "SECURITY.md",
                    "docker-compose.yml", "Makefile", "scripts/", "docs/"]

    found_rotation = False
    for fname in search_files:
        fpath = os.path.join(project_dir, fname)
        if os.path.isdir(fpath):
            continue
        content = _read_file(project_dir, fname)
        if not content:
            continue
        if any(kw in content.lower() for kw in rotation_keywords):
            found_rotation = True
            break

    if not found_rotation:
        return AuditFinding(
            id="SEC-005",
            name="No Key Rotation Documentation",
            category="secrets",
            severity="medium",
            passed=False,
            description="No key rotation policy or instructions found",
            detail="API keys that are never rotated accumulate risk over time",
            fix="Add a SECURITY.md or comment in .env:\n"
                "  # Key rotation schedule: rotate every 90 days\n"
                "  # Last rotated: 2026-06-10",
        )
    return AuditFinding(
        id="SEC-005", name="Key Rotation Policy Found", category="secrets",
        severity="medium", passed=True,
        description="Key rotation documentation detected",
    )


# ============================================================
# Probe registry
# ============================================================

# File-based probes (no network needed)
FILE_PROBES = [
    check_secrets_hardcoded_keys,
    check_secrets_env_leak,
    check_secrets_default_keys,
    check_secrets_key_strength,
    check_secrets_key_rotation,
    check_network_ports,
    check_config_rate_limiting,
    check_config_resource_limits,
    check_config_debug_mode,
    check_deploy_root_user,
    check_deploy_privileged,
    check_deploy_readonly_rootfs,
    check_deploy_image_pinning,
    check_deploy_healthcheck,
    check_deploy_restart_policy,
    check_deploy_docker_socket,
]

# Network-based probes (need endpoint + API key)
NETWORK_PROBES = [
    check_access_cors,
    check_access_no_auth,
    check_access_model_permissions,
    check_access_security_headers,
    check_network_https,
    check_network_tls_cert,
    check_network_exposed_admin,
]

FILE_PROBE_COUNT = len(FILE_PROBES)
NETWORK_PROBE_COUNT = len(NETWORK_PROBES)
TOTAL_PROBES = FILE_PROBE_COUNT + NETWORK_PROBE_COUNT


# ============================================================
# Risk Knowledge Base — plain-language explanations per probe
# ============================================================
# Probes set their own risk_what/effort if they want custom text.
# Otherwise the reporter falls back to these defaults by probe ID.

RISK_KNOWLEDGE = {
    "SEC-001": {
        "risk_what": "Anyone with access to your config files (teammates, CI logs, "
                     "backups, or an attacker who gains read access) gets full control "
                     "of your AI provider account. They can max out your billing, "
                     "steal data, or get your account permanently banned.",
        "effort": "5min",
    },
    "SEC-002": {
        "risk_what": "One accidental 'git add .' and your API keys are permanently "
                     "in git history. Even if you delete the file later, the keys "
                     "remain in old commits forever. Anyone who clones your repo "
                     "gets your keys.",
        "effort": "1min",
    },
    "SEC-003": {
        "risk_what": "Placeholder keys in active config files can be accidentally "
                     "deployed to production. If the default key has any permissions, "
                     "it gives attackers a free entry point.",
        "effort": "5min",
    },
    "SEC-004": {
        "risk_what": "Short API keys can be brute-forced. A 12-char key can be "
                     "cracked in hours with modest hardware. Your AI bill, user data, "
                     "and service reputation are on the other side of that key.",
        "effort": "5min",
    },
    "SEC-005": {
        "risk_what": "Keys that never rotate accumulate risk. Every day a key exists, "
                     "the chance it has been silently compromised increases. "
                     "Without a rotation policy, you won't know until the bill arrives.",
        "effort": "30min",
    },
    "ACC-001": {
        "risk_what": "Any website on the internet can make requests to your API "
                     "from a visitor's browser. An attacker sets up a malicious page, "
                     "a victim visits it, and their browser calls YOUR API using "
                     "THEIR credentials.",
        "effort": "5min",
    },
    "ACC-002": {
        "risk_what": "Anyone who discovers your API URL can use it. No password, "
                     "no key, nothing. Your AI provider bills you for every request. "
                     "A single attacker can run up thousands of dollars overnight.",
        "effort": "5min",
    },
    "ACC-003": {
        "risk_what": "One API key unlocks every model. A user on your free tier "
                     "can access your most expensive model. A compromised key gives "
                     "attackers access to everything, not just what you intended.",
        "effort": "15min",
    },
    "ACC-004": {
        "risk_what": "Missing security headers make your API easier to attack via "
                     "clickjacking, MIME sniffing, and XSS. Browsers use these "
                     "headers to protect users — without them, the browser can't help.",
        "effort": "5min",
    },
    "NET-001": {
        "risk_what": "All API traffic is transmitted in plain text. Anyone on the "
                     "same network (coffee shop WiFi, ISP, VPS provider) can read "
                     "every request and response — including API keys, user prompts, "
                     "and generated content.",
        "effort": "30min",
    },
    "NET-002": {
        "risk_what": "Your admin dashboard is on the public internet. If an attacker "
                     "guesses or brute-forces the password, they get full control: "
                     "create/delete keys, change models, view all usage data.",
        "effort": "5min",
    },
    "NET-003": {
        "risk_what": "Services bound to public interfaces are reachable from the "
                     "internet. If a database or admin panel is accidentally exposed, "
                     "attackers can connect directly, bypassing all application-level "
                     "security.",
        "effort": "5min",
    },
    "NET-004": {
        "risk_what": "Expired or inconsistent certificates cause outages. Different "
                     "CDN nodes with different certificates mean some users can "
                     "connect while others get security errors. In the worst case, "
                     "an expired certificate on one node blocks all traffic through "
                     "that region.",
        "effort": "15min",
    },
    "CFG-001": {
        "risk_what": "Without rate limiting, one user or attacker can send unlimited "
                     "requests. Your AI bill scales linearly with usage — a script "
                     "running overnight can generate a five-figure charge. Rate "
                     "limiting is your financial circuit breaker.",
        "effort": "5min",
    },
    "CFG-002": {
        "risk_what": "A memory leak or traffic spike can take down your entire VPS. "
                     "Without resource limits, one container can consume all RAM, "
                     "freezing SSH access and requiring a hard reboot.",
        "effort": "5min",
    },
    "CFG-003": {
        "risk_what": "Debug output in production logs exposes internal state: API "
                     "keys in error messages, full request/response bodies, internal "
                     "IP addresses. Anyone who can read your logs gets a map of your "
                     "infrastructure.",
        "effort": "1min",
    },
    "DEP-001": {
        "risk_what": "If an attacker compromises your container, running as root "
                     "means they get root on the host. With no-new-privileges "
                     "(which you have), escalation is harder but lateral movement "
                     "to other containers is still possible.",
        "effort": "15min",
    },
    "DEP-002": {
        "risk_what": "A privileged container has near-complete host access. "
                     "Compromise of this container = compromise of the entire "
                     "server. This is the Docker equivalent of running everything "
                     "as root with no sandbox.",
        "effort": "5min",
    },
    "DEP-003": {
        "risk_what": "A compromised container can write malware, modify configs, "
                     "or plant backdoors that survive container restart. Read-only "
                     "rootfs prevents attackers from establishing persistence.",
        "effort": "15min",
    },
    "DEP-004": {
        "risk_what": ":latest tags change without warning. A new version can break "
                     "your deployment silently, introduce security vulnerabilities, "
                     "or change behavior in unexpected ways. You get the update "
                     "whether you want it or not.",
        "effort": "5min",
    },
    "DEP-005": {
        "risk_what": "Without health checks, Docker doesn't know if your service "
                     "is actually working. A hung process that still accepts "
                     "connections looks 'healthy' — health checks catch the "
                     "difference between 'running' and 'working'.",
        "effort": "5min",
    },
    "DEP-006": {
        "risk_what": "Without a restart policy, a crashed service stays dead until "
                     "someone manually restarts it. At 3 AM on a Sunday, that means "
                     "your API is down for hours.",
        "effort": "1min",
    },
    "DEP-007": {
        "risk_what": "This is the worst Docker misconfiguration. Mounting the "
                     "Docker socket into a container gives that container full "
                     "control over the host — start new privileged containers, "
                     "escape to host, delete everything. Never do this.",
        "effort": "1min",
    },
}

