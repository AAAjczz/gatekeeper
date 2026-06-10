# Gatekeeper

> AI Infrastructure Security Auditor — because your deployment has bugs your model scanner can't find.

**14 probes across 5 categories.** Point it at any AI API deployment directory
and get a security score with specific fixes. Tests the INFRASTRUCTURE layer
that garak, augustus, and promptfoo don't touch.

## Where Gatekeeper Fits

```
AI Security Stack:
├── Model Layer  → garak, augustus       (prompt injection, jailbreaks)
├── Code Layer   → promptfoo             (data flow: prompt → LLM → sink)
├── Deploy Layer → GATEKEEPER (this)     (docker, secrets, CORS, rate limits)
└── Infra Layer  → your existing tools   (firewall, OS hardening)
```

Gatekeeper is the missing piece: deployment-level security for self-hosted AI APIs.

## Quick Start

```bash
pip install -e .

# Audit a project directory
gatekeeper audit -d /path/to/chinai-gateway

# With network checks
gatekeeper audit -d . -e http://localhost:4000/v1

# Check what config files exist
gatekeeper files -d .
```

## What It Tests

| Category | Checks | Examples |
|----------|--------|----------|
| **Secrets** | 3 | Hardcoded keys in config, .env in gitignore, default passwords |
| **Access Control** | 3 | CORS wildcard, unauthenticated access, per-model permissions |
| **Network** | 3 | HTTPS enforcement, exposed admin UI, public port bindings |
| **Configuration** | 2 | Rate limiting, container resource limits |
| **Deployment** | 3 | Root user (with mitigation detection), privileged mode, read-only rootfs |

## Example Output

```
+---------------------- Gatekeeper Infrastructure Audit ----------------------+
| Security Score: 44.4%                                                       |
+----------------------------- 2026-06-10 21:13 ------------------------------+
  Project:   /path/to/chinai-gateway
  Passed:    4 / 9
  Failed:    5 / 9
  Serious issues — do not deploy publicly yet

Results by Category
┌────────────┬────────┬───────┬──────┐
│ secrets    │      2 │     3 │  67% │
│ network    │      1 │     1 │ 100% │
│ config     │      0 │     2 │   0% │
│ deployment │      1 │     3 │  33% │
└────────────┴────────┴───────┴──────┘

FAIL  SEC-002 — .env Variants Not Protected                    [MEDIUM]
FAIL  CFG-001 — No Rate Limiting in Project Config             [HIGH]
       If rate limiting is on external Nginx, add a note or nginx.conf
       so CI tools can verify it.
FAIL  DEP-001 — Running as Root — Partial Mitigations Present  [MEDIUM]
       security_opt: no-new-privileges blocks escalation (+ user: recommended)
```

## Output Formats

```bash
gatekeeper audit -f terminal   # Rich terminal table (default)
gatekeeper audit -f json       # JSON for CI/CD pipelines
gatekeeper audit -f html       # HTML for sharing
gatekeeper audit -f all        # All three at once
```

## Exit Codes

- `0` — no critical or high-severity findings
- `1` — at least one critical/high vulnerability found

## Comparison

| | garak | promptfoo | Gatekeeper |
|---|---|---|---|
| Scope | Model responses | Code data flow | Deployment config |
| Tests | Jailbreaks, injection | Prompt→LLM→sink | Secrets, CORS, ports, limits |
| Install | `pip install garak` | `npx promptfoo` | `pip install gatekeeper-ai` |
| Backed by | NVIDIA | OpenAI (acquired) | Independent (MIT) |

## License

MIT — audit everything. Built to pair with [chinai-gateway](https://github.com/AAAjczz/chinai-gateway).
