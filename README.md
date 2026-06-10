# Gatekeeper

## 1. What is this?

**An infrastructure security scanner for self-hosted AI APIs.**

Point it at your project directory. It finds the deployment mistakes that your model scanner can't see: hardcoded API keys, missing rate limits, CORS misconfiguration, containers running as root, TLS certificates about to expire.

**Who it's for:** Developers running their own AI API gateway (LiteLLM, chinai-gateway, or any OpenAI-compatible endpoint). If you `docker compose up` an AI service, this is for you.

```bash
pip install gatekeeper-audit
gatekeeper audit -d /path/to/your-project
```

## 2. What problem does it solve?

You deployed an AI API. You tested the model — jailbreaks, prompt injection, the works. But did you check if your `.env` file is in `.gitignore`? Or if your API accepts requests without authentication? Or if your TLS certificate expires next week?

**Model scanners test your model. Gatekeeper tests your deployment.** They're different attack surfaces.

What you get:
- A security score and a **priority action plan** — what to fix first, how long it takes
- **Plain-language risk explanations** — not "CRITICAL severity", but "your API key is in git history and anyone who clones your repo can use it"
- **Copy-paste fixes** — exact YAML snippets, exact commands
- **CI/CD integration** — SARIF output, GitHub Actions, PR comments

## 3. Why not just use garak or promptfoo?

| | garak | promptfoo | Gatekeeper |
|---|---|---|---|
| What it tests | Model responses | Code data flow | **Deployment config** |
| Finds hardcoded API keys? | No | No | **Yes** |
| Finds missing rate limits? | No | No | **Yes** |
| Finds expiring TLS certs? | No | No | **Yes** |
| Finds CORS misconfiguration? | No | No | **Yes** |
| Finds privileged containers? | No | No | **Yes** |
| Backed by | NVIDIA | OpenAI (acquired) | **Independent (MIT)** |

**garak and promptfoo are the right tools for model-level and code-level security.** Gatekeeper is the missing layer: deployment-level. They don't compete — they stack.

## 4. Free or paid?

**Free. MIT license.** No API key required. No cloud service. No telemetry. Everything runs locally — your config files never leave your machine.

If you want deeper AI-powered analysis, bring your own DeepSeek/OpenAI key and we'll give you the prompt template. But the built-in knowledge base covers the common cases without any API calls.

---

## Quick Start

```bash
pip install git+https://github.com/AAAjczz/gatekeeper.git

# Audit a project (file checks)
gatekeeper audit -d /path/to/chinai-gateway

# Full audit (file + network checks)
gatekeeper audit -d . -e https://api.deepseek.com/v1 -k YOUR_KEY

# Output formats
gatekeeper audit -f terminal   # default
gatekeeper audit -f sarif      # GitHub code scanning
gatekeeper audit -f html       # shareable report
gatekeeper audit -f all        # everything
```

## Real Finding

Gatekeeper's multi-domain TLS probe scanned `api.deepseek.com` and found 3 different certificates across CDN nodes — earliest expiring in 8 days:

```
deepseek.io       → GoDaddy     → expires in 8 days
api.deepseek.com  → TrustAsia   → expires in 24 days
deepseek.com      → DigiCert    → expires in 177 days
```

No model scanner or code scanner would find this. Infrastructure auditing does.

## License

MIT — [github.com/AAAjczz/gatekeeper](https://github.com/AAAjczz/gatekeeper)
