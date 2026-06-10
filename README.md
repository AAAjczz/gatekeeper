# Gatekeeper

> LLM API security scanner — red team your AI endpoints in one command.

**17 probes across 6 categories.** Point it at any OpenAI-compatible API endpoint and get a security score with detailed pass/fail results in 30 seconds.

## Why

- **Promptfoo was acquired by OpenAI** — vendor-neutral security testing needs independent tools
- **LLM APIs are the new attack surface** — prompt injection, jailbreaking, data extraction
- **Your gateway needs a gatekeeper** — built to pair with [chinai-gateway](https://github.com/AAAjczz/chinai-gateway)

## Quick Start

```bash
pip install -e .

# Scan the default endpoint (chinai-gateway on localhost)
gatekeeper scan

# Scan any OpenAI-compatible API
gatekeeper scan --endpoint https://api.deepseek.com/v1 -k YOUR_API_KEY

# Check connectivity first
gatekeeper probe -e https://api.openai.com/v1 -k sk-xxx
```

## What It Tests

| Category | Probes | What It Checks |
|----------|--------|---------------|
| **Injection** | 3 | Direct override, context switching, multi-shot injection |
| **Jailbreak** | 3 | DAN, hypothetical framing, poetic evasion |
| **Extraction** | 2 | System prompt extraction via formatting & emotional appeal |
| **Leakage** | 2 | PII probing, token/model info disclosure |
| **Evasion** | 3 | Base64 encoding, Unicode homoglyph, multi-language bypass |
| **Boundary** | 2 | Malware generation, hate speech boundary testing |

## Output Formats

```bash
# Terminal table (default)
gatekeeper scan -f terminal

# JSON report (for CI/CD)
gatekeeper scan -f json -o ./reports

# HTML report (for sharing)
gatekeeper scan -f html -o ./reports

# All formats
gatekeeper scan -f all
```

## Exit Codes

- `0` — no critical or high-severity failures
- `1` — at least one critical or high-severity vulnerability found

CI/CD friendly: fail your pipeline if the model is vulnerable.

## Example Output

```
╭──────────────────────────────────────────╮
│ Gatekeeper Scan Report                   │
│                                          │
│ Security Score: 82.4%                    │
│ Endpoint: http://localhost:4000/v1       │
│ Model: deepseek-chat                     │
│ Passed: 14/17  Failed: 3/17              │
│ Adequate — some probes require attention │
╰──────────────────────────────────────────╯

Results by Category
┌────────────┬────────┬───────┬──────┐
│ Category   │ Passed │ Total │ Rate │
├────────────┼────────┼───────┼──────┤
│ injection  │      3 │     3 │ 100% │
│ jailbreak  │      3 │     3 │ 100% │
│ extraction │      1 │     2 │  50% │
│ leakage    │      2 │     2 │ 100% │
│ evasion    │      2 │     3 │  67% │
│ boundary   │      3 │     4 │  75% │
└────────────┴────────┴───────┴──────┘
```

## Integrating with chinai-gateway

Add to `docker-compose.yml`:

```yaml
services:
  gatekeeper:
    image: python:3.11-slim
    command: >
      sh -c "pip install gatekeeper-ai &&
             gatekeeper scan -e http://litellm:4000/v1 -f json -o /reports"
    volumes:
      - ./reports:/reports
    depends_on:
      - litellm
```

## License

MIT — use it, fork it, ship it.
