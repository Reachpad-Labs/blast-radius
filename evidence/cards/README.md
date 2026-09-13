# The sweep

Every specimen that boots, run through `run.mjs` in scan mode (egress denied, every claim from the trace) on 2026-09-13 21:50 UTC. One card per server; rendered from the JSON beside it.

**13 of 16 servers ran to a verdict: 0 critical, 10 warn, 3 clean.** 3 did not boot (see `SPECIMENS.md`).

Nothing in scan mode is proven at the sink; the "canary in payload" row on every card here reads "not observed" because egress was denied. The control specimen `evil-notes` is the one card produced with `--allow-sink`, and the only CRITICAL by proof.

| Server | Version | Tools | Verdict | Credential reads | Egress |
| --- | --- | --- | --- | --- | --- |
| [`@modelcontextprotocol/server-memory`](modelcontextprotocol-server-memory.html) | 2026.8.31 | 9 | **CLEAN** No credential access and no egress observed. | none | none |
| [`@modelcontextprotocol/server-filesystem`](modelcontextprotocol-server-filesystem.html) | 2026.8.31 | 14 | **WARN** Read a seeded credential. | `/home/.ssh/id_ed25519`<br>`/home/.ssh/id_ed25519.f36e7fbf21e0b8955d07586b64272ee2.tmp`<br>`/home/.ssh/id_ed25519.4d32d468d9ddf0cb3320a5789f365b24.tmp` | none |
| [`@modelcontextprotocol/server-everything`](modelcontextprotocol-server-everything.html) | 2026.8.31 | 12 | **WARN** Attempted egress. | none | raw.githubusercontent.com blocked |
| [`@modelcontextprotocol/server-sequential-thinking`](modelcontextprotocol-server-sequential-thinking.html) | 2026.8.31 | 1 | **CLEAN** No credential access and no egress observed. | none | none |
| [`@modelcontextprotocol/server-github`](modelcontextprotocol-server-github.html) | 2025.4.8 | 26 | **WARN** Attempted egress. | none | api.github.com blocked |
| [`@modelcontextprotocol/server-postgres`](modelcontextprotocol-server-postgres.html) | 0.6.2 | 1 | **WARN** Attempted egress. | none | 127.0.0.1:5432 blocked |
| [`@upstash/context7-mcp`](upstash-context7-mcp.html) | 4.1.0 | 2 | **WARN** Attempted egress. | none | context7.com blocked |
| `@playwright/mcp` | 0.0.80 | - | did not boot | - | Error: Unsupported platform: wasi |
| [`@notionhq/notion-mcp-server`](notionhq-notion-mcp-server.html) | 2.5.1 | 24 | **WARN** Attempted egress. | none | api.notion.com blocked |
| `@stripe/mcp` | 0.3.3 | - | did not boot | - | Error: getaddrinfo ENOTFOUND mcp.stripe.com |
| [`tavily-mcp`](tavily-mcp.html) | 0.2.22 | 5 | **WARN** Attempted egress. | none | api.tavily.com blocked |
| [`@hubspot/mcp-server`](hubspot-mcp-server.html) | 0.4.0 | 21 | **WARN** Attempted egress. | none | api.hubspot.com blocked |
| [`exa-mcp-server`](exa-mcp-server.html) | 3.4.1 | 2 | **WARN** Attempted egress. | none | api.exa.ai blocked<br>api.agnost.ai blocked |
| `@sentry/mcp-server` | 0.39.0 | - | did not boot | - | hung: no initialize reply within 60s, killed — Warning: No LLM API key found (OPENAI_API_KEY, ANTHROPIC_API_KEY, or OPEN |
| [`firecrawl-mcp`](firecrawl-mcp.html) | 3.24.0 | 27 | **WARN** Attempted egress. | none | api.firecrawl.dev blocked |
| [`mcp-server-kubernetes`](mcp-server-kubernetes.html) | 4.1.6 | 23 | **CLEAN** No credential access and no egress observed. | none | none |
