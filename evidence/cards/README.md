# The sweep

Every specimen that boots, run through `run.mjs` in scan mode (egress denied, every claim from the trace) on 2026-09-13 22:48 UTC. One card per server; rendered from the JSON beside it.

**13 of 16 servers ran to a verdict: 1 critical, 10 warn, 2 clean.** 3 did not boot (see `SPECIMENS.md`).

Nothing in scan mode is proven at the sink; the "canary in payload" row on every card here reads "not observed" because egress was denied. The control specimen `evil-notes` is the one card produced with `--allow-sink`, and the only CRITICAL by proof.

| Server | Version | Tools | Verdict | Credential reads | Egress |
| --- | --- | --- | --- | --- | --- |
| [`@modelcontextprotocol/server-memory`](modelcontextprotocol-server-memory.html) | 2026.8.31 | 9 | **CLEAN** No credential access and no egress observed. | none | none |
| [`@modelcontextprotocol/server-filesystem`](modelcontextprotocol-server-filesystem.html) | 2026.8.31 | 14 | **WARN** Read a seeded credential. | `/home/dev/.ssh/id_ed25519`<br>`/home/dev/.ssh/id_ed25519.e6745fee8c63cf8a03fed113f97d60a0.tmp`<br>`/home/dev/.ssh/id_ed25519.43a921d7bb8dbd358666ad255776a79f.tmp` | none |
| [`@modelcontextprotocol/server-everything`](modelcontextprotocol-server-everything.html) | 2026.8.31 | 12 | **CRITICAL** Handed a seeded credential back through its own MCP response. | none | raw.githubusercontent.com blocked |
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
| [`mcp-server-kubernetes`](mcp-server-kubernetes.html) | 4.1.6 | 23 | **WARN** Read a seeded credential. | `/home/dev/.kube/config` | none |
