# The sweep

Every specimen that boots, run through `run.mjs` in scan mode (egress denied, every claim from the trace) on 2026-09-13 21:10 UTC. One card per server; rendered from the JSON beside it.

**8 of 10 servers ran to a verdict: 0 critical, 6 warn, 2 clean.** 2 did not boot (see `SPECIMENS.md`).

Nothing in scan mode is proven at the sink; the "canary in payload" row on every card here reads "not observed" because egress was denied. The control specimen `evil-notes` is the one card produced with `--allow-sink`, and the only CRITICAL by proof.

| Server | Version | Tools | Verdict | Credential reads | Egress |
| --- | --- | --- | --- | --- | --- |
| [`@modelcontextprotocol/server-memory`](modelcontextprotocol-server-memory.html) | 2026.8.31 | 9 | **CLEAN** No credential access and no egress observed. | none | none |
| [`@modelcontextprotocol/server-filesystem`](modelcontextprotocol-server-filesystem.html) | 2026.8.31 | 14 | **WARN** Read a seeded credential. | `/home/.ssh/id_ed25519`<br>`/home/.ssh/id_ed25519.29e062ef88540920e8b13f39ef544e46.tmp`<br>`/home/.ssh/id_ed25519.de94a6e92b16e333ea7f72a0c52baca7.tmp` | none |
| [`@modelcontextprotocol/server-everything`](modelcontextprotocol-server-everything.html) | 2026.8.31 | 12 | **WARN** Attempted egress. | none | raw.githubusercontent.com blocked |
| [`@modelcontextprotocol/server-sequential-thinking`](modelcontextprotocol-server-sequential-thinking.html) | 2026.8.31 | 1 | **CLEAN** No credential access and no egress observed. | none | none |
| [`@modelcontextprotocol/server-github`](modelcontextprotocol-server-github.html) | 2025.4.8 | 26 | **WARN** Attempted egress. | none | api.github.com blocked |
| [`@modelcontextprotocol/server-postgres`](modelcontextprotocol-server-postgres.html) | 0.6.2 | 1 | **WARN** Attempted egress. | none | 127.0.0.1:5432 blocked |
| [`@upstash/context7-mcp`](upstash-context7-mcp.html) | 4.1.0 | 2 | **WARN** Attempted egress. | none | context7.com blocked |
| `@playwright/mcp` | 0.0.80 | - | did not boot | - | Error: Unsupported platform: wasi |
| [`@notionhq/notion-mcp-server`](notionhq-notion-mcp-server.html) | 2.5.1 | 24 | **WARN** Attempted egress. | none | api.notion.com blocked |
| `@stripe/mcp` | 0.3.3 | - | did not boot | - | Error: getaddrinfo ENOTFOUND mcp.stripe.com |
