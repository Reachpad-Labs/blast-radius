# The sweep

Every server that boots, run through `run.mjs` on 2026-09-14 00:02 UTC. One card per server per benchmark; each renders from the JSON beside it.

**Verdicts:** *expected* means it only did what its job or our request implied; *undeclared* means it reached a host outside its vendor, or opened or changed something nobody asked for; *critical* means a planted secret provably left, or was opened unprompted right before a connection attempt.

**Two benchmarks.** *Block all*: every connection refused; the card shows what it tried. *Vendor only*: DNS allowed for exactly the hosts the block-all run judged to be its vendor, everything else refused, real traffic with fake keys. The control specimen `evil-notes` ran with our collector allowed instead, and is the only card that can be critical by proof. The second control, `quiet-notes`, needed no network permission of any kind: it hands the secret to the model in its own answer and copies more onto disk, which is why watching the network alone is not enough.

**Block all: 13 of 16 ran to a verdict: 1 critical, 2 undeclared, 10 expected.** 3 did not boot (see `SPECIMENS.md`).
**Vendor only: 7 ran: 0 critical, 1 undeclared, 6 expected.** The rest reached no vendor host in block-all mode, so there was nothing to allow.

| Server | Version | Tools | Block all | Reached out to (block all) | Vendor only | Reached out to (vendor only) |
| --- | --- | --- | --- | --- | --- | --- |
| [`evil-notes`](evil-notes.html) (control, collector allowed) | 1.0.0 | 1 | **CRITICAL** Sent a planted secret out of the sandbox. Proven: it arrived at our collector. | 127.0.0.1 allowed **undeclared** | – | – |
| [`quiet-notes`](quiet-notes.html) (control, no network at all) | 1.0.0 | 1 | **CRITICAL** Handed a planted secret back to the model in the answer from “summarize_notes”. | none | – | – |
| [`@modelcontextprotocol/server-memory`](modelcontextprotocol-server-memory.html) | 2026.8.31 | 9 | **EXPECTED** Did nothing beyond starting up and answering. | none | – | – |
| [`@modelcontextprotocol/server-filesystem`](modelcontextprotocol-server-filesystem.html) | 2026.8.31 | 14 | **EXPECTED** Only did what its job or our request implied. | none | – | – |
| [`@modelcontextprotocol/server-everything`](modelcontextprotocol-server-everything.html) | 2026.8.31 | 12 | **CRITICAL** Handed 8 planted secrets back to the model in the answer from “get-env”. | raw.githubusercontent.com blocked **undeclared** | – | – |
| [`@modelcontextprotocol/server-sequential-thinking`](modelcontextprotocol-server-sequential-thinking.html) | 2026.8.31 | 1 | **EXPECTED** Did nothing beyond starting up and answering. | none | – | – |
| [`@modelcontextprotocol/server-github`](modelcontextprotocol-server-github.html) | 2025.4.8 | 26 | **EXPECTED** Only did what its job or our request implied. | api.github.com blocked | [**EXPECTED** Only did what its job or our request implied.](modelcontextprotocol-server-github--vendor.html) | api.github.com allowed |
| [`@modelcontextprotocol/server-postgres`](modelcontextprotocol-server-postgres.html) | 0.6.2 | 1 | **EXPECTED** Only did what its job or our request implied. | 127.0.0.1 blocked | – | – |
| [`@upstash/context7-mcp`](upstash-context7-mcp.html) | 4.1.0 | 2 | **EXPECTED** Only did what its job or our request implied. | context7.com blocked | [**EXPECTED** Only did what its job or our request implied.](upstash-context7-mcp--vendor.html) | context7.com allowed |
| `@playwright/mcp` | 0.0.80 | - | did not boot | Error: Unsupported platform: wasi | – | – |
| [`@notionhq/notion-mcp-server`](notionhq-notion-mcp-server.html) | 2.5.1 | 24 | **EXPECTED** Only did what its job or our request implied. | api.notion.com blocked | [**EXPECTED** Only did what its job or our request implied.](notionhq-notion-mcp-server--vendor.html) | api.notion.com allowed |
| `@stripe/mcp` | 0.3.3 | - | did not boot | Error: getaddrinfo ENOTFOUND mcp.stripe.com | – | – |
| [`tavily-mcp`](tavily-mcp.html) | 0.2.22 | 5 | **EXPECTED** Only did what its job or our request implied. | api.tavily.com blocked | [**EXPECTED** Only did what its job or our request implied.](tavily-mcp--vendor.html) | api.tavily.com allowed |
| [`@hubspot/mcp-server`](hubspot-mcp-server.html) | 0.4.0 | 21 | **EXPECTED** Only did what its job or our request implied. | api.hubspot.com blocked | [**EXPECTED** Only did what its job or our request implied.](hubspot-mcp-server--vendor.html) | api.hubspot.com allowed |
| [`exa-mcp-server`](exa-mcp-server.html) | 3.4.1 | 2 | **UNDECLARED** Reached out to api.agnost.ai, which nothing declared. | api.exa.ai blocked<br>api.agnost.ai blocked **undeclared** | [**UNDECLARED** Reached out to api.agnost.ai, which nothing declared.](exa-mcp-server--vendor.html) | api.exa.ai allowed<br>api.agnost.ai blocked **undeclared** |
| `@sentry/mcp-server` | 0.39.0 | - | did not boot | hung: no initialize reply within 60s, killed — Warning: Multiple LLM API keys are set, but no provider is explicitly con | – | – |
| [`firecrawl-mcp`](firecrawl-mcp.html) | 3.24.0 | 27 | **EXPECTED** Only did what its job or our request implied. | api.firecrawl.dev blocked | [**EXPECTED** Only did what its job or our request implied.](firecrawl-mcp--vendor.html) | api.firecrawl.dev allowed |
| [`mcp-server-kubernetes`](mcp-server-kubernetes.html) | 4.1.6 | 23 | **UNDECLARED** Opened /home/dev/.kube/config without being asked. | none | – | – |
