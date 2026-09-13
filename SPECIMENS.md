# Specimens: boot coverage under Wasmer edgejs

Measured 2026-09-13 23:43 UTC on wasmer/edgejs@0.2.0, `--experimental-napi`, default-deny network.
Each server received `initialize` then `tools/list` on stdin. Booted means it answered `initialize`.

**13 of 16 booted. 13 of 16 listed tools.** Native-module screen (`find specimens/node_modules -name "*.node"`): 0 hits.

| Server | Version | Booted | Tools | Time | Failure reason / note |
| --- | --- | --- | --- | --- | --- |
| `@modelcontextprotocol/server-memory` | 2026.8.31 | yes | 9 | 2.4s | official |
| `@modelcontextprotocol/server-filesystem` | 2026.8.31 | yes | 14 | 2.2s | official; allowed roots are argv |
| `@modelcontextprotocol/server-everything` | 2026.8.31 | yes | 12 | 2.4s | official reference server |
| `@modelcontextprotocol/server-sequential-thinking` | 2026.8.31 | yes | 1 | 1.8s | official |
| `@modelcontextprotocol/server-github` | 2025.4.8 | yes | 26 | 1.4s | official, archived upstream; token from env |
| `@modelcontextprotocol/server-postgres` | 0.6.2 | yes | 1 | 0.8s | official, archived upstream; DB url is argv |
| `@upstash/context7-mcp` | 4.1.0 | yes | 2 | 3.6s | third-party, Upstash |
| `@playwright/mcp` | 0.0.80 | no | - | 1.7s | Error: Unsupported platform: wasi — third-party, Microsoft |
| `@notionhq/notion-mcp-server` | 2.5.1 | yes | 24 | 1.1s | third-party, Notion |
| `@stripe/mcp` | 0.3.3 | no | - | 1.6s | Error: getaddrinfo ENOTFOUND mcp.stripe.com — third-party, Stripe; a stdio proxy to mcp.stripe.com |
| `tavily-mcp` | 0.2.22 | yes | 5 | 3.5s | third-party, Tavily |
| `@hubspot/mcp-server` | 0.4.0 | yes | 21 | 2.5s | third-party, HubSpot |
| `exa-mcp-server` | 3.4.1 | yes | 2 | 1.1s | third-party, Exa |
| `@sentry/mcp-server` | 0.39.0 | no | - | 60.1s | hung: no initialize reply within 60s, killed — Warning: Multiple LLM API keys are set, but no provider is explicitly configured. | Please set EMBEDDED_AGENT_PROVIDER='openai', 'azure-openai', 'anthropic', or 'openrouter' to specify which provider to use. — third-party, Sentry |
| `firecrawl-mcp` | 3.24.0 | yes | 27 | 4.3s | third-party, Firecrawl |
| `mcp-server-kubernetes` | 4.1.6 | yes | 23 | 21.9s | third-party; shells out to kubectl, which is not in the sandbox |

Raw results with tool names and integrity hashes: `evidence/boot-test.json`.
Per-specimen argv and env used: `src/specimens.mjs`.
