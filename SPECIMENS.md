# Specimens: boot coverage under Wasmer edgejs

Measured 2026-09-13 21:10 UTC on wasmer/edgejs@0.2.0, `--experimental-napi`, default-deny network.
Each server received `initialize` then `tools/list` on stdin. Booted means it answered `initialize`.

**8 of 10 booted. 8 of 10 listed tools.** Native-module screen (`find specimens/node_modules -name "*.node"`): 0 hits.

| Server | Version | Booted | Tools | Time | Failure reason / note |
| --- | --- | --- | --- | --- | --- |
| `@modelcontextprotocol/server-memory` | 2026.8.31 | yes | 9 | 1.0s | official |
| `@modelcontextprotocol/server-filesystem` | 2026.8.31 | yes | 14 | 0.5s | official; allowed roots are argv |
| `@modelcontextprotocol/server-everything` | 2026.8.31 | yes | 12 | 0.5s | official reference server |
| `@modelcontextprotocol/server-sequential-thinking` | 2026.8.31 | yes | 1 | 0.4s | official |
| `@modelcontextprotocol/server-github` | 2025.4.8 | yes | 26 | 0.4s | official, archived upstream; token from env |
| `@modelcontextprotocol/server-postgres` | 0.6.2 | yes | 1 | 0.2s | official, archived upstream; DB url is argv |
| `@upstash/context7-mcp` | 4.1.0 | yes | 2 | 0.9s | third-party, Upstash |
| `@playwright/mcp` | 0.0.80 | no | - | 0.4s | Error: Unsupported platform: wasi — third-party, Microsoft |
| `@notionhq/notion-mcp-server` | 2.5.1 | yes | 24 | 0.3s | third-party, Notion |
| `@stripe/mcp` | 0.3.3 | no | - | 0.4s | Error: getaddrinfo ENOTFOUND mcp.stripe.com — third-party, Stripe; a stdio proxy to mcp.stripe.com |

Raw results with tool names and integrity hashes: `evidence/boot-test.json`.
Per-specimen argv and env used: `src/specimens.mjs`.
