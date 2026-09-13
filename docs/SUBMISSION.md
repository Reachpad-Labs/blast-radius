# Submission text

Paste-ready for the BuilderBase form. Numbers are from today's runs; if the
sweep is re-run before submitting, check them against `SPECIMENS.md` and
`evidence/cards/README.md`.

**Track:** Wasmer

**One line.** Blast Radius detonates an npm MCP server inside Wasmer against a
fake home directory full of unique canary secrets, traces every syscall it
makes, and prints a card saying what it touched and where it tried to send it.

## What it does

You `npm install` an MCP server and it runs beside your agent with your
filesystem and your tokens. You read the README, not the code. Blast Radius
runs that server under `wasmer/edgejs` with the world mounted at `/home`, drives
it over MCP (initialize, tools/list, then a call to every tool it advertises),
and turns the WASIX syscall trace into a verdict card: which credential files it
opened, which hosts it dialed, whether it wrote outside its own tree, and, when
egress is routed to a collector we control, whether a specific canary string
actually left the box.

## Why the WASI boundary is the instrument, not just the runtime

A Node server can hide a network call behind any library it likes, but it
cannot open a file or a socket without crossing the WASI import table, and
Wasmer logs every crossing with its arguments and its errno. We did not write
a monitor; we rented the one syscall boundary the code cannot route around,
and put policy (`--net`) on the same boundary so a refused connection is both
observed and survivable: the server keeps running and keeps answering.

## The numbers, measured 2026-09-13

- **10 real npm MCP servers** were installed and screened for native code
  (`find node_modules -name "*.node"` returns nothing).
- **8 of 10 boot** under edgejs and list their tools, each in under a second.
  `@playwright/mcp` refuses the platform itself
  (`Error: Unsupported platform: wasi`). `@stripe/mcp` is a stdio proxy to
  `mcp.stripe.com` with no local tools; it cannot answer `initialize` with
  egress denied.
- **8 of 8 ran to a verdict**: 6 warn, 2 clean, 0 critical. Every archived
  official server and every third-party server dialed its vendor
  (api.github.com, api.notion.com, context7.com, raw.githubusercontent.com,
  the Postgres URL), and every dial was blocked.
- The control specimen, a notes summariser that quietly reads
  `~/.ssh/id_ed25519` and posts it to a collector, lands at **CRITICAL** with
  the per-run canary matched at the sink. With egress denied it is refused and
  still returns a normal summary.

## Limitations, stated plainly

- **Coverage is 8 of 10, not 10 of 10.** Reasons above and in `SPECIMENS.md`.
- **Payload bytes are not in the trace.** `sock_send` reports a byte count. A
  card says "dialed host X, blocked" from the trace alone; it says "your key
  left the box" only when egress was routed to a sink we control and the
  canary string was found in the capture. The two tiers are labelled on every
  card and never mixed.
- **One execution path.** We call every tool once with plausible arguments.
  Anything that fires on the fiftieth call, after a date, or only with real
  credentials traces clean.
- **Writes are seen by their side effects.** The trace carries no open flags,
  so a write is detected from a rename onto a path or an unlink of it (which
  catches atomic writes, and caught `server-filesystem` overwriting the seeded
  key when asked). An in-place open-then-write is not yet resolved back to its
  path.
- **Environment reads are invisible.** `environ_get` reports sizes only. A
  server that reads `GITHUB_TOKEN` and ships it is caught at the sink, not in
  the trace.
- **Python MCP servers are out entirely.** `pip install mcp` reaches `rpds-py`,
  a Rust extension with no wasm32-wasi wheel.
- **Native Node modules are out.** Anything on better-sqlite3, sharp, node-pty
  or a browser binary cannot run.
- **One run is one sample.** A card describes behaviour observed in a single
  execution against a canary world. It is not a claim about the package in
  general, and we name real packages, so every card says so in its footer.

## Links

- Repository: https://github.com/Reachpad-Labs/blast-radius (flip to public
  before submitting: `gh repo edit Reachpad-Labs/blast-radius --visibility public`)
- Coverage table: `SPECIMENS.md`
- Verdict index and cards: `evidence/cards/README.md`
- Everything we measured and every trap: `docs/FINDINGS.md`
- Video: (add the upload URL)
