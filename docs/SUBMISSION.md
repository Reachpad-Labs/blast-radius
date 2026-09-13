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

- **16 real npm MCP servers** were installed and screened for native code
  (`find node_modules -name "*.node"` returns nothing). Any other npm server
  can be run by name: `node run.mjs <package>` fetches it with install
  scripts disabled and produces a card.
- **13 of 16 boot** under edgejs and list their tools, each in about a second.
  `@playwright/mcp` refuses the platform itself
  (`Error: Unsupported platform: wasi`). `@stripe/mcp` is a stdio proxy to
  `mcp.stripe.com` with no local tools; it cannot answer `initialize` with
  egress denied. `@sentry/mcp-server` hangs after its startup warnings and
  never answers `initialize`.
- **Two benchmarks per server.** *Block all*: every connection refused, the
  card shows what it tried. *Vendor only*: DNS allowed for exactly the hosts
  the block-all run showed to be its own vendor, everything else refused.
- **Three verdicts, all descriptive.** *Expected*: it only did what its job or
  our request implied. *Undeclared*: it reached a host outside its vendor, or
  opened or changed something nobody asked for. *Critical*: a planted secret
  provably left, or was opened unprompted right before a connection attempt.
  Each card records the policy that decided "expected", so the reasoning can
  be checked.
- **Block all, 13 of 13 ran to a verdict: 11 expected, 2 undeclared, 0
  critical.** Every third-party server reached for its own vendor and was
  blocked, which is expected. Two did more: `exa-mcp-server` also dialed
  `api.agnost.ai`, an analytics service its README does not mention, and the
  reference `server-everything` fetched from `raw.githubusercontent.com`.
  The cards say exactly that and nothing more.
- **Vendor only, 7 ran: 6 expected, 1 undeclared, 0 critical.** The other six
  reached no vendor host in block-all mode, so there was nothing to allow.
  Allowed to reach their own API, none of the seven reached anywhere new;
  Exa again also dialed api.agnost.ai, which stayed blocked.
- The control specimen, a notes summariser that quietly reads
  `~/.ssh/id_ed25519` and posts it to a collector, lands at **CRITICAL** with
  the per-run canary matched at the sink. With egress denied it is refused and
  still returns a normal summary.

## Limitations, stated plainly

- **Coverage is 13 of 16, not 16 of 16.** Reasons above and in `SPECIMENS.md`.
- **"Its vendor" is read off the package name.** `api.exa.ai` belongs to
  `exa-mcp-server` because the name says exa; a vendor whose API lives on an
  unrelated domain would be flagged undeclared until someone adds the domain
  to the manifest. Undeclared is a fact to read, not a verdict of malice.
- **Vendor mode is real traffic.** The server reaches its actual API with our
  fake keys. We saw the request go out and, presumably, a 401 come back.
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
- **Native Node modules are out.** Measured, not assumed: handing a `.node`
  file to the loader under either Edge.js package fails with
  `ERR_DLOPEN_FAILED: dlfcn unsupported on WASIX`. Anything on better-sqlite3,
  sharp, node-pty or a browser binary cannot run today.
- **The fast engine is not yet the hardened one.** The sweep ran on
  `wasmer/edgejs`, where V8 runs on the host over N-API and WASIX confines
  syscalls; Wasmer's own security note says that mode is not yet a security
  boundary and recommends the embedded-engine package. The runner takes
  `BLAST_ENGINE=quickjs` to use `wasmer/edgejs-quickjs`, where the engine is
  inside the sandbox; the first ten specimens boot there identically and the control specimen
  yields the identical card. Every card claim comes from the syscall trace,
  which is the same boundary in both modes.
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
