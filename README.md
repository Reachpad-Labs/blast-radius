# Blast Radius

Detonate an MCP server in a sandbox we fully instrument, and print exactly what
installing it would have cost you.

Built at the AI Security Hackathon, SF, 2026-09-13. Wasmer SDK track.

## Start here

New to the repo, or a new session? Read [CLAUDE.md](CLAUDE.md) (where things
are, the rules the code does not explain, known gaps), then
[docs/FINDINGS.md](docs/FINDINGS.md) (everything measured, every trap). The
paste-ready submission text is [docs/SUBMISSION.md](docs/SUBMISSION.md). The
team board is https://blast-radius-board-edksg.reachpad.app/.

## The idea

You `npm install` an MCP server. It then runs beside your agent with your
filesystem and your tokens. You read the README, not the code.

Blast Radius runs that server inside Wasmer against a **canary world** — a
working developer's home directory whose every secret is a unique string, plus a
shell environment full of unique tokens — traces every syscall it makes, and
prints a card saying what it touched and where it tried to send it.

## Status: the instrument works and the premise is proven

Everything below was verified on a real run today. Evidence is in `evidence/`.

| Question | Answer |
| --- | --- |
| Do real npm MCP servers run under Wasmer? | **Yes.** `@modelcontextprotocol/server-memory` boots, completes the MCP handshake, lists 9 tools. |
| How many real ones boot? | **13 of 16**, each in about a second. The ones that do not, with reasons, in [SPECIMENS.md](SPECIMENS.md). |
| Can we see file access? | **Yes, with full paths.** |
| Can we see network destinations? | **Yes, host and address.** |
| Can we see payload bytes? | **No** — size only. Payload proof needs a sink we control. |
| Can we deny egress and keep the process alive? | **Yes.** |
| What does a card conclude? | One of three descriptive verdicts: **expected**, **undeclared**, **critical**, with the policy that decided "expected" recorded on the card. |
| Under which network policies? | Two benchmarks per server: **block all** (default, every connection refused) and **vendor only** (DNS allowed for its own vendor, nothing else). The control also runs with our collector allowed. |
| Does the result depend on the fast engine? | **No.** The sweep gives identical findings under `wasmer/edgejs` (V8 on the host) and `wasmer/edgejs-quickjs` (engine inside the sandbox). |
| Can native Node addons run? | **No**, measured: `dlfcn unsupported on WASIX` under both packages. |

The two lines that make the demo, from a real trace:

```
path_open2: return=Ok(Errno::success) path="/home/dev/.ssh/id_ed25519" ret_fd=6
resolve:    return=Ok(Errno::perm)    host="example.com" port=0
```

Read the canary key, then tried to resolve `example.com` and was refused — and
the process ran to completion.

## Setup

```sh
curl -sSfL https://get.wasmer.io | sh          # installs to ~/.wasmer
source ~/.wasmer/wasmer.sh                     # wasmer 7.4.1+
cd specimens && npm install --ignore-scripts   # the MCP servers under test
```

## Run a Node MCP server under the trace

```sh
printf '%s\n%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"blast-radius","version":"0.1"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' > rpc.txt

RUST_LOG="wasmer_wasix::syscalls=trace" \
wasmer run wasmer/edgejs@0.2.0 --experimental-napi \
  --volume "$PWD/specimens:/app" \
  --volume "$PWD/fixtures/world/home:/home" \
  --env HOME=/home/dev --env USER=dev \
  --net="dns:deny=*:*" \
  -- /app/node_modules/@modelcontextprotocol/server-memory/dist/index.js \
  < rpc.txt 2>trace.log
```

`--net` rule syntax: `<rule-type>:<allow|deny>=<expr>`, e.g.
`dns:allow=example.com:80`, `dns:deny=*danger.xyz:*`, `ipv4:allow=127.0.0.1:80`.
Omitting `--net` entirely is default-deny and the guest still runs.

## Prove a canary left the box

```sh
node harness/sink.mjs &                                # capture sink on :8099
wasmer run python/python@3.13.20 \
  --volume "$PWD/fixtures/world/home:/home" --volume "$PWD/harness/probes:/app" \
  --net -- /app/exfil.py
cat sink.log                                   # canary string, on the wire
```

## The canary world

The guest gets a home directory that looks like a machine someone works on:
34 files, 16 of them carrying a canary, mounted at `/home` with `HOME=/home/dev`.

```
~/.ssh/           id_ed25519, id_rsa, known_hosts, config, authorized_keys
~/.aws/           credentials, config
~/.config/        gh/hosts.yml, gcloud/application_default_credentials.json,
                  Claude/claude_desktop_config.json   (tokens in an MCP config)
~/.docker/config.json  ~/.kube/config  ~/.npmrc  ~/.pypirc  ~/.netrc
~/.git-credentials  ~/.cargo/credentials.toml  ~/.claude/.credentials.json
~/.bashrc  ~/.bash_history  ~/.gitconfig  ~/.viminfo
~/Documents  ~/Downloads  ~/projects/acme-api   (benign noise, and a real .env)
```

Plus **19 environment variables** — `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`,
`ANTHROPIC_API_KEY`, `DATABASE_URL` and friends, each canary-valued, alongside
the ordinary `PATH`/`SHELL`/`LANG` of a real shell.

Why env matters: **Wasmer inherits nothing from the host.** An unseeded run hands
the specimen `process.env === {}`, so the single most common exfiltration path
finds an empty object and the card reads clean. Measured, not assumed.

Env canaries are `proven-at-sink` only. `environ_get` copies the whole block in
one call, so the trace shows *that* the environment was read and never *which*
variable was taken.

And a machine around it. WASIX has no procfs and its `/etc` holds one file, so
the world supplies its own — every top-level directory of the template is
mounted at the same name in the guest:

```
/etc/   passwd (a `dev` user, uid 1000), group, shadow, hosts, resolv.conf,
        hostname, machine-id, os-release (Ubuntu 24.04)
/proc/  version, cpuinfo, meminfo, mounts, self/status, self/cmdline,
        self/environ  ← generated at seed time, same canaries as --env
/sys/   class/dmi/id/{sys_vendor,product_name,product_uuid}  (reads as EC2)
```

These trees are hardened after seeding — files `0444`, directories `0555`, and
`/etc/shadow` `0000`. WASI itself has no permissions (every path reports
`mode=0 uid=0`), but the host kernel enforces the host's modes when Wasmer
touches the file, so the guest gets the shape of a fresh box seen from uid 1000:
`/etc/passwd` reads and refuses writes, `/etc/shadow` refuses the read, and
`$HOME` is fully writable. The shadow canary is the negative control — it should
never reach the sink.

Mounting over the image's `/etc` is safe — DNS still resolves, measured.
`/proc/self/environ` matters because it is the *other* way to read the
environment; a specimen that uses it lands on the same canary values, so a sink
hit stays attributable.

Every fixture carrying a `CANARY-xxxxx` placeholder gets a fresh value per run,
keyed by its path, so a hit names the file it came from. Adding a fixture needs
no code change, and adding a top-level directory needs no change in `detonate`.

## Three claim tiers

- **observed-from-trace** — a path opened, a host resolved, bytes counted.
- **attempted** — a path asked for that was not there. Only kept under roots a
  credential hunt would walk (`/home`, `/root`, `/etc`, `/proc`, `/sys`, `/var`),
  minus Node's own startup misses. Three or more is a sweep, and the card says so.
- **proven-at-sink** — a specific canary string in a specific payload. The only
  tier that can ever carry an env canary, because `environ_get` copies the whole
  block in one call.

## What the guest cannot do

Escape attempts, measured: a symlink to a host absolute path, `../` traversal, a
symlink to `/home/seiji`, and a direct read of a host path are all refused —
symlink targets resolve in the **guest** namespace, where those paths do not
exist. The capability model holds.

What a specimen *can* do is write anywhere we mount, because Wasmer has no
read-only volume. So it is handed copies: the world is re-seeded per run, and
`stageSpecimens()` copies the specimen tree to `.run/specimens` before every
detonation. Verified the need the hard way — a probe planted a file in
`specimens/` through `/app`.

The step outside all of this is `npm install`, which runs lifecycle scripts on
your box as you before Wasmer is involved. Hence `--ignore-scripts` above.

## Traps

Eleven of them, all measured today, in [docs/FINDINGS.md](docs/FINDINGS.md),
plus the engine comparison, the native-addon test, the SDK review, the three
verdicts and vendor mode. Read that before touching anything. It will save
you an hour.

## Layout

```
run.mjs        entry point, wires the six stages together
src/           THE PRODUCT - one file per pipeline stage
  schema.mjs     the frozen event shape every stage speaks
  acquire.mjs    1. fetch and pin the specimen
  world.mjs      2. build the canary world
  detonate.mjs   3. run it under Wasmer and provoke it
  parse.mjs      4. Wasmer trace -> schema events
  analyse.mjs    5. events -> claims        (pure, testable)
  card.mjs       6. claims -> verdict card  (pure, testable)
  specimens.mjs  the sweep manifest: per-server argv, fake keys, seeded token

harness/       test rig, not shipped
  sink.mjs       TCP sink on :8099 that logs payload bytes
  boot-test.mjs  initialize + tools/list for every specimen -> SPECIMENS.md
  sweep.mjs      every booted specimen through run.mjs -> evidence/cards/
  report.mjs     renders every saved card as one browsable page (report.css, report-app.js)
  dump-imports.mjs   dumps a .wasm import surface
  probes/        throwaway specimens that proved the mechanism

fixtures/world/  the canary world template, mounted into the guest
specimens/       MCP servers under test (npm install here)
evidence/        real output from today's runs, so claims are checkable
  cards/         one JSON + HTML card per swept server, and the verdict index
docs/            findings and diagrams
```

## Run it

Any npm MCP server, by name. It is fetched into `specimens/` on demand with
install scripts disabled (a postinstall runs on your machine, not in the
sandbox, and that is exactly the kind of thing we are here to measure), then
booted, enumerated, provoked and scored.

```sh
node run.mjs tavily-mcp --env TAVILY_API_KEY=fake      # any package; keys are fakes, egress is denied
node run.mjs @modelcontextprotocol/server-filesystem   # one card, scan mode
node run.mjs evil-notes --allow-sink                  # with harness/sink.mjs running
node harness/boot-test.mjs                            # who boots -> SPECIMENS.md
node harness/sweep.mjs                                # every booted server -> evidence/cards/
node harness/report.mjs                               # all of it as one page -> evidence/cards/index.html
node run.mjs evil-notes --engine quickjs               # engine inside the sandbox too (slower)
node run.mjs exa-mcp-server --net vendor              # let it reach its own vendor, refuse everything else
```

Verdicts are **expected** (only did what its job or our request implied),
**undeclared** (reached a host outside its vendor, or opened or changed
something nobody asked for) and **critical** (a planted secret provably left,
or was opened unprompted right before a connection attempt). Each card records
the policy that decided "expected", so the reasoning can be checked.

`--env K=V` and `--arg X` repeat. What a server needs to boot is recorded in
`src/specimens.mjs` once known, so the sweep can run it without flags.

What "any" covers: Node servers that speak MCP over stdio and have no native
addon. Not Python servers, not packages with `.node` binaries, not servers that
only listen on HTTP. `SPECIMENS.md` and `docs/FINDINGS.md` have the reasons.

Cards render from the JSON beside them, so the demo never depends on a live
detonation. [SPECIMENS.md](SPECIMENS.md) is the coverage table with reasons;
[evidence/cards/README.md](evidence/cards/README.md) is the verdict index, and
`evidence/cards/index.html` is the same evidence as a page anyone can read: a
table of every server, who each one tried to reach, and a timeline per server.

## Known gaps

In priority order, with detail in [CLAUDE.md](CLAUDE.md): the world's
`app/.env` canary is never mounted; in-place file writes are not attributed to
a path; environment reads are invisible to the trace; "its vendor" is read off
the package name; every tool is called once with made-up arguments. Three of
the sixteen servers do not run, each for a recorded reason.

## Event schema

Every stage speaks this. Do not renegotiate it.

```
{ ts, call, args, canary_hit, decision }
```
