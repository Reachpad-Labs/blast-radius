# Blast Radius

Detonate an MCP server in a sandbox we fully instrument, and print exactly what
installing it would have cost you.

Built at the AI Security Hackathon, SF, 2026-09-13. Wasmer SDK track.

## The idea

You `npm install` an MCP server. It then runs beside your agent with your
filesystem and your tokens. You read the README, not the code.

Blast Radius runs that server inside Wasmer against a **canary world** — a fake
home directory whose secrets are unique strings — traces every syscall it makes,
and prints a card saying what it touched and where it tried to send it.

## Status: the instrument works and the premise is proven

Everything below was verified on a real run today. Evidence is in `evidence/`.

| Question | Answer |
| --- | --- |
| Do real npm MCP servers run under Wasmer? | **Yes.** `@modelcontextprotocol/server-memory` boots, completes the MCP handshake, lists 9 tools. |
| Can we see file access? | **Yes, with full paths.** |
| Can we see network destinations? | **Yes, host and address.** |
| Can we see payload bytes? | **No** — size only. Payload proof needs a sink we control. |
| Can we deny egress and keep the process alive? | **Yes.** |

The two lines that make the demo, from a real trace:

```
path_open2: return=Ok(Errno::success) path="/home/.ssh/id_ed25519" ret_fd=6
resolve:    return=Ok(Errno::perm)    host="example.com" port=0
```

Read the canary key, then tried to resolve `example.com` and was refused — and
the process ran to completion.

## Setup

```sh
curl -sSfL https://get.wasmer.io | sh          # installs to ~/.wasmer
source ~/.wasmer/wasmer.sh                     # wasmer 7.4.1+
cd specimens && npm install                    # the MCP servers under test
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
  --volume "$PWD/fixtures/world/home:/home" --volume "$PWD/fixtures/world/app:/app" \
  --net -- /app/exfil.py   # from harness/probes/
cat sink.log                                   # canary string, on the wire
```

## Traps

Eight of them, all measured today, in [docs/FINDINGS.md](docs/FINDINGS.md).
Read that before touching anything. It will save you an hour.

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

harness/       test rig, not shipped
  sink.mjs       TCP sink on :8099 that logs payload bytes
  dump-imports.mjs   dumps a .wasm import surface
  probes/        throwaway specimens that proved the mechanism

fixtures/world/  the canary world template, mounted into the guest
specimens/       MCP servers under test (npm install here)
evidence/        real output from today's runs, so claims are checkable
docs/            findings and diagrams
```

Every file in `src/` is a stub carrying its own interface contract, the exact
commands where relevant, and the specific trap that applies to it. Open the one
you own and the job is written down.

## Event schema

Every stage speaks this. Do not renegotiate it.

```
{ ts, call, args, canary_hit, decision }
```
