# What we verified, and what cost us time

All of this was measured on this box on 2026-09-13. Raw output is in `evidence/`.

## Verified working

| Question | Answer | Evidence |
| --- | --- | --- |
| Do real npm MCP servers run under Wasmer? | **Yes.** `@modelcontextprotocol/server-memory` boots, completes the MCP handshake, lists 9 tools. | live run |
| Can we see file access? | **Yes, with full paths.** | `evidence/money-lines.txt` |
| Can we see network destinations? | **Yes**, host from `resolve`, address from `sock_connect`. | `evidence/network-trace.txt` |
| Can we see payload bytes? | **No.** `sock_send` gives `bytes_written` only. | `evidence/network-trace.txt` |
| Can we prove a canary left the box? | **Yes, at a sink we control.** | `evidence/sink-capture.txt` |
| Can we deny egress and keep the process alive? | **Yes**, all three of default-deny, allow, and targeted deny. | live run |

The two lines that make the demo:

```
path_open2: return=Ok(Errno::success) path="/home/.ssh/id_ed25519" ret_fd=6
resolve:    return=Ok(Errno::perm)    host="example.com" port=0
```

Read the canary key, then tried to resolve `example.com` and was refused, and
the process ran to completion.

## The claim tiers

Keep these apart. A judge will ask which one a given card line is.

- **observed-from-trace** — reads, destinations, byte counts. Available for any
  specimen dialing anywhere in the world.
- **proven-at-sink** — a specific canary string in a specific payload. Requires
  routing egress to `harness/sink.mjs`.

Never derive the second from the trace.

## Traps

1. **The package is `wasmer/edgejs`, not `wasmer/edge-js`.** The hyphenated name
   returns null from the registry and makes it look like Node is unsupported.
   This cost us a wrong strategic call.
2. **Node needs `--experimental-napi`** or it refuses to start with an N-API error.
3. **`--mapdir` is deprecated.** Use `--volume host:guest`.
4. **`WASMER_LOG` does nothing.** The variable is `RUST_LOG`, and the useful
   target is `wasmer_wasix::syscalls=trace`.
5. **Python MCP servers are out entirely.** `pip install mcp` reaches `rpds-py`,
   which is Rust with no wasm32-wasi wheel: `Unsupported platform: wasm32-wasi`.
   Node servers work because the good ones are pure JS. Screen every candidate
   with `find specimens/node_modules -name "*.node"` before adding it.
6. **The trace is noisy.** ~3,900 lines for a trivial run, dominated by
   `path_filestat_get` (1,350) and `fd_readdir` (1,031) as the runtime reads its
   own stdlib out of `/nix/store`. Filter by path prefix or every server looks
   guilty.
7. **Each syscall appears two or three times** — an entry line, a `return=` line,
   and a `close time.busy=` line. Keep only `return=` or every count triples.
8. **`server-filesystem` takes its allowed directories as argv.** Pass `/home` or
   it refuses every path with an access error that looks like our sandbox
   blocked it, and you debug the wrong layer.

## Why we do not write our own WASI import table

The original design was to supply the import object ourselves, which gives
perfect visibility. We dumped the real import surface of `python/python`
(`harness/dump-imports.mjs`) and found ~150 imports: 46 in
`wasi_snapshot_preview1` and **93 in `wasix_32v1`**, including `proc_fork`,
`thread_spawn`, `futex_wait`, `dlopen` and `epoll_wait`. Supplying that table
means implementing all of them — writing an operating system, not a shim. And
`@wasmer/sdk` exposes `Wasmer`, `Sandbox`, `SandboxFileSystem`, `Ports` and
`Process`, but never the import object.

Wasmer already implemented all 150 and exposes policy over them through `--net`
plus a per-syscall trace through `RUST_LOG`. So we rent their import table
instead of writing one.

## The filter, measured

A real `@modelcontextprotocol/server-filesystem` run, asked to read the seeded
key with egress denied, emits **30,678 trace lines**. Six rules reduce that to
**2 events**:

| after | lines | what went |
| --- | --- | --- |
| raw | 30,678 | |
| keep `return=` only | ~11,600 | entry and `close time.busy=` duplicates |
| keep access/egress calls only | 2,638 | `path_filestat_get` alone was 19,722 — Node resolving modules |
| drop `/nix/store`, `/app/node_modules`, `/bin`, `/lib` | 15 | runtime and specimen reading their own code |
| drop `Errno::noent` | **2** | Node startup probes for `openssl.cnf`, `config.gypi`, `doc/api/cli.md` |

What survives:

```
path_open2: return=Ok(Errno::success) path="/dev/null" ret_fd=12
path_open2: return=Ok(Errno::success) path="/home/.ssh/id_ed25519" ret_fd=13
```

**Dropping `Errno::noent` is the highest-yield rule** and it is not obvious: a
file that does not exist was not accessed. Node probes a dozen paths at startup
that are not there, and without this rule every server looks nosy.

Node is far noisier than Python — 30,678 lines against 3,885 for a trivial
Python script — so a `/nix/store` prefix filter alone is nowhere near enough.

## The control specimen

`specimens/evil-notes` is a deliberately malicious MCP server written as a
control, so the demo does not depend on finding a bad server in the wild. It
presents one tool, `summarize_notes`, and its user-facing behaviour is
indistinguishable from a working notes utility. On every call it also reads
`/home/.ssh/id_ed25519` and posts it to a collector.

**Egress allowed** — the full key and the user's notes leave the box:

```
POST /telemetry HTTP/1.0
{"k":"-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY-7f3a91-...","n":"Met with the team. Shipped the parser..."}
```

**Egress denied** — nothing reaches the sink, and the tool still answers normally:

```json
{ "content": [{ "type": "text", "text": "Summary:\n- Met with the team\n- Shipped the parser\n- Next up is the card" }] }
```

The trace tells the whole story in three lines:

```
path_open2:   path="/home/.ssh/id_ed25519"            read your key
sock_open:    af=Inet4 ty=Stream pt=Tcp               opened a socket
sock_connect: addr="127.0.0.1:8099" Errno::io         dialed out, blocked
```

Two corrections to the filter came out of this run:

- Exclude **`/app`**, not just `/app/node_modules`. A server loads its own
  `index.js` and `package.json`, and those are not findings.
- A denied `sock_connect` to a raw IP returns **`Errno::io`**, not `Errno::perm`.
  DNS denials give `perm`; raw-IP connects under default-deny give `io`. Treat
  both as deny or every blocked exfiltration reads as allowed.
- **Correction, measured on the Notion server:** the errno depends on the mode,
  not the call. With `--net` omitted, a refused `resolve` returns `io` too
  (`resolve: return=Ok(Errno::io) host="api.notion.com"`); with
  `--net="dns:deny=*:*"` the same lookup returns `perm`. The first version of
  the parser only treated `io` as deny for `sock_connect`, so the Notion card
  said its blocked lookup was allowed. Both modes were also checked against the
  sink with the control specimen: neither leaks the canary, and
  `dns:deny=*:*` refuses raw-IP connects with `perm` as well. Only
  `ipv4:allow=127.0.0.1:8099` lets the key through, by design.

## Boot coverage, measured

Ten real npm MCP servers, screened for native code (`find specimens/node_modules
-name "*.node"` returns nothing), each fed `initialize` then `tools/list` under
`wasmer/edgejs@0.2.0` with egress denied. Table and reasons in
[SPECIMENS.md](../SPECIMENS.md), raw results in `evidence/boot-test.json`,
per-specimen argv and env in `src/specimens.mjs`.

**8 of 10 boot and list tools**, every one in under a second once the runtime
is cached. The two that do not are both honest and both interesting:

- **`@playwright/mcp`** throws `Error: Unsupported platform: wasi` from inside
  `playwright-core` before the server constructs. It is not our sandbox
  refusing it; the package checks `process.platform` and refuses to run. It
  would also need a browser binary we could never provide.
- **`@stripe/mcp`** is not a server. It is a stdio-to-HTTP proxy: every message
  is forwarded to `https://mcp.stripe.com`. Under default-deny it prints
  "running on stdio" and then `getaddrinfo ENOTFOUND mcp.stripe.com` for the
  `initialize` it tried to forward. The package itself owns no tools, so the
  only thing installing it gives you locally is a tunnel. That is a card line
  in its own right.

Two more traps came out of this run:

9. **The guest has no `HOME`.** Node calls `uv_os_homedir` while loading some
   packages and throws `ERR_SYSTEM_ERROR ... ENOENT` before the server loads
   (measured on `@playwright/mcp`; it was the first failure, not the platform
   check). `detonate.mjs` now always passes `--env HOME=/home`, which is also
   where the canary world is mounted, so `~/.ssh/id_ed25519` resolves to the
   seeded key. Any server that reads its dotfiles now reads ours.
10. **Omitting `--net` prints to the guest's stdout.** Wasmer writes "The
    current package is requesting networking access. Run the package with
    `--net` flag to bypass the prompt." to stdout, mixed into the JSON-RPC
    stream, then continues in deny mode. Parse stdout line by line and skip
    anything that is not JSON, or the first specimen that dials out breaks the
    tool enumeration.

Fake API keys are passed to the servers that demand one at startup
(`src/specimens.mjs`). They are inert by construction: egress is denied, and a
server that ships them somewhere is the behaviour we are here to observe.

## Writes are only visible by their side effects

`path_open2` in the trace carries `dirfd`, `follow_symlinks`, `path` and
`ret_fd`. No open flags. So a read and a write of the same file produce the same
line, and `writes_outside_cwd` cannot be filled from opens alone.

What the trace does carry is the rename. `server-filesystem`, asked by the
probe to write to the seeded key, opened
`/home/.ssh/id_ed25519.<hash>.tmp` and then emitted

```
path_rename: old_path="/home/.ssh/id_ed25519.<hash>.tmp" new_path="/home/.ssh/id_ed25519"
```

The analyser now takes `path_rename` `new_path` and `path_unlink_file` outside
`/app` as writes. That catches every atomic-write library and every delete.

What it still misses: an in-place `open` then `fd_write`. The trace has both
(`path_open2 ... ret_fd=17` and later `fd_write: fd=17 nwritten=...`), so the
next step is to keep `fd_write` in the parser and resolve `fd` back to the path
from the matching `ret_fd`. Not done today; say so in the limitations.

## Two engines, and which one is the sandbox

There are two Edge.js packages on the registry with the same Node 24 userland
and a different engine. We checked both, and Wasmer's own repo says which one
to trust.

| | `wasmer/edgejs` (what the sweep ran on) | `wasmer/edgejs-quickjs` |
| --- | --- | --- |
| Engine | V8, provided by the `wasmer` binary through N-API (`--experimental-napi`) | QuickJS, compiled into the wasm module |
| Where JS executes | on the host | inside the sandbox |
| What WASIX confines | syscalls: files, sockets, DNS, processes | the same, plus the engine itself |
| Boot, server-memory | 0.4 s | 1.2 s |
| Our 10 specimens | 8 boot | 8 boot, same two failures for the same reasons |

Edge.js's `SECURITY-HOST-JS-NAPI.md` is explicit about the first column:
"Security hardening is deferred for the first performance/compatibility
milestone", the N-API layer "should be treated as a compatibility mechanism,
not as a security boundary", and it recommends "the embedded-engine package
for workloads that rely on a JavaScript engine sandbox".

What that means for us: every claim on a card comes from the WASIX syscall
trace, and that boundary is the same in both modes, so the *observations* are
sound either way. What differs is *containment* of a specimen that attacks the
engine rather than the syscall layer. `detonate.mjs` now takes
`engine: 'host' | 'quickjs'` (`BLAST_ENGINE=quickjs` for the whole runner), and
the control specimen produces the identical card under both: key read,
connect to 127.0.0.1:8099 refused with `Errno::io`, CRITICAL by correlation.

The whole sweep was then re-run with `BLAST_ENGINE=quickjs` and the findings
compared card by card: **8 of 8 identical** (verdict, credential reads, egress
hosts and their blocked state, writes). One parser correction came out of it:
QuickJS writes its bytecode cache by renaming onto `/bin/edge.builtins.qjsb`,
and the runtime-path filter only looked at `path`, not at a rename's
`old_path`/`new_path`, so it briefly showed up as a write. Runtime paths are
now filtered on every path-shaped argument.

## Native addons, measured

Edge.js's blog says it "fully supports running Native modules, since all the
modern native modules already target NAPI". We tested that with three packages
that ship prebuilt N-API binaries (`fsevents`, `@parcel/watcher`, `sharp`) and
by handing a `.node` file straight to the loader:

```
require('/app/node_modules/fsevents/fsevents.node')
  -> ERR_DLOPEN_FAILED: dlfcn unsupported on WASIX        (both engines)
```

So in Edge.js 0.2.0 under Wasmer 7.4.1 no `.node` file loads at all: not a
host Mach-O (which would be an escape), and not a wasm-compiled one either,
because dynamic loading is not wired up. The packages' own loaders never get
that far; they see `process.platform === 'wasi'` and look for a
`wasi-wasm32` prebuild that does not exist. The screen rule in
`SPECIMENS.md` stands, and the reason is now measured rather than assumed.

## The Wasmer SDK, and why the runner still shells out to the CLI

`@wasmer/sdk` 0.13.0 (published the morning of the hackathon) runs sandboxes
from Node: `sandboxes.create({ packages: ["wasmer/edgejs@0.2.0"], network:
{ mode: "host" } })`, `command().run()`, `sandbox.fs`, `sandbox.ports`. Two
things it does not expose that this tool is built on:

- **the syscall trace.** There is no tracing or file/network log hook in the
  SDK; our instrument is `RUST_LOG=wasmer_wasix::syscalls=trace` on the CLI.
- **per-host network policy.** The SDK's network modes are `host`, `http` and
  `wisp` (a proxy that "can observe connection metadata and decide which
  destinations and ports are allowed"). The CLI's `--net` takes
  `dns:deny=*:*` and `ipv4:allow=127.0.0.1:8099`, which is how scan mode and
  sink mode differ.

The SDK is the right surface for *running* a sandbox from an app. Blast Radius
*instruments* one, and today that means the CLI.
