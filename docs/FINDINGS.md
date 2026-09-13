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
