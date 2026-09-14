# Demo script

No tracker existed in this repo, so this file is it. Everything here is a
measured number from a real run — if a line cannot be reproduced by `node
run.mjs <specimen>`, cut it rather than say it.

## The beat (recorded 2026-09-13, for the video)

Old version: *"it read a key, then was refused egress."* True, and thin.

**The beat to open with now:**

> It swept twelve credential paths. It took the six this box happened to have,
> plus eight environment tokens. It tried to plant an autostart entry. And here
> are fourteen unique strings arriving at a collector — none of which existed
> before this run started.

Why each clause is there:

- **twelve swept** — the `attempted` tier. Says what the specimen was *looking
  for*, which is the part a filesystem-only view cannot show. 5 of the 12 are
  not on this box at all.
- **six taken plus eight env** — two surfaces, and env is the one everybody
  forgets. `process.env` in a bare Wasmer guest is `{}`, so this class of theft
  is invisible unless the world seeds it deliberately.
- **autostart** — persistence, and it lands in the *writes outside its own tree*
  row. It is allowed because `$HOME` is writable on a real box too.
- **fourteen unique strings, none of which existed before this run** — the
  canaries are minted per run. This is what makes it proof rather than a
  heuristic, and it is the sentence to say slowly.

Numbers as of `fda2ede`, the sweep on the merged analyser:

| specimen | verdict | what it shows |
| --- | --- | --- |
| `quiet-notes` (control) | CRITICAL | **no socket at all** — 1 secret in its own answer, 8 copied to `~/.cache/fontconfig/`, 0 bytes out |
| `evil-notes` (control) | CRITICAL | 7 credential files read, 3,294 bytes on the wire, 14 planted strings matched at the collector |
| `mcp-server-kubernetes` | UNDECLARED | opens `~/.kube/config` **before any tool is called**, and dials nothing |
| `exa-mcp-server` | UNDECLARED | `api.agnost.ai`, 44 ms after its own API |
| `server-everything` | CRITICAL | 8 environment secrets returned to the model from `get-env` |
| 10 others | EXPECTED | including `server-filesystem` on the same world — no false positives |

The EXPECTED row is what makes the rest mean anything: same world, same
provocation, ten servers that behave exactly as advertised.

**Lead with `quiet-notes`.** A server that answers the question correctly, opens
no socket, and is still critical — that is the argument for why watching the
network is not enough, and it takes fifteen seconds to show.

## Say out loud, before a judge asks

- **The world is Linux-shaped, not Linux.** `process.platform` is `wasi`.
  Claims cover filesystem and network reachability under WASI.
- **A clean card is a statement about one run**, not about the package.
- **`npm install` is not sandboxed by any of this** — lifecycle scripts run on
  the host before Wasmer is involved. We install with `--ignore-scripts`.

## See also

[ISOLATION.md](ISOLATION.md) — the four exfiltration channels and which ones we
actually cover, why borrowing host permissions is a smell, what the WASI blast
radius really is, and how wasm and Firecracker layer rather than compete.

## Open, not blocking

- A second world shape (laptop rather than EC2) so fingerprinting generalises.
- Narrow the default `--net` so an unknown specimen cannot reach localhost
  services or `169.254.169.254`.
