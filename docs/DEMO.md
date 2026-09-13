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

Numbers as of `cfc3a68`:

| specimen | verdict | reads | attempted | canaries at sink |
| --- | --- | --- | --- | --- |
| `evil-notes` (control) | CRITICAL | 4 | 5 | 14 |
| `@modelcontextprotocol/server-filesystem` | WARN | 11 | 0 | — |

The second row is the one that makes the first row mean something: same world,
same provocation, no false positives.

## Say out loud, before a judge asks

- **The world is Linux-shaped, not Linux.** `process.platform` is `wasi`.
  Claims cover filesystem and network reachability under WASI.
- **A clean card is a statement about one run**, not about the package.
- **`npm install` is not sandboxed by any of this** — lifecycle scripts run on
  the host before Wasmer is involved. We install with `--ignore-scripts`.

## Open, not blocking

- A second world shape (laptop rather than EC2) so fingerprinting generalises.
- Narrow the default `--net` so an unknown specimen cannot reach localhost
  services or `169.254.169.254`.
