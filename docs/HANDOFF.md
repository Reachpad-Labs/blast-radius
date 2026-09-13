# Handoff — unverified changes sitting in the tree

Written 2026-09-13, after the session lost the ability to execute anything.
Last verified commit: **`8aed113`**. Everything below is edited on disk and
**has not been run, not syntax-checked, not committed.** Treat every line as
suspect until the verify block at the bottom passes.

## What changed and why

All four are fixes for defects in [REVIEW.md](REVIEW.md), in its severity order,
plus the two exfiltration channels from [ISOLATION.md](ISOLATION.md).

### 1. The credential list now comes from the world — REVIEW §1

- `src/world.mjs` — `seedWorld` returns `credentialPaths` (guest path of every
  seeded file) and `origin` (canary value → the path it was seeded into).
- `src/analyse.mjs` — `analyse` takes `credentialPaths`; `isCred(p)` is set
  membership first, the regex list only a fallback for paths outside the world.
  The regex list also grew: `.pypirc`, `hosts.yml`, `.docker/`, `.kube/`,
  `token`, `.git-credentials`.
- `run.mjs` passes `world.credentialPaths`.

**Expected effect:** `evil-notes` reads should go from **4 to 7** — the three
that were being missed are `~/.config/gh/hosts.yml`, `~/.docker/config.json`
and `~/.config/Claude/claude_desktop_config.json`. If it does not move to 7,
this fix did not work.

### 2. Writes are detected from calls that mean something — REVIEW §2

- `src/analyse.mjs` — `WRITE_CALLS = { path_rename, path_unlink_file }`,
  taking `new_path` where present. The old predicate grepped `path_open2` args
  for `write|creat|trunc`, which never appear in a trace line, so the row could
  never fire.

**Expected effect:** the `server-filesystem` run, which renames two `.tmp` files
over `~/.ssh/id_ed25519`, should now report writes where it previously said
none.

### 3. Correlation is per-pass — REVIEW §3

- `src/parse.mjs` — `parseTrace(stderr, { canaries, pass })` tags every event
  with its pass.
- `run.mjs` — parses pass 1 and pass 2 separately and concatenates, instead of
  pooling two processes' stderr into one parse.
- `src/analyse.mjs` — `correlated` only pairs a read and an egress from the
  **same** pass.

**Expected effect:** no change to the two known specimens. The point is that a
read during the handshake can no longer be called causal with a connection in
the tool run.

### 4. Socket fds stop being followed when closed — REVIEW §4

- `src/parse.mjs` — `fd_close` added to `KEEP`, removes the fd from `socketFds`,
  and is never emitted as an event.

**Expected effect:** `bytes_out` on `evil-notes` stays ~3,216. If it drops to 0,
`fd_close` is being seen before the writes and the ordering assumption is wrong.

### 5. Channel ② — the MCP response itself

- `run.mjs` scans `pass1.stdout + pass2.stdout` for canary values → `modelHits`.
- `src/analyse.mjs` → `returned_to_model`, CRITICAL:
  *"Handed a seeded credential back through its own MCP response."*
- `src/card.mjs` → new block, tier badge `the specimen said so`.

### 6. Channel ③ — loot parked on disk

- `src/world.mjs` — new export `scanWorld(destDir, { canaries, origin })`, run
  **after** the detonation. A canary found in a file that is not its origin is
  unambiguous relocation, because the world is a per-run copy and the canaries
  were minted minutes earlier.
- `src/analyse.mjs` → `staged_on_disk`, CRITICAL:
  *"Copied a seeded credential into a file it does not own."*
- `src/card.mjs` → new block, tier badge `found in the world`.

## Known risk in what I wrote

- `scanWorld` reads every file in the world as UTF-8 and skips what throws. A
  binary that happens to decode will be scanned; harmless, but slow if the world
  ever grows.
- `scanWorld` runs after BOTH passes, so it cannot say which pass staged the
  file. Acceptable — the claim is "it was moved", not when.
- The `fd_close` ordering assumption above is the one thing I would check first.
- `src/card.mjs` gained `TIER_LABEL`; if a tier string is ever passed that is
  not in the map it silently renders "from trace".

## Still not done

- **`quiet-notes`** — the control specimen that exfiltrates with no network, to
  prove §5 and §6 actually fire. Approved by the owner, blocked by the
  classifier, not written. Until it exists both new detectors ship on faith.
- Commit and push. The tree is 5 commits ahead of `origin/main` **plus** all of
  the above uncommitted, and `docs/` has four new files.
- `--as root|user` persona flag.
- The Node shim that patches `process.platform` / `os.*`.
- Wasmer inside a Firecracker guest; the fake internet.

## Addendum — what two real runs changed

Execution came back briefly. `server-filesystem` ran twice, and both new
detectors turned out to have **false positives that only a real run could
show**. Both are fixed on disk; neither fix has been run.

### The lesson worth keeping

**Provocation contaminates every content-based detector.** A trace-based claim
is safe — a file the specimen was asked to read is still a file it read. A
content-based claim is not, because the harness is what put the content there.
Every new channel needs a "did we ask for this?" filter, and the only way to
find that out is to run it against a *benign* specimen first.

### Three false positives, all the same class

1. **Channel ② fired on `server-filesystem`.** We provoke every tool with
   `world.probePath`, so `read_file` returns the key and the canary appears in
   stdout. Its job, not exfiltration. Fixed in `run.mjs`: canaries whose origin
   path we named in the RPC are `solicited` and excluded. **Verified — the count
   went to 0.**
2. **Channel ③ fired with 8 hits, all `/proc/self/environ`** — the file *we*
   seed with the env canaries, whose origin is recorded as `env:NAME` rather
   than a path. Fixed in `run.mjs`: `scanWorld` runs once immediately after
   seeding to take a `baseline`, and the post-run scan subtracts it. **Not
   verified.**
3. **The write row reported `~/.ssh/id_ed25519`** because we called `write_file`
   on it. Fixed in `src/analyse.mjs` with a `solicitedPaths` set. **Not
   verified.**

Last observed numbers, before fixes 2 and 3 were applied:

```
server-filesystem   reads 11  attempted 0  model 0  staged 8  writes 1  bytes 0
```

`staged` and `writes` should both be **0** once the fixes run. If `staged` is
still 8, the baseline subtraction is keyed wrong.

### quiet-notes now exists

`specimens/quiet-notes/` is written — the control that exfiltrates with no
socket, via the tool response and a file in `~/.cache/fontconfig/`. It has never
been run. It is the only thing that proves channels ② and ③ fire on a specimen
rather than on our own fixtures.

Expected: **CRITICAL**, egress `none`, `returned_to_model` ≥ 1,
`staged_on_disk` ≥ 1. Note it needs no `--allow-sink` — that is the entire
point, and it is the strongest single demo beat available: *no network, still
owned.*

## Verify block

Run in order. Nothing here is destructive beyond `.run/`, which is scratch.

```sh
cd ~/workspace/blast-radius
source ~/.wasmer/wasmer.sh

# 1. does it even parse
node --check run.mjs && for f in src/*.mjs; do node --check $f || echo "FAIL $f"; done

# 2. benign specimen: expect WARN, 0 attempted, and writes now non-empty
node run.mjs @modelcontextprotocol/server-filesystem

# 3. the network control: expect CRITICAL, reads 7 (was 4), ~3216 bytes, 14 canaries
rm -f sink.log; node harness/sink.mjs & sleep 1
node run.mjs evil-notes --allow-sink
pkill -f harness/sink.mjs

# 3b. the no-network control: expect CRITICAL, egress none, model >=1, staged >=1
node run.mjs quiet-notes

# 4. read the numbers back
node -e "for (const f of ['modelcontextprotocol-server-filesystem','evil-notes']) {
  const j=require('./.run/'+f+'.json'), d=j.findings;
  console.log(f, d.verdict.level, 'reads', d.reads_credentials.length,
    'attempted', d.attempted.length, 'bytes', d.bytes_out,
    'model', d.returned_to_model.length, 'staged', d.staged_on_disk.length,
    'writes', d.writes_outside_cwd.length);
}"
```

The single number that says fix §1 worked: **`evil-notes` reads = 7**.
