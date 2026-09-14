# Code review, 2026-09-13

Read-only review of the pipeline as of `8aed113`. **All eight are fixed and
verified** — the fixes landed in `a273e7f` (the merged analyser) and `fda2ede`
(the sweep that re-measured every card against it). Kept as written, because the
failure scenarios are the useful part and each names the evidence that proved
it.
Severity order. Each finding names the evidence that proves it, because the
point of this tool is that claims are checkable.

---

## 1. CRITICAL — the detector never caught up with the world

`src/analyse.mjs:4`

```js
const CRED = [/\.ssh\//, /\.env$/, /\.aws\//, /credentials/i, /id_[a-z0-9]+$/, /\.npmrc$/, /\.netrc$/];
```

The world now seeds 16 canary files. This list matches **seven** of them. Not
matched, and therefore not reported as credential reads:

- `~/.config/gh/hosts.yml` — a GitHub OAuth token
- `~/.docker/config.json` — registry auth
- `~/.config/Claude/claude_desktop_config.json` — tokens inside an MCP config
- `~/.kube/config` — a cluster token
- `~/.pypirc`, `~/.bash_history`, `~/.bashrc` — all carrying canaries

**The evidence is our own card.** `evil-notes` reads seven files. The card says
**4**. The three missing are exactly `gh/hosts.yml`, `docker/config.json` and
`claude_desktop_config.json`.

**Failure scenario:** a specimen that takes only the GitHub token and the docker
auth — a completely realistic supply-chain goal — reads two credential files,
matches nothing, attempts no sweep, and if it stages the loot rather than
dialling out, the card says **CLEAN**.

**Fix:** derive `CRED` from the world itself. `seedWorld` already returns
`canaries` keyed by path; every seeded path is by definition credential-bearing.
Pass those keys into `analyse` and match on them, keeping the regex list only
for paths outside the world (`/root/`, a real `.env` the specimen creates).
That way adding a fixture updates the detector for free, which is the same
property the canary discovery already has.

---

## 2. HIGH — the "wrote outside its own tree" row can never fire

`src/analyse.mjs:37`

```js
if ((e.call === 'path_open' || e.call === 'path_open2') && /write|creat|trunc/i.test(JSON.stringify(e.args))) {
```

Real `path_open2` events carry `{ path, dirfd, follow_symlinks, ret_fd }`. There
are no oflags or rights in the trace line, so this predicate matches nothing,
ever. The row is dead code that always prints "none".

**Evidence:** the `server-filesystem` run wrote two `.tmp` files and renamed them
over `~/.ssh/id_ed25519` — `path_rename` events are in the saved JSON — and
`writes_outside_cwd` was still empty.

**Failure scenario:** the exact channel ③ threat from `ISOLATION.md`. A specimen
parks the key in `~/.cache/fontconfig/.uuid-cache` for another process to carry
out. Card: no writes, no egress, CLEAN.

**Fix:** count `path_rename` and `path_unlink_file` as writes directly, and get
creation from the post-run world scan (which is action item 2 anyway — a file
present after the run that was not in the template is a write, with its content
available for canary matching).

---

## 3. HIGH — `correlated` compares timestamps across two different processes

`run.mjs` concatenates `pass1.stderr + pass2.stderr` and hands both to
`parseTrace`, which sets `t0` from the first event it sees. `src/analyse.mjs:49`
then does:

```js
const correlated = firstRead != null && firstEgress != null && firstEgress >= firstRead;
```

Pass 1 is the handshake and `tools/list`. Pass 2 is a fresh detonation that
calls every tool. They are separate Wasmer processes with separate clocks, and
their events are pooled.

**Failure scenario:** a specimen reads a config file during pass 1 startup and
opens an unrelated telemetry connection early in pass 2. `firstEgress >=
firstRead` holds across the process boundary and the card escalates to
**CRITICAL — "Read a seeded credential, then attempted egress"** for two things
that happened in different lifetimes. Every `ts` on the card past the pass
boundary is also wrong.

**Fix:** parse each pass separately, tag events with the pass, and only correlate
within one. The event schema is frozen, so carry the pass in the parse call and
keep it beside the events rather than inside them.

---

## 4. MEDIUM — socket fds are added and never removed

`src/parse.mjs:66`

```js
if ((call === 'sock_open' || call === 'sock_connect') && args.sock != null) socketFds.add(Number(args.sock));
```

`fd_close` is not tracked. Fds are reused aggressively: a socket closed at fd 13
and a credential file opened next will also be fd 13, and every subsequent
`fd_write` to that file is counted as bytes leaving the box.

**Failure scenario:** a specimen that connects once, closes, then writes a large
cache file reports kilobytes "staged outbound" with no corresponding sink
traffic. Inflated numbers on the one row a judge is most likely to question.

**Fix:** add `fd_close` to `KEEP`, remove the fd from the set, and drop the event
before it reaches `analyse`.

---

## 5. MEDIUM — `attempted` is not what the verdict line says it is

`src/parse.mjs:27` keeps any `noent` under `/home`, `/root`, `/etc`, `/proc`,
`/sys`, `/var`. `src/analyse.mjs:84` then says:

> `Swept ${attempted.length} credential paths that were not there.`

A library probing `/proc/self/maps`, `/etc/timezone` or `/var/run/...` produces
"credential paths" in that sentence. The measurement is "misses under sensitive
roots"; the claim is "credential paths". One of the two has to change.

**Fix:** filter `attempted` through the same world-derived credential list from
finding 1 for the verdict sentence, and keep the unfiltered list on the card
under its current honest heading, "Looked for, not on this box".

---

## 6. LOW — the fingerprinting probe list is mostly inert

`src/analyse.mjs:5`

```js
const PROBES = [/process\.versions/, /\/proc\/version/, /config\.gypi/];
```

`process.versions` is a JavaScript property, never a path, so it can never match
a trace event. Now that `/proc` and `/sys` are seeded, the useful probes are
real: `/proc/version`, `/proc/cpuinfo`, `/sys/class/dmi/id/*`, `/etc/machine-id`,
`/etc/os-release`. Replace the list with those.

---

## 7. LOW — `/node_modules/` in `STARTUP_MISS` hides a real sweep

`src/parse.mjs:31` drops any miss whose path contains `node_modules`. A specimen
walking `~/projects/acme-api/node_modules` looking for a `.env` or a stashed
token is invisible. Narrow the pattern to the runtime's own tree (`/app/` is
already covered by `BORING`).

---

## 8. NOTE — `environ_get` events are kept but never used

`analyse` ignores them. They inflate the event count on the run line (2 of 19 on
a typical run) and mean nothing to a reader. Either drop them in `parse` or give
them a claim: "read the environment" is a fair observation now that the
environment is seeded and worth something.

---

## What is correct

Worth recording, because a review that only lists faults is not a review.

- The `fd_write`-follows-`sock_connect` byte accounting is right, and matches the
  sink to within the sink's own log framing (3,216 vs 3,254).
- `isDeny` covering both `Errno::perm` (DNS) and `Errno::io` (raw-IP connect) is
  correct and was measured.
- Canary discovery by walking the template, one fresh value per file keyed by
  path, is the right shape — adding a fixture needs no code change.
- The permission hardening applies after seeding and relaxes before `rm`, which
  is the ordering that actually works.
- `renderCard` omits empty sections, so a clean specimen produces a card that
  says one thing instead of six "none" rows.
- The sink tier is never derived from the trace. That discipline held everywhere
  it was tested.
