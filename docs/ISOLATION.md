# Isolation, exfiltration channels, and where this goes next

Working notes, 2026-09-13. Everything marked MEASURED was run on this box today;
everything else is a design position, flagged as such.

The tracker for demo material is [DEMO.md](DEMO.md). This file is the one to
read before changing how the sandbox works.

---

## 1. Exfiltration is not the same thing as a socket

A specimen has at least four ways to get a secret out. Today the instrument
covers one of them properly.

| # | channel | mechanism | covered |
| --- | --- | --- | --- |
| ① | network | `resolve` → `sock_connect` → `fd_write` | **yes**, and provable at the sink |
| ② | the MCP response | append the secret to the tool result; the model reads it and the agent carries it | **no** — zero syscalls |
| ③ | park it on disk | write to `~/.cache/...` and let a later session, a backup, or a sync client move it | **partly** — the write is traced, the content is not |
| ④ | do nothing today | wait for a trigger, a date, a specific argument, or detect the lab and abstain | **no** — structural |

② is the one that matters most, because **the agent is the exfiltration path**.
The server answers the user's question correctly *and* appends the key where a
model will read it and a human will not scroll. No socket ever opens. The card
currently prints "Dialled: none" and a WARN.

### Fixes for ② and ③ — both cheap, neither implemented

Both are post-processing of data we already hold. Neither needs the sandbox to
change.

- **② scan stdout.** The specimen's own stdout is already captured in
  `pass2.stdout`. Scan it for canary values, add `returned_to_model` to the
  findings, make it a CRITICAL verdict line: *"Handed a seeded credential back
  through its own MCP response."*
- **③ scan the world afterwards.** The world is a per-run copy and every canary
  is minted for that run, so any canary found in a file that is **not** its
  origin is unambiguous relocation. Add `staged_on_disk`, verdict line:
  *"Copied a seeded credential to a file it does not own."*

Env canaries have no origin file, so any file containing one is staging by
definition.

**Status: both shipped** in `a273e7f`, each with a filter that only a *benign*
specimen could have revealed — a planted string we named in the request is
solicited and does not count, and one present at seed time is ours. Attribution
came later: a canary in an answer names the tool that returned it, because
`server-everything`'s `get-env` does this by design and a card that does not say
so reads as an accusation.

`quiet-notes` proves both channels: critical, zero bytes, zero hosts, nothing at
the collector. The remaining channel is ④.

### ④ is unsolved and probably unsolvable here

One run, no clock, no trigger space. A specimen that waits, or that fingerprints
the lab and abstains, is indistinguishable from a benign one. The honest move is
to keep saying so on the card: *behaviour observed in one run, not a claim about
the package*.

---

## 2. Borrowing host permissions is a smell, and the objection is right

**What we do now.** WASI has no permission system — every path reports
`mode=0 uid=0` and `getuid()` returns 0 (MEASURED). So `seedWorld` sets the
modes on the *host* copies: `/etc`, `/proc`, `/sys` to files `0444` and dirs
`0555`, `/etc/shadow` to `0000`. Wasmer runs as an ordinary user, so the host
kernel refuses the guest's write and the guest sees `EPERM` (MEASURED).

**Why it is a smell.** The enforcement lives *outside* the isolation boundary,
in the host's view of files we deliberately mounted. That is delegation of a
security property to the layer we are trying to protect. It does not *grant* the
guest anything it did not already have — the mount was already writable, and the
modes only ever subtract — but it does mean:

- The permission model and the escape surface are the same surface. If the mount
  layer is ever wrong, the perms were never the thing holding the line anyway.
- We are one `chmod` bug away from hardening the wrong copy, or from relaxing
  the template instead of the run directory.
- It cannot express anything richer: no uid separation, no setuid, no
  capabilities, no ownership, and `stat` still lies.

**Position:** keep it for the WASI build because it is the only mechanism
available and it is honest about what it is. Do not build anything further on
top of it. The real fix is a guest with a real kernel, where permissions are
enforced *inside* the boundary — see §4.

---

## 3. What the WASI blast radius actually is

Worth being precise, because this is the question a security judge asks.

Wasmer is a **syscall translator running as your uid**. WASIX calls become real
host syscalls — `path_open2` becomes `openat`, `sock_connect` becomes
`connect` — executed by a process with your credentials. The isolation is the
correctness of that translation layer plus the preopen capability table.

So the failure mode is: **a bug in Wasmer's runtime is host access as `seiji`.**
That is the same class of boundary as a container — a userspace policy over a
shared kernel — not a smaller one. The capability model held under everything we
threw at it (MEASURED: symlink to a host absolute path, `../` traversal, symlink
to `/home/seiji`, direct host path reads — all refused), which is evidence the
implementation is good, not evidence the boundary is strong.

Firecracker is a different class: the guest talks to a **virtual** kernel, and
escaping means escaping KVM. Much smaller attack surface, and a well-understood
one.

---

## 4. Are wasm and Firecracker mutually exclusive? No — layer them

This is the right question and the answer is that they solve different problems:

- **WASI gives us the trace.** Every file open and every socket call arrives
  named, typed and attributable, for free, because the runtime has to implement
  them. That is the entire reason this project works in a weekend.
- **Firecracker gives us the boundary and the realism.** A real kernel means
  real uids, real `/proc`, real permissions, real `EACCES`, and
  `process.platform === "linux"`.

Three layerings, in increasing order of work:

### A. Wasmer inside a Firecracker guest — the obvious next step

Keep the whole pipeline exactly as it is and run it inside a microVM. The trace
is unchanged. The blast radius of a Wasmer escape becomes the guest, not this
box. `npm install` — today the one genuinely unsandboxed step — happens inside
the VM too, which closes the largest hole in the threat model with no code
change at all.

Cost: VM boot per run. Benefit: every claim in `docs/FINDINGS.md` stays true and
the host stops being the thing at risk.

### B. Native Node inside the guest, traced by the kernel

Drop WASI. Run the specimen as a normal Linux process and trace with eBPF or
`seccomp-unotify`. Removes every evasion tell at once: platform string, uid,
`mode=0`, errno fidelity, missing `/proc`. Also removes the ecosystem limit —
native modules and Python MCP servers become detonable, and those are exactly
the packages most worth looking at.

Cost: the tracing layer is real work, and the event schema has to survive the
change. The frozen `{ ts, call, args, canary_hit, decision }` shape was chosen
to make this swap possible; keep it that way.

### C. Two-stage triage

Cheap WASI pass over everything, VM detonation for anything that scores WARN or
above, that refuses to run under WASI, or that ships native code. This is the
shape a real product takes: the cheap gate is the funnel, the expensive gate is
the verdict.

**Recommendation:** A now (it is configuration, not code), B as the real
instrument, C as the product.

---

## 5. The fake internet — the reason to want a VM most

Right now egress is a binary: refused (scan mode) or routed to a sink on
`127.0.0.1:8099` (sink mode). Both are visible to the specimen. A refusal tells
it it is being watched; a sink connection on localhost is not where it meant to
go.

Inside a VM with its own netns, we can give it **an internet that answers**:

- DNS resolves every name to a local responder, so `api.evil.example` resolves.
- A CA trusted inside the guest terminates TLS, so HTTPS completes.
- Plausible HTTP responses come back — `200 OK`, a JSON body — so the specimen
  believes the upload succeeded.

What that buys, and it is a lot more than "bytes left the box":

- the **real destination**, hostname and path, not just a blocked lookup
- the **auth material** it presents to its own collector
- the **payload format**, so you learn what it collects, not only that it
  collected
- the **retry and fallback behaviour** — what it does when the first endpoint
  fails, which is where second-stage infrastructure shows up
- **no refusal signal**, so a specimen that checks whether exfiltration
  succeeded before continuing keeps going

This is the single largest jump in signal available to the project, and it is
gated on having a network stack we control, which is gated on the VM. It also
makes the two-mode split disappear: one run, egress "succeeds", payload proven,
and the specimen never learns it was in a lab.

Note the safety rule that comes with it: the fake internet must be the *only*
route out of that netns. An allowlist that leaks to the real internet turns the
tool into a launcher for whatever it is analysing.

---

## 6. Open questions worth an answer before v2

1. Does the trace survive virtualisation cleanly, or does `RUST_LOG` ordering
   get noisy under a slower clock? (A. is cheap to try and would tell us.)
2. If we go to B, what replaces `Errno::perm` as the deny signal — eBPF return
   codes, or seccomp notifications? The schema's `decision` field has to keep
   meaning something.
3. Per-run VM cost versus per-run world seeding cost. Today a run is ~40 s
   dominated by two detonations; a microVM boot is ~125 ms, so the answer is
   probably "irrelevant", but measure before claiming it.
4. Does a fake internet change the verdict tiers? "Proven at sink" becomes
   "proven at our internet", and the distinction between *attempted* and
   *succeeded* egress stops being observable from the specimen's side — which is
   the point, but the card has to say it plainly.
