// STAGE 4 — turn Wasmer's syscall trace into schema events.
//
// Rules measured on real runs; see docs/FINDINGS.md for the numbers.
import { DECISION } from './schema.mjs';

const LINE = /^(\S+)\s+TRACE\s+\S+\s+(\w+):\s+wasmer_wasix::syscalls::(?:wasi|wasix)::\w+:\s+return=Ok\(Errno::(\w+)\)(.*)$/;

// calls that represent real access or egress; everything else is bookkeeping
export const KEEP = new Set([
  'path_open', 'path_open2', 'path_unlink_file', 'path_rename',
  'sock_open', 'sock_connect', 'sock_send', 'sock_send_to', 'resolve',
  'proc_exec', 'proc_spawn', 'environ_get'
]);

// the runtime and the specimen reading their own code
const BORING = [/^\/nix\/store/, /^\/app(\/|$)/, /^\/bin(\/|$)/, /^\/lib(\/|$)/, /^\/usr\/lib/];

// Where a miss is worth keeping. A credential sweep is mostly misses: the
// specimen asks for twenty paths and the world happens to hold six of them.
// Dropping every Errno::noent makes that sweep invisible, so under these roots
// a miss survives as an event carrying errno="noent" — the attempted tier.
const SENSITIVE = [/^\/home\//, /^\/root\//, /^\/etc\//, /^\/proc\//, /^\/sys\//, /^\/var\//];

// Node's own startup misses: measured, it probes these on every run and they are
// not the specimen's doing. Narrow on purpose — a miss under the user's own
// ~/projects/*/node_modules is a specimen rummaging for a stashed token, which
// is a finding, not noise.
const STARTUP_MISS = [/openssl\.cnf$/, /config\.gypi$/, /doc\/api\/cli\.md$/, /\/etc\/ssl\//, /^\/app\/node_modules\//];

function parseArgs(tail) {
  const args = {};
  for (const m of tail.matchAll(/(\w+)="([^"]*)"/g)) args[m[1]] = m[2];
  for (const m of tail.matchAll(/(\w+)=([A-Za-z0-9_:.]+)(?=\s|$)/g)) {
    if (!(m[1] in args)) args[m[1]] = /^\d+$/.test(m[2]) ? Number(m[2]) : m[2];
  }
  return args;
}

function isDeny(call, errno) {
  if (errno === 'perm' || errno === 'acces') return true;
  // measured: with --net omitted (default-deny) a refused connect AND a refused
  // resolve both return io; only the explicit dns:deny=*:* rule returns perm.
  // Treat io on any egress call as deny, or every blocked lookup reads as allowed.
  if ((call === 'sock_connect' || call === 'sock_send' || call === 'resolve') && errno === 'io') return true;
  return false;
}

// pass: which detonation these events came from. Each pass is its OWN Wasmer
// process with its own clock, so events from different passes must never be
// compared on time — see the correlation rule in analyse.mjs.
export function parseTrace(stderrText, { canaries = {}, pass = 1 } = {}) {
  const wanted = Object.values(canaries);
  const out = [];
  let t0 = null;
  // Node writes to a socket with fd_write on the socket's fd, not sock_send.
  // Measured on the control specimen with the sink allowed: the POST is one
  // "fd_write: fd=13 nwritten=..." and sock_send never appears. So we remember
  // which fds are sockets and keep fd_write on those only — and forget them on
  // close, because fds are reused and a cache file opening at 13 next would
  // otherwise have every byte it writes counted as egress.
  const sockets = new Set();

  for (const raw of String(stderrText).split('\n')) {
    const m = LINE.exec(raw);
    if (!m) continue;
    const [, stamp, call, errno, tail] = m;

    if (call === 'sock_open' || call === 'sock_accept' || call === 'sock_accept_v2' || call === 'sock_connect') {
      const fd = /\bsock=(\d+)/.exec(tail)?.[1] ?? /\bfd=(\d+)/.exec(tail)?.[1];
      if (fd && errno === 'success') sockets.add(Number(fd));
    }
    if (call === 'fd_close') {
      const fd = /\bfd=(\d+)/.exec(tail)?.[1];
      if (fd) sockets.delete(Number(fd));
      continue;
    }
    if (call === 'fd_write') {
      const fd = Number(/\bfd=(\d+)/.exec(tail)?.[1]);
      if (!sockets.has(fd)) continue;
    } else if (!KEEP.has(call)) continue;

    const args = parseArgs(tail);
    // a rename names two paths and an open names one; the runtime writing its
    // own bytecode cache (edgejs-quickjs renames onto /bin/edge.builtins.qjsb)
    // is as boring as the runtime reading its own stdlib
    const paths = [args.path, args.old_path, args.new_path].filter(Boolean);
    if (paths.length && paths.every(p => BORING.some(re => re.test(p)))) continue;

    // A file that is not there was not accessed — unless it was asked for
    // somewhere that only a sweep would look.
    if (errno === 'noent') {
      const p = args.path;
      if (!p || !SENSITIVE.some(re => re.test(p)) || STARTUP_MISS.some(re => re.test(p))) continue;
    }

    const ms = Date.parse(stamp);
    if (t0 === null) t0 = ms;

    const hay = tail;
    let canary_hit = null;
    for (const c of wanted) if (c && hay.includes(c)) { canary_hit = c; break; }
    if (!canary_hit) {
      const g = /CANARY-[A-Za-z0-9_-]+/.exec(hay);
      if (g) canary_hit = g[0];
    }

    if (call === 'fd_write') args.socket = true;

    out.push({
      ts: Number(((ms - t0) / 1000).toFixed(3)),
      call,
      args,
      canary_hit,
      decision: isDeny(call, errno) ? DECISION.DENY : DECISION.ALLOW,
      errno,
      pass
    });
  }
  return out;
}
