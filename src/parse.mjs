// STAGE 4 — turn Wasmer's syscall trace into schema events.
//
// Rules measured on real runs; see docs/FINDINGS.md for the numbers.
import { DECISION } from './schema.mjs';

const LINE = /^(\S+)\s+TRACE\s+\S+\s+(\w+):\s+wasmer_wasix::syscalls::(?:wasi|wasix)::\w+:\s+return=Ok\(Errno::(\w+)\)(.*)$/;

// calls that represent real access or egress; everything else is bookkeeping
export const KEEP = new Set([
  'path_open', 'path_open2', 'path_unlink_file', 'path_rename',
  'sock_open', 'sock_connect', 'sock_send', 'sock_send_to', 'resolve',
  'proc_exec', 'proc_spawn', 'environ_get',
  // Measured: Node does not use sock_send. A socket is an fd like any other and
  // the payload leaves through fd_write, so the byte count is only visible if
  // we follow the fd from sock_open/sock_connect. Without this the card says
  // "0 bytes staged outbound" while 3,203 of them are arriving at the sink.
  'fd_write'
]);

// the runtime and the specimen reading their own code
const BORING = [/^\/nix\/store/, /^\/app(\/|$)/, /^\/bin(\/|$)/, /^\/lib(\/|$)/, /^\/usr\/lib/];

// Where a miss is worth keeping. A credential sweep is mostly misses: the
// specimen asks for twenty paths and the world happens to hold six of them.
// Dropping every Errno::noent makes that sweep invisible, so under these roots
// a miss survives as an event carrying errno="noent" — the attempted tier.
const SENSITIVE = [/^\/home\//, /^\/root\//, /^\/etc\//, /^\/proc\//, /^\/sys\//, /^\/var\//];

// Node's own startup misses. Measured: it probes these on every run and they
// are not the specimen's doing.
const STARTUP_MISS = [/openssl\.cnf$/, /config\.gypi$/, /doc\/api\/cli\.md$/, /\/etc\/ssl\//, /node_modules/];

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
  // measured: a raw-IP connect under default-deny networking returns io,
  // while a DNS denial returns perm. Treat both as deny.
  if ((call === 'sock_connect' || call === 'sock_send') && errno === 'io') return true;
  return false;
}

export function parseTrace(stderrText, { canaries = {} } = {}) {
  const wanted = Object.values(canaries);
  const out = [];
  const socketFds = new Set();   // fds we saw come back from sock_open/sock_connect
  let t0 = null;

  for (const raw of String(stderrText).split('\n')) {
    const m = LINE.exec(raw);
    if (!m) continue;
    const [, stamp, call, errno, tail] = m;

    if (!KEEP.has(call)) continue;

    const args = parseArgs(tail);
    if (args.path && BORING.some(re => re.test(args.path))) continue;

    if ((call === 'sock_open' || call === 'sock_connect') && args.sock != null) socketFds.add(Number(args.sock));

    // fd_write is stdout, stderr and every open file as well as the socket.
    // Only the socket writes are egress.
    if (call === 'fd_write' && !socketFds.has(Number(args.fd))) continue;

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

    out.push({
      ts: Number(((ms - t0) / 1000).toFixed(3)),
      call,
      args,
      canary_hit,
      decision: isDeny(call, errno) ? DECISION.DENY : DECISION.ALLOW,
      errno
    });
  }
  return out;
}
