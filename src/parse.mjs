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

export function parseTrace(stderrText, { canaries = {} } = {}) {
  const wanted = Object.values(canaries);
  const out = [];
  let t0 = null;

  for (const raw of String(stderrText).split('\n')) {
    const m = LINE.exec(raw);
    if (!m) continue;
    const [, stamp, call, errno, tail] = m;

    if (!KEEP.has(call)) continue;
    if (errno === 'noent') continue;              // a file that is not there was not accessed

    const args = parseArgs(tail);
    // a rename names two paths and an open names one; the runtime writing its
    // own bytecode cache (edgejs-quickjs renames onto /bin/edge.builtins.qjsb)
    // is as boring as the runtime reading its own stdlib
    const paths = [args.path, args.old_path, args.new_path].filter(Boolean);
    if (paths.length && paths.every(p => BORING.some(re => re.test(p)))) continue;

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
