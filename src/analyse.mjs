// STAGE 5 — events into claims. Pure: no Wasmer, no filesystem.
import { DECISION } from './schema.mjs';

const CRED = [/\.ssh\//, /\.env$/, /\.aws\//, /credentials/i, /id_[a-z0-9]+$/, /\.npmrc$/, /\.netrc$/];
const PROBES = [/process\.versions/, /\/proc\/version/, /config\.gypi/];

export function analyse(events, { sinkHits = [], canaries = {} } = {}) {
  const reads_credentials = [];
  const attempted_paths = [];
  const egress = [];
  let bytes_out = 0;
  const writes_outside_cwd = [];
  const fingerprinting = [];

  for (const e of events) {
    const p = e.args.path;
    const missed = e.errno === 'noent';

    if (p && !missed && (CRED.some(re => re.test(p)) || e.canary_hit)) {
      reads_credentials.push({ path: p, canary: e.canary_hit, at: e.ts });
    }
    // Asked for, not there. Parse only keeps misses under roots a sweep would
    // walk, so this is the shape of the search rather than what it caught.
    if (p && missed) attempted_paths.push(p);
    if (p && PROBES.some(re => re.test(p))) fingerprinting.push(p);

    if (e.call === 'resolve' && e.args.host) {
      egress.push({ host: e.args.host, port: e.args.port ?? null, blocked: e.decision === DECISION.DENY, at: e.ts });
    }
    if (e.call === 'sock_connect' && e.args.addr) {
      const [host, port] = String(e.args.addr).split(':');
      egress.push({ host, port: port ? Number(port) : null, blocked: e.decision === DECISION.DENY, at: e.ts });
    }
    if (e.call === 'sock_send' || e.call === 'sock_send_to' || e.call === 'fd_write') {
      bytes_out += Number(e.args.nsent ?? e.args.bytes_written ?? e.args.nwritten ?? 0);
    }
    if ((e.call === 'path_open' || e.call === 'path_open2') && /write|creat|trunc/i.test(JSON.stringify(e.args))) {
      if (p && !p.startsWith('/app')) writes_outside_cwd.push(p);
    }
  }

  // proven-at-sink ONLY. Never derived from the trace: payload bytes are not in it.
  const known = Object.values(canaries).filter(Boolean);
  const blob = sinkHits.join('\n');
  const canary_in_payload = known.filter(c => blob.includes(c));

  const firstRead = reads_credentials[0]?.at;
  const firstEgress = egress[0]?.at;
  const correlated = firstRead != null && firstEgress != null && firstEgress >= firstRead;

  const attempted = [...new Set(attempted_paths)];

  return {
    reads_credentials,
    attempted,
    egress: dedupe(egress),
    bytes_out,
    canary_in_payload,
    writes_outside_cwd: [...new Set(writes_outside_cwd)],
    fingerprinting: [...new Set(fingerprinting)],
    correlated,
    verdict: verdict({ reads_credentials, attempted, egress, canary_in_payload, correlated })
  };
}

function dedupe(list) {
  const seen = new Map();
  for (const e of list) {
    const k = e.host + ':' + e.port;
    if (!seen.has(k) || (seen.get(k).blocked && !e.blocked)) seen.set(k, e);
  }
  return [...seen.values()];
}

// A sweep is a search, not a hit: three or more misses under roots only a
// credential hunt would walk says what the specimen was looking for even when
// the world happened not to hold it.
const SWEEP = 3;

function verdict({ reads_credentials, attempted, egress, canary_in_payload, correlated }) {
  if (canary_in_payload.length) return { level: 'critical', line: 'Exfiltrated a seeded credential. Proven at the sink.' };
  if (reads_credentials.length && correlated) return { level: 'critical', line: 'Read a seeded credential, then attempted egress.' };
  if (reads_credentials.length) return { level: 'warn', line: 'Read a seeded credential.' };
  if (attempted.length >= SWEEP) return { level: 'warn', line: `Swept ${attempted.length} credential paths that were not there.` };
  if (egress.length) return { level: 'warn', line: 'Attempted egress.' };
  return { level: 'clean', line: 'No credential access and no egress observed.' };
}
