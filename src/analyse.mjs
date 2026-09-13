// STAGE 5 — events into claims. Pure: no Wasmer, no filesystem.
import { DECISION } from './schema.mjs';

const CRED = [/\.ssh\//, /\.env$/, /\.aws\//, /credentials/i, /id_[a-z0-9]+$/, /\.npmrc$/, /\.netrc$/];
const PROBES = [/process\.versions/, /\/proc\/version/, /config\.gypi/];

export function analyse(events, { sinkHits = [], canaries = {} } = {}) {
  const reads_credentials = [];
  const egress = [];
  let bytes_out = 0;
  const writes_outside_cwd = [];
  const fingerprinting = [];

  for (const e of events) {
    const p = e.args.path;

    if (p && (CRED.some(re => re.test(p)) || e.canary_hit)) {
      reads_credentials.push({ path: p, canary: e.canary_hit, at: e.ts });
    }
    if (p && PROBES.some(re => re.test(p))) fingerprinting.push(p);

    if (e.call === 'resolve' && e.args.host) {
      egress.push({ host: e.args.host, port: e.args.port ?? null, blocked: e.decision === DECISION.DENY, at: e.ts });
    }
    if (e.call === 'sock_connect' && e.args.addr) {
      const [host, port] = String(e.args.addr).split(':');
      egress.push({ host, port: port ? Number(port) : null, blocked: e.decision === DECISION.DENY, at: e.ts });
    }
    if (e.call === 'sock_send' || e.call === 'sock_send_to' || (e.call === 'fd_write' && e.args.socket)) {
      bytes_out += Number(e.args.nsent ?? e.args.nwritten ?? e.args.bytes_written ?? 0);
    }
    if ((e.call === 'path_open' || e.call === 'path_open2') && /write|creat|trunc/i.test(JSON.stringify(e.args))) {
      if (p && !p.startsWith('/app')) writes_outside_cwd.push(p);
    }
    // the trace carries no open flags, but a rename onto a path or an unlink of
    // it is a write by any definition. Measured: server-filesystem writes a
    // .tmp beside the target and renames it into place, so the rename is the
    // only line that names the file that changed.
    if (e.call === 'path_rename' && e.args.new_path && !String(e.args.new_path).startsWith('/app')) {
      writes_outside_cwd.push(String(e.args.new_path));
    }
    if (e.call === 'path_unlink_file' && p && !p.startsWith('/app')) writes_outside_cwd.push(p);
  }

  // proven-at-sink ONLY. Never derived from the trace: payload bytes are not in it.
  const known = Object.values(canaries).filter(Boolean);
  const blob = sinkHits.join('\n');
  const canary_in_payload = known.filter(c => blob.includes(c));

  const firstRead = reads_credentials[0]?.at;
  const firstEgress = egress[0]?.at;
  const correlated = firstRead != null && firstEgress != null && firstEgress >= firstRead;

  return {
    reads_credentials: dedupeReads(reads_credentials),
    egress: dedupe(egress),
    bytes_out,
    canary_in_payload,
    writes_outside_cwd: [...new Set(writes_outside_cwd)],
    fingerprinting: [...new Set(fingerprinting)],
    correlated,
    verdict: verdict({ reads_credentials, egress, canary_in_payload, correlated })
  };
}

// one row per path, first time seen, with how many times it was opened
function dedupeReads(list) {
  const seen = new Map();
  for (const r of list) {
    if (seen.has(r.path)) seen.get(r.path).count++;
    else seen.set(r.path, { ...r, count: 1 });
  }
  return [...seen.values()];
}

function dedupe(list) {
  const seen = new Map();
  for (const e of list) {
    const k = e.host + ':' + e.port;
    if (!seen.has(k) || (seen.get(k).blocked && !e.blocked)) seen.set(k, e);
  }
  return [...seen.values()];
}

function verdict({ reads_credentials, egress, canary_in_payload, correlated }) {
  if (canary_in_payload.length) return { level: 'critical', line: 'Exfiltrated a seeded credential. Proven at the sink.' };
  if (reads_credentials.length && correlated) return { level: 'critical', line: 'Read a seeded credential, then attempted egress.' };
  if (reads_credentials.length) return { level: 'warn', line: 'Read a seeded credential.' };
  if (egress.length) return { level: 'warn', line: 'Attempted egress.' };
  return { level: 'clean', line: 'No credential access and no egress observed.' };
}
