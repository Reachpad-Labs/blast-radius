// STAGE 5 — events into claims. Pure: no Wasmer, no filesystem.
//
// Egress is not the same thing as a socket. A specimen can hand the secret back
// through its own MCP response, where the model reads it and the agent carries
// it, or park it in an ordinary file for something else to move later. Both are
// invisible to a trace that only watches sockets, so both arrive here already
// measured: modelHits from the specimen's stdout, stagedHits from a scan of the
// world after the run. See docs/ISOLATION.md for the channel model.
import { DECISION } from './schema.mjs';

// Fallback only. The real credential list is credentialPaths, derived from the
// world the specimen was actually given — adding a fixture updates the detector
// for free. These catch paths outside the seeded world.
const CRED = [
  /\.ssh\//, /\.env$/, /\.aws\//, /credentials/i, /id_[a-z0-9]+$/,
  /\.npmrc$/, /\.netrc$/, /\.pypirc$/, /hosts\.yml$/, /\.docker\//,
  /\.kube\//, /token/i, /\.git-credentials$/
];

// Paths that only exist to tell a process what machine it is on. Real now that
// /proc and /sys are seeded — before that this list could never match.
const PROBES = [
  /^\/proc\/version$/, /^\/proc\/cpuinfo$/, /^\/proc\/meminfo$/,
  /^\/sys\/(class|devices)\/.*dmi/, /^\/etc\/machine-id$/, /^\/etc\/os-release$/
];

// A write we can see in the trace. path_open2 carries no oflags, so an open
// tells us nothing about intent — but a rename or an unlink is unambiguous.
// Creation is caught by the world scan instead, which also gets the content.
const WRITE_CALLS = new Set(['path_rename', 'path_unlink_file']);

export function analyse(events, {
  sinkHits = [], modelHits = [], stagedHits = [], solicitedPaths = [], createdPaths = [],
  canaries = {}, credentialPaths = []
} = {}) {
  const seeded = new Set(credentialPaths);
  const isCred = p => seeded.has(p) || CRED.some(re => re.test(p));
  // We provoke every tool with a real path, so a file server told to write to
  // the key path does. A write to a path we named is the harness's doing.
  const solicited = new Set(solicitedPaths);

  const reads_credentials = [];
  const attempted_paths = [];
  const egress = [];
  let bytes_out = 0;
  const writes_outside_cwd = [];
  const fingerprinting = [];

  for (const e of events) {
    const p = e.args.path;
    const missed = e.errno === 'noent';

    if (p && !missed && (isCred(p) || e.canary_hit)) {
      reads_credentials.push({ path: p, canary: e.canary_hit, at: e.ts, pass: e.pass });
    }
    // Asked for, not there. Parse keeps misses only under roots a sweep would
    // walk, so this is the shape of the search rather than what it caught.
    if (p && missed) attempted_paths.push(p);
    if (p && PROBES.some(re => re.test(p))) fingerprinting.push(p);

    if (e.call === 'resolve' && e.args.host) {
      egress.push({ host: e.args.host, port: e.args.port ?? null, blocked: e.decision === DECISION.DENY, at: e.ts, pass: e.pass });
    }
    if (e.call === 'sock_connect' && e.args.addr) {
      const [host, port] = String(e.args.addr).split(':');
      egress.push({ host, port: port ? Number(port) : null, blocked: e.decision === DECISION.DENY, at: e.ts, pass: e.pass });
    }
    if (e.call === 'sock_send' || e.call === 'sock_send_to' || (e.call === 'fd_write' && e.args.socket)) {
      bytes_out += Number(e.args.nsent ?? e.args.nwritten ?? e.args.bytes_written ?? 0);
    }
    // The trace carries no open flags, but a rename onto a path or an unlink of
    // it is a write by any definition. Measured: server-filesystem writes a .tmp
    // beside the target and renames it into place, so the rename is the only
    // line that names the file that changed. Paths we named ourselves in a tool
    // call are the provocation, not the specimen.
    if (WRITE_CALLS.has(e.call)) {
      const target = e.args.new_path || e.args.path;
      if (target && !target.startsWith('/app') && !solicited.has(target)) writes_outside_cwd.push(target);
    }
  }

  // proven-at-sink ONLY. Never derived from the trace: payload bytes are not in it.
  const known = Object.values(canaries).filter(Boolean);
  const blob = sinkHits.join('\n');
  const canary_in_payload = known.filter(c => blob.includes(c));

  // one row per canary per tool that said it
  const returned_to_model = [...new Map(
    modelHits.map(h => [h.canary + '|' + h.tool, h])
  ).values()];
  const staged_on_disk = stagedHits;

  // Correlate ONLY within one pass. Each pass is a separate Wasmer process with
  // its own clock; comparing across them would call a read in the handshake and
  // an unrelated connection in the tool run a causal chain.
  const correlated = [...new Set(reads_credentials.map(r => r.pass))].some(pass => {
    const read = reads_credentials.find(r => r.pass === pass);
    const out = egress.find(g => g.pass === pass);
    return read && out && out.at >= read.at;
  });

  const attempted = [...new Set(attempted_paths)];
  const attempted_credentials = attempted.filter(isCred);

  return {
    reads_credentials: dedupeReads(reads_credentials),
    attempted,
    attempted_credentials,
    returned_to_model,
    staged_on_disk,
    egress: dedupe(egress),
    bytes_out,
    canary_in_payload,
    // Renames and unlinks come from the trace; creations come from the world
    // snapshot, because an open tells us nothing about intent.
    writes_outside_cwd: [...new Set([
      ...writes_outside_cwd,
      ...createdPaths.filter(p => !p.startsWith('/app') && !solicited.has(p))
    ])],
    fingerprinting: [...new Set(fingerprinting)],
    correlated,
    verdict: verdict({
      reads_credentials, attempted_credentials, egress,
      canary_in_payload, returned_to_model, staged_on_disk, correlated
    })
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

// A sweep is a search, not a hit: three or more misses on paths that would have
// held credentials says what the specimen was looking for even when this
// particular box did not have them.
const SWEEP = 3;

function verdict({ reads_credentials, attempted_credentials, egress, canary_in_payload, returned_to_model, staged_on_disk, correlated }) {
  if (canary_in_payload.length) return { level: 'critical', line: 'Exfiltrated a seeded credential. Proven at the sink.' };
  if (returned_to_model.length) {
    const tools = [...new Set(returned_to_model.map(h => h.tool))];
    const what = returned_to_model.length === 1 ? 'a seeded credential' : `${returned_to_model.length} seeded credentials`;
    return { level: 'critical', line: `Returned ${what} to the model from ${tools.map(t => `“${t}”`).join(', ')}.` };
  }
  if (staged_on_disk.length) return { level: 'critical', line: 'Copied a seeded credential into a file it does not own.' };
  if (reads_credentials.length && correlated) return { level: 'critical', line: 'Read a seeded credential, then attempted egress.' };
  if (reads_credentials.length) return { level: 'warn', line: 'Read a seeded credential.' };
  if (attempted_credentials.length >= SWEEP) return { level: 'warn', line: `Swept ${attempted_credentials.length} credential paths that were not there.` };
  if (egress.length) return { level: 'warn', line: 'Attempted egress.' };
  return { level: 'clean', line: 'No credential access and no egress observed.' };
}
