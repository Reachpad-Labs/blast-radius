// STAGE 5 — events into claims. Pure: no Wasmer, no filesystem.
//
// Three verdicts, all descriptive:
//   expected    it only did what its job or our request implied: reached its own
//               vendor, opened a file we passed as an argument, connected to the
//               database URL we gave it, or did nothing at all
//   undeclared  it did something nobody asked for and nothing announced: reached a
//               host outside its vendor's domains, opened a secret file no argument
//               pointed at, or changed a file outside its own folder unprompted
//   critical    a planted secret provably arrived at our collector, or a secret was
//               opened unprompted and a connection was attempted right after
//
// "Expected" is decided by a policy the runner passes in, and the policy is
// returned in the findings so a reader can check the reasoning:
//   vendorTokens  words in the package name (plus a manifest `vendor` list) that
//                 name the vendor; a host whose registrable label is one of them is
//                 the vendor's own (api.exa.ai -> exa; api.hubspot.com -> hubspot)
//   argHosts      hosts and addresses we ourselves put in argv or env
//   probePaths    paths our probe passed as tool arguments; opening them is doing
//                 what it was told
import { DECISION } from './schema.mjs';

const CRED = [/\.ssh\//, /\.env$/, /\.aws\//, /credentials/i, /id_[a-z0-9]+$/, /\.npmrc$/, /\.netrc$/];
const PROBES = [/process\.versions/, /\/proc\/version/, /config\.gypi/];
// words in a package name that do not identify a vendor
const GENERIC = new Set(['mcp', 'server', 'servers', 'modelcontextprotocol', 'io', 'dev', 'ai', 'com', 'app', 'api', 'cli', 'node', 'js', 'official', 'tools', 'tool', 'the', 'for', 'and']);

export const LEVEL = { CRITICAL: 'critical', UNDECLARED: 'undeclared', EXPECTED: 'expected' };

// words from a package name that could name its vendor: "@hubspot/mcp-server" -> ["hubspot"]
export function vendorTokensFor(name, extra = []) {
  const toks = String(name).toLowerCase().split(/[^a-z0-9]+/).filter(t => t.length > 2 && !GENERIC.has(t));
  return [...new Set([...toks, ...extra.map(e => String(e).toLowerCase())])];
}

// hosts and IPs that appear inside argv or env values (a database URL, a collector)
export function hostsIn(strings) {
  const out = new Set();
  for (const s of strings) {
    for (const m of String(s).matchAll(/(?:[a-z][a-z0-9+.-]*:\/\/)?\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?/gi)) {
      const h = m[1].toLowerCase();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || /\.[a-z]{2,}$/.test(h)) out.add(h);
    }
  }
  return [...out];
}

// "127.0.0.1:8099" -> { ip, port }; "[2606:4700::1]:443" -> { ip, port }
function splitAddr(addr) {
  const s = String(addr);
  const m6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
  if (m6) return { ip: m6[1], port: m6[2] ? Number(m6[2]) : null };
  const i = s.lastIndexOf(':');
  if (i < 0) return { ip: s, port: null };
  return { ip: s.slice(0, i), port: Number(s.slice(i + 1)) || null };
}

// the label that names the owner of a host: api.hubspot.com -> hubspot,
// raw.githubusercontent.com -> githubusercontent, an IP -> null
function ownerLabel(host) {
  const h = String(host).toLowerCase();
  if (/^[\d.]+$/.test(h) || h.includes(':')) return null;
  const parts = h.split('.').filter(Boolean);
  if (parts.length < 2) return parts[0] || null;
  const second = parts[parts.length - 2];
  if (parts.length >= 3 && ['co', 'com', 'net', 'org', 'gov', 'ac', 'edu'].includes(second)) return parts[parts.length - 3];
  return second;
}

export function analyse(events, { sinkHits = [], canaries = {}, policy = {} } = {}) {
  const vendorTokens = new Set((policy.vendorTokens || []).map(t => String(t).toLowerCase()));
  const argHosts = new Set((policy.argHosts || []).map(h => String(h).toLowerCase()));
  const probePaths = policy.probePaths || [];
  const asked = p => probePaths.some(q => p === q || p.startsWith(q + '.') || p.startsWith(q + '/'));
  const judgeHost = host => {
    const h = String(host).toLowerCase();
    if (argHosts.has(h)) return { expected: true, why: 'from our arguments' };
    const label = ownerLabel(h);
    if (label && vendorTokens.has(label)) return { expected: true, why: 'its vendor, by name' };
    return { expected: false, why: 'undeclared' };
  };

  const reads_credentials = [];
  const egress = [];
  let bytes_out = 0;
  const writes_outside_cwd = [];
  const fingerprinting = [];
  // Node looks a name up and then connects to the addresses it got back, so a
  // connect to a bare IP right after a successful lookup belongs to that name.
  // With no successful lookup before it (scan mode, or a hard-coded address)
  // the IP stands on its own.
  let lastResolved = null;

  for (const e of events) {
    const p = e.args.path;

    if (p && (CRED.some(re => re.test(p)) || e.canary_hit)) {
      reads_credentials.push({ path: p, canary: e.canary_hit, at: e.ts, asked: asked(p) });
    }
    if (p && PROBES.some(re => re.test(p))) fingerprinting.push(p);

    if (e.call === 'resolve' && e.args.host) {
      egress.push({ host: e.args.host, port: e.args.port ?? null, blocked: e.decision === DECISION.DENY, at: e.ts, ...judgeHost(e.args.host) });
      lastResolved = e.decision === DECISION.DENY ? null : e.args.host;
    }
    if (e.call === 'sock_connect' && e.args.addr) {
      const { ip, port } = splitAddr(e.args.addr);
      const host = lastResolved || ip;
      egress.push({ host, ip: host === ip ? undefined : ip, port, blocked: e.decision === DECISION.DENY, at: e.ts, ...judgeHost(host) });
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

  const reads = dedupeReads(reads_credentials);
  const hosts = dedupe(egress);
  const writes = [...new Set(writes_outside_cwd)];
  const unprompted_reads = reads.filter(r => !r.asked);
  const undeclared_hosts = hosts.filter(h => !h.expected);
  const unprompted_writes = writes.filter(p => !asked(p));

  const firstRead = unprompted_reads[0]?.at;
  const firstEgress = egress[0]?.at;
  const correlated = firstRead != null && firstEgress != null && firstEgress >= firstRead;

  return {
    reads_credentials: reads,
    egress: hosts,
    bytes_out,
    canary_in_payload,
    writes_outside_cwd: writes,
    fingerprinting: [...new Set(fingerprinting)],
    unprompted_reads: unprompted_reads.map(r => r.path),
    undeclared_hosts: undeclared_hosts.map(h => h.host + (h.port ? ':' + h.port : '')),
    unprompted_writes,
    correlated,
    policy: { vendorTokens: [...vendorTokens], argHosts: [...argHosts], probePaths: [...probePaths] },
    verdict: verdict({ reads, unprompted_reads, hosts, undeclared_hosts, unprompted_writes, canary_in_payload, correlated })
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
    const cur = seen.get(k);
    if (!cur) { seen.set(k, { ...e, ips: e.ip ? [e.ip] : [] }); continue; }
    if (e.ip && !cur.ips.includes(e.ip)) cur.ips.push(e.ip);
    if (cur.blocked && !e.blocked) Object.assign(cur, { blocked: false, at: e.at });
  }
  return [...seen.values()].map(e => { const { ip, ...rest } = e; return rest; });
}

const cap = s => s.charAt(0).toUpperCase() + s.slice(1);

function verdict({ reads, unprompted_reads, hosts, undeclared_hosts, unprompted_writes, canary_in_payload, correlated }) {
  if (canary_in_payload.length) return { level: LEVEL.CRITICAL, line: 'Sent a planted secret out of the sandbox. Proven: it arrived at our collector.' };
  if (unprompted_reads.length && hosts.length && correlated) return { level: LEVEL.CRITICAL, line: 'Opened a planted secret without being asked, then tried to reach a server.' };
  const notes = [];
  if (undeclared_hosts.length) notes.push('reached out to ' + undeclared_hosts.map(h => h.host).join(' and ') + ', which nothing declared');
  if (unprompted_reads.length) notes.push('opened ' + unprompted_reads.map(r => r.path).join(' and ') + ' without being asked');
  if (unprompted_writes.length) notes.push('changed ' + unprompted_writes.join(' and ') + ' without being asked');
  if (notes.length) return { level: LEVEL.UNDECLARED, line: cap(notes.join('; ')) + '.' };
  if (!reads.length && !hosts.length) return { level: LEVEL.EXPECTED, line: 'Did nothing beyond starting up and answering.' };
  return { level: LEVEL.EXPECTED, line: 'Only did what its job or our request implied.' };
}
