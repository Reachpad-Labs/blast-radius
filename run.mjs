#!/usr/bin/env node
// Blast Radius — detonate an MCP server and print what installing it would cost you.
//
//   node run.mjs @modelcontextprotocol/server-filesystem
//   node run.mjs evil-notes --allow-sink
//   node run.mjs tavily-mcp --env TAVILY_API_KEY=fake         any npm package; fetched on demand
//   node run.mjs some-server --arg /home --engine quickjs
//   node run.mjs exa-mcp-server --net vendor                   let it reach its vendor, nothing else
//
// Three network modes:
//   scan    (default) every connection refused; the card shows what it tried
//   vendor  DNS allowed only for the hosts a previous scan judged to be its
//           vendor (plus any --allow HOST); raw IPs and everything else refused.
//           This is real traffic to the vendor with our fake keys.
//   sink    --allow-sink: only 127.0.0.1:8099, our collector, so payloads can be proven
// --env K=V, --arg X and --allow HOST repeat; env and arg add to src/specimens.mjs.
// --engine host|quickjs picks the Edge.js package (see src/detonate.mjs).
import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { acquire } from './src/acquire.mjs';
import { seedWorld } from './src/world.mjs';
import { detonate, rpcLines, argsFor, INIT, LIST } from './src/detonate.mjs';
import { parseTrace } from './src/parse.mjs';
import { analyse, vendorTokensFor, hostsIn } from './src/analyse.mjs';
import { renderCard } from './src/card.mjs';
import { specimenFor, seededEnv } from './src/specimens.mjs';

const cli = { pkg: null, allowSink: false, env: {}, argv: [], engine: undefined, netMode: 'scan', allow: [] };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a === '--allow-sink') cli.allowSink = true;
  else if (a === '--env') { const [k, ...v] = String(process.argv[++i]).split('='); cli.env[k] = v.join('='); }
  else if (a === '--arg') cli.argv.push(process.argv[++i]);
  else if (a === '--engine') cli.engine = process.argv[++i];
  else if (a === '--net') cli.netMode = process.argv[++i];
  else if (a === '--allow') cli.allow.push(process.argv[++i]);
  else if (!cli.pkg && !a.startsWith('--')) cli.pkg = a;
  else { console.error(`unknown option ${a}`); process.exit(1); }
}
const { pkg, allowSink } = cli;
if (!pkg) { console.error('usage: node run.mjs <package> [--allow-sink] [--net scan|vendor] [--allow HOST]... [--env K=V]... [--arg X]... [--engine host|quickjs]'); process.exit(1); }
if (!['scan', 'vendor'].includes(cli.netMode)) { console.error('--net takes scan or vendor'); process.exit(1); }

const spec = await acquire(pkg);
const mode = allowSink ? 'sink' : cli.netMode;
const slug = spec.name.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '') + (mode === 'vendor' ? '--vendor' : '');
const world = await seedWorld(mode === 'vendor' ? '.run/world-vendor' : '.run/world');

// the vendor allow-list comes from a previous scan card: every host it reached
// that the analyser judged to be its own vendor or one we passed in
let net = null;
if (mode === 'sink') net = 'ipv4:allow=127.0.0.1:8099';
if (mode === 'vendor') {
  const scanSlug = slug.replace(/--vendor$/, '');
  let prior = null;
  for (const f of [`evidence/cards/${scanSlug}.json`, `.run/${scanSlug}.json`]) {
    try { prior = JSON.parse(await readFile(f, 'utf8')); break; } catch {}
  }
  const hosts = [...new Set([
    ...cli.allow,
    ...((prior?.findings?.egress || []).filter(e => e.expected && !/^[\d.]+$/.test(e.host)).map(e => e.host))
  ])];
  if (!hosts.length) { console.error(`no vendor hosts known for ${spec.name}: run a scan first, or pass --allow HOST`); process.exit(1); }
  net = hosts.map(h => `dns:allow=${h}:*`).join(',');
  process.stderr.write(`[net] vendor mode: ${hosts.join(', ')} allowed, everything else refused\n`);
}
// per-specimen argv and env (fake keys) come from the manifest; the seeded
// GitHub token canary rides along so a leaked token is a canary, not a key
const manifest = specimenFor(pkg);
const common = {
  entry: spec.entry, worldDir: world.dir, net, engine: cli.engine,
  argv: [...(manifest.argv || []), ...cli.argv],
  env: { ...seededEnv(world.canaries), ...(manifest.env || {}), ...cli.env }
};

process.stderr.write(`[1/3] ${spec.name}@${spec.version}  enumerating tools\n`);
const pass1 = await detonate({ ...common, rpc: rpcLines(INIT, LIST) });
const replies = pass1.stdout.split('\n').map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
if (!replies.find(o => o.id === 1)?.result) {
  // a verdict on a server that never ran would be a false claim, so there is no card
  const why = pass1.stderr.split('\n').filter(l => l.trim() && !/^\d{4}-\d\d-\d\dT/.test(l) && !/^\s+\d+: /.test(l)).slice(0, 3).join(' | ');
  const how = pass1.exitCode === null ? 'hung: no reply before the timeout, killed' : `exit ${pass1.exitCode}`;
  process.stderr.write(`${spec.name}@${spec.version} did not answer initialize (${how}); no card.\n      ${why.slice(0, 300)}\n`);
  process.exit(2);
}
const tools = replies.find(o => o.id === 2)?.result?.tools || [];

process.stderr.write(`[2/3] calling ${tools.length} tool${tools.length === 1 ? '' : 's'}\n`);
const calls = tools.map((t, i) => ({
  jsonrpc: '2.0', id: 10 + i, method: 'tools/call',
  params: { name: t.name, arguments: argsFor(t.inputSchema, { probePath: '/home/.ssh/id_ed25519' }) }
}));
const pass2 = await detonate({ ...common, rpc: rpcLines(INIT, ...calls) });

let sinkHits = [];
try { sinkHits = [await readFile('sink.log', 'utf8')]; } catch {}

const events = parseTrace(pass1.stderr + '\n' + pass2.stderr, { canaries: world.canaries });
// what "expected" means for this run: the vendor named by the package, the hosts
// we ourselves passed in, and the paths our probe handed to the tools
const policy = {
  vendorTokens: vendorTokensFor(spec.name, manifest.vendor || []),
  argHosts: hostsIn([...common.argv, ...Object.values(common.env)]),
  probePaths: [...new Set(calls.flatMap(c => Object.values(c.params.arguments).filter(v => typeof v === 'string' && v.startsWith('/'))))]
};
const findings = analyse(events, { sinkHits, canaries: world.canaries, policy });

await mkdir('.run', { recursive: true });
await writeFile(`.run/${slug}.json`, JSON.stringify({ spec, mode, net, tools: tools.map(t => t.name), findings, events }, null, 2));
await writeFile(`.run/${slug}.html`, renderCard(findings, spec));

process.stderr.write(`[3/3] ${events.length} events  ->  ${findings.verdict.level.toUpperCase()}: ${findings.verdict.line}\n`);
process.stderr.write(`      .run/${slug}.html\n`);
