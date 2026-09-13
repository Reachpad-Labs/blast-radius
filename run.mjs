#!/usr/bin/env node
// Blast Radius — detonate an MCP server and print what installing it would cost you.
//
//   node run.mjs @modelcontextprotocol/server-filesystem
//   node run.mjs evil-notes --allow-sink
//   node run.mjs tavily-mcp --env TAVILY_API_KEY=fake         any npm package; fetched on demand
//   node run.mjs some-server --arg /home --engine quickjs
//
// Default is scan mode: egress denied, every claim comes from the trace.
// --allow-sink routes egress to harness/sink.mjs so payloads can be proven.
// --env K=V and --arg X repeat; they add to whatever src/specimens.mjs knows.
// --engine host|quickjs picks the Edge.js package (see src/detonate.mjs).
import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { acquire } from './src/acquire.mjs';
import { seedWorld } from './src/world.mjs';
import { detonate, rpcLines, argsFor, INIT, LIST } from './src/detonate.mjs';
import { parseTrace } from './src/parse.mjs';
import { analyse } from './src/analyse.mjs';
import { renderCard } from './src/card.mjs';
import { specimenFor, seededEnv } from './src/specimens.mjs';

const cli = { pkg: null, allowSink: false, env: {}, argv: [], engine: undefined };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a === '--allow-sink') cli.allowSink = true;
  else if (a === '--env') { const [k, ...v] = String(process.argv[++i]).split('='); cli.env[k] = v.join('='); }
  else if (a === '--arg') cli.argv.push(process.argv[++i]);
  else if (a === '--engine') cli.engine = process.argv[++i];
  else if (!cli.pkg && !a.startsWith('--')) cli.pkg = a;
  else { console.error(`unknown option ${a}`); process.exit(1); }
}
const { pkg, allowSink } = cli;
if (!pkg) { console.error('usage: node run.mjs <package> [--allow-sink] [--env K=V]... [--arg X]... [--engine host|quickjs]'); process.exit(1); }

const spec = await acquire(pkg);
const world = await seedWorld('.run/world');
const net = allowSink ? 'ipv4:allow=127.0.0.1:8099' : null;
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
const findings = analyse(events, { sinkHits, canaries: world.canaries });

await mkdir('.run', { recursive: true });
const slug = spec.name.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '');
await writeFile(`.run/${slug}.json`, JSON.stringify({ spec, tools: tools.map(t => t.name), findings, events }, null, 2));
await writeFile(`.run/${slug}.html`, renderCard(findings, spec));

process.stderr.write(`[3/3] ${events.length} events  ->  ${findings.verdict.level.toUpperCase()}: ${findings.verdict.line}\n`);
process.stderr.write(`      .run/${slug}.html\n`);
