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
import { seedWorld, scanWorld, snapshotPaths } from './src/world.mjs';
import { detonate, stageSpecimens, rpcLines, argsFor, INIT, LIST } from './src/detonate.mjs';
import { parseTrace } from './src/parse.mjs';
import { analyse, vendorTokens } from './src/analyse.mjs';
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

// Where every canary already lives before anything runs. /proc/self/environ is
// seeded with the env canaries by design, so without this baseline the world
// scan reports our own fixture as relocation — measured, it reported 8.
const baseline = new Set((await scanWorld(world.dir, world)).map(h => h.path + '|' + h.canary));
const before = await snapshotPaths(world.dir);
const specimensDir = await stageSpecimens();   // the guest gets a copy, never our tree
const net = allowSink ? 'ipv4:allow=127.0.0.1:8099' : null;
// Per-specimen argv and env (fake keys) come from the manifest. The seeded world
// supplies the rest of the environment, so every token a specimen can find is a
// canary minted for this run rather than a real key — manifest and CLI values
// win where they overlap, because some servers refuse to boot without their own.
const manifest = specimenFor(pkg);
const common = {
  entry: spec.entry, worldDir: world.dir, mounts: world.mounts, specimensDir,
  net, engine: cli.engine,
  argv: [...(manifest.argv || []), ...cli.argv],
  env: { ...world.env, ...seededEnv(world), ...(manifest.env || {}), ...cli.env }
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
  params: { name: t.name, arguments: argsFor(t.inputSchema, world) }
}));
const rpc2 = rpcLines(INIT, ...calls);
const pass2 = await detonate({ ...common, rpc: rpc2 });

let sinkHits = [];
try { sinkHits = [await readFile('sink.log', 'utf8')]; } catch {}

// Channel ② — the MCP response itself. A server can answer the user's question
// correctly and append the key where the model will read it and a human will
// not scroll. No socket, no syscall: the only place it shows is stdout.
//
// But we provoke every tool with a real path, so a file server asked to read
// the key returns the key, and that is its job. Only an UNSOLICITED canary is a
// finding: one we never named in the request that produced the answer. Without
// this, server-filesystem scores CRITICAL for doing exactly what it says on the
// tin — measured, it did.
// Attributed to the tool that said it, by JSON-RPC id. Without the name this
// reads as an accusation; with it, it is a capability. Measured: calling every
// tool blindly means calling server-everything's get-env, which returns the
// environment because that is what it advertises. The reader needs to see that.
const asked = rpc2 + rpcLines(INIT, LIST);
const solicited = new Set(
  Object.entries(world.origin).filter(([, where]) => asked.includes(where)).map(([canary]) => canary)
);
const modelHits = [];
for (const [i, line] of (pass1.stdout + '\n' + pass2.stdout).split('\n').entries()) {
  let reply; try { reply = JSON.parse(line); } catch { continue; }
  const tool = reply?.id >= 10 ? (calls[reply.id - 10]?.params.name || 'unknown tool') : 'the handshake';
  for (const [where, canary] of Object.entries(world.canaries)) {
    if (!canary || solicited.has(canary) || !line.includes(canary)) continue;
    modelHits.push({ canary, tool, from: where.startsWith('env:') ? where.slice(4) : '/' + where });
  }
}

// Channel ③ — loot parked in the world for something else to carry out. Only
// what moved during the run: anything present at seed time is ours.
const stagedHits = (await scanWorld(world.dir, world))
  .filter(h => !baseline.has(h.path + '|' + h.canary));

// Paths we ourselves named in a tool call. A file server told to write to the
// key path writes to the key path; that is the provocation, not the specimen.
const solicitedPaths = world.credentialPaths.filter(p => asked.includes(p));

// Files that did not exist before the run. Catches a plant with no canary in
// it, which neither the trace nor the content scan can see.
const createdPaths = [...await snapshotPaths(world.dir)].filter(p => !before.has(p));

// Each pass is its own process with its own clock. Parse separately so nothing
// downstream can correlate a read in one with an egress in the other.
const events = [
  ...parseTrace(pass1.stderr, { canaries: world.canaries, pass: 1 }),
  ...parseTrace(pass2.stderr, { canaries: world.canaries, pass: 2 })
];
const findings = analyse(events, {
  sinkHits, modelHits, stagedHits, solicitedPaths, createdPaths,
  canaries: world.canaries, credentialPaths: world.credentialPaths,
  // who the specimen's own service is, and every address we handed it ourselves
  vendor: vendorTokens(spec.name),
  askedText: (asked + ' ' + JSON.stringify(common.argv) + ' ' + JSON.stringify(common.env)).toLowerCase()
});

await mkdir('.run', { recursive: true });
const slug = spec.name.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '');
await writeFile(`.run/${slug}.json`, JSON.stringify({ spec, tools: tools.map(t => t.name), findings, events }, null, 2));
await writeFile(`.run/${slug}.html`, renderCard(findings, spec));

process.stderr.write(`[3/3] ${events.length} events  ->  ${findings.verdict.level.toUpperCase()}: ${findings.verdict.line}\n`);
process.stderr.write(`      .run/${slug}.html\n`);
