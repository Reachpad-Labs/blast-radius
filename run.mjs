#!/usr/bin/env node
// Blast Radius — detonate an MCP server and print what installing it would cost you.
//
//   node run.mjs @modelcontextprotocol/server-filesystem
//   node run.mjs evil-notes --allow-sink
//
// Default is scan mode: egress denied, every claim comes from the trace.
// --allow-sink routes egress to harness/sink.mjs so payloads can be proven.
import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { acquire } from './src/acquire.mjs';
import { seedWorld } from './src/world.mjs';
import { detonate, rpcLines, argsFor, INIT, LIST } from './src/detonate.mjs';
import { parseTrace } from './src/parse.mjs';
import { analyse } from './src/analyse.mjs';
import { renderCard } from './src/card.mjs';

const pkg = process.argv[2];
const allowSink = process.argv.includes('--allow-sink');
if (!pkg) { console.error('usage: node run.mjs <package> [--allow-sink]'); process.exit(1); }

const spec = await acquire(pkg);
const world = await seedWorld('.run/world');
const net = allowSink ? 'ipv4:allow=127.0.0.1:8099' : null;
const argv = /filesystem/.test(spec.name) ? [world.home] : [];
const common = { entry: spec.entry, worldDir: world.dir, mounts: world.mounts, net, argv, env: world.env };

process.stderr.write(`[1/3] ${spec.name}@${spec.version}  enumerating tools\n`);
const pass1 = await detonate({ ...common, rpc: rpcLines(INIT, LIST) });
const tools = (pass1.stdout.split('\n')
  .map(l => { try { return JSON.parse(l); } catch { return null; } })
  .find(o => o && o.id === 2)?.result?.tools) || [];

process.stderr.write(`[2/3] calling ${tools.length} tool${tools.length === 1 ? '' : 's'}\n`);
const calls = tools.map((t, i) => ({
  jsonrpc: '2.0', id: 10 + i, method: 'tools/call',
  params: { name: t.name, arguments: argsFor(t.inputSchema, world) }
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
