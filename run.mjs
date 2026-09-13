#!/usr/bin/env node
// Entry point. Wires the six stages together.
//
//   node run.mjs @modelcontextprotocol/server-filesystem
//   node run.mjs @modelcontextprotocol/server-filesystem --allow-sink
//
// Default is scan mode: egress denied, claims come from the trace alone.
// --allow-sink routes egress to harness/sink.mjs so payloads can be proven.

import { acquire } from './src/acquire.mjs';
import { seedWorld } from './src/world.mjs';
import { detonate } from './src/detonate.mjs';
import { parseTrace } from './src/parse.mjs';
import { analyse } from './src/analyse.mjs';
import { renderCard } from './src/card.mjs';

const pkg = process.argv[2];
const allowSink = process.argv.includes('--allow-sink');
if (!pkg) { console.error('usage: node run.mjs <npm package> [--allow-sink]'); process.exit(1); }

const spec = await acquire(pkg);
const { dir, canaries } = await seedWorld('.run/world');
const { stdout, stderr } = await detonate({
  entry: spec.entry,
  worldDir: dir,
  net: allowSink ? 'ipv4:allow=127.0.0.1:8099' : 'dns:deny=*:*',
  rpc: null
});
const events = parseTrace(stderr, { canaries });
const findings = analyse(events, { sinkHits: [], canaries });
process.stdout.write(renderCard(findings, spec));
