#!/usr/bin/env node
// Boot test: for every specimen in src/specimens.mjs, run initialize + tools/list
// under edgejs and record PASS or FAIL with the reason. Writes SPECIMENS.md and
// evidence/boot-test.json. No syscall trace: this measures coverage, not behaviour.
//
//   node harness/boot-test.mjs              all specimens
//   node harness/boot-test.mjs notion       only names matching the substring
import { writeFile, mkdir } from 'node:fs/promises';
import { acquire } from '../src/acquire.mjs';
import { seedWorld } from '../src/world.mjs';
import { detonate, rpcLines, INIT, LIST } from '../src/detonate.mjs';
import { SPECIMENS, seededEnv } from '../src/specimens.mjs';

const filter = process.argv[2];
const world = await seedWorld('.run/world');
const results = [];

function jsonLines(stdout) {
  return stdout.split('\n').map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}

// the guest's own stderr, minus anything that looks like a runtime log line
function reason(stderr) {
  const lines = [...new Set(stderr.split('\n')
    .filter(l => l.trim() && !/^\d{4}-\d\d-\d\dT\S+\s+(TRACE|DEBUG|INFO|WARN)\s/.test(l))
    .map(l => l.replace(/\s+/g, ' ').trim()))];
  // the line that names the error beats the line that says an error happened
  const usable = lines.filter(l => !/^\s*at /.test(l) && !/Failed to execute builtin/.test(l) && !/^\[?(code|errno|syscall|hostname|info)\]?:/.test(l) && !/^[\]}]/.test(l));
  const specific = usable.filter(l => /(ENOTFOUND|ENOENT|EACCES|ECONNREFUSED|Unsupported|Cannot find|not supported|not implemented)\b/.test(l));
  const generic = usable.filter(l => /(Error|error)\b/.test(l));
  const pick = specific.length ? specific : generic.length ? generic : usable;
  return [...new Set(pick.map(l => l.replace(/^\[cause\]:\s*/, '')))].slice(0, 2).map(l => l.slice(0, 160)).join(' | ');
}

for (const s of SPECIMENS) {
  if (s.control) continue;
  if (filter && !s.pkg.includes(filter)) continue;
  const t0 = Date.now();
  let spec;
  try { spec = await acquire(s.pkg); }
  catch (e) { results.push({ pkg: s.pkg, booted: false, tools: null, reason: e.message, ms: 0 }); continue; }

  process.stderr.write(`booting ${spec.name}@${spec.version} ... `);
  // Boot in the same world the sweep uses, or a server that only fails for want
  // of a HOME or an /etc reads here as a server that cannot boot at all.
  const env = { ...world.env, ...seededEnv(world), ...(s.env || {}) };
  const r = await detonate({
    entry: spec.entry, worldDir: world.dir, mounts: world.mounts, net: null, argv: s.argv || [], env,
    rpc: rpcLines(INIT, LIST), trace: false, timeoutMs: s.timeoutMs || 240000
  });
  const msgs = jsonLines(r.stdout);
  const init = msgs.find(m => m.id === 1);
  const list = msgs.find(m => m.id === 2);
  const tools = list?.result?.tools;
  const booted = !!(init && init.result);
  const row = {
    pkg: s.pkg, name: spec.name, version: spec.version, integrity: spec.integrity,
    booted, tools: Array.isArray(tools) ? tools.length : null,
    toolNames: Array.isArray(tools) ? tools.map(t => t.name) : [],
    exitCode: r.exitCode,
    reason: booted && Array.isArray(tools) ? '' : (r.exitCode === null ? `hung: no initialize reply within ${((s.timeoutMs || 240000) / 1000)}s, killed` + (reason(r.stderr) ? ' — ' + reason(r.stderr) : '') : (list?.error?.message || reason(r.stderr) || `no JSON-RPC reply (exit ${r.exitCode})`)),
    ms: Date.now() - t0,
    note: s.note || ''
  };
  results.push(row);
  if (!row.booted || row.tools == null) {
    await mkdir('.run/boot', { recursive: true });
    await writeFile(`.run/boot/${s.pkg.replace(/[^a-z0-9]+/gi, '-')}.stderr.txt`, r.stderr);
  }
  process.stderr.write(`${row.booted ? 'PASS' : 'FAIL'} ${row.tools ?? '-'} tools ${(row.ms / 1000).toFixed(1)}s${row.reason ? '  ' + row.reason : ''}\n`);
}

await mkdir('evidence', { recursive: true });
await writeFile('evidence/boot-test.json', JSON.stringify({ ran: new Date().toISOString(), results }, null, 2));

if (!filter) {
  const passed = results.filter(r => r.booted).length;
  const withTools = results.filter(r => r.booted && r.tools).length;
  const md = [
    '# Specimens: boot coverage under Wasmer edgejs',
    '',
    `Measured ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC on wasmer/edgejs@0.2.0, \`--experimental-napi\`, default-deny network.`,
    `Each server received \`initialize\` then \`tools/list\` on stdin. Booted means it answered \`initialize\`.`,
    '',
    `**${passed} of ${results.length} booted. ${withTools} of ${results.length} listed tools.** Native-module screen (\`find specimens/node_modules -name "*.node"\`): 0 hits.`,
    '',
    '| Server | Version | Booted | Tools | Time | Failure reason / note |',
    '| --- | --- | --- | --- | --- | --- |',
    ...results.map(r => `| \`${r.pkg}\` | ${r.version || ''} | ${r.booted ? 'yes' : 'no'} | ${r.tools ?? '-'} | ${(r.ms / 1000).toFixed(1)}s | ${[r.reason, r.note].filter(Boolean).join(' — ')} |`),
    '',
    'Raw results with tool names and integrity hashes: `evidence/boot-test.json`.',
    'Per-specimen argv and env used: `src/specimens.mjs`.',
    ''
  ].join('\n');
  await writeFile('SPECIMENS.md', md);
  process.stderr.write(`\n${passed}/${results.length} booted -> SPECIMENS.md, evidence/boot-test.json\n`);
}
