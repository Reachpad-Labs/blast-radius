#!/usr/bin/env node
// The sweep: every specimen that boots goes through run.mjs in scan mode, and
// the cards land in evidence/cards/ with an index. These are the real numbers
// for the video, so nothing here is hand-edited.
//
//   node harness/boot-test.mjs        first, so the boot gate is fresh
//   node harness/sweep.mjs            everything that booted
//   node harness/sweep.mjs notion     only names matching the substring
//   node harness/sweep.mjs --index-only   rebuild the index from the saved cards, no runs
//   node harness/sweep.mjs --net vendor   second benchmark: each server may reach its own vendor only
import { spawn } from 'node:child_process';
import { readFile, writeFile, copyFile, mkdir, readdir } from 'node:fs/promises';
import { SPECIMENS } from '../src/specimens.mjs';

const indexOnly = process.argv.includes('--index-only');
const netIdx = process.argv.indexOf('--net');
const netMode = netIdx > 0 ? process.argv[netIdx + 1] : 'scan';
const suffix = netMode === 'vendor' ? '--vendor' : '';
const filter = process.argv.slice(2).find((a, i, all) => !a.startsWith('--') && all[i - 1] !== '--net');
const boot = JSON.parse(await readFile('evidence/boot-test.json', 'utf8')).results;
const booted = new Map(boot.map(r => [r.pkg, r]));
const countBy = list => [...list.reduce((m, x) => m.set(x, (m.get(x) || 0) + 1), new Map())];
const slugOf = name => name.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '');

function runOne(pkg) {
  return new Promise(resolve => {
    const p = spawn(process.execPath, ['run.mjs', pkg, ...(netMode === 'vendor' ? ['--net', 'vendor'] : [])], { stdio: ['ignore', 'pipe', 'pipe'] });
    let err = '';
    p.stderr.on('data', d => { err += d; });
    p.on('close', code => resolve({ code, err }));
  });
}

await mkdir('evidence/cards', { recursive: true });
const rows = [];
for (const s of SPECIMENS) {
  if (s.control) continue;
  if (filter && !s.pkg.includes(filter)) continue;
  const b = booted.get(s.pkg);
  if (!b?.booted) {
    rows.push({ pkg: s.pkg, version: b?.version || '', booted: false, note: b?.reason || 'not in boot-test.json' });
    continue;
  }
  process.stderr.write(`sweep ${s.pkg} ... `);
  const { code, err } = indexOnly ? { code: 0, err: '' } : await runOne(s.pkg);
  const tail = err.split('\n').filter(l => l.trim() && !/^\d{4}-\d\d-\d\dT/.test(l)).slice(-2).join(' | ');
  if (code !== 0) {
    const skipped = /no vendor hosts known/.test(err);
    rows.push({ pkg: s.pkg, version: b.version, booted: true, note: (skipped ? 'nothing to allow: its block-all run reached no vendor host' : 'run.mjs failed: ' + tail.slice(0, 200)) });
    process.stderr.write(skipped ? 'skipped, no vendor hosts to allow\n' : `FAILED  ${tail.slice(0, 120)}\n`);
    continue;
  }
  const slug = slugOf(s.pkg) + suffix;
  if (!indexOnly) {
    await copyFile(`.run/${slug}.json`, `evidence/cards/${slug}.json`);
    await copyFile(`.run/${slug}.html`, `evidence/cards/${slug}.html`);
  }
  const rec = JSON.parse(await readFile(`evidence/cards/${slug}.json`, 'utf8'));
  const f = rec.findings;
  rows.push({
    pkg: s.pkg, version: rec.spec.version, booted: true, slug,
    tools: rec.tools.length, events: rec.events.length,
    verdict: f.verdict, reads: countBy(f.reads_credentials.map(r => r.path)), egress: f.egress,
    proven: f.canary_in_payload.length
  });
  process.stderr.write(`${f.verdict.level.toUpperCase()}  ${rec.tools.length} tools, ${rec.events.length} events, egress ${f.egress.map(e => e.host + (e.blocked ? ' blocked' : ' ALLOWED')).join(', ') || 'none'}\n`);
}

if (filter) process.exit(0);

// the index is built from the saved cards of both benchmarks, whatever this run did
const saved = {};
for (const f of await readdir('evidence/cards')) if (f.endsWith('.json')) saved[f.slice(0, -5)] = JSON.parse(await readFile(`evidence/cards/${f}`, 'utf8'));
const hostsOf = f => { const m = new Map(); for (const e of f.egress) { const k = e.host; const c = m.get(k) || { host: k, blocked: true, expected: e.expected }; if (!e.blocked) c.blocked = false; m.set(k, c); } return [...m.values()]; };
const fmtHosts = f => hostsOf(f).map(h => `${h.host} ${h.blocked ? 'blocked' : 'allowed'}${h.expected === false ? ' **undeclared**' : ''}`).join('<br>') || 'none';
const V = f => `**${f.verdict.level.toUpperCase()}** ${f.verdict.line}`;
const all = SPECIMENS.filter(s => !s.control).map(s => { const k = slugOf(s.pkg); return { s, k, scan: saved[k], vendor: saved[k + '--vendor'], boot: booted.get(s.pkg) }; });
// Both controls, in the order that tells the story: the one that needs the
// network, then the one that does not.
const controls = [
  { slug: 'evil-notes', label: '(control, collector allowed)' },
  { slug: 'quiet-notes', label: '(control, no network at all)' }
].map(c => ({ ...c, card: saved[c.slug] })).filter(c => c.card);
const count = (mode, lv) => all.filter(x => x[mode] && x[mode].findings.verdict.level === lv).length;
const ranScan = all.filter(x => x.scan).length, ranVendor = all.filter(x => x.vendor).length;
const md = [
  '# The sweep',
  '',
  `Every server that boots, run through \`run.mjs\` on ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC. One card per server per benchmark; each renders from the JSON beside it.`,
  '',
  '**Verdicts:** *expected* means it only did what its job or our request implied; *undeclared* means it reached a host outside its vendor, or opened or changed something nobody asked for; *critical* means a planted secret provably left, or was opened unprompted right before a connection attempt.',
  '',
  '**Two benchmarks.** *Block all*: every connection refused; the card shows what it tried. *Vendor only*: DNS allowed for exactly the hosts the block-all run judged to be its vendor, everything else refused, real traffic with fake keys. The control specimen `evil-notes` ran with our collector allowed instead, and is the only card that can be critical by proof. The second control, `quiet-notes`, needed no network permission of any kind: it hands the secret to the model in its own answer and copies more onto disk, which is why watching the network alone is not enough.',
  '',
  `**Block all: ${ranScan} of ${all.length} ran to a verdict: ${count('scan', 'critical')} critical, ${count('scan', 'undeclared')} undeclared, ${count('scan', 'expected')} expected.** ${all.length - ranScan} did not boot (see \`SPECIMENS.md\`).`,
  ranVendor ? `**Vendor only: ${ranVendor} ran: ${count('vendor', 'critical')} critical, ${count('vendor', 'undeclared')} undeclared, ${count('vendor', 'expected')} expected.** The rest reached no vendor host in block-all mode, so there was nothing to allow.` : '',
  '',
  '| Server | Version | Tools | Block all | Reached out to (block all) | Vendor only | Reached out to (vendor only) |',
  '| --- | --- | --- | --- | --- | --- | --- |',
  ...controls.map(c => `| [\`${c.slug}\`](${c.slug}.html) ${c.label} | ${c.card.spec.version} | ${c.card.tools.length} | ${V(c.card.findings)} | ${fmtHosts(c.card.findings)} | – | – |`),
  ...all.map(x => x.scan
    ? `| [\`${x.s.pkg}\`](${x.k}.html) | ${x.scan.spec.version} | ${x.scan.tools.length} | ${V(x.scan.findings)} | ${fmtHosts(x.scan.findings)} | ${x.vendor ? '[' + V(x.vendor.findings) + '](' + x.k + '--vendor.html)' : '–'} | ${x.vendor ? fmtHosts(x.vendor.findings) : '–'} |`
    : `| \`${x.s.pkg}\` | ${x.boot?.version || ''} | - | did not boot | ${(x.boot?.reason || '').replace(/\|/g, '/').slice(0, 120)} | – | – |`),
  ''
].join('\n');
await writeFile('evidence/cards/README.md', md);
process.stderr.write(`\n${ranScan}/${all.length} block-all, ${ranVendor} vendor-only -> evidence/cards/README.md\n`);
