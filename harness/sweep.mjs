#!/usr/bin/env node
// The sweep: every specimen that boots goes through run.mjs in scan mode, and
// the cards land in evidence/cards/ with an index. These are the real numbers
// for the video, so nothing here is hand-edited.
//
//   node harness/boot-test.mjs        first, so the boot gate is fresh
//   node harness/sweep.mjs            everything that booted
//   node harness/sweep.mjs notion     only names matching the substring
//   node harness/sweep.mjs --index-only   rebuild the index from the saved cards, no runs
import { spawn } from 'node:child_process';
import { readFile, writeFile, copyFile, mkdir } from 'node:fs/promises';
import { SPECIMENS } from '../src/specimens.mjs';

const indexOnly = process.argv.includes('--index-only');
const filter = process.argv.slice(2).find(a => !a.startsWith('--'));
const boot = JSON.parse(await readFile('evidence/boot-test.json', 'utf8')).results;
const booted = new Map(boot.map(r => [r.pkg, r]));
const countBy = list => [...list.reduce((m, x) => m.set(x, (m.get(x) || 0) + 1), new Map())];
const slugOf = name => name.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '');

function runOne(pkg) {
  return new Promise(resolve => {
    const p = spawn(process.execPath, ['run.mjs', pkg], { stdio: ['ignore', 'pipe', 'pipe'] });
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
    rows.push({ pkg: s.pkg, version: b.version, booted: true, note: 'run.mjs failed: ' + tail.slice(0, 200) });
    process.stderr.write(`FAILED  ${tail.slice(0, 120)}\n`);
    continue;
  }
  const slug = slugOf(s.pkg);
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

const ran = rows.filter(r => r.slug);
const levels = { critical: 0, warn: 0, clean: 0 };
for (const r of ran) levels[r.verdict.level] = (levels[r.verdict.level] || 0) + 1;
const fmtEgress = r => r.egress?.length ? r.egress.map(e => `${e.host}${e.port ? ':' + e.port : ''} ${e.blocked ? 'blocked' : 'allowed'}`).join('<br>') : 'none';

const md = [
  '# The sweep',
  '',
  `Every specimen that boots, run through \`run.mjs\` in scan mode (egress denied, every claim from the trace) on ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC. One card per server; rendered from the JSON beside it.`,
  '',
  `**${ran.length} of ${rows.length} servers ran to a verdict: ${levels.critical || 0} critical, ${levels.warn || 0} warn, ${levels.clean || 0} clean.** ${rows.length - ran.length} did not boot (see \`SPECIMENS.md\`).`,
  '',
  'Nothing in scan mode is proven at the sink; the "canary in payload" row on every card here reads "not observed" because egress was denied. The control specimen `evil-notes` is the one card produced with `--allow-sink`, and the only CRITICAL by proof.',
  '',
  '| Server | Version | Tools | Verdict | Credential reads | Egress |',
  '| --- | --- | --- | --- | --- | --- |',
  ...rows.map(r => r.slug
    ? `| [\`${r.pkg}\`](${r.slug}.html) | ${r.version} | ${r.tools} | **${r.verdict.level.toUpperCase()}** ${r.verdict.line} | ${r.reads.length ? r.reads.map(([p, n]) => '`' + p + '`' + (n > 1 ? ' ×' + n : '')).join('<br>') : 'none'} | ${fmtEgress(r)} |`
    : `| \`${r.pkg}\` | ${r.version} | - | did not boot | - | ${r.note.replace(/\|/g, '/').slice(0, 120)} |`),
  ''
].join('\n');
await writeFile('evidence/cards/README.md', md);
process.stderr.write(`\n${ran.length}/${rows.length} ran -> evidence/cards/README.md\n`);
