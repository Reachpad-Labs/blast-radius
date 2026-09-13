#!/usr/bin/env node
// Render every saved card as one browsable page. Reads evidence/, writes
// evidence/cards/index.html. Nothing here changes the data: the page embeds
// the JSON exactly as the sweep wrote it, and all the reading happens in the
// browser (harness/report-app.js, styled by harness/report.css).
//
//   node harness/report.mjs                      -> evidence/cards/index.html
//   node harness/report.mjs --fragment out.html  also write a head-less copy for publishing
import { readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { SPECIMENS } from '../src/specimens.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const css = await readFile(path.join(here, 'report.css'), 'utf8');
const js = await readFile(path.join(here, 'report-app.js'), 'utf8');
const boot = JSON.parse(await readFile('evidence/boot-test.json', 'utf8'));
const slugOf = n => n.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '');

const cards = {};
for (const f of await readdir('evidence/cards')) {
  if (f.endsWith('.json')) cards[f.slice(0, -5)] = JSON.parse(await readFile(path.join('evidence/cards', f), 'utf8'));
}

const SEV = { critical: 0, warn: 1, clean: 2, noboot: 3 };
const servers = [];
for (const s of SPECIMENS) {
  const b = boot.results.find(r => r.pkg === s.pkg);
  const c = cards[slugOf(s.pkg)];
  if (!b && !c) continue;
  servers.push({
    slug: slugOf(s.pkg), pkg: s.pkg,
    name: c?.spec.name || b?.name || s.pkg,
    version: c?.spec.version || b?.version || '',
    integrity: c?.spec.integrity || b?.integrity || '',
    entry: c?.spec.entry || '',
    note: s.note || '', control: !!s.control,
    booted: s.control ? !!c : !!b?.booted,
    bootReason: b?.reason || '', bootMs: b?.ms ?? null,
    tools: c?.tools || b?.toolNames || [],
    findings: c?.findings || null,
    events: c?.events || [],
    level: c ? c.findings.verdict.level : 'noboot',
    line: c ? c.findings.verdict.line : (b?.reason || 'No card')
  });
}
servers.sort((a, b) => (SEV[a.level] - SEV[b.level]) || (a.control ? -1 : b.control ? 1 : 0) || a.name.localeCompare(b.name));

const data = {
  generated: new Date().toISOString(),
  ran: boot.ran,
  engine: 'Wasmer running Edge.js 0.2.0 (Node 24 as WebAssembly); every file and network request passes through the sandbox and is recorded',
  mode: 'internet blocked',
  servers
};
const json = JSON.stringify(data).replace(/<\//g, '<\\/');

const fragment = `<title>Blast Radius Sweep</title>
<style>${css}</style>
<div class="app">
  <aside class="sidebar" id="sidebar" aria-label="Servers"></aside>
  <main class="content" id="content"></main>
</div>
<div class="tip" id="tip" role="tooltip"></div>
<script id="br-data" type="application/json">${json}</script>
<script>${js}</script>
`;
const full = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
${fragment}</head><body></body></html>`;
// the head/body split above is only cosmetic: browsers hoist the markup either way,
// but keep the real structure honest for the committed file
const fullDoc = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>Blast Radius Sweep</title>
<style>${css}</style>
</head><body>
<div class="app">
  <aside class="sidebar" id="sidebar" aria-label="Servers"></aside>
  <main class="content" id="content"></main>
</div>
<div class="tip" id="tip" role="tooltip"></div>
<script id="br-data" type="application/json">${json}</script>
<script>${js}</script>
</body></html>
`;
void full;
await writeFile('evidence/cards/index.html', fullDoc);
const fi = process.argv.indexOf('--fragment');
if (fi > 0 && process.argv[fi + 1]) await writeFile(process.argv[fi + 1], fragment);
process.stderr.write(`${servers.length} servers (${servers.filter(s => s.findings).length} with cards) -> evidence/cards/index.html${fi > 0 ? ' + fragment' : ''} (${(fullDoc.length / 1024).toFixed(0)} KB)\n`);
