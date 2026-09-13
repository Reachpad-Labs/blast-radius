// STAGE 6 — render the verdict card. Pure: takes findings, returns HTML.
// Renders from a saved JSON file with no live run, so the video can never be
// broken by a flaky detonation.
//
// A card, not a log. One glance answers: how bad, what did it take, and how do
// we know. Everything else is evidence underneath, in the specimen's own words.
//
// Describe capabilities, never accuse. We are naming real packages.

const C = {
  critical: '#F0736A', warn: '#E8B339', clean: '#6EE7A8',
  ground: '#0E100F', surface: '#161918', raise: '#1C201E', line: '#2A2E2C',
  ink: '#ECE7DE', mute: '#8C918C', dim: '#636965', sink: '#7FB2E5'
};

const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const bytes = n => n >= 1024 ? (n / 1024).toFixed(1) + ' KB' : n + ' B';
const short = p => p.replace(/^\/home\/[^/]+\//, '~/');

function tile(value, label, tone) {
  return `<div class="tile"><div class="num" style="color:${tone}">${value}</div><div class="cap">${esc(label)}</div></div>`;
}

// One evidence block: a tier badge, a heading, and the specimen's own paths.
const TIER_LABEL = {
  sink: 'proven at sink', attempt: 'attempted',
  stdout: 'the specimen said so', world: 'found in the world', trace: 'from trace'
};

function block(tier, heading, lines, tone) {
  if (!lines.length) return '';
  return `<section class="ev">
    <div class="evhead"><span class="badge b-${tier}">${TIER_LABEL[tier] || 'from trace'}</span>
      <h2 style="color:${tone}">${esc(heading)}</h2></div>
    <ul>${lines.map(l => `<li>${l}</li>`).join('')}</ul>
  </section>`;
}

export function renderCard(f, meta = {}) {
  const v = f.verdict;
  const attempted = f.attempted || [];
  const proven = f.canary_in_payload || [];
  const allowed = f.egress.filter(e => !e.blocked);

  const tiles = [
    tile(f.reads_credentials.length, f.reads_credentials.length === 1 ? 'credential read' : 'credentials read',
      f.reads_credentials.length ? C.critical : C.clean),
    tile(attempted.length, 'more sought', attempted.length ? C.warn : C.dim),
    tile(f.bytes_out ? bytes(f.bytes_out) : '0', 'staged outbound', f.bytes_out ? C.warn : C.clean),
    tile(proven.length, proven.length === 1 ? 'canary proven' : 'canaries proven', proven.length ? C.critical : C.dim)
  ].join('');

  const blocks = [
    block('trace', 'Took', f.reads_credentials.map(r =>
      `<code>${esc(short(r.path))}</code>${r.canary ? ` <span class="tag">${esc(r.canary)}</span>` : ''}`), C.critical),

    block('attempt', 'Looked for, not on this box', attempted.map(p => `<code class="faint">${esc(short(p))}</code>`), C.warn),

    block('trace', 'Dialled', f.egress.map(e =>
      `<code>${esc(e.host)}${e.port ? ':' + e.port : ''}</code> <span style="color:${e.blocked ? C.clean : C.critical}">${e.blocked ? 'refused' : 'connected'}</span>`), C.warn),

    block('sink', 'Arrived at a collector we control', proven.slice(0, 6).map(c =>
      `<code class="hit">${esc(c)}</code>`).concat(proven.length > 6
        ? [`<span class="faint">and ${proven.length - 6} more</span>`] : []), C.critical),

    // Two ways out that never touch a socket. See docs/ISOLATION.md.
    block('stdout', 'Handed back through its own MCP response', (f.returned_to_model || []).map(c =>
      `<code class="hit">${esc(c)}</code>`), C.critical),

    block('world', 'Parked on disk for something else to collect', (f.staged_on_disk || []).map(h =>
      `<code>${esc(short(h.path))}</code> <span class="tag">${esc(h.canary)} from ${esc(short(h.from))}</span>`), C.critical),

    block('trace', 'Wrote outside its own tree', (f.writes_outside_cwd || []).map(p => `<code>${esc(short(p))}</code>`), C.warn),

    block('trace', 'Fingerprinted the machine', (f.fingerprinting || []).map(p => `<code>${esc(p)}</code>`), C.warn)
  ].join('');

  const nothing = !f.reads_credentials.length && !f.egress.length && !attempted.length
    ? `<section class="ev"><div class="evhead"><span class="badge b-trace">from trace</span>
        <h2 style="color:${C.clean}">Nothing to report</h2></div>
        <p class="quiet">No credential path opened, no host dialled, no sweep. In this run.</p></section>` : '';

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark">
<title>${esc(meta.name || 'specimen')} — Blast Radius</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700&display=swap">
<style>
*{box-sizing:border-box}
body{background:${C.ground};color:${C.ink};font-family:Inter,system-ui,sans-serif;margin:0;padding:0 20px;padding-block:0 52px;font-size:15px;-webkit-font-smoothing:antialiased}
.wrap{max-width:680px;margin:0 auto}
header{padding-block:40px 0}
.eyebrow{font-family:"JetBrains Mono",monospace;font-size:10.5px;letter-spacing:.18em;color:${C.dim};text-transform:uppercase}
h1{font-family:"JetBrains Mono",monospace;font-size:25px;font-weight:700;margin:9px 0 0;letter-spacing:-.02em;word-break:break-all}
.ver{color:${C.dim};font-size:12px;font-family:"JetBrains Mono",monospace;margin-top:5px}

.verdict{margin-top:24px;border:1px solid ${C[v.level]};border-radius:6px;background:linear-gradient(180deg,${C.raise},${C.surface});padding:20px 22px}
.lvl{display:inline-block;font-family:"JetBrains Mono",monospace;font-size:10px;font-weight:700;letter-spacing:.16em;color:${C.ground};background:${C[v.level]};padding:3px 8px;border-radius:3px}
.line{font-size:19px;line-height:1.35;margin-top:12px;letter-spacing:-.01em}

.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:${C.line};border:1px solid ${C.line};border-radius:6px;margin-top:14px;overflow:hidden}
.tile{background:${C.surface};padding:15px 14px}
.num{font-family:"JetBrains Mono",monospace;font-size:24px;font-weight:700;letter-spacing:-.03em;line-height:1}
.cap{color:${C.mute};font-size:11.5px;margin-top:7px;line-height:1.25}

.ev{margin-top:26px}
.evhead{display:flex;align-items:baseline;gap:10px}
.evhead h2{font-size:14.5px;font-weight:600;margin:0;letter-spacing:-.01em}
.badge{font-family:"JetBrains Mono",monospace;font-size:9px;letter-spacing:.12em;text-transform:uppercase;padding:3px 6px;border-radius:3px;border:1px solid ${C.line};color:${C.dim};white-space:nowrap}
.b-sink{color:${C.sink};border-color:${C.sink}55}
.b-attempt{color:${C.warn};border-color:${C.warn}55}
.b-stdout,.b-world{color:${C.critical};border-color:${C.critical}55}
ul{list-style:none;margin:10px 0 0;padding:0}
li{padding:7px 0;border-bottom:1px solid ${C.line};font-size:13.5px}
li:last-child{border-bottom:0}
code{font-family:"JetBrains Mono",monospace;font-size:12.5px;word-break:break-all}
.faint{color:${C.dim}}
.hit{color:${C.critical}}
.tag{font-family:"JetBrains Mono",monospace;font-size:10.5px;color:${C.dim};margin-left:6px}
.quiet{color:${C.mute};margin:10px 0 0;font-size:13.5px}

footer{margin-top:34px;padding-top:16px;border-top:1px solid ${C.line};color:${C.dim};font-size:12px;line-height:1.6}
@media(max-width:560px){.tiles{grid-template-columns:repeat(2,1fr)}h1{font-size:21px}.line{font-size:17px}}
</style></head><body><div class="wrap">
<header>
  <div class="eyebrow">Blast radius</div>
  <h1>${esc(meta.name || 'specimen')}</h1>
  <div class="ver">${esc(meta.version || '')}${meta.integrity ? ' · sha256 ' + esc(meta.integrity.slice(0, 16)) + '…' : ''}</div>
</header>
<div class="verdict"><span class="lvl">${v.level.toUpperCase()}</span><div class="line">${esc(v.line)}</div></div>
<div class="tiles">${tiles}</div>
${blocks}${nothing}
<footer>
One execution under Wasmer against a canary world seeded fresh for this run — every string above
was minted minutes ago and exists nowhere else. <b>From trace</b> is what the runtime reported at the
WASI boundary. <b>Proven at sink</b> required routing egress to a collector we control; payload bytes
are not in the trace.<br>
Behaviour observed in one run. Not a claim about the package in general.
</footer>
</div></body></html>`;
}
