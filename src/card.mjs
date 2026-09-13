// STAGE 6 — render the verdict card. Pure: takes findings, returns HTML.
// Renders from a saved JSON file with no live run, so the video can never be
// broken by a flaky detonation.
//
// Describe capabilities, never accuse. We are naming real packages.

const C = {
  critical: '#F0736A', undeclared: '#E8B339', expected: '#6EE7A8', warn: '#E8B339', clean: '#6EE7A8',
  ground: '#0E100F', surface: '#161918', line: '#2A2E2C', ink: '#ECE7DE', mute: '#8C918C', dim: '#636965'
};

const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function row(tier, label, value, tone) {
  return `<tr><td class="tier t-${tier}">${tier === 'sink' ? 'PROVEN AT SINK' : 'FROM TRACE'}</td>
    <td class="lab">${esc(label)}</td><td class="val" style="color:${tone || C.ink}">${value}</td></tr>`;
}

export function renderCard(f, meta = {}) {
  const v = f.verdict;
  const rows = [];

  rows.push(row('trace', 'Reads credentials',
    f.reads_credentials.length
      ? f.reads_credentials.map(r => `<code>${esc(r.path)}</code>${r.count > 1 ? ` <span class="none">×${r.count}</span>` : ''}`).join('<br>')
      : '<span class="none">none</span>',
    f.reads_credentials.length ? C.critical : C.clean));

  rows.push(row('trace', 'Egress attempted',
    f.egress.length
      ? f.egress.map(e => `<code>${esc(e.host)}${e.port ? ':' + e.port : ''}</code> <span style="color:${e.blocked ? C.clean : C.critical}">${e.blocked ? 'blocked' : 'allowed'}</span>`).join('<br>')
      : '<span class="none">none</span>',
    f.egress.length ? C.warn : C.clean));

  rows.push(row('trace', 'Bytes staged outbound', f.bytes_out ? `${f.bytes_out} B` : '<span class="none">0</span>', f.bytes_out ? C.warn : C.clean));

  rows.push(row('sink', 'Canary in payload',
    f.canary_in_payload.length
      ? f.canary_in_payload.map(c => `<code>${esc(c)}</code>`).join('<br>')
      : '<span class="none">not observed</span>',
    f.canary_in_payload.length ? C.critical : C.clean));

  rows.push(row('trace', 'Writes outside its own tree',
    f.writes_outside_cwd.length ? f.writes_outside_cwd.map(p => `<code>${esc(p)}</code>`).join('<br>') : '<span class="none">none</span>',
    f.writes_outside_cwd.length ? C.warn : C.clean));

  rows.push(row('trace', 'Runtime fingerprinting',
    f.fingerprinting.length ? f.fingerprinting.map(p => `<code>${esc(p)}</code>`).join('<br>') : '<span class="none">none</span>',
    f.fingerprinting.length ? C.warn : C.clean));

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark">
<title>${esc(meta.name || 'specimen')} — Blast Radius</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700&display=swap">
<style>
*{box-sizing:border-box}
body{background:${C.ground};color:${C.ink};font-family:Inter,system-ui,sans-serif;margin:0;padding:0 20px;padding-block:0 60px;font-size:15px}
.wrap{max-width:820px;margin:0 auto}
header{padding-block:44px 22px;border-bottom:1px solid ${C.line}}
.eyebrow{font-family:"JetBrains Mono",monospace;font-size:11px;letter-spacing:.16em;color:${C.dim};text-transform:uppercase}
h1{font-family:"JetBrains Mono",monospace;font-size:28px;font-weight:700;margin:10px 0 0;letter-spacing:-.02em;word-break:break-all}
.ver{color:${C.mute};font-size:13px;font-family:"JetBrains Mono",monospace;margin-top:6px}
.verdict{margin-top:26px;border:1px solid ${C[v.level]};border-left-width:3px;border-radius:4px;background:${C.surface};padding:18px 20px}
.verdict .lvl{font-family:"JetBrains Mono",monospace;font-size:11px;font-weight:700;letter-spacing:.14em;color:${C[v.level]}}
.verdict .line{font-size:17px;margin-top:7px}
table{width:100%;border-collapse:collapse;margin-top:28px}
td{border-bottom:1px solid ${C.line};padding:13px 10px;vertical-align:top;font-size:13.5px}
.tier{font-family:"JetBrains Mono",monospace;font-size:9.5px;letter-spacing:.1em;white-space:nowrap;width:1%;padding-top:16px}
.t-trace{color:${C.dim}} .t-sink{color:#7FB2E5}
.lab{color:${C.mute};white-space:nowrap;width:1%;padding-right:26px}
.val code{font-family:"JetBrains Mono",monospace;font-size:12.5px;word-break:break-all}
.none{color:${C.dim}}
footer{margin-top:34px;color:${C.dim};font-size:12.5px;line-height:1.65}
@media(max-width:560px){.tier{display:none}.lab{white-space:normal}}
</style></head><body><div class="wrap">
<header>
  <div class="eyebrow">Blast radius</div>
  <h1>${esc(meta.name || 'specimen')}</h1>
  <div class="ver">${esc(meta.version || '')}${meta.integrity ? ' · ' + esc(meta.integrity.slice(0, 24)) + '…' : ''}</div>
</header>
<div class="verdict"><div class="lvl">${v.level.toUpperCase()}</div><div class="line">${esc(v.line)}</div></div>
<table>${rows.join('')}</table>
<footer>
Observed in one execution under Wasmer against a canary world. Rows marked FROM TRACE are what the
runtime reported at the WASI boundary. The row marked PROVEN AT SINK required routing egress to a
collector we control; payload bytes are not present in the trace.<br>
This describes behaviour observed in a single run. It is not a claim about the package in general.
</footer>
</div></body></html>`;
}
