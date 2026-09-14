/* Blast Radius Sweep — page logic. Reads the embedded JSON and renders; never edits it. */
(function () {
  'use strict';
  var DATA = JSON.parse(document.getElementById('br-data').textContent);
  var servers = DATA.servers;
  var byslug = {};
  servers.forEach(function (s) { byslug[s.slug] = s; });

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function $(sel, root) { return (root || document).querySelector(sel); }
  function plural(n, w) { return n + ' ' + w + (n === 1 ? '' : 's'); }
  function shortName(n) { var i = n.indexOf('/'); return n.charAt(0) === '@' && i > 0 ? n.slice(i + 1) : n; }
  function scopeOf(n) { var i = n.indexOf('/'); return n.charAt(0) === '@' && i > 0 ? n.slice(0, i) : ''; }

  var I = {
    critical: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1a7 7 0 1 1 0 14A7 7 0 0 1 8 1zm-.75 3.5v4.5h1.5V4.5h-1.5zm0 6v1.5h1.5v-1.5h-1.5z"/></svg>',
    warn: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M7.14 1.5a1 1 0 0 1 1.72 0l6.3 11a1 1 0 0 1-.86 1.5H1.7a1 1 0 0 1-.86-1.5l6.3-11zM7.25 5v4.5h1.5V5h-1.5zm0 6v1.5h1.5V11h-1.5z"/></svg>',
    clean: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1a7 7 0 1 1 0 14A7 7 0 0 1 8 1zm3.03 4.72-3.9 3.9-1.66-1.66-1.06 1.06 2.72 2.72 4.96-4.96-1.06-1.06z"/></svg>',
    noboot: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1a7 7 0 1 1 0 14A7 7 0 0 1 8 1zM4.5 7.25v1.5h7v-1.5h-7z"/></svg>',
    control: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M6 1h4v1.5h-.5v3.6l3.9 6.8A1.5 1.5 0 0 1 12.1 15H3.9a1.5 1.5 0 0 1-1.3-2.1l3.9-6.8V2.5H6V1zm1.5 1.5v4l-2.2 3.8h5.4L8.5 6.5v-4h-1z"/></svg>',
    overview: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M2 2h5v5H2V2zm7 0h5v5H9V2zM2 9h5v5H2V9zm7 0h5v5H9V9z"/></svg>',
    search: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M6.5 1a5.5 5.5 0 0 1 4.38 8.83l3.65 3.64-1.06 1.06-3.64-3.65A5.5 5.5 0 1 1 6.5 1zm0 1.5a4 4 0 1 0 0 8 4 4 0 0 0 0-8z"/></svg>',
    back: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M10.5 2 4.5 8l6 6 1.06-1.06L6.62 8l4.94-4.94L10.5 2z"/></svg>',
    sort: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2l3 4H5l3-4zm0 12l-3-4h6l-3 4z"/></svg>',
    x: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3.5 2.5 8 7l4.5-4.5 1 1L9 8l4.5 4.5-1 1L8 9l-4.5 4.5-1-1L7 8 2.5 3.5l1-1z"/></svg>',
    check: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M13.4 3.6 6.5 10.5 3.6 7.6 2.5 8.7l4 4 8-8-1.1-1.1z"/></svg>',
    flask: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M6 1h4v1.5h-.5v3.6l3.9 6.8A1.5 1.5 0 0 1 12.1 15H3.9a1.5 1.5 0 0 1-1.3-2.1l3.9-6.8V2.5H6V1z"/></svg>',
    flag: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 1.5h1.5v13H3v-13zm2.5 0h7.5l-2.2 3.25 2.2 3.25H5.5v-6.5z"/></svg>'
  };
  var LV = { critical: 'Critical', undeclared: 'Undeclared', expected: 'Expected', warn: 'Warning', clean: 'Clean', noboot: 'Did not run' };
  var WHY = {
    critical: 'a planted secret provably left, or was opened unprompted right before a connection attempt',
    undeclared: 'it did something nobody asked for and nothing announced',
    expected: 'it only did what its job or our request implied',
    noboot: 'it never finished starting up, so there is nothing to judge'
  };
  // the card data keeps its own wording; this is how each known line reads to a non-specialist
  var PLAIN = {
    'Exfiltrated a seeded credential. Proven at the sink.': 'Sent a planted secret out of the sandbox. Proven: it arrived at our collector.',
    'Read a seeded credential, then attempted egress.': 'Opened a planted secret, then tried to reach a server.',
    'Read a seeded credential.': 'Opened a planted secret.',
    'Attempted egress.': 'Tried to reach a server outside the sandbox.',
    'No credential access and no egress observed.': 'Did not open any secret or try to reach any server.'
  };
  function plainLine(t) { return PLAIN[t] || t; }
  var SEV = { critical: 0, undeclared: 1, warn: 1, expected: 2, clean: 2, noboot: 3 };
  var CRED = [/\.ssh\//, /\.env$/, /\.aws\//, /credentials/i, /id_[a-z0-9]+$/, /\.npmrc$/, /\.netrc$/];

  var state = { sel: 'overview', q: '', sortKey: 'sev', sortDir: 1, run: null };
  var POLICY = {
    scan: 'Block all: every connection refused. The card shows what it tried.',
    vendor: 'Vendor only: allowed to reach the hosts its block-all run showed to be its own vendor, everything else refused. Real traffic, fake keys.',
    sink: 'Collector allowed: it may reach our collector and nothing else, so what it sends can be read.'
  };
  function runOf(s) { var r = (s.runs || []).filter(function (r) { return r.mode === state.run; })[0]; return r || (s.runs || [])[0] || null; }
  // one row per host, whatever ports or addresses it used
  function hostsOf(f) {
    var m = {}, order = [];
    (f.egress || []).forEach(function (e) {
      var c = m[e.host]; if (!c) { c = m[e.host] = { host: e.host, blocked: true, expected: e.expected, why: e.why, at: e.at, ports: [], ips: [] }; order.push(c); }
      if (!e.blocked) c.blocked = false;
      if (e.port && c.ports.indexOf(e.port) < 0 && e.port !== 65535 && e.port !== 0) c.ports.push(e.port);
      (e.ips || []).forEach(function (ip) { if (c.ips.indexOf(ip) < 0) c.ips.push(ip); });
    });
    return order;
  }

  /* ---------- event classification (rendering only) ---------- */
  function classify(e) {
    var a = e.args || {};
    var deny = e.decision === 'deny';
    if (e.call === 'environ_get') return { lane: 'env', key: 'environment', deny: deny };
    if (e.call === 'path_open2' || e.call === 'path_open') {
      var p = a.path || '';
      var cred = e.canary_hit || CRED.some(function (re) { return re.test(p); });
      return { lane: cred ? 'cred' : 'file', key: p, deny: deny, errno: e.errno };
    }
    if (e.call === 'path_rename') return { lane: 'write', key: a.new_path || '', from: a.old_path || '', deny: deny };
    if (e.call === 'path_unlink_file') return { lane: 'write', key: a.path || '', unlink: true, deny: deny };
    if (e.call === 'resolve') return { lane: 'dns', key: a.host || '', deny: deny };
    if (e.call === 'sock_connect') return { lane: 'connect', key: a.addr || '', deny: deny };
    if (e.call === 'sock_send' || e.call === 'sock_send_to' || (e.call === 'fd_write' && a.socket)) return { lane: 'send', key: a.addr || 'socket', bytes: Number(a.nsent || a.nwritten || a.bytes_written || 0), deny: deny };
    if (e.call === 'sock_open') return null;
    if (e.call === 'proc_exec' || e.call === 'proc_spawn') return { lane: 'write', key: a.path || a.name || 'process', spawn: true, deny: deny };
    return null;
  }
  function phrase(e, c) {
    var isCred = c.lane === 'cred';
    switch (c.lane) {
      case 'env': return { t: 'read its environment variables', cls: 'x' };
      case 'file': case 'cred':
        if (c.errno && c.errno !== 'success') return { t: 'tried to open <code>' + esc(c.key) + '</code> (' + esc(c.errno) + ')', cls: 'x' };
        return { t: (isCred ? 'opened secret file ' : 'opened ') + '<code>' + esc(c.key) + '</code>', cls: isCred ? 'cred' : '' };
      case 'write':
        if (c.spawn) return { t: 'started a process <code>' + esc(c.key) + '</code>', cls: 'cred' };
        if (c.unlink) return { t: 'deleted <code>' + esc(c.key) + '</code>', cls: 'cred' };
        return { t: 'replaced <code>' + esc(c.key) + '</code> (wrote <code>' + esc(c.from) + '</code>, then renamed it into place)', cls: 'cred' };
      case 'dns': return c.deny ? { t: 'looked up <code>' + esc(c.key) + '</code> <b>blocked</b>', cls: 'deny' } : { t: 'looked up <code>' + esc(c.key) + '</code>', cls: 'allowed' };
      case 'connect': return c.deny ? { t: 'tried to connect to <code>' + esc(c.key) + '</code> <b>blocked</b>', cls: 'deny' } : { t: 'connected to <code>' + esc(c.key) + '</code>', cls: 'allowed' };
      case 'send': return { t: 'sent ' + c.bytes + ' bytes over the connection', cls: 'send' };
    }
    return { t: e.call, cls: 'x' };
  }

  /* ---------- timeline ---------- */
  var LANES = [['env', 'Env variables'], ['file', 'Files'], ['cred', 'Secret files'], ['write', 'File changes'], ['dns', 'Lookups (DNS)'], ['connect', 'Connections'], ['send', 'Data sent']];
  function niceStep(maxT) {
    var steps = [0.05, 0.1, 0.2, 0.25, 0.5, 1, 2, 5, 10, 20];
    for (var i = 0; i < steps.length; i++) if (maxT / steps[i] <= 6) return steps[i];
    return 50;
  }
  function timeline(events) {
    var W = 760, left = 104, right = 22, top = 8, laneH = 26, bottom = 30;
    var H = top + LANES.length * laneH + bottom;
    var maxT = Math.max(0.5, Math.max.apply(null, events.map(function (e) { return e.ts; }).concat([0]))) * 1.05;
    var x = function (t) { return left + (t / maxT) * (W - left - right); };
    // a burst of activity in one lane becomes one mark: a dot, or a bar when it spans time
    var byLane = {};
    events.forEach(function (e) {
      var c = classify(e); if (!c) return;
      var list = byLane[c.lane] || (byLane[c.lane] = []);
      var last = list[list.length - 1];
      if (last && x(e.ts) - x(last.tEnd) < 9) {
        last.n++; last.tEnd = e.ts; last.bytes += c.bytes || 0;
        var k = last.keys[c.key] || (last.keys[c.key] = { n: 0, deny: 0 }); k.n++; if (c.deny) k.deny++;
        if (!c.deny) last.allDeny = false;
        return;
      }
      var keys = {}; keys[c.key] = { n: 1, deny: c.deny ? 1 : 0 };
      list.push({ ts: e.ts, tEnd: e.ts, n: 1, bytes: c.bytes || 0, keys: keys, allDeny: !!c.deny, errno: c.errno, from: c.from });
    });
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Timeline of what the server did in this run">';
    var step = niceStep(maxT);
    for (var t = 0; t <= maxT; t += step) {
      var xx = x(t);
      s += '<line class="gridline" x1="' + xx.toFixed(1) + '" y1="' + top + '" x2="' + xx.toFixed(1) + '" y2="' + (top + LANES.length * laneH) + '"/>';
      s += '<text class="tick" x="' + xx.toFixed(1) + '" y="' + (top + LANES.length * laneH + 16) + '" text-anchor="middle">' + (Math.round(t * 100) / 100) + 's</text>';
    }
    LANES.forEach(function (ln, i) {
      var y = top + i * laneH + laneH / 2;
      var marks = byLane[ln[0]] || [];
      s += '<text class="' + (marks.length ? 'lane-label' : 'lane-none') + '" x="' + (left - 10) + '" y="' + (y + 3.5) + '" text-anchor="end">' + esc(ln[1]) + '</text>';
      s += '<line class="lane-line" x1="' + left + '" y1="' + y + '" x2="' + (W - right) + '" y2="' + y + '"/>';
      marks.forEach(function (m) {
        var x0 = x(m.ts), x1 = x(m.tEnd), span = x1 - x0 > 2;
        var cls = 'm ' + ln[0] + (m.allDeny ? ' deny' : '');
        if (span) s += '<rect class="' + cls + '" x="' + (x0 - 5).toFixed(1) + '" y="' + (y - 5) + '" width="' + (x1 - x0 + 10).toFixed(1) + '" height="10" rx="5"/>';
        else s += '<circle class="' + cls + '" cx="' + x0.toFixed(1) + '" cy="' + y + '" r="5"/>';
        if (m.allDeny) { var cx = span ? (x0 + x1) / 2 : x0; s += '<line class="slash ' + ln[0] + '" x1="' + (cx - 4.2).toFixed(1) + '" y1="' + (y + 4.2) + '" x2="' + (cx + 4.2).toFixed(1) + '" y2="' + (y - 4.2) + '"/>'; }
        if (m.n > 1) s += '<text class="badge" x="' + (x1 + 7).toFixed(1) + '" y="' + (y - 6) + '">×' + m.n + '</text>';
        var keys = Object.keys(m.keys).map(function (k) { return { k: k, n: m.keys[k].n, deny: m.keys[k].deny }; });
        var tip = { lane: ln[1], t: m.ts, tEnd: m.tEnd, n: m.n, deny: m.allDeny, bytes: m.bytes, errno: m.errno, from: m.from, keys: keys };
        var title = ln[1] + ': ' + keys.map(function (k) { return k.k + (k.n > 1 ? ' ×' + k.n : '') + (k.deny ? ' (blocked)' : ''); }).join(', ');
        if (span) s += '<rect class="hit" x="' + (x0 - 11).toFixed(1) + '" y="' + (y - 11) + '" width="' + (x1 - x0 + 22).toFixed(1) + '" height="22" tabindex="0" data-tip="' + esc(JSON.stringify(tip)) + '"><title>' + esc(title) + '</title></rect>';
        else s += '<circle class="hit" cx="' + x0.toFixed(1) + '" cy="' + y + '" r="11" tabindex="0" data-tip="' + esc(JSON.stringify(tip)) + '"><title>' + esc(title) + '</title></circle>';
      });
    });
    s += '</svg>';
    return s;
  }
  function legend() {
    return '<div class="legend">' +
      '<span class="c-cred"><i class="f"></i>secret file opened</span>' +
      '<span class="c-file"><i class="f"></i>ordinary file or env variable read</span>' +
      '<span class="c-write"><i class="f"></i>file changed or deleted</span>' +
      '<span class="c-net"><i class="f"></i>network: look up, connect, send</span>' +
      '<span class="c-net"><i></i>hollow with a slash: blocked by the sandbox</span>' +
      '</div>';
  }
  function logList(events) {
    var rows = [], last = null;
    events.forEach(function (e) {
      var c = classify(e); if (!c) return;
      var p = phrase(e, c);
      if (last && last.t === p.t) { last.n++; return; }
      last = { ts: e.ts, t: p.t, cls: p.cls, n: 1 }; rows.push(last);
    });
    if (!rows.length) return '<div class="log"><div><span class="ts"></span><span class="x">nothing beyond the runtime starting up</span></div></div>';
    return '<div class="log">' + rows.map(function (r) {
      return '<div><span class="ts">' + r.ts.toFixed(2) + 's</span><span class="' + r.cls + '">' + r.t + (r.n > 1 ? ' <span class="x">×' + r.n + '</span>' : '') + '</span></div>';
    }).join('') + '</div>';
  }

  /* ---------- pieces ---------- */
  function verdictIcon(level) { return { critical: I.critical, undeclared: I.flag, warn: I.warn, expected: I.clean, clean: I.clean, noboot: I.noboot }[level] || I.noboot; }
  function hostTag(e) {
    if (e.expected === undefined) return '';
    return e.expected ? '<span class="pill vendor">' + esc(e.why || 'expected') + '</span>' : '<span class="pill undeclared">' + I.flag + 'undeclared</span>';
  }
  function pillHost(e) {
    return '<span class="pill ' + (e.blocked ? 'blocked' : 'allowed') + '">' + (e.blocked ? I.x : I.check) + (e.blocked ? 'blocked' : 'went through') + '</span>';
  }
  function whyLine(s) {
    if (s.level === 'noboot') return s.bootReason || 'It never finished starting up.';
    var f = s.findings, parts = [];
    if (f.policy) {
      if (f.canary_in_payload.length) return 'The planted secret arrived at our collector, so the leak is proven rather than guessed.';
      if (s.level === 'critical') return 'It opened a secret no tool argument pointed at, then tried to connect right after. Together that is the shape of a leak, even though the connection was blocked.';
      var hs = hostsOf(f), vendor = hs.filter(function (e) { return e.expected; }), other = hs.filter(function (e) { return e.expected === false; });
      if (other.length) parts.push('reached out to ' + other.map(function (e) { return e.host; }).join(' and ') + ', which neither its name nor our arguments explain');
      if (f.unprompted_reads && f.unprompted_reads.length) parts.push('opened ' + f.unprompted_reads.join(' and ') + ' with no tool argument pointing at it');
      if (f.unprompted_writes && f.unprompted_writes.length) parts.push('changed ' + f.unprompted_writes.join(' and ') + ' unprompted');
      if (parts.length) { var t0 = parts.join('; '); return t0.charAt(0).toUpperCase() + t0.slice(1) + '. Everything else it did was expected.'; }
      var ok = [];
      if (vendor.length) ok.push('every host it reached (' + vendor.map(function (e) { return e.host; }).join(', ') + ') is its own vendor or one we passed in');
      if (f.reads_credentials.length) ok.push('the secret file it opened was one our probe asked for');
      if (!ok.length) return 'Did not open any secret or try to reach any server in this run. It could still do either in a situation we did not trigger.';
      var t1 = ok.join(', and '); return t1.charAt(0).toUpperCase() + t1.slice(1) + '.';
    }
    if (f.canary_in_payload.length) parts.push('the planted secret arrived at our collector, so the leak is proven rather than guessed');
    if (f.reads_credentials.length) parts.push('opened ' + plural(f.reads_credentials.length, 'secret file'));
    if (f.egress.length) { var b = f.egress.filter(function (e) { return e.blocked; }).length; parts.push('tried to reach ' + plural(f.egress.length, 'server') + ' (' + b + ' blocked' + (f.egress.length - b ? ', ' + (f.egress.length - b) + ' went through' : '') + ')'); }
    if (f.writes_outside_cwd.length) parts.push('changed files outside its own folder');
    if (f.correlated && s.level === 'critical' && !f.canary_in_payload.length) parts.push('it opened the secret first and tried to connect right after');
    if (!parts.length) return 'Did not open any secret or try to reach any server in this run. It could still do either in a situation we did not trigger.';
    var t = parts.join('; ');
    return t.charAt(0).toUpperCase() + t.slice(1) + '.';
  }

  /* ---------- sidebar ---------- */
  function matches(s, q) {
    if (!q) return true;
    var hay = [s.name, s.version, s.note, s.line].concat(s.tools).concat(s.findings ? s.findings.egress.map(function (e) { return e.host; }) : []).join(' ').toLowerCase();
    return hay.indexOf(q) >= 0;
  }
  function renderSidebar() {
    var q = state.q.trim().toLowerCase();
    var groups = [['critical', 'Critical'], ['undeclared', 'Undeclared'], ['warn', 'Warning'], ['expected', 'Expected'], ['clean', 'Clean'], ['noboot', 'Did not run']];
    var nNpm = servers.filter(function (s) { return !s.control; }).length;
    var nOurs = servers.filter(function (s) { return s.control; }).length;
    var h = '<div class="brand"><span class="mark">' + I.critical + '</span><div><b>Blast Radius</b><span>' + nNpm + ' servers from npm · ' + nOurs + ' of our own</span></div></div>';
    h += '<label class="search">' + I.search + '<input id="q" type="search" placeholder="Search servers, hosts, tools" value="' + esc(state.q) + '" aria-label="Search"></label>';
    h += '<div class="group"><button class="row" data-sel="overview" aria-current="' + (state.sel === 'overview') + '"><span class="sym overview">' + I.overview + '</span><span class="t"><span class="name">Overview</span><span class="sub">every server in one table</span></span></button></div>';
    groups.forEach(function (g) {
      var list = servers.filter(function (s) { return s.level === g[0] && matches(s, q); });
      if (!list.length) return;
      h += '<div class="group"><h3>' + g[1] + '</h3>';
      list.forEach(function (s) {
        h += '<button class="row" data-sel="' + esc(s.slug) + '" aria-current="' + (state.sel === s.slug) + '">' +
          '<span class="sym ' + (s.control ? 'control' : s.level) + '">' + (s.control ? I.flask : verdictIcon(s.level)) + '</span>' +
          '<span class="t"><span class="name">' + esc(shortName(s.name)) + '</span><span class="sub">' + esc(scopeOf(s.name) ? scopeOf(s.name) + ' · ' : '') + esc(s.version) + (s.control ? ' · ours, deliberately malicious' : '') + '</span></span>' +
          (s.tools.length ? '<span class="count num" title="tools exposed">' + s.tools.length + '</span>' : '') + '</button>';
      });
      h += '</div>';
    });
    if (q && !servers.some(function (s) { return matches(s, q); })) h += '<div class="empty">Nothing matches “' + esc(state.q) + '”.</div>';
    $('#sidebar').innerHTML = h;
  }

  /* ---------- overview ---------- */
  function sortServers(list) {
    var k = state.sortKey, d = state.sortDir;
    var val = function (s) {
      var f = s.findings;
      switch (k) {
        case 'name': return s.name.toLowerCase();
        case 'sev': return SEV[s.level] * 1000 + (s.control ? -1 : 0);
        case 'tools': return s.tools.length;
        case 'reads': return f ? f.reads_credentials.length : -1;
        case 'egress': return f ? f.egress.length : -1;
        case 'writes': return f ? f.writes_outside_cwd.length : -1;
        case 'bytes': return f ? f.bytes_out : -1;
        case 'proven': return f ? f.canary_in_payload.length : -1;
        case 'vendor': { var v = (s.runs || []).filter(function (r) { return r.mode === 'vendor'; })[0]; return v ? SEV[v.level] : 9; }
        case 'boot': return s.bootMs == null ? 1e9 : s.bootMs;
      }
      return 0;
    };
    return list.slice().sort(function (a, b) { var va = val(a), vb = val(b); if (va < vb) return -d; if (va > vb) return d; return a.name < b.name ? -1 : 1; });
  }
  function th(key, label, right) {
    var sort = state.sortKey === key ? (state.sortDir === 1 ? 'ascending' : 'descending') : 'none';
    return '<th' + (right ? ' class="r"' : '') + ' aria-sort="' + sort + '"><button data-sort="' + key + '">' + esc(label) + I.sort + '</button></th>';
  }
  function renderOverview() {
    var npm = servers.filter(function (s) { return !s.control; });
    var booted = npm.filter(function (s) { return s.booted; }).length;
    var n = function (lv) { return servers.filter(function (s) { return s.level === lv; }).length; };
    var ran = DATA.ran ? new Date(DATA.ran) : null;
    var when = ran ? ran.toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: 'numeric' }) : '';
    // The first screen answers one question: of the servers that ran, how many
    // did something nobody asked for? Everything else is a row away.
    // Counts are npm servers only — ours are controls, and counting them here
    // would inflate the finding with servers we wrote to be caught.
    var nn = function (lv) { return npm.filter(function (s) { return s.level === lv; }).length; };
    var nOdd = nn('critical') + nn('undeclared') + nn('warn');
    var ours = servers.filter(function (s) { return s.control; });
    var h = '<div class="hdr"><h1>' + nOdd + ' of ' + booted + ' servers did something nobody asked for</h1>' +
      '<div class="meta"><span>We gave each one a fake home folder full of secrets and asked it to use every tool it offers. This is what it did. Nothing could reach the internet.</span></div></div>';
    h += '<div class="tiles">' +
      '<div class="tile critical"><span class="n">' + nn('critical') + '</span><span class="l">critical<small>a planted secret left, or went to the model</small></span></div>' +
      '<div class="tile undeclared"><span class="n">' + (nn('undeclared') + nn('warn')) + '</span><span class="l">undeclared<small>a host, a file, or a change nobody asked for</small></span></div>' +
      '<div class="tile expected"><span class="n">' + (nn('expected') + nn('clean')) + '</span><span class="l">expected<small>only did what its job implied</small></span></div>' +
      '</div>';
    if (ours.length) {
      h += '<p class="ours">Plus ' + plural(ours.length, 'server') + ' we wrote ourselves, to check the instrument catches both routes out: ' +
        ours.map(function (s) { return '<button data-sel="' + esc(s.slug) + '">' + esc(shortName(s.name)) + '</button>'; }).join(' and ') +
        '. One sends the secret over the network. The other never opens a socket.</p>';
    }
    h += '<section class="sec"><div class="sec-h"><h2>All servers</h2><span class="tier">' + npm.length + ' from npm, ' + booted + ' started · ' + esc(when) + ' · ' + esc(DATA.mode) + ' · click a row for the full run</div><div class="box tablewrap"><table><thead><tr>' +
      th('name', 'Server') + th('sev', 'Block all') + th('vendor', 'Vendor only') + th('tools', 'Tools', true) + th('reads', 'Secrets', true) + th('egress', 'Reached out to') + th('proven', 'Proven leak') + th('boot', 'Startup', true) +
      '</tr></thead><tbody>';
    sortServers(servers).forEach(function (s) {
      var f = s.findings;
      h += '<tr tabindex="0" data-sel="' + esc(s.slug) + '">' +
        '<td><div class="name">' + esc(s.name) + (s.control ? ' <span class="pill count">control</span>' : '') + '</div><div class="ver">' + esc(s.version) + (s.note ? ' · ' + esc(s.note.split(/[;,]/)[0]) : '') + '</div></td>' +
        '<td><span class="vd ' + s.level + '">' + verdictIcon(s.level) + LV[s.level] + '</span></td>' +
        '<td>' + (function () { var v = (s.runs || []).filter(function (r) { return r.mode === 'vendor'; })[0]; return v ? '<span class="vd ' + v.level + '">' + verdictIcon(v.level) + LV[v.level] + '</span>' : '<span class="none">' + (s.control ? 'collector run' : f ? 'nothing to allow' : '–') + '</span>'; })() + '</td>' +
        '<td class="r">' + (s.tools.length || '<span class="none">–</span>') + '</td>' +
        '<td class="r">' + (f ? (f.reads_credentials.length || '<span class="none">0</span>') : '<span class="none">–</span>') + '</td>' +
        '<td>' + (f ? (f.egress.length ? '<div class="dots">' + hostsOf(f).map(function (e) { return '<span class="dot ' + (e.blocked ? 'blocked' : 'allowed') + '"><i></i>' + esc(e.host) + (e.ports.length === 1 ? ':' + e.ports[0] : '') + (e.expected === false ? '<em>undeclared</em>' : '') + '</span>'; }).join('') + '</div>' : '<span class="none">none</span>') : '<span class="none">–</span>') + '</td>' +

        '<td>' + (f ? (f.canary_in_payload.length ? '<span class="pill sink">' + I.check + 'yes, proven</span>' : '<span class="none">not observed</span>') : '<span class="none">–</span>') + '</td>' +
        '<td class="r">' + (s.bootMs != null ? (s.booted ? (s.bootMs / 1000).toFixed(1) + 's' : '<span class="vd noboot">' + I.noboot + 'no</span>') : (s.control ? '<span class="none">–</span>' : '<span class="none">–</span>')) + '</td>' +
        '</tr>';
    });
    h += '</tbody></table></div><p class="foot">Sorted by severity. <b>Expected</b>: it only did what its job or our request implied. <b>Undeclared</b>: it reached a host outside its vendor, or opened or changed something nobody asked for. <b>Critical</b>: a planted secret provably left, or was opened unprompted right before a connection attempt. Reached out to: a green dot means the sandbox blocked it, red means it went through. File changes and bytes sent are on each server’s page.</p></section>';

    // host map
    var hosts = {};
    servers.forEach(function (s) { if (!s.findings) return; s.findings.egress.forEach(function (e) { var k = e.host + (e.port ? ':' + e.port : ''); (hosts[k] = hosts[k] || []).push({ s: s, blocked: e.blocked, expected: e.expected }); }); });
    var keys = Object.keys(hosts).sort(function (a, b) { return hosts[b].length - hosts[a].length || (a < b ? -1 : 1); });
    h += '<section class="sec"><div class="sec-h"><h2>Who they try to reach</h2><span class="tier">seen by the sandbox</span></div><div class="box hostmap">';
    keys.forEach(function (k) {
      var who = hosts[k];
      var und = who.filter(function (w) { return w.expected === false; }).length;
      h += '<div><div class="h">' + esc(k) + '<small>' + plural(who.length, 'server') + ' · ' + (who.every(function (w) { return w.blocked; }) ? 'all blocked' : who.some(function (w) { return w.blocked; }) ? 'partly blocked' : 'allowed') + (und ? ' · <span style="color:var(--orange)">undeclared</span>' : who.some(function (w) { return w.expected; }) ? ' · expected' : '') + '</small></div><div class="who">' +
        who.map(function (w) { return '<button data-sel="' + esc(w.s.slug) + '">' + esc(w.s.name) + '</button>'; }).join('') + '</div></div>';
    });
    h += '</div><p class="foot">Every third-party server tries to reach its own vendor’s API. One also tries a second host its README never mentions; open its page to see which.</p></section>';

    h += '<section class="sec"><div class="sec-h"><h2>How to read this</h2></div><div class="about">' +
      '<p><b>Seen by the sandbox.</b> Each server runs inside a WebAssembly sandbox (Wasmer). It cannot open a file or make a network connection without asking the sandbox, and the sandbox writes down every request: which file, which host, how many bytes. Those records are facts about one run.</p>' +
      '<p><b>Received by our collector.</b> The one row that can say a secret actually left. Every run plants a unique fake secret in the sandbox’s home folder. For our deliberately malicious server we let it connect to a collector we control; the fake secret showed up in what arrived, so that leak is proven. Every other server was blocked from connecting, so their row reads “not observed” by design. The sandbox never sees the contents of a message, so nothing else on these pages claims to know what a server would have sent.</p>' +
      '<p><b>Three verdicts, all descriptive.</b> <b>Expected</b> means it only did what its job or our request implied: reached its own vendor, opened a file we passed as an argument, connected to the database we gave it, or did nothing. <b>Undeclared</b> means it did something nobody asked for and nothing announced: a host outside its vendor’s domains, a secret file no argument pointed at, a change outside its own folder. <b>Critical</b> means a planted secret provably arrived at our collector, or was opened unprompted right before a connection attempt. “Its vendor” is read off the package name: api.exa.ai belongs to exa-mcp-server, api.hubspot.com to @hubspot/mcp-server.</p>' +
      '<p><b>One run, not a reputation.</b> Each tool was called once with made-up arguments. A verdict says what the server did here, not what it might do on your machine over months. Sandbox: ' + esc(DATA.engine) + '.</p>' +
      '</div></section>';
    return h;
  }

  /* ---------- detail ---------- */
  function kv(rows) {
    return '<div class="box"><div class="kv">' + rows.map(function (r) { return '<div class="k">' + r[0] + '</div><div class="v">' + r[1] + '</div>'; }).join('') + '</div></div>';
  }
  function renderDetail(s) {
    var run = runOf(s);
    var f = run ? run.findings : null;
    var view = run ? { level: run.level, findings: run.findings, bootReason: s.bootReason } : s;
    var events = run ? run.events : [];
    var h = '<button class="back" data-sel="overview">' + I.back + 'Servers</button>';
    h += '<div class="hdr"><span class="eyebrow">' + (s.control ? 'Our planted bad server, written to prove the tool catches a real leak' : 'npm package') + (s.note ? ' · ' + esc(s.note) : '') + '</span>' +
      '<h1>' + esc(s.name) + '</h1><div class="meta">' +
      '<span>version <code>' + esc(s.version) + '</code></span>' +
      (s.integrity ? '<span>file fingerprint <code title="' + esc(s.integrity) + '">' + esc(s.integrity.slice(0, 16)) + '…</code></span>' : '') +
      (s.tools.length ? '<span>' + plural(s.tools.length, 'tool') + ' offered</span>' : '') +
      (s.bootMs != null && s.booted ? '<span>started in ' + (s.bootMs / 1000).toFixed(1) + 's</span>' : '') +
      '</div></div>';
    if (run) {
      // the switch is always there, so nobody has to guess whether a second benchmark exists
      var modes = s.control ? ['sink', 'scan', 'vendor'] : ['scan', 'vendor'];
      var LABELS = { scan: 'Block all', vendor: 'Vendor only', sink: 'Collector allowed' };
      var missing = {
        scan: s.control ? 'the control runs with our collector allowed instead, so the leak can be proven' : 'not run',
        vendor: s.control ? 'the control runs with our collector allowed instead' : 'nothing to allow, its block-all run reached no vendor host',
        sink: 'only the control runs this way'
      };
      var has = function (m) { return s.runs.filter(function (x) { return x.mode === m; })[0]; };
      h += '<div class="seg" role="tablist" aria-label="Network policy">' + modes.map(function (m) {
        var r = has(m);
        return r ? '<button role="tab" aria-selected="' + (r === run) + '" data-run="' + m + '">' + esc(LABELS[m]) + '</button>'
                 : '<button role="tab" aria-selected="false" disabled title="' + esc(missing[m]) + '">' + esc(LABELS[m]) + '</button>';
      }).join('') + '</div>';
      var off = modes.filter(function (m) { return !has(m); });
      h += '<p class="policy-line">' + esc(POLICY[run.mode] || '') + (run.mode === 'vendor' && run.net ? ' Allowed: <code>' + esc(run.net.replace(/dns:allow=/g, '').replace(/:\*/g, '')) + '</code>.' : '') +
        (off.length ? ' <span class="none">' + off.map(function (m) { return LABELS[m] + ' is greyed out: ' + missing[m]; }).join('. ') + '.</span>' : '') + '</p>';
    }
    var lvl = view.level;
    h += '<div class="verdict ' + lvl + '">' + verdictIcon(lvl) + '<div><div class="lvl">' + LV[lvl] + '</div><div class="line" title="' + esc(f ? f.verdict.line : '') + '">' + esc(f ? plainLine(f.verdict.line) : 'Never finished starting up.') + '</div><div class="why">' + esc(whyLine(view)) + (WHY[lvl] ? ' <span class="none">' + esc(LV[lvl]) + ' means ' + esc(WHY[lvl]) + '.</span>' : '') + '</div></div></div>';

    if (f) {
      h += '<section class="sec"><div class="sec-h"><h2>What it did, in order</h2><span class="tier">seen by the sandbox · ' + plural(events.length, 'action') + ', runtime noise removed</span></div><div class="box"><div class="tl">' + timeline(events) + '</div>' + legend() + logList(events) + '</div>' +
        '<p class="foot">Time runs left to right. We started the server, asked for its tool list, then called every tool once with made-up arguments. Hover a dot for details; the log underneath says the same thing in words.</p></section>';

      h += '<section class="sec"><div class="sec-h"><h2>Who it tried to reach</h2><span class="tier">seen by the sandbox, except the last row</span></div>' + kv([
        ['Servers contacted', f.egress.length ? '<div class="hosts">' + hostsOf(f).map(function (e) { return '<div><code>' + esc(e.host) + (e.ports.length ? ':' + e.ports.join(',') : '') + '</code>' + pillHost(e) + hostTag(e) + (e.ips.length ? '<span class="none">' + esc(e.ips.slice(0, 2).join(', ')) + (e.ips.length > 2 ? ' +' + (e.ips.length - 2) : '') + '</span>' : '') + '<span class="none num">at ' + e.at.toFixed(2) + 's</span></div>'; }).join('') + '</div>' : '<span class="none">none</span>'],
        ['Data sent', f.bytes_out ? '<b>' + f.bytes_out + ' bytes</b> over an open connection' : '<span class="none">none, no connection was allowed</span>'],
        ['Planted secret received <span class="tier sink">by our collector</span>', f.canary_in_payload.length ? f.canary_in_payload.map(function (c) { return '<code>' + esc(c) + '</code>'; }).join(' ') + ' <span class="pill sink">' + I.check + 'arrived at our collector</span>' : '<span class="none">not observed' + (f.egress.length && f.egress.every(function (e) { return e.blocked; }) ? ' — its connections were blocked, so nothing could arrive' : '') + '</span>']
      ]) + '</section>';

      h += '<section class="sec"><div class="sec-h"><h2>Files it touched</h2><span class="tier">seen by the sandbox</span></div>' + kv([
        ['Secret files opened', f.reads_credentials.length ? f.reads_credentials.map(function (r) { return '<div><code>' + esc(r.path) + '</code>' + (r.count > 1 ? ' <span class="pill count">×' + r.count + '</span>' : '') + (r.asked === true ? ' <span class="pill asked">our probe asked for it</span>' : r.asked === false ? ' <span class="pill unprompted">' + I.flag + 'unprompted</span>' : '') + (r.canary ? ' <span class="pill sink">planted secret</span>' : '') + '</div>'; }).join('') : '<span class="none">none</span>'],
        ['Files changed outside its own folder', f.writes_outside_cwd.length ? f.writes_outside_cwd.map(function (p) { return '<div><code>' + esc(p) + '</code></div>'; }).join('') : '<span class="none">none</span>'],
        ['Probing the runtime (engine, version)', f.fingerprinting.length ? f.fingerprinting.map(function (p) { return '<div><code>' + esc(p) + '</code></div>'; }).join('') : '<span class="none">none</span>']
      ]) + '</section>';
    }

    if (s.tools.length) {
      h += '<section class="sec"><div class="sec-h"><h2>Tools it offers</h2><span class="tier">' + s.tools.length + ' · each was called once</span></div><div class="box"><div class="chips">' + s.tools.map(function (t) { return '<span class="chip">' + esc(t) + '</span>'; }).join('') + '</div></div></section>';
    }
    if (!f) {
      h += '<section class="sec"><div class="sec-h"><h2>Why there is no verdict</h2></div>' + kv([
        ['What happened', esc(s.bootReason || 'It never finished starting up.')],
        ['Time to failure', s.bootMs != null ? (s.bootMs / 1000).toFixed(1) + 's' : '<span class="none">–</span>']
      ]) + '<p class="foot">A verdict on a server that never ran would be a false claim, so there is none.</p></section>';
    }
    h += '<section class="sec"><div class="sec-h"><h2>What exactly ran</h2></div>' + kv([
      ['Package', '<code>' + esc(s.pkg) + '</code>'],
      ['Version', '<code>' + esc(s.version) + '</code>'],
      ['File fingerprint (SHA-256)', s.integrity ? '<code>' + esc(s.integrity) + '</code>' : '<span class="none">–</span>'],
      ['Start file inside the sandbox', s.entry ? '<code>' + esc(s.entry) + '</code>' : '<span class="none">–</span>'],
      ['How “expected” was decided', f && f.policy ? '<div>vendor words from its name: ' + (f.policy.vendorTokens.length ? f.policy.vendorTokens.map(function (t) { return '<code>' + esc(t) + '</code>'; }).join(' ') : '<span class="none">none</span>') + '</div><div>hosts we passed in: ' + (f.policy.argHosts.length ? f.policy.argHosts.map(function (t) { return '<code>' + esc(t) + '</code>'; }).join(' ') : '<span class="none">none</span>') + '</div><div>paths our probe handed to its tools: ' + (f.policy.probePaths.length ? f.policy.probePaths.map(function (t) { return '<code>' + esc(t) + '</code>'; }).join(' ') : '<span class="none">none</span>') + '</div>' : '<span class="none">older card, no policy recorded</span>'],
      ['Sandbox', esc(DATA.engine)],
      ['Network policy', run ? esc(run.label) + (run.net ? ' · rule <code>' + esc(run.net) + '</code>' : ' · no rule, which refuses everything') : '<span class="none">–</span>'],
      ['When', esc(DATA.ran ? new Date(DATA.ran).toLocaleString() : '')]
    ]) + '</section>';
    return h;
  }

  /* ---------- routing / render ---------- */
  function render() {
    renderSidebar();
    var s = byslug[state.sel];
    $('#content').innerHTML = s ? renderDetail(s) : renderOverview();
    document.body.classList.toggle('detail', !!s);
    document.title = (s ? s.name + ' · ' : '') + 'Blast Radius Sweep';
    if (window.claude && window.claude.hot && window.claude.hot.snapshot) window.claude.hot.snapshot(function () { return { sel: state.sel, q: state.q }; });
  }
  function select(sel, push) {
    state.sel = byslug[sel] ? sel : 'overview';
    if (push !== false) { try { history.replaceState(null, '', state.sel === 'overview' ? '#overview' : '#s/' + state.sel); } catch (e) {} }
    render();
    window.scrollTo({ top: 0, behavior: 'auto' });
  }
  function fromHash() {
    var m = /^#s\/([^/]+)(?:\/([a-z]+))?$/.exec(location.hash || '');
    if (m && m[2]) state.run = m[2];
    return m ? decodeURIComponent(m[1]) : 'overview';
  }

  document.addEventListener('click', function (ev) {
    var t = ev.target.closest('[data-sel]');
    if (t) { select(t.getAttribute('data-sel')); return; }
    var rt = ev.target.closest('[data-run]');
    if (rt) { state.run = rt.getAttribute('data-run'); render(); try { history.replaceState(null, '', '#s/' + state.sel + '/' + state.run); } catch (e) {} return; }
    var st = ev.target.closest('[data-sort]');
    if (st) { var k = st.getAttribute('data-sort'); if (state.sortKey === k) state.sortDir = -state.sortDir; else { state.sortKey = k; state.sortDir = 1; } render(); }
  });
  document.addEventListener('keydown', function (ev) {
    var tr = ev.target.closest && ev.target.closest('tr[data-sel]');
    if (tr && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); select(tr.getAttribute('data-sel')); return; }
    if (ev.target.classList && ev.target.classList.contains('row') && (ev.key === 'ArrowDown' || ev.key === 'ArrowUp')) {
      var rows = Array.prototype.slice.call(document.querySelectorAll('.sidebar .row'));
      var i = rows.indexOf(ev.target) + (ev.key === 'ArrowDown' ? 1 : -1);
      if (rows[i]) { ev.preventDefault(); rows[i].focus(); }
    }
  });
  document.addEventListener('input', function (ev) {
    if (ev.target.id === 'q') { state.q = ev.target.value; var pos = ev.target.selectionStart; renderSidebar(); var q = $('#q'); q.focus(); try { q.setSelectionRange(pos, pos); } catch (e) {} }
  });
  window.addEventListener('hashchange', function () { select(fromHash(), false); });

  // tooltip
  var tip = $('#tip');
  function showTip(el, x, y) {
    var d; try { d = JSON.parse(el.getAttribute('data-tip')); } catch (e) { return; }
    var net = d.lane === 'Lookups (DNS)' || d.lane === 'Connections';
    var when = d.tEnd !== d.t ? d.t.toFixed(2) + 's to ' + d.tEnd.toFixed(2) + 's' : 'at ' + d.t.toFixed(2) + 's';
    var lines = (d.keys || []).map(function (k) {
      return '<code>' + esc(k.k) + '</code>' + (k.n > 1 ? ' ×' + k.n : '') +
        (k.deny ? ' <b style="display:inline;color:var(--green)">blocked' + (k.deny < k.n ? ', ' + k.deny + ' of ' + k.n : '') + '</b>' : (net ? ' · went through' : ''));
    });
    tip.innerHTML = '<b>' + esc(d.lane) + (d.n > 1 ? ' · ' + d.n + ' actions' : '') + '</b>' + lines.join('<br>') +
      '<br><span class="none">' + esc(when) + (d.bytes ? ' · ' + d.bytes + ' bytes' : '') + (d.errno && d.errno !== 'success' ? ' · ' + esc(d.errno) : '') + (d.from ? ' · from <code>' + esc(d.from) + '</code>' : '') + '</span>';
    tip.style.display = 'block';
    var r = tip.getBoundingClientRect();
    var left = Math.min(x + 14, window.innerWidth - r.width - 12), top = y + 16;
    if (top + r.height > window.innerHeight - 8) top = y - r.height - 12;
    tip.style.left = Math.max(8, left) + 'px'; tip.style.top = Math.max(8, top) + 'px';
  }
  document.addEventListener('mouseover', function (ev) { var el = ev.target.closest && ev.target.closest('.hit'); if (el) showTip(el, ev.clientX, ev.clientY); });
  document.addEventListener('mousemove', function (ev) { if (tip.style.display === 'block') { var el = ev.target.closest && ev.target.closest('.hit'); if (el) showTip(el, ev.clientX, ev.clientY); } });
  document.addEventListener('mouseout', function (ev) { if (ev.target.closest && ev.target.closest('.hit')) tip.style.display = 'none'; });
  document.addEventListener('focusin', function (ev) { if (ev.target.classList && ev.target.classList.contains('hit')) { var r = ev.target.getBoundingClientRect(); showTip(ev.target, r.left + r.width / 2, r.top + r.height / 2); } });
  document.addEventListener('focusout', function (ev) { if (ev.target.classList && ev.target.classList.contains('hit')) tip.style.display = 'none'; });

  function start(saved) {
    if (saved && saved.q) state.q = saved.q;
    select((saved && saved.sel) || fromHash(), false);
  }
  if (window.claude && window.claude.hot && window.claude.hot.ready) window.claude.hot.ready(start); else start(window.claude && window.claude.hot ? window.claude.hot.data : null);
})();
