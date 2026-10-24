// Copyright 2026 Dunkel Cloud GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The approval page: shows a pending request as ToolMesh describes it, in
// plain language first and the technical details folded away, lets the
// approver narrow it, fetches the statement ToolMesh writes for those
// choices, signs it in the page (or takes a signature from a wallet) and
// sends the signature. Everything shown is set as text, never as markup.
// The texts come from i18n.js, one catalog per language; the statement stays
// English and gets a reading aid that is not part of what is signed.
(function () {
  'use strict';

  const B = window.ToolMeshBIP322;
  const CATALOGS = window.ToolMeshI18n || {};
  const $ = (id) => document.getElementById(id);
  const main = $('main');
  const requestID = main.dataset.request;
  const base = location.pathname.replace(/\/+$/, '');
  const NS = 'http://www.w3.org/2000/svg';
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const LANG_KEY = 'toolmesh-approve-lang';

  // RANK orders the effects as ToolMesh does, the most far-reaching first.
  // LEVEL is the plain-language risk of the most far-reaching effect granted.
  const RANK = { all: 0, dangerous: 1, admin: 2, other: 3, unclassified: 3, write: 4, read: 5 };
  const LEVEL = { all: 'high', dangerous: 'high', admin: 'elevated', other: 'elevated', unclassified: 'elevated', write: 'medium', read: 'low' };
  // Tools are drawn one cell each up to these counts.
  const MAX_CELLS = 200;
  const MAX_ENTRY_CELLS = 24;

  let lang = pickLang();
  let view = '';
  let infoKind = '';
  let request = null;
  let on = [];   // per entry: still granted
  let safe = []; // per entry: kept by "without dangerous actions"
  let customPicked = false;
  let ttl = '';          // the duration chosen; '' while the one typed is not valid
  let ttlOwn = false;    // the approver types the duration
  let statement = null; // { text, body, ttl } for the choices it was written for
  let result = null;    // the answer to the signed approval
  let showGloss = true;
  let holding = false;
  let holdStart = 0;
  let raf = 0;
  const matrixCells = [];
  const barSegs = {};

  // ---------- language ----------

  // pickLang takes ?lang=, then the language chosen here before, then the
  // browser's languages, then English.
  function pickLang() {
    const wanted = [];
    try {
      const q = new URLSearchParams(location.search).get('lang');
      if (q) wanted.push(q);
    } catch (e) {
      // no query
    }
    try {
      const s = localStorage.getItem(LANG_KEY);
      if (s) wanted.push(s);
    } catch (e) {
      // storage may be blocked
    }
    (navigator.languages || [navigator.language || '']).forEach((l) => wanted.push(l));
    for (const w of wanted) {
      const code = String(w).toLowerCase().split('-')[0];
      if (CATALOGS[code]) return code;
    }
    return 'en';
  }

  function t(key) {
    const own = CATALOGS[lang] && CATALOGS[lang][key];
    if (own !== undefined) return own;
    const en = CATALOGS.en && CATALOGS.en[key];
    return en !== undefined ? en : key;
  }

  const nf = (n) => new Intl.NumberFormat(lang).format(n);

  function pick(key, n) {
    const v = t(key);
    if (typeof v === 'string') return v;
    return v[new Intl.PluralRules(lang).select(n)] || v.other;
  }

  const plural = (key, n) => pick(key, n).replace('{n}', nf(n));
  const sub = (s, vals) => String(s).replace(/\{(\w+)\}/g, (m, k) => (vals[k] !== undefined ? String(vals[k]) : m));

  // minutesOf reads a duration as ToolMesh writes it ("4h", "90m", "1h30m0s").
  function minutesOf(d) {
    const re = /(\d+(?:\.\d+)?)([hms])/g;
    let m;
    let total = 0;
    let seen = 0;
    while ((m = re.exec(d))) {
      total += Number(m[1]) * { h: 60, m: 1, s: 1 / 60 }[m[2]];
      seen += m[0].length;
    }
    return seen > 0 && seen === String(d).length ? total : null;
  }

  function dur(d, display) {
    const min = minutesOf(d);
    if (min === null || !Number.isInteger(min)) return d;
    const hours = min % 60 === 0;
    return new Intl.NumberFormat(lang, { style: 'unit', unit: hours ? 'hour' : 'minute', unitDisplay: display || 'long' })
      .format(hours ? min / 60 : min);
  }

  // unitName is the name of a unit of time as the page's language counts two.
  function unitName(unit) {
    return new Intl.NumberFormat(lang, { style: 'unit', unit, unitDisplay: 'long' }).formatToParts(2)
      .filter((p) => p.type === 'unit').map((p) => p.value).join('').trim();
  }

  function clock(sec) {
    sec = Math.max(0, Math.floor(sec));
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    const p = (x) => String(x).padStart(2, '0');
    return h ? h + ':' + p(m) + ':' + p(s) : m + ':' + p(s);
  }

  const dt = (ms, opts) => new Intl.DateTimeFormat(lang, opts).format(new Date(ms));
  const utc = (ms) => new Date(ms).toISOString().slice(0, 19) + 'Z';
  const rel = (ms) => new Intl.RelativeTimeFormat(lang, { numeric: 'auto' }).format(Math.round((ms - Date.now()) / 60000), 'minute');
  const short = (a) => (a.length > 16 ? a.slice(0, 8) + '…' + a.slice(-4) : a);

  function initials(name) {
    const parts = String(name).split('@')[0].split(/[.\-_ ]+/).filter(Boolean);
    return parts.slice(0, 2).map((p) => Array.from(p)[0].toUpperCase()).join('') || '?';
  }

  // fill sets a text with {placeholders}; the values become text nodes, or
  // spans of the class wrap names for them. Never markup.
  function fill(node, s, vals, wrap) {
    node.replaceChildren();
    String(s).split(/(\{\w+\})/).forEach((part) => {
      const m = part.match(/^\{(\w+)\}$/);
      if (!m || vals[m[1]] === undefined) {
        if (part) node.append(part);
        return;
      }
      const v = String(vals[m[1]]);
      if (wrap && wrap[m[1]]) node.append(el('span', wrap[m[1]], v));
      else node.append(v);
    });
  }

  // setUser sets a user id so that it wraps before its @, not inside a word.
  function setUser(node, user) {
    const at = user.indexOf('@');
    node.replaceChildren();
    if (at <= 0) {
      node.textContent = user;
      return;
    }
    node.append(user.slice(0, at), document.createElement('wbr'), user.slice(at));
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function svgEl(tag, attrs) {
    const e = document.createElementNS(NS, tag);
    Object.keys(attrs || {}).forEach((k) => e.setAttribute(k, attrs[k]));
    return e;
  }

  function icon(name, cls) {
    const s = svgEl('svg', { class: 'i ' + (cls === undefined ? 'sm' : cls), 'aria-hidden': 'true' });
    s.append(svgEl('use', { href: '#i-' + name }));
    return s;
  }

  function buildLangSelect() {
    const sel = $('lang');
    const codes = Object.keys(CATALOGS).sort((a, b) => (a === 'en' ? -1 : b === 'en' ? 1 : a.localeCompare(b)));
    codes.forEach((code) => {
      const o = el('option', '', CATALOGS[code].language || code);
      o.value = code;
      o.lang = code;
      sel.append(o);
    });
    sel.closest('.lang').hidden = codes.length < 2;
    sel.value = lang;
    sel.addEventListener('change', () => {
      lang = sel.value;
      try {
        localStorage.setItem(LANG_KEY, lang);
      } catch (e) {
        // storage may be blocked
      }
      rerender();
    });
  }

  // applyStatic sets the texts the page names with data-t. Without a
  // catalog the English the page ships with stays.
  function applyStatic() {
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-t]').forEach((n) => {
      const v = t(n.dataset.t);
      if (typeof v === 'string' && v !== n.dataset.t) n.textContent = v;
    });
    fill($('setup-text'), t('setupText'), { file: 'config/authz.yaml' }, { file: 'mono' });
    fill($('setup-hint'), t('setupHint'), { file: 'config/authz.yaml' }, { file: 'mono' });
    $('lang').value = lang;
  }

  function rerender() {
    applyStatic();
    if (view === 'info') showInfo(infoKind);
    if (request) renderReview();
    if (view === 'sign') renderSign();
    if (view === 'done') renderDone(false);
    renderSteps();
    tick();
  }

  // ---------- talking to ToolMesh ----------

  async function call(path, body) {
    const init = body === undefined
      ? { headers: { Accept: 'application/json' } }
      : { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) };
    const res = await fetch(base + path, init);
    let data = {};
    try {
      data = await res.json();
    } catch (e) {
      // keep the empty object; the status tells what went wrong
    }
    if (!res.ok) throw new Error(data.error || 'The request failed (HTTP ' + res.status + ').');
    return data;
  }

  function fail(msg) {
    $('error-text').textContent = msg || '';
    $('error').hidden = !msg;
    if (msg) $('error').scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'nearest' });
  }

  // ---------- pictures ----------

  // buildArt draws the requester, the approver's gate and the kit; open is
  // the gate after the approval.
  function buildArt(box, open) {
    box.replaceChildren();
    const who = el('div', 'art-node');
    const badge = el('span', 'art-badge');
    badge.append(icon('spark', ''));
    who.append(badge, el('span', 'art-av', initials(request.user)), el('span', 'art-l', request.user.split('@')[0]));
    const gate = el('div', 'art-gate');
    const core = el('span', 'art-core');
    core.append(icon(open ? 'check' : 'lock', ''));
    gate.append(el('span', 'art-ring'), el('span', 'art-ring r2'), core, el('span', 'art-l', open ? t('s3') : t('artYou')));
    const kit = el('div', 'art-node');
    const tile = el('span', 'art-tile');
    tile.append(icon('server', ''));
    kit.append(tile, el('span', 'art-l', request.kit));
    box.append(who, el('div', 'art-line in'), gate, el('div', 'art-line out'), kit);
  }

  // glyph draws the fingerprint as a mesh: each of its 16 hex digits is a
  // node, its bits pick the node's size and fill and which links it draws.
  let glyphs = 0;
  function glyph(fp) {
    const hex = fp.replace(/[^0-9A-Fa-f]/g, '').padEnd(16, '0').slice(0, 16);
    const v = Array.from(hex).map((c) => parseInt(c, 16));
    const hue = Math.round((parseInt(hex.slice(2, 4), 16) / 255) * 360);
    const svg = svgEl('svg', { viewBox: '0 0 100 100', class: 'glyph', 'aria-hidden': 'true' });
    const id = 'tmglyph' + (++glyphs);
    const lg = svgEl('linearGradient', { id, gradientUnits: 'userSpaceOnUse', x1: '10', y1: '10', x2: '90', y2: '90' });
    lg.append(svgEl('stop', { offset: '0', 'stop-color': '#20a0e8' }), svgEl('stop', { offset: '1', 'stop-color': 'hsl(' + hue + ' 78% 62%)' }));
    const defs = svgEl('defs');
    defs.append(lg);
    svg.append(defs);
    const at = (r, c) => ({ x: 17 + c * 20 + (r % 2 ? 10 : 0), y: 20 + r * 20 });
    const ghost = svgEl('g', { class: 'gh' });
    const lit = svgEl('g', { class: 'ga', stroke: 'url(#' + id + ')' });
    const line = (g, a, b) => g.append(svgEl('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y }));
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) {
        const a = at(r, c);
        const val = v[r * 4 + c];
        if (c < 3) {
          line(ghost, a, at(r, c + 1));
          if (val & 4) line(lit, a, at(r, c + 1));
        }
        if (r < 3) {
          line(ghost, a, at(r + 1, c));
          if (val & 8) line(lit, a, at(r + 1, c));
          const d = c + (r % 2 ? 1 : -1);
          if (d >= 0 && d < 4) {
            line(ghost, a, at(r + 1, d));
            if (val & 2) line(lit, a, at(r + 1, d));
          }
        }
      }
    }
    svg.append(ghost, lit);
    v.forEach((val, i) => {
      const p = at(i >> 2, i & 3);
      const radius = 2.6 + (val & 3) * 1.55;
      svg.append(svgEl('circle', (val + i) % 3 !== 0
        ? { cx: p.x, cy: p.y, r: radius, fill: 'url(#' + id + ')' }
        : { cx: p.x, cy: p.y, r: radius, class: 'hollow', stroke: 'url(#' + id + ')' }));
    });
    return svg;
  }

  // guilloche is the security-print rosette behind the grant pass's stub.
  function guilloche() {
    const svg = svgEl('svg', { viewBox: '0 0 200 200', class: 'guill', 'aria-hidden': 'true' });
    for (let j = 0; j < 15; j++) {
      let d = '';
      for (let s = 0; s <= 360; s++) {
        const a = (s / 360) * Math.PI * 2;
        const r = 34 + j * 3.6 + 7 * Math.sin(14 * a + j * 0.45) + 3 * Math.sin(5 * a - j * 0.3);
        d += (s ? 'L' : 'M') + (100 + r * Math.cos(a)).toFixed(2) + ' ' + (100 + r * Math.sin(a)).toFixed(2);
      }
      svg.append(svgEl('path', { d: d + 'Z' }));
    }
    return svg;
  }

  // ---------- what is granted ----------

  function coverageKnown() {
    return !!request.coverage_known && request.entries.every((e) => typeof e.tools === 'number' && typeof e.new === 'number');
  }

  // totals sums up the entries mask keeps: tools, tools new to the user, the
  // most far-reaching effect and its plain-language level.
  function totals(mask) {
    mask = mask || on;
    const known = coverageKnown();
    const s = { known, tools: 0, fresh: 0, all: 0, off: 0, entries: 0, offEntries: 0, top: null, by: {} };
    request.entries.forEach((e, i) => {
      const n = known ? e.tools : 0;
      s.all += n;
      if (!mask[i]) {
        s.off += n;
        s.offEntries++;
        return;
      }
      s.entries++;
      s.tools += n;
      s.fresh += known ? e.new : 0;
      s.by[e.effect] = (s.by[e.effect] || 0) + (known ? n : 1);
      if (s.top === null || RANK[e.effect] < RANK[s.top]) s.top = e.effect;
    });
    s.level = s.top ? LEVEL[s.top] || 'elevated' : null;
    if (s.level === 'high') s.levelCount = (s.by.dangerous || 0) + (s.by.all || 0);
    else if (s.level === 'elevated') s.levelCount = (s.by.admin || 0) + (s.by.other || 0) + (s.by.unclassified || 0);
    else s.levelCount = 0;
    return s;
  }

  function levelText(s) {
    if (!s.level) return '';
    if (s.top === 'all') return t('lvlText').highAll;
    if (!s.known && (s.level === 'high' || s.level === 'elevated')) return t('lvlTextNoCount')[s.level];
    return sub(t('lvlText')[s.level], { n: nf(s.levelCount), all: nf(s.tools) });
  }

  const hasSafe = () => safe.some((v) => !v) && safe.some(Boolean);

  function preset() {
    if (customPicked) return 'custom';
    if (on.every(Boolean)) return 'all';
    if (hasSafe() && on.every((v, i) => v === safe[i])) return 'safe';
    return 'custom';
  }

  function scopeLabel() {
    const p = preset();
    return p === 'all' ? t('optAll') : p === 'safe' ? t('optSafe') : t('sumCustom');
  }

  function tween(node, to) {
    const from = node.dataset.v === undefined ? to : Number(node.dataset.v);
    node.dataset.v = String(to);
    if (reduce || from === to) {
      node.textContent = nf(to);
      return;
    }
    const begin = performance.now();
    const step = (now) => {
      const k = Math.min(1, (now - begin) / 460);
      node.textContent = nf(Math.round(from + (to - from) * (1 - Math.pow(1 - k, 3))));
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  // ---------- 1 · review ----------

  function renderReview() {
    const r = request;
    const asked = Date.parse(r.requested_at);
    const lapses = Date.parse(r.lapses_at);
    buildArt($('art-review'), false);
    fill($('eyebrow'), t('eyebrow'), { ago: rel(asked) });
    // A non-breaking hyphen keeps a kit name such as net-diag-read on one line.
    fill($('hero-title'), t('heroTitle'), { kit: r.kit.replace(/-/g, '\u2011'), ttl: dur(r.ttl) }, { kit: 'hl-kit', ttl: 'hl-ttl' });
    $('desc').textContent = r.description;
    $('g-av').textContent = initials(r.user);
    setUser($('g-user'), r.user);
    $('g-conn').textContent = sub(t('whoConn'), { conn: r.connection });
    $('g-when').textContent = sub(t('whoMeta'), { ago: rel(asked) });
    $('fp-code').textContent = r.fingerprint;
    $('warning-box').hidden = !r.warning;
    $('warning').textContent = r.warning || '';
    $('reason').textContent = r.reason;
    const client = $('client');
    client.hidden = !r.client_name;
    if (r.client_name) fill(client, t('clientName'), { name: r.client_name }, { name: 'cn' });
    $('tech-sub').textContent = sub(t('techSub'), { n: nf(r.entries.length) });
    setUser($('f-user'), r.user);
    $('f-conn').textContent = r.connection;
    $('f-id').textContent = r.id;
    $('f-req').textContent = dt(asked, { timeStyle: 'short' });
    $('f-req-meta').textContent = dt(asked, { dateStyle: 'medium' });
    $('f-req-utc').textContent = utc(asked);
    $('f-before').textContent = dt(lapses, { timeStyle: 'short' });
    $('f-before-meta').textContent = dt(lapses, { dateStyle: 'medium' });
    $('f-before-utc').textContent = utc(lapses);
    $('f-asked').textContent = dur(r.ttl);
    renderEntries();
    renderDecide();
    updateReach();
    if (view !== 'done') document.title = sub(t('docTitle'), { kit: r.kit });
  }

  function entryText(e) {
    if (e.kind === 'tool') return t('eTool');
    if (!e.backend) return e.access ? t('eGrantAnyBackend') : t('eEverything');
    return sub(e.access ? t('eGrant') : t('eGrantAll'), { backend: e.backend });
  }

  function renderEntries() {
    const box = $('entries');
    const known = coverageKnown();
    box.replaceChildren();
    let current = null;
    let group = null;
    request.entries.forEach((e, i) => {
      if (e.effect !== current) {
        current = e.effect;
        group = el('div', 'group g-' + e.effect);
        const h = el('div', 'group-h');
        h.append(el('span', 'dot'), el('span', 'group-name', t('groups')[e.effect] || e.effect), el('span', 'group-desc', t('groupDesc')[e.effect] || ''));
        group.append(h);
        box.append(group);
      }
      const row = el('label', 'entry' + (on[i] ? '' : ' off'));
      const sw = el('span', 'switch');
      const box2 = el('input');
      box2.type = 'checkbox';
      box2.id = 'entry-' + i;
      box2.checked = on[i];
      box2.setAttribute('role', 'switch');
      box2.addEventListener('change', () => {
        on[i] = box2.checked;
        customPicked = false;
        row.classList.toggle('off', !box2.checked);
        renderCount(row, e, i);
        updateReach();
      });
      sw.append(box2, el('span', 'track'));
      const what = el('span', 'e-main');
      const title = el('span', 'e-title');
      if (e.kind === 'tool') title.append(el('code', 'mono', e.entry));
      else title.append(el('span', '', e.backend || t('eEveryBackend')), el('code', 'e-raw', e.entry));
      what.append(title, el('span', 'e-sub', entryText(e)));
      const meta = el('span', 'e-meta');
      if (known && e.tools <= MAX_ENTRY_CELLS) {
        const cells = el('span', 'e-cells');
        for (let k = 0; k < e.tools; k++) cells.append(el('i', k < e.new ? 'n' : ''));
        meta.append(cells);
      }
      meta.append(el('span', 'e-count'));
      row.append(sw, what, meta);
      row.addEventListener('mouseenter', () => focusCells(i));
      row.addEventListener('mouseleave', () => focusCells(null));
      group.append(row);
      renderCount(row, e, i);
    });
  }

  function renderCount(row, e, i) {
    const c = row.querySelector('.e-count');
    c.replaceChildren();
    if (!on[i]) {
      c.append(el('span', 'excl', t('excluded')));
      return;
    }
    if (!coverageKnown()) return;
    c.append(el('span', '', plural('tools', e.tools)), el('span', '', '·'),
      e.new ? el('span', 'is-new', plural('newCount', e.new)) : el('span', '', t('noneNew')));
  }

  function buildMatrix() {
    const known = coverageKnown();
    const total = known ? request.entries.reduce((s, e) => s + e.tools, 0) : 0;
    $('mx').hidden = !known || total === 0 || total > MAX_CELLS;
    if (!$('mx').hidden) {
      const m = $('matrix');
      const rows = Math.max(1, Math.ceil(total / 13));
      m.style.gridTemplateColumns = 'repeat(' + Math.ceil(total / rows) + ', minmax(0, 1fr))';
      request.entries.forEach((e, i) => {
        for (let j = 0; j < e.tools; j++) {
          const c = el('span', 'cell g-' + e.effect + (j < e.new ? ' n' : ''));
          c.dataset.i = String(i);
          m.append(c);
          matrixCells.push(c);
        }
      });
    }
    const effects = Array.from(new Set(request.entries.map((e) => e.effect))).sort((a, b) => RANK[a] - RANK[b]);
    effects.forEach((eff) => {
      const s = el('span', 'g-' + eff);
      $('bar').append(s);
      barSegs[eff] = s;
    });
  }

  function focusCells(i) {
    $('matrix').classList.toggle('focus', i !== null);
    matrixCells.forEach((c) => c.classList.toggle('f', i !== null && c.dataset.i === String(i)));
  }

  function updateReach() {
    const s = totals();
    $('g-risk').className = 'gtile risk' + (s.level ? ' l-' + s.level : '');
    $('g-lvl').textContent = s.level ? t('lvl')[s.level] : t('ctaNone');
    $('g-lvl-text').textContent = levelText(s);
    $('bar').hidden = !s.known;
    $('legend').hidden = !s.known;
    if (s.known) {
      Object.keys(barSegs).forEach((eff) => {
        barSegs[eff].style.width = (s.all ? ((s.by[eff] || 0) / s.all) * 100 : 0) + '%';
      });
      const lg = $('legend');
      lg.replaceChildren();
      Object.keys(s.by).sort((a, b) => RANK[a] - RANK[b]).forEach((eff) => {
        const li = el('li', 'g-' + eff);
        li.append(el('i'), el('span', '', t('groups')[eff] || eff), el('span', 'c', nf(s.by[eff])));
        lg.append(li);
      });
      tween($('g-new-num'), s.fresh);
      $('g-new-unit').textContent = pick('actionsUnit', s.fresh);
      $('g-new-text').textContent = s.fresh ? t('newText') : t('newNone');
    } else {
      delete $('g-new-num').dataset.v;
      $('g-new-num').textContent = t('newUnknown');
      $('g-new-unit').textContent = '';
      $('g-new-text').textContent = t('newUnknownText');
    }
    if (!$('mx').hidden) {
      tween($('mx-num'), s.tools);
      $('mx-unit').textContent = pick('toolsUnit', s.tools);
      if (s.fresh) fill($('mx-sub'), t('reachNotYet'), { n: nf(s.fresh) }, { n: 'b' });
      else $('mx-sub').textContent = t('newNone');
      matrixCells.forEach((c) => c.classList.toggle('off', !on[Number(c.dataset.i)]));
    }
    renderOpts();
    const nar = $('narrowed');
    nar.hidden = !s.offEntries;
    if (s.offEntries) {
      nar.replaceChildren(icon('check'));
      nar.append(s.known && s.off
        ? sub(t('narrowed'), { off: nf(s.off), all: nf(s.all) })
        : sub(t('narrowedNoCount'), { off: nf(s.offEntries), all: nf(request.entries.length) }));
    }
    const blocked = !s.entries || !ttl || request.approvers.length === 0;
    $('cta').disabled = blocked;
    $('m-cta').disabled = blocked;
    $('cta-l').textContent = s.entries ? t('cta') : t('ctaNone');
    $('m-num').textContent = !s.entries ? t('ctaNone') : s.known ? plural('actions', s.tools) : scopeLabel();
    $('m-meta').textContent = [dur(ttl, 'short'), s.level ? t('gRisk') + ' ' + t('lvl')[s.level] : ''].filter(Boolean).join(' · ');
  }

  function renderOpts() {
    const box = $('opts');
    const current = preset();
    const known = coverageKnown();
    const opts = [{ v: 'all', label: t('optAll'), s: totals(request.entries.map(() => true)) }];
    if (hasSafe()) opts.push({ v: 'safe', label: t('optSafe'), s: totals(safe) });
    opts.push({ v: 'custom', label: t('optCustom'), small: t('optCustomSub') });
    box.replaceChildren();
    opts.forEach((o) => {
      const b = el('button', 'opt');
      b.type = 'button';
      b.setAttribute('role', 'radio');
      b.setAttribute('aria-checked', String(o.v === current));
      const text = el('span', 'ot');
      text.append(el('b', '', o.label));
      if (o.small) text.append(el('small', '', o.small));
      b.append(el('span', 'radio'), text);
      if (o.s) {
        const c = el('span', 'oc l-' + o.s.level);
        c.append(el('i'), known ? plural('actions', o.s.tools) : t('lvl')[o.s.level]);
        b.append(c);
      } else {
        b.append(el('span'));
      }
      b.addEventListener('click', () => applyPreset(o.v));
      box.append(b);
    });
  }

  function applyPreset(p) {
    if (p === 'custom') {
      customPicked = true;
      renderOpts();
      $('tech').open = true;
      setTimeout(() => $('scope').scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' }), 40);
      return;
    }
    customPicked = false;
    request.entries.forEach((e, i) => {
      on[i] = p === 'all' ? true : safe[i];
    });
    renderEntries();
    updateReach();
  }

  function renderDecide() {
    $('g-dur').textContent = ttl ? dur(ttl) : '–';
    const pills = $('ttl');
    pills.replaceChildren();
    // The last choice, '', is a duration of the approver's own.
    const items = request.ttl_choices.concat(['']);
    items.forEach((d, i) => {
      const checked = d === '' ? ttlOwn : !ttlOwn && d === ttl;
      const b = el('button');
      b.type = 'button';
      b.setAttribute('role', 'radio');
      b.setAttribute('aria-checked', String(checked));
      b.tabIndex = checked ? 0 : -1;
      b.append(el('span', '', d === '' ? t('ttlOwn') : dur(d, 'short')));
      if (d === request.ttl) b.append(el('small', '', t('asAsked')));
      b.addEventListener('click', () => (d === '' ? chooseOwnTTL(true) : chooseTTL(d)));
      b.addEventListener('keydown', (ev) => {
        const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[ev.key];
        if (!step) return;
        ev.preventDefault();
        const next = items[(i + step + items.length) % items.length];
        if (next === '') chooseOwnTTL(false);
        else chooseTTL(next);
        pills.querySelector('[aria-checked="true"]').focus();
      });
      pills.append(b);
    });
    const unit = $('ttl-unit');
    unit.options[0].textContent = unitName('minute');
    unit.options[1].textContent = unitName('hour');
    $('ttl-own').hidden = !ttlOwn;
    $('ttl-hint').hidden = !ttlOwn;
    $('ttl-hint').classList.toggle('warn', !ttl);
    $('ttl-hint-l').textContent = sub(t('ttlMax'), { max: dur(request.ttl_max) });
    const sel = $('approver');
    const chosen = sel.value;
    sel.replaceChildren();
    request.approvers.forEach((a) => {
      const o = el('option', '', a.name + ' · ' + short(a.address));
      o.value = a.name;
      sel.append(o);
    });
    if (chosen) sel.value = chosen;
    sel.disabled = request.approvers.length === 0;
    $('no-signers').hidden = request.approvers.length > 0;
  }

  function chooseTTL(d) {
    ttlOwn = false;
    ttl = d;
    renderDecide();
    updateReach();
  }

  // chooseOwnTTL starts the duration typed from the one chosen.
  function chooseOwnTTL(focus) {
    if (!ttlOwn) {
      const min = minutesOf(ttl);
      const hours = min !== null && min % 60 === 0;
      $('ttl-n').value = min === null ? '' : String(hours ? min / 60 : min);
      $('ttl-unit').value = hours ? 'h' : 'm';
      ttlOwn = true;
    }
    readOwnTTL();
    if (focus) $('ttl-n').focus();
  }

  // readOwnTTL takes the duration typed: whole minutes or hours, up to the
  // kit's maximum.
  function readOwnTTL() {
    const n = Number($('ttl-n').value);
    const unit = $('ttl-unit').value;
    const ok = Number.isInteger(n) && n > 0 && n * (unit === 'h' ? 60 : 1) <= minutesOf(request.ttl_max);
    ttl = ok ? n + unit : '';
    renderDecide();
    updateReach();
  }

  function choices() {
    const body = { approver: $('approver').value, ttl, grants: [], tools: [] };
    request.entries.forEach((e, i) => {
      if (on[i]) (e.kind === 'tool' ? body.tools : body.grants).push(e.entry);
    });
    return body;
  }

  async function prepare() {
    fail('');
    const body = choices();
    if (body.grants.length + body.tools.length === 0) {
      fail(t('ctaNone'));
      return;
    }
    if (!ttl) {
      fail(sub(t('ttlMax'), { max: dur(request.ttl_max) }));
      return;
    }
    $('cta').disabled = true;
    $('m-cta').disabled = true;
    try {
      const st = await call('/statement', body);
      statement = { text: st.statement, body, ttl: st.ttl };
      $('key').value = '';
      $('signature').value = '';
      $('stmt-wrap').open = false;
      go('sign');
      renderSign();
    } catch (e) {
      fail(e.message);
    } finally {
      updateReach();
    }
  }

  // ---------- 2 · sign ----------

  function selectedApprover() {
    const name = statement ? statement.body.approver : $('approver').value;
    return request.approvers.find((a) => a.name === name) || { name, address: '' };
  }

  function renderSign() {
    const ap = selectedApprover();
    const s = totals();
    $('avatar').textContent = initials(ap.name);
    $('signer-name').textContent = ap.name;
    $('signer-addr').textContent = short(ap.address);
    $('signer-addr').title = ap.address;
    setUser($('sum-who'), request.user);
    $('sum-who-meta').textContent = sub(t('whoConn'), { conn: request.connection });
    $('sum-what').textContent = request.kit + ' · ' + scopeLabel();
    const meta = $('sum-what-meta');
    meta.replaceChildren();
    if (s.known) meta.append(plural('actions', s.tools) + ' · ');
    meta.append(t('gRisk') + ' ', el('span', 'lvl l-' + s.level, t('lvl')[s.level]));
    $('sum-how').textContent = dur(statement.ttl);
    renderStatement();
    setHold(t('hold'));
    checkKey();
    $('sign-wallet').disabled = !$('signature').value.trim();
  }

  // renderStatement shows the statement line by line as ToolMesh wrote it,
  // with the reading aid of the page's language beside it.
  function renderStatement() {
    const gloss = lang === 'en' ? null : t('glossLines');
    const ol = $('stmt');
    ol.replaceChildren();
    statement.text.replace(/\n$/, '').split('\n').forEach((raw, i) => {
      const li = el('li');
      const line = el('span', 'line');
      const aid = el('span', 'gl');
      const m = raw.match(/^([^:]+): (.*)$/);
      if (i === 0) li.className = 'head';
      if (m) {
        const label = m[1];
        if (label === 'Warning') li.className = 'warn';
        else if (label.startsWith('Left out')) li.className = 'left';
        else if (label.endsWith('states it')) li.className = 'claim';
        else if (label === 'Duration') li.className = 'dur';
        line.append(el('span', 'k', label + ': '), el('span', 'v', m[2]));
        if (gloss && gloss[label]) aid.textContent = gloss[label] + glossValue(label, m[2]);
      } else {
        line.textContent = raw;
        if (gloss && gloss[raw]) aid.textContent = gloss[raw];
      }
      li.append(line, aid);
      ol.append(li);
    });
    ol.classList.toggle('with-gloss', !!gloss && showGloss);
    $('gloss-wrap').hidden = !gloss;
    $('gloss-note').hidden = !gloss || !showGloss;
  }

  function glossValue(label, value) {
    if (label === 'Duration') {
      const d = value.split(' ')[0];
      return minutesOf(d) === null ? '' : ': ' + dur(d);
    }
    if (label === 'Approve before') {
      const ms = Date.parse(value);
      return Number.isNaN(ms) ? '' : ': ' + dt(ms, { dateStyle: 'medium', timeStyle: 'short' });
    }
    return '';
  }

  function checkKey() {
    const out = $('key-check');
    const button = $('hold');
    button.disabled = true;
    out.replaceChildren();
    if ($('key').disabled) {
      // the warning about plain HTTP stays
      out.hidden = false;
      out.className = 'check bad';
      out.append(icon('alert'), el('span', '', t('insecure')));
      return;
    }
    const text = $('key').value.trim();
    const ap = request && selectedApprover();
    out.hidden = !text || !ap || !ap.address;
    if (out.hidden) return;
    const span = el('span');
    try {
      const address = B.addressOf(B.publicKey(B.parsePrivateKey(text)), B.networkOf(ap.address));
      const ok = address === ap.address.toLowerCase();
      out.className = 'check' + (ok ? '' : ' bad');
      fill(span, ok ? t('keyOk') : t('keyBad'), { addr: short(address), name: ap.name }, { addr: 'mono' });
      out.append(icon(ok ? 'check' : 'alert'), span);
      button.disabled = !ok || !statement;
    } catch (e) {
      out.className = 'check bad';
      span.textContent = t('keyInvalid');
      out.append(icon('alert'), span);
    }
  }

  function setHold(text) {
    ['hold-a', 'hold-b'].forEach((id) => $(id).replaceChildren(icon('sign', ''), document.createTextNode(text)));
  }

  // Signing in the page takes a press held for a second, so that a stray
  // click approves nothing.
  function holdBegin(ev) {
    const b = $('hold');
    if (b.disabled || holding) return;
    if (ev) ev.preventDefault();
    holding = true;
    holdStart = performance.now();
    setHold(t('holding'));
    const step = (now) => {
      if (!holding) return;
      const p = Math.min(1, (now - holdStart) / 1100);
      b.style.setProperty('--p', p.toFixed(3));
      if (p >= 1) {
        holding = false;
        signWithKey();
        return;
      }
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
  }

  function holdEnd() {
    if (!holding) return;
    holding = false;
    cancelAnimationFrame(raf);
    $('hold').style.setProperty('--p', '0');
    setHold(t('hold'));
  }

  async function signWithKey() {
    const b = $('hold');
    b.disabled = true;
    setHold(t('signing'));
    let signature = '';
    try {
      signature = B.signMessage(B.parsePrivateKey($('key').value), statement.text);
    } catch (e) {
      fail(e.message);
    } finally {
      $('key').value = '';
    }
    if (signature) await approve(signature);
    b.style.setProperty('--p', '0');
    setHold(t('hold'));
    checkKey();
  }

  async function approve(signature) {
    fail('');
    if (!statement) return;
    try {
      result = await call('', Object.assign({}, statement.body, { signature }));
      go('done');
      renderDone(true);
    } catch (e) {
      fail(e.message);
    }
  }

  function selectTab(wallet) {
    $('tab-key').setAttribute('aria-selected', String(!wallet));
    $('tab-wallet').setAttribute('aria-selected', String(wallet));
    $('panel-key').hidden = wallet;
    $('panel-wallet').hidden = !wallet;
  }

  function copyStatement(labelID) {
    if (!statement) return;
    const done = () => {
      $(labelID).textContent = t('copied');
      setTimeout(() => {
        $(labelID).textContent = t('copy');
      }, 1600);
    };
    const select = () => {
      $('stmt-wrap').open = true;
      const range = document.createRange();
      range.selectNodeContents($('stmt'));
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(statement.text).then(done, select);
    else select();
  }

  // ---------- 3 · approved ----------

  async function renderDone(first) {
    const s = totals();
    const ap = selectedApprover();
    const expires = Date.parse(result.expires_at);
    buildArt($('art-done'), true);
    fill($('done-lead'), t('doneLead'), { user: request.user, kit: result.kit, ttl: dur(result.ttl) }, { user: 'b', kit: 'b' });
    $('p-kit').textContent = result.kit;
    setUser($('p-holder'), request.user);
    $('p-holder-meta').textContent = request.connection;
    $('p-valid').textContent = dt(expires, { dateStyle: 'medium', timeStyle: 'short' });
    $('p-valid-meta').textContent = sub(t('remaining'), { t: clock((expires - Date.now()) / 1000) });
    $('p-scope').textContent = sub(t('scopeSum'), { n: s.known ? plural('actions', s.tools) : scopeLabel(), lvl: t('lvl')[s.level] });
    $('p-scope-meta').textContent = result.part
      ? sub(t('partial'), { n: nf(s.entries), all: nf(request.entries.length) })
      : request.entries.map((e) => e.entry).join(', ');
    $('p-by').textContent = ap.name;
    $('p-by-meta').textContent = short(ap.address);
    $('p-fp').textContent = request.fingerprint;
    $('p-rid').textContent = t('fRequest') + ' ' + request.id;
    document.title = t('doneTitle') + ' · ' + result.kit;
    if (first) {
      const pass = $('pass');
      pass.classList.remove('go');
      void pass.offsetWidth;
      pass.classList.add('go');
    }
    $('p-audit').hidden = true;
    try {
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(statement.text));
      const hex = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
      $('p-audit').textContent = sub(t('audit'), { h: hex.slice(0, 12) + '…' + hex.slice(-8) });
      $('p-audit').hidden = false;
    } catch (e) {
      // crypto.subtle needs a secure context; the pass works without it
    }
  }

  // ---------- views ----------

  function go(v) {
    const moved = view && view !== v;
    view = v;
    ['review', 'sign', 'done', 'info'].forEach((x) => {
      $('view-' + x).hidden = x !== v;
    });
    $('steps').hidden = v === 'info';
    $('timer').hidden = v !== 'review' && v !== 'sign';
    fail('');
    renderSteps();
    tick();
    if (moved) window.scrollTo({ top: 0, behavior: reduce ? 'auto' : 'smooth' });
  }

  function renderSteps() {
    const order = ['review', 'sign', 'done'];
    const at = order.indexOf(view);
    document.querySelectorAll('#steps li').forEach((li) => {
      const k = order.indexOf(li.dataset.s);
      li.classList.toggle('is-done', k < at || view === 'done');
      li.classList.toggle('is-cur', k === at && view !== 'done');
      if (k === at) li.setAttribute('aria-current', 'step');
      else li.removeAttribute('aria-current');
    });
  }

  // showInfo is the page without a request to decide on: the key setup, a
  // request no longer pending, or one that could not be loaded.
  function showInfo(kind) {
    infoKind = kind;
    $('info').className = 'wrap info ' + kind;
    $('info-icon').setAttribute('href', kind === 'setup' ? '#i-key' : kind === 'gone' ? '#i-hourglass' : '#i-alert');
    $('info-title').textContent = t(kind + 'Title');
    $('info-text').textContent = t(kind === 'setup' ? 'setupLead' : kind + 'Text');
    document.title = t(kind + 'Title');
    // the page's own heading says it already
    $('setup-lead').hidden = kind === 'setup';
    if (kind === 'setup') $('setup').open = true;
    if (view !== 'info') go('info');
  }

  function tick() {
    if (!request) return;
    const now = Date.now();
    if (view === 'review' || view === 'sign') {
      const begin = Date.parse(request.requested_at);
      const end = Date.parse(request.lapses_at);
      const left = (end - now) / 1000;
      if (left > 0) fill($('timer-l'), t('timer'), { t: clock(left) }, { t: 't' });
      else $('timer-l').textContent = t('timerOver');
      $('timer').classList.toggle('warn', left < 300 && left >= 60);
      $('timer').classList.toggle('crit', left < 60);
      const share = end > begin ? Math.max(0, Math.min(1, (end - now) / (end - begin))) : 0;
      $('ring').style.strokeDashoffset = String(50.27 * (1 - share));
      if (Math.floor(now / 1000) % 20 === 0) {
        fill($('eyebrow'), t('eyebrow'), { ago: rel(begin) });
        $('g-when').textContent = sub(t('whoMeta'), { ago: rel(begin) });
      }
    }
    if (view === 'done' && result) {
      $('p-valid-meta').textContent = sub(t('remaining'), { t: clock((Date.parse(result.expires_at) - now) / 1000) });
    }
  }

  // ---------- key setup ----------

  function generate() {
    const random = new Uint8Array(32);
    let key = null;
    while (!key) {
      crypto.getRandomValues(random);
      try {
        key = B.generateKey(random, 'bc');
      } catch (e) {
        // out of range, try again
      }
    }
    random.fill(0);
    $('new-key').value = key.wif;
    $('new-config').textContent = 'approvers:\n  - name: your-name\n    address: ' + key.address + '\n';
    $('generated').hidden = false;
  }

  function openSetup(ev) {
    ev.preventDefault();
    $('setup').open = true;
    $('setup').scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
  }

  function insecure() {
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
    return location.protocol !== 'https:' && !local;
  }

  // ---------- start ----------

  function wire() {
    $('cta').addEventListener('click', prepare);
    $('m-cta').addEventListener('click', prepare);
    $('back').addEventListener('click', () => {
      statement = null;
      go('review');
    });
    $('gloss').addEventListener('change', (ev) => {
      showGloss = ev.target.checked;
      renderStatement();
    });
    $('copy').addEventListener('click', () => copyStatement('copy-l'));
    $('copy2').addEventListener('click', () => copyStatement('copy2-l'));
    $('tab-key').addEventListener('click', () => selectTab(false));
    $('tab-wallet').addEventListener('click', () => selectTab(true));
    $('key').addEventListener('input', checkKey);
    $('ttl-n').addEventListener('input', readOwnTTL);
    $('ttl-unit').addEventListener('change', readOwnTTL);
    $('signature').addEventListener('input', () => {
      $('sign-wallet').disabled = !$('signature').value.trim();
    });
    $('sign-wallet').addEventListener('click', () => approve($('signature').value.trim()));
    const hold = $('hold');
    hold.addEventListener('pointerdown', holdBegin);
    ['pointerup', 'pointerleave', 'pointercancel'].forEach((name) => hold.addEventListener(name, holdEnd));
    hold.addEventListener('keydown', (ev) => {
      if ((ev.key === 'Enter' || ev.key === ' ') && !ev.repeat) holdBegin(ev);
    });
    hold.addEventListener('keyup', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') holdEnd();
    });
    hold.addEventListener('click', (ev) => ev.preventDefault());
    hold.addEventListener('contextmenu', (ev) => ev.preventDefault());
    if (insecure()) {
      selectTab(true);
      $('key').disabled = true;
    }
  }

  async function start() {
    buildLangSelect();
    applyStatic();
    $('generate').addEventListener('click', generate);
    $('setup-link').addEventListener('click', openSetup);
    if (!requestID) {
      showInfo('setup');
      return;
    }
    if (main.dataset.found !== 'true') {
      showInfo(main.dataset.status === '404' ? 'gone' : 'failed');
      return;
    }
    wire();
    try {
      request = await call('/request');
    } catch (e) {
      showInfo('failed');
      fail(e.message);
      return;
    }
    on = request.entries.map(() => true);
    safe = request.entries.map((e) => e.effect !== 'dangerous' && e.effect !== 'all');
    ttl = request.ttl;
    $('fp-glyph').append(glyph(request.fingerprint));
    $('stub-glyph').append(glyph(request.fingerprint));
    $('stub').prepend(guilloche());
    buildMatrix();
    renderReview();
    go('review');
    setInterval(tick, 1000);
  }

  start();
})();
