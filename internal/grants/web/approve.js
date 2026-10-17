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

// The approval page: shows a pending request as ToolMesh describes it, lets
// the approver narrow it, fetches the statement ToolMesh writes for those
// choices, signs it in the page (or takes a signature from a wallet) and
// sends the signature. Everything shown is set as text, never as markup.
(function () {
  'use strict';

  const B = window.ToolMeshBIP322;
  const $ = (id) => document.getElementById(id);
  const main = $('main');
  const requestID = main.dataset.request;
  const base = location.pathname.replace(/\/+$/, '');

  let request = null;
  let statement = null; // { text, body } for the choices it was written for

  const GROUPS = {
    all: 'Every access class, dangerous and admin included',
    dangerous: 'Dangerous',
    admin: 'Admin',
    other: 'Other classifications',
    unclassified: 'Without access classification',
    write: 'Write',
    read: 'Read',
  };

  function show(el, on) {
    el.hidden = !on;
  }

  function fail(msg) {
    const e = $('error');
    e.textContent = msg || '';
    show(e, !!msg);
  }

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

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function when(iso) {
    const d = new Date(iso);
    return d.toLocaleString() + ' (' + d.toISOString().slice(0, 19) + 'Z)';
  }

  function entryLabel(e) {
    if (e.kind === 'tool') return 'Tool ' + e.entry + (e.access ? ' (' + e.access + ')' : '');
    if (!e.backend && !e.access) return 'Every tool of every backend';
    if (!e.backend) return 'Every backend, access class ' + e.access;
    if (!e.access) return e.backend + ', every access class';
    return e.backend + ', access class ' + e.access;
  }

  function invalidate() {
    statement = null;
    show($('sign'), false);
    fail('');
  }

  function renderEntries() {
    const box = $('entries');
    box.replaceChildren();
    let group = null;
    let current = '';
    request.entries.forEach((e, i) => {
      if (e.effect !== current) {
        current = e.effect;
        group = el('div', 'group ' + e.effect);
        group.append(el('h3', '', GROUPS[e.effect] || e.effect));
        box.append(group);
      }
      const row = el('label', 'entry');
      const box2 = el('input');
      box2.type = 'checkbox';
      box2.checked = true;
      box2.dataset.index = String(i);
      box2.addEventListener('change', () => {
        row.classList.toggle('off', !box2.checked);
        invalidate();
      });
      row.append(box2, el('span', 'what', entryLabel(e)));
      if (request.coverage_known && e.tools !== undefined) {
        row.append(el('span', 'count', e.tools + (e.tools === 1 ? ' tool' : ' tools') + ', ' + e.new + ' new'));
      }
      group.append(row);
    });
  }

  function renderRequest() {
    $('user').textContent = request.user;
    $('connection').textContent = request.connection;
    $('kit').textContent = request.kit + ': ' + request.description;
    $('ttl').textContent = request.ttl;
    $('lapses').textContent = when(request.lapses_at);
    $('fingerprint').textContent = request.fingerprint;
    $('reason').textContent = request.reason;
    if (request.warning) {
      $('warning').textContent = request.warning;
      show($('warning'), true);
    }
    if (request.client_name) {
      $('client-name').textContent = 'The client calls itself “' + request.client_name + '”.';
      show($('client-name'), true);
    }
    renderEntries();

    const ttl = $('ttl-choice');
    request.ttl_choices.forEach((t, i) => {
      const o = el('option', '', i === 0 ? t + ' (as asked)' : t);
      o.value = t;
      ttl.append(o);
    });
    ttl.addEventListener('change', invalidate);

    const who = $('approver');
    request.approvers.forEach((a) => {
      const o = el('option', '', a.name + ' (' + a.address + ')');
      o.value = a.name;
      who.append(o);
    });
    who.addEventListener('change', () => {
      invalidate();
      checkKey();
    });
    if (request.approvers.length === 0) {
      show($('no-signers'), true);
      $('prepare').disabled = true;
    }
    show($('request'), true);
  }

  function choices() {
    const body = { approver: $('approver').value, ttl: $('ttl-choice').value, grants: [], tools: [] };
    document.querySelectorAll('#entries input[type=checkbox]').forEach((c) => {
      if (!c.checked) return;
      const e = request.entries[Number(c.dataset.index)];
      (e.kind === 'tool' ? body.tools : body.grants).push(e.entry);
    });
    return body;
  }

  async function prepare() {
    fail('');
    const body = choices();
    if (body.grants.length + body.tools.length === 0) {
      fail('Tick at least one entry. To refuse the request, let it lapse or deny it on the approver API.');
      return;
    }
    try {
      const st = await call('/statement', body);
      statement = { text: st.statement, body };
      $('statement').textContent = st.statement;
      $('key').value = '';
      $('signature').value = '';
      checkKey();
      show($('sign'), true);
      $('sign').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
      fail(e.message);
    }
  }

  function selectedApprover() {
    return request.approvers.find((a) => a.name === $('approver').value);
  }

  function checkKey() {
    const out = $('key-check');
    const button = $('sign-key');
    button.disabled = true;
    if ($('key').disabled) return; // the warning about plain HTTP stays
    out.className = 'hint';
    const text = $('key').value.trim();
    const approver = request && selectedApprover();
    if (!text || !approver) {
      out.textContent = '';
      return;
    }
    try {
      const address = B.addressOf(B.publicKey(B.parsePrivateKey(text)), B.networkOf(approver.address));
      if (address === approver.address.toLowerCase()) {
        out.textContent = 'This key belongs to ' + address + ', the address of ' + approver.name + '.';
        out.className = 'hint ok';
        button.disabled = !statement;
      } else {
        out.textContent = 'This key belongs to ' + address + ', not to the address of ' + approver.name + '.';
        out.className = 'hint bad';
      }
    } catch (e) {
      out.textContent = e.message;
      out.className = 'hint bad';
    }
  }

  async function approve(signature) {
    fail('');
    if (!statement) return;
    try {
      const res = await call('', Object.assign({}, statement.body, { signature }));
      let text = 'Approved: ' + request.user + ' holds the kit ' + res.kit + ' for ' + res.ttl + ', until ' + when(res.expires_at) + '.';
      if (res.part) {
        const kept = (res.part.grants || []).concat((res.part.tools || []).map((t) => 'tool ' + t));
        text += ' Granted in part: ' + kept.join(', ') + '.';
      }
      $('result-text').textContent = text;
      $('result-text').className = 'ok';
      show($('request'), false);
      show($('sign'), false);
      show($('result'), true);
    } catch (e) {
      fail(e.message);
    }
  }

  function selectTab(wallet) {
    $('tab-key').setAttribute('aria-selected', String(!wallet));
    $('tab-wallet').setAttribute('aria-selected', String(wallet));
    show($('panel-key'), !wallet);
    show($('panel-wallet'), wallet);
  }

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
    show($('generated'), true);
  }

  function insecure() {
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
    return location.protocol !== 'https:' && !local;
  }

  async function start() {
    $('generate').addEventListener('click', generate);
    if (!requestID || main.dataset.found !== 'true') return;
    $('prepare').addEventListener('click', prepare);
    $('key').addEventListener('input', checkKey);
    $('sign-key').addEventListener('click', () => {
      let signature;
      try {
        signature = B.signMessage(B.parsePrivateKey($('key').value), statement.text);
      } catch (e) {
        fail(e.message);
        return;
      } finally {
        $('key').value = '';
        checkKey();
      }
      approve(signature);
    });
    $('sign-wallet').addEventListener('click', () => approve($('signature').value.trim()));
    $('copy-statement').addEventListener('click', () => {
      if (navigator.clipboard && statement) navigator.clipboard.writeText(statement.text);
    });
    $('tab-key').addEventListener('click', () => selectTab(false));
    $('tab-wallet').addEventListener('click', () => selectTab(true));
    if (insecure()) {
      selectTab(true);
      $('key').disabled = true;
      $('key-check').textContent = 'This page is not served over HTTPS, so someone on the network could change it. Do not enter a key here; sign in your wallet.';
      $('key-check').className = 'hint bad';
    }
    try {
      request = await call('/request');
      renderRequest();
    } catch (e) {
      fail(e.message);
    }
  }

  start();
})();
