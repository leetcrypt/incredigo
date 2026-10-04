'use strict';
// Headless harness for extension/background.js: loads the service worker into a vm context
// with a stubbed `chrome` (tabs + native port), drives it with host command frames, and
// asserts WHERE each DOM command is delivered. No browser. Run by extension_harness_test.go:
//
//	node testdata/background_harness.js extension/background.js
//
// Fake data only; the "secret" below is a placeholder string, never a real credential.

const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

function makeChrome() {
  const tabs = new Map(); // id -> { id, url, status, ready, marker, nav }
  const state = { active: null, sent: [], replies: [], nextTab: 1 };
  const updated = new Set();
  const removed = new Set();
  let onMessage = null;

  const noSuchTab = (id) => new Error('No tab with id: ' + id + '.');
  const fire = (id, info) => { for (const fn of [...updated]) fn(id, info); };
  // A navigating submit: the click is acked first (content.js replies before navigation
  // commits), THEN the tab starts loading, completes, and the content script re-injects last.
  function startNav(t) {
    const nav = t.nav;
    t.nav = null;
    setTimeout(() => { t.status = 'loading'; t.ready = false; fire(t.id, { status: 'loading' }); }, 20);
    setTimeout(() => { t.url = nav.url; t.status = 'complete'; fire(t.id, { status: 'complete' }); }, 80);
    setTimeout(() => { t.marker = nav.marker; t.ready = true; }, 150);
  }
  const chrome = {
    runtime: {
      lastError: undefined,
      connectNative() {
        return {
          onMessage: { addListener(fn) { onMessage = fn; } },
          onDisconnect: { addListener() {} },
          postMessage(m) { state.replies.push(m); },
        };
      },
    },
    tabs: {
      async query() {
        const t = tabs.get(state.active);
        return t ? [{ ...t }] : [];
      },
      async get(id) {
        const t = tabs.get(id);
        if (!t) throw noSuchTab(id);
        return { ...t };
      },
      async update(id, props) {
        const t = tabs.get(id);
        if (!t) throw noSuchTab(id);
        t.url = props.url;
        t.status = 'loading';
        setTimeout(() => { t.status = 'complete'; fire(id, { status: 'complete' }); }, 1);
        return { ...t };
      },
      async sendMessage(id, msg) {
        const t = tabs.get(id);
        if (!t || !t.ready || t.status === 'loading') {
          throw new Error('Could not establish connection. Receiving end does not exist.');
        }
        state.sent.push({ tabId: id, method: msg.method });
        if (msg.method === 'click' && t.nav) startNav(t);
        return msg.method === 'text' ? { text: t.marker } : { ok: true };
      },
      onUpdated: { addListener(fn) { updated.add(fn); }, removeListener(fn) { updated.delete(fn); } },
      onRemoved: { addListener(fn) { removed.add(fn); }, removeListener(fn) { removed.delete(fn); } },
    },
  };

  const api = {
    chrome,
    state,
    addTab(url, { activate = true } = {}) {
      const id = state.nextTab++;
      tabs.set(id, { id, url, status: 'complete', ready: true, marker: 'ok-marker', nav: null });
      if (activate) state.active = id;
      return id;
    },
    activate(id) { state.active = id; },
    setURL(id, url) { tabs.get(id).url = url; },
    navigateOnClick(id, url, marker) { const t = tabs.get(id); t.marker = 'stale-old-page'; t.nav = { url, marker }; },
    closeTab(id) {
      tabs.delete(id);
      for (const fn of [...removed]) fn(id, {});
      if (state.active === id) state.active = null;
    },
    // send a host command and await its reply frame
    async cmd(method, params) {
      const id = state.replies.length + 1000 + Math.floor(Math.random() * 1e6);
      onMessage({ id, method, params: params || {} });
      for (let i = 0; i < 10000; i++) {
        const r = state.replies.find((x) => x.id === id);
        if (r) return r;
        await new Promise((res) => setTimeout(res, 1));
      }
      throw new Error('no reply for ' + method);
    },
  };
  return api;
}

function load(src) {
  const h = makeChrome();
  const ctx = vm.createContext({ chrome: h.chrome, setTimeout, clearTimeout, console, String, Error, Promise, URL });
  vm.runInContext(src, ctx, { filename: 'background.js' });
  return h;
}

const FAKE_SECRET = Buffer.from('fake-placeholder').toString('base64');
const cases = [];
const test = (name, fn) => cases.push({ name, fn });

test('DOM commands go to the pinned tab after focus moves', async (src) => {
  const h = load(src);
  const site = h.addTab('https://git.example.org/');
  assert.ok(!(await h.cmd('open')).error);
  const g = await h.cmd('goto', { url: 'https://git.example.org/user/settings/account' });
  assert.ok(!g.error, g.error);
  const other = h.addTab('https://unrelated.example.net/'); // user focuses another tab
  for (const m of ['fill', 'fill', 'click', 'text']) {
    const r = await h.cmd(m, { selector: '#x', secret: FAKE_SECRET });
    assert.ok(!r.error, m + ': ' + r.error);
  }
  assert.deepStrictEqual(h.state.sent.map((s) => s.tabId), [site, site, site, site]);
  assert.ok(!h.state.sent.some((s) => s.tabId === other), 'a command reached the unrelated tab');
});

test('goto navigates the pinned tab, not the newly focused one', async (src) => {
  const h = load(src);
  const site = h.addTab('https://git.example.org/');
  await h.cmd('open');
  const other = h.addTab('https://unrelated.example.net/');
  const g = await h.cmd('goto', { url: 'https://git.example.org/user/login' });
  assert.ok(!g.error, g.error);
  const tabs = h.chrome.tabs;
  assert.strictEqual((await tabs.get(site)).url, 'https://git.example.org/user/login');
  assert.strictEqual((await tabs.get(other)).url, 'https://unrelated.example.net/');
});

test('pinned tab closed -> error, never falls back to the active tab', async (src) => {
  const h = load(src);
  const site = h.addTab('https://git.example.org/');
  await h.cmd('open');
  await h.cmd('goto', { url: 'https://git.example.org/user/settings/account' });
  h.addTab('https://git.example.org/other'); // same origin, still must not be used
  h.closeTab(site);
  const r = await h.cmd('fill', { selector: '#x', secret: FAKE_SECRET });
  assert.ok(r.error && /session tab/.test(r.error), 'want session-tab error, got ' + JSON.stringify(r));
  assert.strictEqual(h.state.sent.length, 0);
});

test('fill refused when the pinned tab left the goto origin', async (src) => {
  const h = load(src);
  const site = h.addTab('https://git.example.org/');
  await h.cmd('open');
  await h.cmd('goto', { url: 'https://git.example.org/user/settings/account' });
  h.setURL(site, 'https://phish.example.com/login'); // e.g. an in-page redirect
  const r = await h.cmd('fill', { selector: '#x', secret: FAKE_SECRET });
  assert.ok(r.error && /origin/.test(r.error), 'want origin error, got ' + JSON.stringify(r));
  assert.strictEqual(h.state.sent.length, 0);
});

test('fill before any goto is refused', async (src) => {
  const h = load(src);
  h.addTab('https://git.example.org/');
  await h.cmd('open');
  const r = await h.cmd('fill', { selector: '#x', secret: FAKE_SECRET });
  assert.ok(r.error, 'fill without a goto origin must be refused');
  assert.strictEqual(h.state.sent.length, 0);
});

test('commands without an open session are refused', async (src) => {
  const h = load(src);
  h.addTab('https://git.example.org/');
  const r = await h.cmd('text', { selector: '#x' });
  assert.ok(r.error && /session/.test(r.error), 'want no-session error, got ' + JSON.stringify(r));
  await h.cmd('open');
  await h.cmd('close');
  const r2 = await h.cmd('click', { selector: '#x' });
  assert.ok(r2.error, 'commands after close must be refused');
  assert.strictEqual(h.state.sent.length, 0);
});

test('open reports the pinned tab id', async (src) => {
  const h = load(src);
  const site = h.addTab('https://git.example.org/');
  const r = await h.cmd('open');
  assert.strictEqual(r.result && r.result.tabId, site);
});

test('text after a navigating submit reads the NEW page, not the old one', async (src) => {
  const h = load(src);
  const site = h.addTab('https://git.example.org/');
  await h.cmd('open');
  await h.cmd('goto', { url: 'https://git.example.org/user/settings/account' });
  h.navigateOnClick(site, 'https://git.example.org/user/settings/account?done', 'ok-marker');
  const c = await h.cmd('click', { selector: '#submit' });
  assert.ok(!c.error, c.error);
  const r = await h.cmd('text', { selector: '#flash' });
  assert.ok(!r.error, 'text failed across the navigation: ' + r.error);
  assert.strictEqual(r.result.text, 'ok-marker', 'read the page the submit navigated away from');
});

test('text waits out a load in progress and a late content script', async (src) => {
  const h = load(src);
  const site = h.addTab('https://git.example.org/');
  await h.cmd('open');
  await h.cmd('goto', { url: 'https://git.example.org/x' });
  h.navigateOnClick(site, 'https://git.example.org/y', 'ok-marker');
  // Drive the navigation directly (click ack already lost), then read immediately.
  await h.chrome.tabs.sendMessage(site, { method: 'click' });
  await new Promise((res) => setTimeout(res, 30)); // mid-load
  const r = await h.cmd('text', { selector: '#flash' });
  assert.ok(!r.error, 'text failed mid-load: ' + r.error);
  assert.strictEqual(r.result.text, 'ok-marker');
});

test('a click that does not navigate still returns promptly', async (src) => {
  const h = load(src);
  h.addTab('https://git.example.org/');
  await h.cmd('open');
  await h.cmd('goto', { url: 'https://git.example.org/x' });
  const t0 = Date.now();
  const c = await h.cmd('click', { selector: '#toggle' });
  assert.ok(!c.error, c.error);
  assert.ok(Date.now() - t0 < 3000, 'non-navigating click blocked too long');
});

(async () => {
  const src = fs.readFileSync(process.argv[2], 'utf8');
  let failed = 0;
  for (const c of cases) {
    try {
      await c.fn(src);
      console.log('PASS ' + c.name);
    } catch (e) {
      failed++;
      console.log('FAIL ' + c.name + ': ' + (e && e.message));
    }
  }
  process.exit(failed ? 1 : 0);
})();
