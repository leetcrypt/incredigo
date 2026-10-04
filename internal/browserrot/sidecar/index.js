#!/usr/bin/env node
// incredigo browserrot Node sidecar.
//
// A single sidecar process == a single browser Session (one browser, one page),
// spawned and torn down by the Go side (internal/browserrot/sidecar.go). It speaks
// newline-delimited JSON-RPC over stdio:
//
//   stdin  <- {"id":N,"method":"open|goto|fill|click|text|heal|close","params":{...}}
//   stdout -> {"id":N,"result":{...}}   |   {"id":N,"error":"message"}
//
// HARD RULES honored here (mirror the Go engine + CLAUDE.md):
//   * Secrets arrive base64-encoded in `fill.params.secret` and cross exactly ONE local
//     process boundary. They are decoded, typed into a field, and dropped. They are
//     NEVER logged, NEVER written to disk, NEVER put in a heal/act request to a model.
//   * stdout carries ONLY JSON-RPC frames. All diagnostics go to stderr. A secret value
//     is never emitted on either stream.
//   * MFA/CAPTCHA are not bypassed here: on a challenge the success marker simply won't
//     match and the Go engine keeps the old secret (see browserrot.go Rotate).
'use strict';

// ---- driver loading: patchright (real fingerprint) preferred, playwright-core fallback.
function loadChromium() {
  try {
    const pw = require('patchright');
    return { chromium: pw.chromium, driver: 'patchright' };
  } catch (_) {
    const pw = require('playwright-core');
    return { chromium: pw.chromium, driver: 'playwright-core' };
  }
}

function log(...a) { process.stderr.write('[sidecar] ' + a.join(' ') + '\n'); }

// ---- humanized input (M-B2). Deliberately simple: randomized per-key delay, a short
// pre-action settle, and a plain cubic-Bézier mouse path to the target before a click.
// NO ML trajectory generation (BROWSERROT-PLAN §5 — DMTG discriminators make learned
// trajectories *more* detectable; plain Bézier+jitter is the right call for a self-login).
function jitter(min, max) { return min + Math.floor(Math.random() * (max - min)); }
async function settle(page) { await page.waitForTimeout(jitter(40, 140)); }

// bezierMove walks the mouse from its last position to (x,y) along a cubic Bézier with
// two randomized control points, in a handful of jittered steps.
async function bezierMove(page, x, y) {
  const start = bezierMove._last || { x: jitter(0, 60), y: jitter(0, 60) };
  const c1 = { x: start.x + (x - start.x) * 0.3 + jitter(-40, 40), y: start.y + (y - start.y) * 0.3 + jitter(-40, 40) };
  const c2 = { x: start.x + (x - start.x) * 0.7 + jitter(-40, 40), y: start.y + (y - start.y) * 0.7 + jitter(-40, 40) };
  const steps = jitter(14, 26);
  for (let i = 1; i <= steps; i++) {
    const t = i / steps, mt = 1 - t;
    const px = mt*mt*mt*start.x + 3*mt*mt*t*c1.x + 3*mt*t*t*c2.x + t*t*t*x;
    const py = mt*mt*mt*start.y + 3*mt*mt*t*c1.y + 3*mt*t*t*c2.y + t*t*t*y;
    await page.mouse.move(px, py);
    await page.waitForTimeout(jitter(4, 16));
  }
  bezierMove._last = { x, y };
}

// humanClick moves along a Bézier path into a random point inside the element, then clicks.
async function humanClick(page, loc) {
  const box = await loc.boundingBox();
  if (box) {
    await bezierMove(page, box.x + box.width * (0.3 + Math.random() * 0.4),
                           box.y + box.height * (0.3 + Math.random() * 0.4));
  }
  await loc.click();
}

class SidecarSession {
  constructor() {
    this.browser = null;
    this.context = null;
    this.page = null;
    this.driver = null;
    this.stealth = false;
    this.timeoutMs = 30000;
  }

  async open(params) {
    const { chromium, driver } = loadChromium();
    this.driver = driver;
    this.stealth = !!params.stealth;
    if (params.timeoutMs) this.timeoutMs = params.timeoutMs;

    const launchOpts = {
      headless: params.headless !== false,
      args: ['--no-sandbox', '--disable-dev-shm-usage'],
    };
    if (params.executablePath) launchOpts.executablePath = params.executablePath;

    this.browser = await chromium.launch(launchOpts);
    // A fresh context per session == fresh profile, so no cookies/state leak between
    // accounts (parity with go-rod's fresh-browser-per-Open).
    this.context = await this.browser.newContext();
    this.page = await this.context.newPage();
    // Navigation gets the full budget; element LOCATION gets a shorter one so a rotted
    // selector fails fast and Tier-2 heal kicks in promptly (rather than blocking the whole
    // per-op timeout). Configurable for slow SPAs.
    this.locateMs = params.locateTimeoutMs || Math.min(this.timeoutMs, 8000);
    this.page.setDefaultNavigationTimeout(this.timeoutMs);
    this.page.setDefaultTimeout(this.locateMs);
    return { ok: true, driver: this.driver, stealth: this.stealth };
  }

  async goto(params) {
    await this.page.goto(params.url, { waitUntil: 'domcontentloaded' });
    await this.page.waitForLoadState('networkidle').catch(() => {});
    return { finalURL: this.page.url() };
  }

  async fill(params) {
    // secret is base64 to survive JSON transport intact and to mark it as sensitive.
    const secret = Buffer.from(params.secret || '', 'base64');
    const loc = this.page.locator(params.selector).first();
    await loc.waitFor({ state: 'visible' });
    await settle(this.page);
    if (this.stealth) {
      // paced, per-key typing — looks human and satisfies JS-validated forms.
      await humanClick(this.page, loc);
      await loc.fill(''); // clear
      await loc.pressSequentially(secret.toString('utf8'), { delay: jitter(35, 110) });
    } else {
      await loc.fill(secret.toString('utf8'));
    }
    secret.fill(0); // best-effort wipe of the decoded buffer
    return { ok: true };
  }

  async click(params) {
    const loc = this.page.locator(params.selector).first();
    await loc.waitFor({ state: 'visible' });
    await settle(this.page);
    if (this.stealth) { await humanClick(this.page, loc); } else { await loc.click(); }
    return { ok: true };
  }

  // probe returns a snapshot of common automation-detection signals so a test can assert
  // the stealth posture (e.g. navigator.webdriver absent under patchright). It reads only
  // page globals — no secret is involved.
  async probe() {
    const sig = await this.page.evaluate(() => ({
      webdriver: navigator.webdriver === true,
      hasChrome: !!window.chrome,
      plugins: navigator.plugins.length,
      languages: (navigator.languages || []).join(','),
      headlessUA: /Headless/.test(navigator.userAgent),
    }));
    return { driver: this.driver, signals: sig };
  }

  async text(params) {
    const loc = this.page.locator(params.selector).first();
    await loc.waitFor({ state: 'visible' });
    return { text: (await loc.textContent()) || '' };
  }

  // heal (Tier-2, M-B3): relocate a field by natural-language description. Receives ONLY
  // a description + sanitized DOM structure — never a secret. Wired to Stagehand when
  // available; otherwise reports unavailable so the Go engine fails closed.
  async heal(params) {
    return healField(this.page, params);
  }

  async close() {
    try { if (this.context) await this.context.close(); } catch (_) {}
    try { if (this.browser) await this.browser.close(); } catch (_) {}
    return { ok: true };
  }
}

// healField is defined in heal.js so Stagehand stays an optional dependency.
let healField;
try {
  healField = require('./heal.js').healField;
} catch (_) {
  healField = async () => { throw new Error('heal unavailable: install @browserbasehq/stagehand and set an LLM key'); };
}

// ---- JSON-RPC dispatch loop over stdio -------------------------------------------
const session = new SidecarSession();

async function dispatch(msg) {
  const { id, method, params } = msg;
  try {
    let result;
    switch (method) {
      case 'open':  result = await session.open(params || {});  break;
      case 'goto':  result = await session.goto(params || {});  break;
      case 'fill':  result = await session.fill(params || {});  break;
      case 'click': result = await session.click(params || {}); break;
      case 'text':  result = await session.text(params || {});  break;
      case 'probe': result = await session.probe(params || {}); break;
      case 'heal':  result = await session.heal(params || {});  break;
      case 'close': result = await session.close(params || {}); break;
      default: throw new Error('unknown method: ' + method);
    }
    reply({ id, result });
  } catch (err) {
    // err.message must never contain a secret: fill()/click() only ever surface the
    // selector, and secret bytes live only in the local `secret` buffer above.
    reply({ id, error: String((err && err.message) || err) });
    if (method === 'close') process.exit(0);
  }
  if (method === 'close') process.exit(0);
}

function reply(obj) { process.stdout.write(JSON.stringify(obj) + '\n'); }

// Optional REDACTED transcript (tests/audit only; off unless INCREDIGO_SIDECAR_TRANSCRIPT
// is set). It records method + params with any `secret` field replaced by a byte-count
// placeholder, so a leak test can prove heal requests carry no secret WITHOUT ever writing
// a real secret to disk (hard rule 3).
const fs = require('fs');
const TRANSCRIPT = process.env.INCREDIGO_SIDECAR_TRANSCRIPT || '';
function record(msg) {
  if (!TRANSCRIPT) return;
  const redacted = { id: msg.id, method: msg.method, params: {} };
  const p = msg.params || {};
  for (const k of Object.keys(p)) {
    redacted.params[k] = (k === 'secret')
      ? '<redacted ' + Buffer.from(String(p[k]), 'base64').length + 'b>'
      : p[k];
  }
  try { fs.appendFileSync(TRANSCRIPT, JSON.stringify(redacted) + '\n'); } catch (_) {}
}

let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buf += chunk;
  let nl;
  while ((nl = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch (e) { log('bad JSON frame:', e.message); continue; }
    record(msg);
    dispatch(msg);
  }
});
process.stdin.on('end', async () => { await session.close().catch(() => {}); process.exit(0); });

process.on('uncaughtException', (e) => { log('uncaught:', e.message); });
process.on('unhandledRejection', (e) => { log('unhandled:', (e && e.message) || e); });

log('ready');
