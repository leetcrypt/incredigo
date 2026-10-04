'use strict';
// Tier-2 self-heal for the browserrot sidecar. Given a natural-language field description
// and the LIVE page, return a fresh CSS selector for that field. The Go engine calls this
// only when a Tier-1 recipe selector misses, then re-persists the healed selector.
//
// HARD RULE (CLAUDE.md 6 / BROWSERROT-PLAN §1): heal receives ONLY a description + the
// page's structure. It is NEVER handed a secret, and it MUST NOT read field VALUES — it
// derives selectors from tag/type/name/id/placeholder/label/aria text only.
//
// Two strategies, in order:
//   1. Stagehand `observe` (LLM) — used when @browserbasehq/stagehand is installed AND an
//      LLM key is present. The model sees sanitized DOM structure, never a value.
//   2. Deterministic DOM heuristic (no model) — a keyword/attribute match over form
//      controls. Hermetic and offline; this is what the lab proof exercises.

// --- keyword buckets derived from the field descriptions the engine sends. ------------
const BUCKETS = [
  { key: 'current', words: ['current', 'old', 'existing'], type: 'password' },
  { key: 'confirm', words: ['confirm', 'again', 're-enter', 'reenter', 'repeat', 'verify'], type: 'password' },
  { key: 'new',     words: ['new'], type: 'password' },
  { key: 'username',words: ['username', 'user name', 'email', 'e-mail', 'login', 'account'], type: 'text' },
  { key: 'password',words: ['password', 'pass'], type: 'password' },
  { key: 'submit',  words: ['submit', 'save', 'change', 'update', 'apply', 'continue'], type: 'button' },
  { key: 'login',   words: ['log in', 'log-in', 'login', 'sign in', 'sign-in'], type: 'button' },
  { key: 'status',  words: ['success', 'error', 'status', 'message', 'result', 'alert'], type: 'text' },
];

function bucketFor(desc) {
  const d = (desc || '').toLowerCase();
  // Most specific buckets first (current/confirm before generic password).
  for (const b of BUCKETS) {
    if (b.words.some((w) => d.includes(w))) return b;
  }
  return null;
}

// heuristicHeal walks the page's form controls and picks the best selector for the bucket.
// It reads structure/attributes only — never element.value.
async function heuristicHeal(page, desc) {
  const bucket = bucketFor(desc);
  const kind = bucket ? bucket.type : 'text';
  const words = bucket ? bucket.words : (desc || '').toLowerCase().split(/\s+/);

  // Collect candidate elements + their non-value descriptive text, in the browser.
  const cands = await page.evaluate((kind) => {
    function labelText(el) {
      let t = '';
      if (el.id) {
        const l = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
        if (l) t += ' ' + l.textContent;
      }
      const p = el.closest('label');
      if (p) t += ' ' + p.textContent;
      return t;
    }
    let sel;
    if (kind === 'password') sel = 'input[type=password]';
    else if (kind === 'button') sel = 'button, input[type=submit], [role=button]';
    else if (kind === 'text') sel = 'input, [role=alert], .message, .result, .status, h1, h2, p, span, div';
    else sel = 'input';
    const out = [];
    let i = 0;
    for (const el of document.querySelectorAll(sel)) {
      // descriptive attributes ONLY — never el.value
      const desc = [
        el.getAttribute('name'), el.id, el.getAttribute('placeholder'),
        el.getAttribute('aria-label'), el.getAttribute('autocomplete'),
        el.getAttribute('title'), labelText(el),
        (el.tagName === 'BUTTON' || el.tagName === 'H1' || el.tagName === 'H2') ? el.textContent : '',
      ].filter(Boolean).join(' ').toLowerCase();
      // stable selector: prefer #id, else name=, else nth of the candidate set
      let css;
      if (el.id) css = '#' + CSS.escape(el.id);
      else if (el.getAttribute('name')) css = el.tagName.toLowerCase() + '[name="' + el.getAttribute('name') + '"]';
      else { el.setAttribute('data-incredigo-heal', String(i)); css = '[data-incredigo-heal="' + i + '"]'; }
      out.push({ css, desc });
      i++;
    }
    return out;
  }, kind);

  // Score by keyword hits; the ordering of BUCKETS already disambiguates current/new/confirm.
  let best = null, bestScore = -1;
  for (const c of cands) {
    let score = 0;
    for (const w of words) if (c.desc.includes(w)) score += 2;
    if (score > bestScore) { bestScore = score; best = c; }
  }
  // For password fields with no keyword hit, fall back to positional convention
  // (current, new, confirm) handled by the caller ordering; here just return first.
  if (!best && cands.length) best = cands[0];
  if (!best) throw new Error('heal: no candidate element for "' + desc + '"');
  return best.css;
}

// stagehandHeal uses the Stagehand `observe` API to locate the field with an LLM. It is
// STRICTLY OPT-IN (INCREDIGO_HEAL_STRATEGY=stagehand) and UNPROVEN: Stagehand owns its own
// browser in LOCAL mode, so wiring it to drive the sidecar's existing page needs more work
// (§9). Until then the deterministic heuristic below is the proven Tier-2. The model would
// see DOM structure only, never a value. Returns null to signal "use heuristic".
async function stagehandHeal(page, desc) {
  if (process.env.INCREDIGO_HEAL_STRATEGY !== 'stagehand') return null; // not opted in
  let Stagehand;
  try { ({ Stagehand } = require('@browserbasehq/stagehand')); }
  catch (_) { return null; } // not installed
  const key = process.env.INCREDIGO_HEAL_LLM_KEY || process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY;
  if (!key) return null; // no key
  const sh = new Stagehand({ env: 'LOCAL', modelName: process.env.INCREDIGO_HEAL_MODEL || 'claude-3-5-sonnet-latest' });
  await sh.init({ page });
  const results = await sh.page.observe({ instruction: 'find ' + desc });
  if (Array.isArray(results) && results.length && results[0].selector) return results[0].selector;
  return null;
}

async function healField(page, params) {
  const desc = (params && params.description) || '';
  // The deterministic heuristic is the default, proven Tier-2. The LLM strategy is opt-in
  // and experimental; if it is enabled and errors, we still fall back to the heuristic.
  try {
    const viaLLM = await stagehandHeal(page, desc);
    if (viaLLM) return { selector: viaLLM, strategy: 'stagehand' };
  } catch (e) {
    process.stderr.write('[sidecar] stagehand heal failed, falling back: ' + e.message + '\n');
  }
  const selector = await heuristicHeal(page, desc);
  return { selector, strategy: 'heuristic' };
}

module.exports = { healField };
