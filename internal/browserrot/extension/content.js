'use strict';
// Incredigo browserrot content actuator (Tier-1).
//
// Runs in the page's isolated world on the ACTIVE tab. On a message from the background
// worker it locates a change-password form field BY THE SAME CSS SELECTOR the deterministic
// recipe (sites.go / Site.Form) uses, and fills / clicks / reads it. This is the browser
// analog of rod.go's Element(selector).Input / Click / Text — a third actuator for the one
// Session contract.
//
// SECRET SEAM (documented honestly): a `fill` command carries the value base64-encoded. It is
// decoded here, assigned to the input's value exactly once (through the native setter so JS-
// framework forms observe the change), then the decoded string is dropped. It is NEVER logged,
// NEVER stored, NEVER sent anywhere but the one input element.
//
// MFA/CAPTCHA are never bypassed here: this actuator only fills the fields the recipe names.
// A challenge simply makes the site's success marker (read via `text`) not match, and the Go
// engine keeps the old secret.

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  handle(msg)
    .then((r) => sendResponse(r))
    .catch((e) => sendResponse({ __error: String((e && e.message) || e) }));
  return true; // keep the message channel open for the async response
});

async function handle(msg) {
  const { method, params } = msg || {};
  switch (method) {
    case 'fill':
      return doFill(params || {});
    case 'click':
      return doClick(params || {});
    case 'text':
      return doText(params || {});
    default:
      throw new Error('content: unknown method ' + method);
  }
}

// find resolves a selector to a single element or throws — the Tier-1 "selector miss" that,
// on the Go side, fails closed (a Session with no Healer). The recipe's selectors are expected
// to match; a miss is surfaced verbatim (no secret involved).
function find(selector) {
  if (!selector) throw new Error('empty selector');
  const el = document.querySelector(selector);
  if (!el) throw new Error('selector not found: ' + selector);
  return el;
}

// base64ToUtf8 decodes the transported secret into the exact bytes to type.
function base64ToUtf8(b64) {
  const bin = atob(b64 || '');
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

// setNativeValue assigns through the prototype's value setter so React/Vue-style value
// trackers observe the change (a plain el.value = x is silently reverted by React).
function setNativeValue(el, value) {
  const proto = Object.getPrototypeOf(el);
  const desc = Object.getOwnPropertyDescriptor(proto, 'value');
  if (desc && desc.set) {
    desc.set.call(el, value);
  } else {
    el.value = value;
  }
}

function doFill(params) {
  const el = find(params.selector);
  let value = base64ToUtf8(params.secret);
  try {
    el.focus();
    setNativeValue(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  } finally {
    // Best-effort drop of the plaintext reference; the browser still holds it in the input's
    // value (unavoidable — that IS the field), but no copy lingers in this closure.
    value = null;
  }
  return { ok: true };
}

function doClick(params) {
  const el = find(params.selector);
  // A submit click typically navigates, which tears this content script down. Trigger the
  // click, then return synchronously in the same task so sendResponse is dispatched BEFORE the
  // navigation commits (the `text` read afterwards runs against the freshly loaded page, whose
  // content script is re-injected by the manifest's content_scripts registration).
  el.click();
  return { ok: true };
}

function doText(params) {
  const el = find(params.selector);
  return { text: (el.textContent || '').trim() };
}
