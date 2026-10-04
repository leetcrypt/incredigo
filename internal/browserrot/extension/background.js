'use strict';
// Incredigo browserrot MV3 background service worker.
//
// This is the extension half of the native-messaging Driver (../extension.go). Chrome
// spawns the Go native host when we connectNative(); from then on the host WRITES command
// frames and READS result frames over its stdio (4-byte little-endian length-prefixed JSON —
// Chrome does that framing for us here, so this side just uses port.postMessage / onMessage).
//
// Command protocol (mirrors rod.go / sidecar.go verbs):
//   host -> { id, method: "open"|"goto"|"fill"|"click"|"text"|"close", params }
//   ext  -> { id, result:{...} }  |  { id, error:"message" }
//
// Division of labor:
//   * open  -> PINS the session to the tab that is active right now (returns its tabId). Every
//              later command targets that tab id only — never "whatever tab is active now" —
//              so a focus change mid-rotation cannot redirect a secret fill to another tab.
//   * goto  -> the background navigates the PINNED tab (content scripts cannot cross-origin
//              navigate), waits for load, and records the final URL's origin.
//   * fill/click/text -> relayed to the content actuator (content.js) on the pinned tab. A
//              fill is refused unless the pinned tab is still on the origin goto reached.
//   * close -> unpins. No browser is launched (it is the USER's browser).
//
// HARD RULES honored here (mirror the Go engine + CLAUDE.md):
//   * A secret arrives base64 in a `fill` command, is passed straight to the content script,
//     and is NEVER logged, NEVER stored, NEVER echoed. This worker does not decode it.
//   * MFA/CAPTCHA are not bypassed: a challenge makes the site's success marker not match,
//     so the Go engine keeps the old secret (browserrot.go Rotate). We just actuate fields.

const HOST_NAME = 'org.incredigo.browserrot';

let port = null;

// The pinned session: { tabId, origin }. origin is set by goto (null until then). A closed
// pinned tab marks the session dead; commands then error instead of falling back.
let session = null;

chrome.tabs.onRemoved.addListener((tabId) => {
  if (session && session.tabId === tabId) session.closed = true;
});

function connect() {
  port = chrome.runtime.connectNative(HOST_NAME);
  port.onMessage.addListener(onCommand);
  port.onDisconnect.addListener(() => {
    // The host exited (rotation finished) or was never installed. Drop the port; a fresh
    // connect happens on the next toolbar action / re-init. lastError is read to silence it.
    void chrome.runtime.lastError;
    port = null;
  });
}

async function onCommand(msg) {
  const { id, method, params } = msg || {};
  try {
    let result;
    switch (method) {
      case 'open': {
        // Re-open re-pins: the engine opens one session per Rotate/Verify, sequentially.
        const tab = await activeTab();
        session = { tabId: tab.id, origin: null, closed: false };
        result = { ok: true, tabId: tab.id };
        break;
      }
      case 'goto':
        result = await gotoSessionTab((params && params.url) || '');
        break;
      case 'fill':
      case 'click':
      case 'text':
        result = await relayToContent(method, params || {});
        break;
      case 'close':
        session = null;
        result = { ok: true };
        break;
      default:
        throw new Error('unknown method: ' + method);
    }
    reply({ id, result });
  } catch (err) {
    // err.message carries only a selector/url/status — never a secret (fill's secret lives
    // only in the base64 param handed to the content script, never in an error path here).
    reply({ id, error: String((err && err.message) || err) });
  }
}

function reply(obj) {
  if (port) port.postMessage(obj);
}

// activeTab returns the active tab in the last-focused normal window. Used ONLY by `open` to
// choose which tab to pin; no other command may consult focus.
async function activeTab() {
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  const tab = tabs && tabs[0];
  if (!tab || tab.id == null) throw new Error('no active tab');
  return tab;
}

// sessionTab returns the live pinned tab, or throws if there is no open session or the pinned
// tab is gone. It never falls back to another tab.
async function sessionTab(method) {
  if (!session) throw new Error(method + ': no open session (open first)');
  if (session.closed) throw new Error(method + ': session tab closed');
  try {
    return await chrome.tabs.get(session.tabId);
  } catch (e) {
    session.closed = true;
    throw new Error(method + ': session tab closed');
  }
}

function originOf(url) {
  try {
    return new URL(url).origin;
  } catch (e) {
    return null;
  }
}

// gotoSessionTab navigates the pinned tab to url and resolves once it finishes loading,
// returning the final URL (after redirects, e.g. an RFC 8615 /.well-known/change-password)
// and recording its origin as the only origin a fill may target.
async function gotoSessionTab(url) {
  if (!url) throw new Error('goto: empty url');
  const tab = await sessionTab('goto');
  const tabId = tab.id;
  const done = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      chrome.tabs.onUpdated.removeListener(listener);
      reject(new Error('goto: navigation timed out'));
    }, 30000);
    function listener(updatedId, info) {
      if (updatedId === tabId && info.status === 'complete') {
        clearTimeout(timer);
        chrome.tabs.onUpdated.removeListener(listener);
        resolve();
      }
    }
    chrome.tabs.onUpdated.addListener(listener);
  });
  await chrome.tabs.update(tabId, { url });
  await done;
  const fresh = await sessionTab('goto');
  const finalURL = fresh.url || url;
  session.origin = originOf(finalURL);
  return { finalURL };
}

// relayToContent forwards a DOM command to the content actuator on the pinned tab and
// normalizes a content-side error ({__error}) into a thrown Error so the host sees an error
// frame. A submit that navigates may tear the content script down before its ack returns; the
// content actuator replies BEFORE the navigation commits to avoid a lost response (see
// content.js doClick). The worker then waits for that navigation to load (settleAfterClick),
// and a `text` read waits for 'complete' and retries until the new page's content script has
// re-injected — so the result is read from the page the submit led to.
async function relayToContent(method, params) {
  const tab = await sessionTab(method);
  if (method === 'fill') {
    // A secret may only be typed into the origin goto reached (the change/login page). If the
    // tab has since moved elsewhere (a redirect, the user navigating), refuse.
    if (!session.origin) throw new Error('fill: refused before goto (no pinned origin)');
    if (originOf(tab.url) !== session.origin) {
      throw new Error('fill: refused, pinned tab left the goto origin');
    }
  }
  // Only a read is retried: re-sending a fill or click could double-type or double-submit.
  const attempts = method === 'text' ? TEXT_ATTEMPTS : 1;
  let res;
  for (let i = 1; ; i++) {
    if (method === 'text') await waitForStatus(tab.id, 'complete', LOAD_TIMEOUT_MS);
    try {
      res = await chrome.tabs.sendMessage(tab.id, { method, params });
      break;
    } catch (e) {
      if (i >= attempts) {
        throw new Error(method + ': content script unreachable on the session tab (' +
          String((e && e.message) || e) + ')');
      }
      // The next page's content script injects at document_idle, after 'complete'.
      await sleep(TEXT_RETRY_MS);
    }
  }
  if (res && res.__error) throw new Error(res.__error);
  // A click (typically a submit) may start a navigation just AFTER content.js acked it. Let it
  // settle so the following text reads the page the click led to, not the one it left.
  if (method === 'click') await settleAfterClick(tab.id);
  return res;
}

const NAV_START_WINDOW_MS = 1000; // how long a click has to start a navigation
const LOAD_TIMEOUT_MS = 30000; // same bound as goto
const TEXT_ATTEMPTS = 10;
const TEXT_RETRY_MS = 300;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// waitForStatus resolves true once tabId reports `status` (immediately if it already does),
// or false after ms. Timing out is not an error here: the read that follows fails on its own,
// and the Go engine treats an unreadable post-submit result as outcome-unknown, not success.
function waitForStatus(tabId, status, ms) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      chrome.tabs.onUpdated.removeListener(listener);
      resolve(v);
    };
    const timer = setTimeout(() => finish(false), ms);
    function listener(updatedId, info) {
      if (updatedId === tabId && info.status === status) finish(true);
    }
    chrome.tabs.onUpdated.addListener(listener); // before the check, so no event is missed
    chrome.tabs.get(tabId).then(
      (t) => { if (t.status === status) finish(true); },
      () => finish(false),
    );
  });
}

// settleAfterClick waits briefly for the click to start a navigation and, if it does, for
// that navigation to finish loading.
async function settleAfterClick(tabId) {
  const started = await waitForStatus(tabId, 'loading', NAV_START_WINDOW_MS);
  if (started) await waitForStatus(tabId, 'complete', LOAD_TIMEOUT_MS);
}

// Connect on load. If the native host is not installed, connect() throws asynchronously via
// onDisconnect; a real build would also (re)connect from a toolbar click.
try {
  connect();
} catch (e) {
  // Swallow — onDisconnect handles the not-installed case; nothing to log (no secrets, and
  // no user-facing surface in a service worker).
  void e;
}
