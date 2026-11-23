// Passless, background: relays WebAuthn requests from the content scripts to the passless
// native messaging host and back. The origin of a request is the URL of the frame the browser
// says sent it, never anything the page wrote. Wire protocol: cmd/passless/src/browser_host/mod.rs.
"use strict";

var NATIVE_HOST = "rs.passless.browser";

var port = null;
var nextWireId = 1;
var inflight = new Map(); // wire id -> {resolve, key}
var byKey = new Map(); // "<tab>:<frame>:<page id>" -> wire id

function origin(url) {
  try {
    var parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.origin : null;
  } catch (e) {
    return null;
  }
}

function settle(wireId, result) {
  var entry = inflight.get(wireId);
  if (!entry) return;
  inflight.delete(wireId);
  byKey.delete(entry.key);
  entry.resolve(result);
}

function connect() {
  if (port) return port;
  var current = browser.runtime.connectNative(NATIVE_HOST);
  current.onMessage.addListener(function (msg) {
    if (!msg || msg.type !== "result" || typeof msg.id !== "number") return;
    if (msg.ok === true && typeof msg.body === "string") settle(msg.id, { ok: true, body: msg.body });
    else settle(msg.id, { ok: false, dom: (msg.error && msg.error.dom) || "NotAllowedError" });
  });
  current.onDisconnect.addListener(function (p) {
    if (port === current) port = null;
    var error = p.error && p.error.message;
    // A missing host means passless is not installed: the page falls back to the browser.
    var unavailable = typeof error === "string" && /no such native application/i.test(error);
    if (error) console.warn("passless host disconnected:", error);
    Array.from(inflight.keys()).forEach(function (wireId) {
      settle(wireId, unavailable ? { unavailable: true } : { ok: false, dom: "NotAllowedError" });
    });
  });
  port = current;
  return port;
}

browser.runtime.onMessage.addListener(function (msg, sender) {
  if (sender.id !== browser.runtime.id || !sender.tab || !msg || typeof msg.id !== "number") return;
  var key = sender.tab.id + ":" + sender.frameId + ":" + msg.id;

  if (msg.type === "abort") {
    var wireId = byKey.get(key);
    if (wireId === undefined) return;
    settle(wireId, { ok: false, dom: "AbortError" });
    if (port) port.postMessage({ type: "abort", id: wireId });
    return;
  }
  if (msg.type !== "request" || (msg.op !== "create" && msg.op !== "get") || typeof msg.body !== "string") return;

  var frameOrigin = origin(sender.url);
  if (!frameOrigin) return Promise.resolve({ ok: false, dom: "NotAllowedError" });
  // A frame other than the top one is cross-origin unless it shares the tab's origin.
  var crossOrigin = sender.frameId !== 0 && origin(sender.tab.url) !== frameOrigin;

  return new Promise(function (resolve) {
    var wireId = nextWireId++;
    inflight.set(wireId, { resolve: resolve, key: key });
    byKey.set(key, wireId);
    try {
      connect().postMessage({
        type: "request",
        id: wireId,
        op: msg.op,
        origin: frameOrigin,
        cross_origin: crossOrigin,
        body: msg.body
      });
    } catch (e) {
      settle(wireId, { ok: false, dom: "NotAllowedError" });
    }
  });
});
