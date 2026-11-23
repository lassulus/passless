// Passless browser extension: service worker (Chromium-family browsers).
//
// The browser hands every WebAuthn request of every page to this worker
// (chrome.webAuthenticationProxy). The worker forwards it, with the origin the browser vouches
// for, to the passless native messaging host and completes the request with the host's
// responseJson verbatim, or with the DOMException name the host gives. All WebAuthn logic,
// clientDataJSON included, lives in the host; this file only relays.
//
// Wire protocol: see cmd/passless/src/browser_host/mod.rs.
(function () {
  "use strict";

  var NATIVE_HOST = "rs.passless.browser";
  var PENDING_PREFIX = "pending:";
  var DOM_NAMES = ["NotAllowedError", "NotSupportedError", "InvalidStateError", "SecurityError", "AbortError"];
  var ERROR_MESSAGE = "The operation either timed out or was not allowed.";

  var proxy = chrome.webAuthenticationProxy;
  var instance = crypto.randomUUID();
  var port = null;
  var nextId = 1;
  var byId = new Map(); // wire id -> {op, requestId}
  var byRequestId = new Map(); // browser requestId -> wire id

  function ignoreLastError() {
    return chrome.runtime.lastError;
  }

  function complete(op, arg) {
    var fn = op === "create" ? "completeCreateRequest" : "completeGetRequest";
    try {
      proxy[fn](arg, ignoreLastError); // "Invalid requestId" after a cancel is expected
    } catch (e) {
      // The request is gone already.
    }
  }

  function fail(op, requestId, name) {
    var dom = DOM_NAMES.indexOf(name) !== -1 ? name : "NotAllowedError";
    complete(op, { requestId: requestId, error: { name: dom, message: ERROR_MESSAGE } });
  }

  // Requests in flight are recorded in storage.session, so a restarted worker can fail the ones
  // its predecessor left behind instead of letting the page wait for its timeout.
  function remember(requestId, op) {
    var item = {};
    item[PENDING_PREFIX + requestId] = { op: op, instance: instance };
    chrome.storage.session.set(item, ignoreLastError);
  }

  function forget(id) {
    var entry = byId.get(id);
    if (!entry) return null;
    byId.delete(id);
    byRequestId.delete(entry.requestId);
    chrome.storage.session.remove(PENDING_PREFIX + entry.requestId, ignoreLastError);
    return entry;
  }

  function failStaleRequests() {
    chrome.storage.session.get(null, function (items) {
      if (ignoreLastError() || !items) return;
      var stale = Object.keys(items).filter(function (key) {
        return key.indexOf(PENDING_PREFIX) === 0 && items[key].instance !== instance;
      });
      stale.forEach(function (key) {
        fail(items[key].op, Number(key.slice(PENDING_PREFIX.length)), "NotAllowedError");
      });
      if (stale.length) chrome.storage.session.remove(stale, ignoreLastError);
    });
  }

  function onMessage(msg) {
    if (!msg || msg.type !== "result" || typeof msg.id !== "number") return;
    var entry = forget(msg.id);
    if (!entry) return;
    if (msg.ok === true && typeof msg.body === "string") {
      complete(entry.op, { requestId: entry.requestId, responseJson: msg.body });
    } else {
      fail(entry.op, entry.requestId, msg.error && msg.error.dom);
    }
  }

  // The host exited or could not be started: every request in flight fails.
  function onDisconnect() {
    var error = ignoreLastError();
    if (error) console.warn("passless host disconnected:", error.message);
    port = null;
    Array.from(byId.keys()).forEach(function (id) {
      var entry = forget(id);
      fail(entry.op, entry.requestId, "NotAllowedError");
    });
  }

  function connect() {
    if (port) return port;
    port = chrome.runtime.connectNative(NATIVE_HOST);
    port.onMessage.addListener(onMessage);
    port.onDisconnect.addListener(onDisconnect);
    return port;
  }

  function handleRequest(op, info) {
    var requestId = info.requestId;
    var details;
    try {
      details = JSON.parse(info.requestDetailsJson);
    } catch (e) {
      fail(op, requestId, "NotAllowedError");
      return;
    }
    // Written by the browser, not the page: the origin of the calling frame.
    var override = details && details.extensions && details.extensions.remoteDesktopClientOverride;
    if (!override || typeof override.origin !== "string") {
      fail(op, requestId, "NotAllowedError");
      return;
    }
    var id = nextId++;
    byId.set(id, { op: op, requestId: requestId });
    byRequestId.set(requestId, id);
    remember(requestId, op);
    try {
      connect().postMessage({
        type: "request",
        id: id,
        op: op,
        origin: override.origin,
        cross_origin: override.sameOriginWithAncestors === false,
        body: info.requestDetailsJson
      });
    } catch (e) {
      forget(id);
      fail(op, requestId, "NotAllowedError");
    }
  }

  function handleCanceled(requestId) {
    var id = byRequestId.get(requestId);
    if (id === undefined) return;
    forget(id);
    if (port) port.postMessage({ type: "abort", id: id });
  }

  // Listeners are registered synchronously at the top level, so a request wakes a stopped worker.
  proxy.onCreateRequest.addListener(function (info) {
    handleRequest("create", info);
  });
  proxy.onGetRequest.addListener(function (info) {
    handleRequest("get", info);
  });
  proxy.onRequestCanceled.addListener(handleCanceled);
  // Pages ask whether a platform authenticator with user verification exists before they offer
  // passkeys. Passless is one: the hardware decrypt of a passkey verifies the user. An
  // unanswered question would hang the page.
  proxy.onIsUvpaaRequest.addListener(function (info) {
    proxy.completeIsUvpaaRequest({ requestId: info.requestId, isUvpaa: true }, ignoreLastError);
  });

  failStaleRequests();
  // The attachment survives worker restarts; attaching again is harmless.
  proxy.attach(ignoreLastError);
})();
