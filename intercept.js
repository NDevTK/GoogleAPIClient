// Main-world script: wraps fetch() and XMLHttpRequest to passively capture
// response bodies.  Communicates back to the isolated-world content script
// via CustomEvent on the shared document.
//
// Replaces the chrome.debugger approach — no yellow bar, no powerful permission.

(function () {
  "use strict";

  const EVENT_NAME = "__uasr_resp";

  // ─── Filters ────────────────────────────────────────────────────────────────

  const SKIP_CT = /^(image|font|video|audio)\//i;
  const SKIP_EXT =
    /\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp[34]|webm|webp)(\?|$)/i;

  function shouldCapture(url, contentType) {
    if (SKIP_EXT.test(url)) return false;
    if (contentType && SKIP_CT.test(contentType)) return false;
    if (contentType && contentType.startsWith("text/css")) return false;
    return true;
  }

  function isBinary(ct) {
    if (!ct) return false;
    const l = ct.toLowerCase();
    if (l.includes("json")) return false;
    if (l.includes("text")) return false;
    if (l.includes("javascript")) return false;
    return (
      l.includes("protobuf") ||
      l.includes("proto") ||
      l.includes("grpc") ||
      l.includes("octet-stream")
    );
  }

  // ─── Helpers ────────────────────────────────────────────────────────────────

  function uint8ToBase64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i += 8192) {
      const chunk = bytes.subarray(i, Math.min(i + 8192, bytes.length));
      bin += String.fromCharCode.apply(null, chunk);
    }
    return btoa(bin);
  }

  // ─── Buffered emit ──────────────────────────────────────────────────────────
  // intercept.js loads at document_start but the content script relay loads at
  // document_idle.  Buffer captured responses until the relay signals ready,
  // then replay and switch to live dispatch.

  let _relayReady = false;
  const _buffer = [];

  function emit(data) {
    if (_relayReady) {
      try {
        document.dispatchEvent(new CustomEvent(EVENT_NAME, { detail: data }));
      } catch (_) {}
    } else {
      _buffer.push(data);
    }
  }

  document.addEventListener("__uasr_ready", () => {
    _relayReady = true;
    for (const data of _buffer) {
      try {
        document.dispatchEvent(new CustomEvent(EVENT_NAME, { detail: data }));
      } catch (_) {}
    }
    _buffer.length = 0;
  });

  // ─── WebSocket send command listener ──────────────────────────────────────
  // Receives commands from content.js to send messages through live WebSocket
  // connections.  Security note: a compromised renderer already has direct
  // access to WebSocket objects, so this relay grants no new capability.

  document.addEventListener("__uasr_ws_send", function (e) {
    if (!e.detail) return;
    var wsId = e.detail.wsId, data = e.detail.data, binary = e.detail.binary;
    var ws = _wsConnections.get(wsId);
    if (!ws || ws.readyState !== 1) return;
    try {
      if (binary && typeof data === "string") {
        var bin = atob(data);
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        ws.send(bytes.buffer);
      } else {
        ws.send(data);
      }
    } catch (_) {}
  });


  // ─── fetch() wrapper ───────────────────────────────────────────────────────

  const _fetch = window.fetch;

  window.fetch = async function (input, init) {
    const response = await _fetch.apply(this, arguments);

    try {
      const raw =
        typeof input === "string"
          ? input
          : input instanceof Request
            ? input.url
            : String(input);
      const url = new URL(raw, location.href).href;
      const method =
        (init && init.method) ||
        (input instanceof Request ? input.method : "GET");
      const ct = response.headers.get("content-type") || "";

      if (shouldCapture(url, ct)) {
        const clone = response.clone();
        // Read body asynchronously — never blocks the caller
        (async () => {
          try {
            const headers = {};
            clone.headers.forEach((v, k) => {
              headers[k] = v;
            });

            let body,
              base64Encoded = false;
            if (isBinary(ct)) {
              const buf = await clone.arrayBuffer();
              body = uint8ToBase64(new Uint8Array(buf));
              base64Encoded = true;
            } else {
              body = await clone.text();
            }

            emit({
              url,
              method: method.toUpperCase(),
              status: clone.status,
              contentType: ct,
              responseHeaders: headers,
              body,
              base64Encoded,
            });
          } catch (_) {}
        })();
      }
    } catch (_) {}

    return response;
  };

  // ─── XMLHttpRequest wrapper ─────────────────────────────────────────────────

  const _xhrOpen = XMLHttpRequest.prototype.open;
  const _xhrSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url) {
    this.__uasr_method = method;
    this.__uasr_url = url;
    return _xhrOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function () {
    if (this.__uasr_hooked) return _xhrSend.apply(this, arguments);
    this.__uasr_hooked = true;
    this.addEventListener("load", function () {
      try {
        const url = new URL(
          String(this.__uasr_url || ""),
          location.href,
        ).href;
        const ct = this.getResponseHeader("content-type") || "";
        if (!shouldCapture(url, ct)) return;

        // Collect response headers
        const rawHeaders = this.getAllResponseHeaders();
        const headers = {};
        for (const line of rawHeaders.trim().split(/\r?\n/)) {
          const idx = line.indexOf(":");
          if (idx > 0)
            headers[line.slice(0, idx).trim().toLowerCase()] =
              line.slice(idx + 1).trim();
        }

        let body,
          base64Encoded = false;
        if (this.responseType === "arraybuffer" && this.response) {
          body = uint8ToBase64(new Uint8Array(this.response));
          base64Encoded = true;
        } else if (this.responseType === "" || this.responseType === "text") {
          body = this.responseText;
          if (!body) return;
        } else if (this.responseType === "json") {
          try {
            body = JSON.stringify(this.response);
            if (!body) return;
          } catch (_) {
            return;
          }
        } else {
          return; // blob, document — skip
        }

        emit({
          url,
          method: (this.__uasr_method || "GET").toUpperCase(),
          status: this.status,
          contentType: ct,
          responseHeaders: headers,
          body,
          base64Encoded,
        });
      } catch (_) {}
    });

    return _xhrSend.apply(this, arguments);
  };

  // ─── WebSocket wrapper ──────────────────────────────────────────────────────

  var _wsIdCounter = 0;
  var _wsConnections = new Map();

  const _WebSocket = window.WebSocket;

  class WrappedWebSocket extends _WebSocket {
    constructor(url, protocols) {
      super(url, protocols);
      const wsUrl = typeof url === "string" ? url : String(url);
      const wsId = "ws_" + (++_wsIdCounter);
      _wsConnections.set(wsId, this);

      this.addEventListener("open", function () {
        try {
          emit({ url: wsUrl, method: "WS_OPEN", wsId: wsId, status: 0,
            contentType: "websocket", responseHeaders: {}, body: null, base64Encoded: false });
        } catch (_) {}
      });

      this.addEventListener("close", function (ev) {
        try {
          emit({ url: wsUrl, method: "WS_CLOSE", wsId: wsId, status: ev.code || 1000,
            contentType: "websocket", responseHeaders: {}, body: ev.reason || "", base64Encoded: false });
        } catch (_) {}
        _wsConnections.delete(wsId);
      });

      // Capture outbound messages
      const _origSend = this.send.bind(this);
      this.send = function (data) {
        try {
          let body, base64Encoded = false;
          if (typeof data === "string") {
            body = data;
          } else if (data instanceof ArrayBuffer) {
            body = uint8ToBase64(new Uint8Array(data));
            base64Encoded = true;
          } else if (data instanceof Uint8Array) {
            body = uint8ToBase64(data);
            base64Encoded = true;
          } else if (typeof Blob !== "undefined" && data instanceof Blob) {
            data.arrayBuffer().then(function (ab) {
              emit({ url: wsUrl, method: "WS_SEND", wsId: wsId, status: 0,
                contentType: "websocket", responseHeaders: {},
                body: uint8ToBase64(new Uint8Array(ab)), base64Encoded: true });
            }).catch(function () {});
            return _origSend(data);
          }
          emit({ url: wsUrl, method: "WS_SEND", wsId: wsId, status: 0,
            contentType: "websocket", responseHeaders: {}, body, base64Encoded });
        } catch (_) {}
        return _origSend(data);
      };

      // Capture inbound messages
      this.addEventListener("message", function (e) {
        try {
          let body, base64Encoded = false;
          if (typeof e.data === "string") {
            body = e.data;
          } else if (e.data instanceof ArrayBuffer) {
            body = uint8ToBase64(new Uint8Array(e.data));
            base64Encoded = true;
          } else if (typeof Blob !== "undefined" && e.data instanceof Blob) {
            e.data.arrayBuffer().then(function (ab) {
              emit({ url: wsUrl, method: "WS_RECV", wsId: wsId, status: 0,
                contentType: "websocket", responseHeaders: {},
                body: uint8ToBase64(new Uint8Array(ab)), base64Encoded: true });
            }).catch(function () {});
            return;
          }
          emit({ url: wsUrl, method: "WS_RECV", wsId: wsId, status: 0,
            contentType: "websocket", responseHeaders: {}, body, base64Encoded });
        } catch (_) {}
      });
    }
  }

  window.WebSocket = WrappedWebSocket;

  // ─── EventSource wrapper ────────────────────────────────────────────────────

  const _EventSource = window.EventSource;

  if (_EventSource) {
    class WrappedEventSource extends _EventSource {
      constructor(url, opts) {
        super(url, opts);
        const esUrl = typeof url === "string" ? url : String(url);

        this.addEventListener("message", function (e) {
          try {
            emit({
              url: esUrl,
              method: "SSE",
              status: 200,
              contentType: "text/event-stream",
              responseHeaders: {},
              body: e.data,
              base64Encoded: false,
            });
          } catch (_) {}
        });
      }
    }

    window.EventSource = WrappedEventSource;
  }

  // ─── sendBeacon wrapper ─────────────────────────────────────────────────────

  const _sendBeacon = navigator.sendBeacon;

  if (_sendBeacon) {
    navigator.sendBeacon = function (url, data) {
      try {
        const beaconUrl = new URL(url, location.href).href;
        let body = null, base64Encoded = false;
        if (typeof data === "string") {
          body = data;
        } else if (data instanceof Uint8Array) {
          body = uint8ToBase64(data);
          base64Encoded = true;
        } else if (data instanceof ArrayBuffer) {
          body = uint8ToBase64(new Uint8Array(data));
          base64Encoded = true;
        } else if (typeof URLSearchParams !== "undefined" && data instanceof URLSearchParams) {
          body = data.toString();
        } else if (typeof FormData !== "undefined" && data instanceof FormData) {
          // FormData can't be serialized simply — skip body
        } else if (typeof Blob !== "undefined" && data instanceof Blob) {
          // Can't read synchronously — emit URL only
        }
        if (shouldCapture(beaconUrl, "")) {
          emit({
            url: beaconUrl,
            method: "BEACON",
            status: 0,
            contentType: "beacon",
            responseHeaders: {},
            body,
            base64Encoded,
          });
        }
      } catch (_) {}
      return _sendBeacon.apply(navigator, arguments);
    };
  }

})();
