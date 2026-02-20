// Main-world script: wraps fetch() and XMLHttpRequest to passively capture
// request headers/bodies and response bodies.  Communicates back to the
// isolated-world content script via CustomEvent on the shared document.
//
// Single capture point — replaces chrome.webRequest for all request data.

(function () {
  "use strict";

  const EVENT_NAME = "__uasr_resp";

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

  function _isInternalUrl(url) {
    return url.includes("#_uasr_send") || url.includes("#_internal_probe");
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


  // ─── Request header/body capture helpers ──────────────────────────────────

  function _captureHeaders(input, init) {
    var h = {};
    try {
      var src = (init && init.headers) || (input instanceof Request ? input.headers : null);
      if (!src) return h;
      if (src instanceof Headers) {
        src.forEach(function (v, k) { h[k] = v; });
      } else if (Array.isArray(src)) {
        for (var i = 0; i < src.length; i++) h[src[i][0].toLowerCase()] = src[i][1];
      } else if (typeof src === "object") {
        for (var k in src) h[k.toLowerCase()] = src[k];
      }
    } catch (_) {}
    return h;
  }

  function _captureBody(bodySource) {
    var reqBody = null, reqBase64 = false;
    try {
      if (bodySource == null) return { body: null, base64: false };
      if (typeof bodySource === "string") {
        reqBody = bodySource;
      } else if (bodySource instanceof ArrayBuffer) {
        reqBody = uint8ToBase64(new Uint8Array(bodySource));
        reqBase64 = true;
      } else if (bodySource instanceof Uint8Array) {
        reqBody = uint8ToBase64(bodySource);
        reqBase64 = true;
      } else if (typeof URLSearchParams !== "undefined" && bodySource instanceof URLSearchParams) {
        reqBody = bodySource.toString();
      }
      // FormData, Blob, ReadableStream — can't serialize simply, skip
    } catch (_) {}
    return { body: reqBody, base64: reqBase64 };
  }

  // ─── fetch() wrapper ───────────────────────────────────────────────────────

  const _fetch = window.fetch;

  window.fetch = async function (input, init) {
    // Snapshot request data before calling fetch (body may be consumed)
    var reqHeaders = _captureHeaders(input, init);
    var bodySource = (init && init.body !== undefined) ? init.body : null;
    var captured = _captureBody(bodySource);
    var reqBody = captured.body;
    var reqBase64 = captured.base64;

    const response = await _fetch.apply(this, arguments);

    try {
      const raw =
        typeof input === "string"
          ? input
          : input instanceof Request
            ? input.url
            : String(input);
      const url = new URL(raw, location.href).href;

      if (_isInternalUrl(url)) return response;

      const method =
        (init && init.method) ||
        (input instanceof Request ? input.method : "GET");
      const ct = response.headers.get("content-type") || "";

      const clone = response.clone();
      // Read body asynchronously — never blocks the caller
      (async () => {
        try {
          const headers = {};
          clone.headers.forEach((v, k) => {
            headers[k] = v;
          });

          // If body wasn't captured synchronously (Request with stream body),
          // try reading from a cloned Request
          if (reqBody === null && input instanceof Request && !init) {
            try {
              var rc = input.clone();
              var ct2 = reqHeaders["content-type"] || "";
              if (isBinary(ct2)) {
                var ab = await rc.arrayBuffer();
                reqBody = uint8ToBase64(new Uint8Array(ab));
                reqBase64 = true;
              } else {
                reqBody = await rc.text();
              }
            } catch (_) {}
          }

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
            requestHeaders: reqHeaders,
            requestBody: reqBody,
            requestBodyBase64: reqBase64,
          });
        } catch (_) {}
      })();
    } catch (_) {}

    return response;
  };

  // ─── XMLHttpRequest wrapper ─────────────────────────────────────────────────

  const _xhrOpen = XMLHttpRequest.prototype.open;
  const _xhrSend = XMLHttpRequest.prototype.send;
  const _xhrSetHeader = XMLHttpRequest.prototype.setRequestHeader;

  XMLHttpRequest.prototype.open = function (method, url) {
    this.__uasr_method = method;
    this.__uasr_url = url;
    this.__uasr_reqHeaders = {};
    return _xhrOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
    if (!this.__uasr_reqHeaders) this.__uasr_reqHeaders = {};
    this.__uasr_reqHeaders[name.toLowerCase()] = value;
    return _xhrSetHeader.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (sendBody) {
    if (this.__uasr_hooked) return _xhrSend.apply(this, arguments);
    this.__uasr_hooked = true;

    // Capture request body before sending
    var captured = _captureBody(sendBody);
    var _reqHeaders = this.__uasr_reqHeaders || {};
    var _reqBody = captured.body;
    var _reqBase64 = captured.base64;

    this.addEventListener("load", function () {
      try {
        const url = new URL(
          String(this.__uasr_url || ""),
          location.href,
        ).href;

        if (_isInternalUrl(url)) return;

        const ct = this.getResponseHeader("content-type") || "";
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
          requestHeaders: _reqHeaders,
          requestBody: _reqBody,
          requestBodyBase64: _reqBase64,
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

})();
