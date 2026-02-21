// Content script: scans the page DOM for API keys and endpoint URLs,
// acts as a fetch relay for the background service worker, and relays
// intercepted response bodies from the main-world intercept script.

(function () {
  // ─── Response Body Relay (must be first — drains intercept.js buffer) ────
  // Threat model: intercept.js (main world) is untrusted — same origin as the page.
  // This relay only forwards to background.js via sendMessage; background validates
  // the RESPONSE_BODY type against the content-script allowlist. See SECURITY.md.

  document.addEventListener("__uasr_resp", (e) => {
    if (!e.detail) return;
    const d = e.detail;
    chrome.runtime.sendMessage({
      type: "RESPONSE_BODY",
      url: d.url,
      method: d.method,
      status: d.status,
      contentType: d.contentType,
      responseHeaders: d.responseHeaders,
      body: d.body,
      base64Encoded: d.base64Encoded,
      wsId: d.wsId || null,
      channelId: d.channelId || null,
      sourceOrigin: d.sourceOrigin || null,
      targetOrigin: d.targetOrigin || null,
      requestHeaders: d.requestHeaders || null,
      requestBody: d.requestBody || null,
      requestBodyBase64: d.requestBodyBase64 || false,
    });
  });
  // Signal intercept.js that the relay is listening — replays buffered events
  document.dispatchEvent(new CustomEvent("__uasr_ready"));

  // ─── postMessage Listener ─────────────────────────────────────────────────
  // Runs in isolated world — no main-world wrapper needed. message events are
  // visible here. Stores event.source per origin for reply from console.

  let _pmIdCounter = 0;
  const _pmChannels = new Map(); // origin → pmId
  const _pmSources = new Map(); // origin → event.source (for reply)

  // ─── MessageChannel Port Tracking ───────────────────────────────────────────
  // Ports arrive via event.ports in postMessage transfers. We store them for
  // bidirectional communication and listen for incoming messages.

  let _mcIdCounter = 0;
  const _mcPorts = new Map(); // mcId → MessagePort (for sending from console)

  function _instrumentPort(port, mcId) {
    _mcPorts.set(mcId, port);
    port.addEventListener("message", (e) => {
      try {
        let body;
        try { body = JSON.stringify(e.data); } catch (_) { body = String(e.data); }
        chrome.runtime.sendMessage({
          type: "RESPONSE_BODY",
          url: location.href,
          method: "MC_RECV",
          channelId: mcId,
          status: 0,
          contentType: "messagechannel",
          responseHeaders: {},
          body: body,
          base64Encoded: false,
        });
      } catch (_) {}
    });
    port.start();
  }

  window.addEventListener("message", (event) => {
    try {
      // Instrument any transferred MessageChannel ports
      if (event.ports && event.ports.length > 0) {
        for (const port of event.ports) {
          const mcId = "mc_" + (++_mcIdCounter);
          _instrumentPort(port, mcId);
          // Notify background that a channel was established
          chrome.runtime.sendMessage({
            type: "RESPONSE_BODY",
            url: location.href,
            method: "MC_OPEN",
            channelId: mcId,
            status: 0,
            contentType: "messagechannel",
            responseHeaders: {},
            body: "",
            base64Encoded: false,
            sourceOrigin: event.origin || "null",
            targetOrigin: location.origin,
          });
        }
      }

      // Filter same-window self-messages (framework noise)
      if (event.source === window) return;
      const from = event.origin || "null";
      if (!_pmChannels.has(from)) _pmChannels.set(from, "pm_" + (++_pmIdCounter));
      const pmId = _pmChannels.get(from);
      if (event.source) _pmSources.set(from, event.source);
      let body;
      try { body = JSON.stringify(event.data); } catch (_) { body = String(event.data); }
      chrome.runtime.sendMessage({
        type: "RESPONSE_BODY",
        url: location.href,
        method: "PM_RECV",
        channelId: pmId,
        status: 0,
        contentType: "postmessage",
        responseHeaders: {},
        body: body,
        base64Encoded: false,
        sourceOrigin: from,
        targetOrigin: location.origin,
      });
    } catch (_) {}
  }, true);

  // ─── Key & Endpoint Patterns ────────────────────────────────────────────

  const API_KEY_PATTERNS = [
    { name: "Google API Key", re: /AIzaSy[\w-]{33}/g },
    { name: "Bearer Token", re: /bearer\s+[a-zA-Z0-9-._~+/]+=*/gi },
    {
      name: "Generic API Key",
      re: /(?:api[-_]?key|access[-_]?token|auth[-_]?token)['"]?\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{16,})['"]?/gi,
    },
    { name: "Firebase Key", re: /AIza[0-9A-Za-z-_]{35}/g },
    { name: "Mapbox Token", re: /pk\.[a-zA-Z0-9.]+/g },
    { name: "GitHub Token", re: /ghp_[a-zA-Z0-9]{36}/g },
    { name: "Stripe Key", re: /[sk|pk]_(?:test|live)_[0-9a-zA-Z]{24}/g },
  ];

  const ENDPOINT_RE = /https?:\/\/[\w.-]+\.[a-z]{2,}(?::\d+)?\/[^\s"'<>)}\]]+/g;

  function isGoogleApisUrl(urlString) {
    if (typeof urlString !== "string") return false;
    try {
      // Try absolute URL first
      let parsed;
      try {
        parsed = new URL(urlString);
      } catch (e) {
        // Fallback: treat as relative to the current page
        parsed = new URL(urlString, window.location.origin);
      }
      const host = parsed.hostname.toLowerCase();
      return host === "googleapis.com" || host.endsWith(".googleapis.com");
    } catch (e) {
      return false;
    }
  }

  function scanText(text) {
    const keys = new Set();
    const endpoints = new Set();

    for (const pattern of API_KEY_PATTERNS) {
      pattern.re.lastIndex = 0;
      let m;
      while ((m = pattern.re.exec(text)) !== null) {
        // Use the captured group if available, otherwise the whole match
        keys.add(m[1] || m[0]);
      }
    }

    ENDPOINT_RE.lastIndex = 0;
    let m;
    while ((m = ENDPOINT_RE.exec(text)) !== null) {
      // Heuristic: must look like an API endpoint
      const url = m[0];
      if (
        url.includes("api") ||
        /\bv\d+\b/.test(url) ||
        url.endsWith(".json") ||
        url.includes("/$rpc/") ||
        url.includes("graphql") ||
        url.includes("/rpc/") ||
        url.includes("/rest/") ||
        url.includes("/data/") ||
        url.includes("/service") ||
        url.includes("/query") ||
        url.includes("/mutation") ||
        url.includes("/batch") ||
        url.includes("/webhook") ||
        isGoogleApisUrl(url) ||
        /\.(svc|asmx|ashx|axd)([?/]|$)/.test(url)
      ) {
        endpoints.add(url);
      }
    }

    return { keys: [...keys], endpoints: [...endpoints] };
  }

  function scanPage() {
    const html = document.documentElement.outerHTML;
    const { keys, endpoints } = scanText(html);

    for (const script of document.querySelectorAll("script:not([src])")) {
      const result = scanText(script.textContent);
      for (const k of result.keys) if (!keys.includes(k)) keys.push(k);
      for (const e of result.endpoints)
        if (!endpoints.includes(e)) endpoints.push(e);
    }

    return { keys: [...new Set(keys)], endpoints: [...new Set(endpoints)] };
  }

  // ─── Form Element Scanning ────────────────────────────────────────────────

  function scanForms() {
    var forms = document.querySelectorAll("form");
    if (!forms.length) return [];
    var results = [];
    for (var i = 0; i < forms.length; i++) {
      var meta = _extractFormMetadata(forms[i]);
      if (meta) results.push(meta);
    }
    return results;
  }

  function _extractFormMetadata(form) {
    var action;
    try {
      action = new URL(form.action || location.href, location.href).href;
    } catch (_) {
      action = location.href;
    }

    var method = (form.method || "GET").toUpperCase();
    var enctype = form.enctype || "application/x-www-form-urlencoded";

    var fields = [];
    var elements = form.elements;
    var seenNames = {};

    for (var i = 0; i < elements.length; i++) {
      var el = elements[i];
      var name = el.name;
      if (!name) continue;
      if (seenNames[name] && el.type === "radio") continue;
      seenNames[name] = true;

      var field = { name: name, tagName: el.tagName.toLowerCase(), type: el.type || null };

      if (el.placeholder) field.placeholder = el.placeholder;
      if (el.required) field.required = true;
      if (el.pattern) field.pattern = el.pattern;
      if (el.minLength > 0) field.minLength = el.minLength;
      if (el.maxLength > 0 && el.maxLength < 524288) field.maxLength = el.maxLength;
      if (el.min) field.min = el.min;
      if (el.max) field.max = el.max;
      if (el.step && el.step !== "any") field.step = el.step;
      if (el.autocomplete && el.autocomplete !== "on" && el.autocomplete !== "off") {
        field.autocomplete = el.autocomplete;
      }
      if (el.value && el.type !== "password") {
        field.defaultValue = el.value;
      }

      // Select options
      if (el.tagName === "SELECT") {
        var options = [];
        for (var j = 0; j < el.options.length && j < 50; j++) {
          options.push({ value: el.options[j].value, label: el.options[j].text || el.options[j].value });
        }
        field.options = options;
      }

      // Radio button group values
      if (el.type === "radio") {
        var radios = form.querySelectorAll("input[type=\"radio\"][name=\"" + CSS.escape(name) + "\"]");
        var radioValues = [];
        for (var r = 0; r < radios.length; r++) radioValues.push(radios[r].value);
        field.options = radioValues.map(function (v) { return { value: v, label: v }; });
      }

      fields.push(field);
    }

    if (fields.length === 0) return null;

    return {
      action: action,
      method: method,
      enctype: enctype,
      id: form.id || null,
      name: form.name || null,
      fields: fields,
    };
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  function isBinaryContentType(ct) {
    if (!ct) return false;
    const lower = ct.toLowerCase();
    // JSPB (json+protobuf) is NOT binary wire format
    if (lower.includes("json")) return false;
    return (
      lower.includes("protobuf") ||
      lower.includes("proto") ||
      lower.includes("grpc") ||
      lower.includes("octet-stream") ||
      lower.startsWith("image/") ||
      lower.startsWith("video/") ||
      lower.startsWith("audio/") ||
      lower.includes("application/pdf") ||
      lower.includes("application/zip")
    );
  }

  function uint8ToBase64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i += 8192) {
      const chunk = bytes.subarray(i, Math.min(i + 8192, bytes.length));
      bin += String.fromCharCode.apply(null, chunk);
    }
    return btoa(bin);
  }

  function base64ToUint8(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ─── Fetch relay: background → content script → response ──────────────────

  async function handlePageFetch(msg) {
    // Strip browser-managed headers
    const headers = { ...(msg.headers || {}) };
    delete headers["Cookie"];
    delete headers["cookie"];
    delete headers["Origin"];
    delete headers["origin"];
    delete headers["Referer"];
    delete headers["referer"];

    const opts = {
      method: msg.method || "GET",
      credentials: "same-origin",
      headers,
    };

    if (msg.body != null) {
      opts.body =
        msg.bodyEncoding === "base64" ? base64ToUint8(msg.body) : msg.body;
    }

    try {
      const fetchUrl = msg.url + (msg.url.includes("#") ? "&" : "#") + "_uasr_send";
      const resp = await fetch(fetchUrl, opts);
      const respHeaders = {};
      resp.headers.forEach((v, k) => {
        respHeaders[k] = v;
      });
      const ct = resp.headers.get("content-type") || "";

      if (isBinaryContentType(ct)) {
        const buf = await resp.arrayBuffer();
        return {
          ok: resp.ok,
          status: resp.status,
          statusText: resp.statusText,
          headers: respHeaders,
          body: uint8ToBase64(new Uint8Array(buf)),
          bodyEncoding: "base64",
        };
      }

      const body = await resp.text();
      return {
        ok: resp.ok,
        status: resp.status,
        statusText: resp.statusText,
        headers: respHeaders,
        body,
      };
    } catch (err) {
      return { error: err.message };
    }
  }

  // Listen for messages from the background service worker.
  // Threat model: this content script runs in the web page's renderer process.
  // It only accepts PING and PAGE_FETCH from background — never reads storage
  // or handles data-returning message types. See SECURITY.md.
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === "PING") {
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "PAGE_FETCH") {
      handlePageFetch(msg).then(sendResponse);
      return true;
    }
    if (msg.type === "WS_SEND_MSG") {
      document.dispatchEvent(new CustomEvent("__uasr_ws_send", {
        detail: { wsId: msg.wsId, data: msg.data, binary: msg.binary || false }
      }));
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "PM_SEND_MSG") {
      if (!msg.targetOrigin) {
        sendResponse({ error: "targetOrigin is required" });
        return;
      }
      // Allow "*" only for sandboxed iframes (null origin) — otherwise require explicit origin
      const origin = msg.targetOrigin;
      const lookupKey = origin === "*" ? "null" : origin;
      const source = _pmSources.get(lookupKey);
      if (!source) {
        sendResponse({ error: "No source window for origin " + lookupKey });
        return;
      }
      if (origin === "*" && lookupKey !== "null") {
        sendResponse({ error: "Wildcard targetOrigin only allowed for sandboxed iframes" });
        return;
      }
      try {
        let data = msg.data;
        try { data = JSON.parse(data); } catch (_) {}
        source.postMessage(data, origin);
        sendResponse({ ok: true });
      } catch (err) {
        sendResponse({ error: err.message });
      }
      return;
    }
    if (msg.type === "MC_SEND_MSG") {
      const port = _mcPorts.get(msg.channelId);
      if (!port) {
        sendResponse({ error: "No port for channel " + msg.channelId });
        return;
      }
      try {
        let data = msg.data;
        try { data = JSON.parse(data); } catch (_) {}
        port.postMessage(data);
        sendResponse({ ok: true });
      } catch (err) {
        sendResponse({ error: err.message });
      }
      return;
    }
  });

  // ─── Init ──────────────────────────────────────────────────────────────────

  const { keys, endpoints } = scanPage();

  if (keys.length > 0) {
    chrome.runtime.sendMessage({
      type: "CONTENT_KEYS",
      keys,
      origin: location.origin,
    });
  }
  if (endpoints.length > 0) {
    chrome.runtime.sendMessage({
      type: "CONTENT_ENDPOINTS",
      endpoints,
      origin: location.origin,
    });
  }

  var forms = scanForms();
  console.log("[UASR] scanForms found", forms.length, "forms", forms);
  if (forms.length > 0) {
    chrome.runtime.sendMessage({
      type: "CONTENT_FORMS",
      forms: forms,
      origin: location.origin,
      pageUrl: location.href,
    });
  }

  // ─── Script Source Extraction (for AST analysis) ────────────────────────────

  const _sentScripts = new Set(); // track URLs/hashes already sent

  function sendScriptSource(url, code) {
    if (!code || code.length < 50) return; // skip trivial scripts
    var key = url || hashCode(code);
    if (_sentScripts.has(key)) return;
    _sentScripts.add(key);
    chrome.runtime.sendMessage({
      type: "SCRIPT_SOURCE",
      url: url || null,
      code: code,
    });
  }

  function hashCode(str) {
    var h = 0;
    for (var i = 0; i < Math.min(str.length, 200); i++) {
      h = ((h << 5) - h + str.charCodeAt(i)) | 0;
    }
    return "inline:" + h;
  }

  function extractScriptSource(scriptEl) {
    // Skip non-JavaScript script types (JSON config, importmaps, templates, etc.)
    var sType = scriptEl.type;
    if (sType && sType !== "text/javascript" && sType !== "module" &&
        !/^(application\/javascript|text\/ecmascript)$/i.test(sType)) {
      return;
    }
    if (scriptEl.src) {
      // External script — send URL to background (it has host_permissions, no CORS issues)
      var src = scriptEl.src;
      if (_sentScripts.has(src)) return;
      _sentScripts.add(src);
      chrome.runtime.sendMessage({
        type: "SCRIPT_SOURCE",
        url: src,
        code: null,  // background will fetch the source
      });
    } else {
      // Inline script
      var code = scriptEl.textContent;
      if (code) sendScriptSource(null, code);
    }
  }

  // Extract all existing scripts on page load
  document.querySelectorAll("script").forEach(extractScriptSource);

  // ─── Mutation Observer (Dynamic Loading) ───────────────────────────────────

  let debounceTimer = null;
  const pendingKeys = new Set();
  const pendingEndpoints = new Set();
  const pendingForms = [];

  const observer = new MutationObserver((mutations) => {
    let changed = false;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          // Check script tags
          if (node.tagName === "SCRIPT") {
            const res = scanText(node.textContent);
            if (res.keys.length || res.endpoints.length) {
              res.keys.forEach((k) => pendingKeys.add(k));
              res.endpoints.forEach((e) => pendingEndpoints.add(e));
              changed = true;
            }
            // Extract source for AST analysis
            extractScriptSource(node);
          }
          // Check form elements
          if (node.tagName === "FORM") {
            var formMeta = _extractFormMetadata(node);
            if (formMeta) { pendingForms.push(formMeta); changed = true; }
          } else if (node.querySelectorAll) {
            var nestedForms = node.querySelectorAll("form");
            for (var fi = 0; fi < nestedForms.length; fi++) {
              var nfMeta = _extractFormMetadata(nestedForms[fi]);
              if (nfMeta) { pendingForms.push(nfMeta); changed = true; }
            }
          }
        }
      }
    }

    if (changed) {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(flushPending, 1000);
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
  });

  function flushPending() {
    debounceTimer = null;
    if (pendingKeys.size > 0) {
      chrome.runtime.sendMessage({
        type: "CONTENT_KEYS",
        keys: [...pendingKeys],
        origin: location.origin,
      });
      pendingKeys.clear();
    }
    if (pendingEndpoints.size > 0) {
      chrome.runtime.sendMessage({
        type: "CONTENT_ENDPOINTS",
        endpoints: [...pendingEndpoints],
        origin: location.origin,
      });
      pendingEndpoints.clear();
    }
    if (pendingForms.length > 0) {
      chrome.runtime.sendMessage({
        type: "CONTENT_FORMS",
        forms: pendingForms.slice(),
        origin: location.origin,
        pageUrl: location.href,
      });
      pendingForms.length = 0;
    }
  }

  // ─── Form Submission Capture ──────────────────────────────────────────────

  document.addEventListener("submit", function (e) {
    console.log("[UASR] submit event fired", e.target?.tagName, e.target?.name);
    if (!e.target || e.target.tagName !== "FORM") return;
    try {
      var form = e.target;
      var action;
      try { action = new URL(form.action || location.href, location.href).href; }
      catch (_) { action = location.href; }

      var method = (form.method || "GET").toUpperCase();
      var enctype = form.enctype || "application/x-www-form-urlencoded";

      var fd;
      try { fd = new FormData(form); } catch (_) { return; }

      // Serialize form fields as key=value pairs
      var fields = [];
      fd.forEach(function (value, key) {
        if (typeof File !== "undefined" && value instanceof File) {
          fields.push({ name: key, value: "[File:" + value.name + "]" });
        } else {
          fields.push({ name: key, value: value });
        }
      });

      if (fields.length === 0) return;

      // For GET forms, build the full URL with query params
      var url = action;
      if (method === "GET") {
        var getUrl = new URL(action);
        for (var i = 0; i < fields.length; i++) {
          if (fields[i].value.indexOf("[File:") !== 0) {
            getUrl.searchParams.set(fields[i].name, fields[i].value);
          }
        }
        url = getUrl.href;
      }

      console.log("[UASR] sending CONTENT_FORM_SUBMIT", method, url, fields.length, "fields", fields);
      chrome.runtime.sendMessage({
        type: "CONTENT_FORM_SUBMIT",
        url: url,
        method: method,
        enctype: enctype,
        fields: fields,
        origin: location.origin,
        pageUrl: location.href,
      });
    } catch (_) {}
  }, true);
})();
