// Content script: scans the page DOM for API keys and endpoint URLs,
// acts as a fetch relay for the background service worker, and relays
// intercepted response bodies from the main-world intercept script.

(function () {
  // ─── Response Body Relay (must be first — drains intercept.js buffer) ────

  document.addEventListener("__uasr_resp", (e) => {
    if (!e.detail) return;
    chrome.runtime.sendMessage({ type: "RESPONSE_BODY", ...e.detail });
  });
  // Signal intercept.js that the relay is listening — replays buffered events
  document.dispatchEvent(new CustomEvent("__uasr_ready"));

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
      // Basic heuristic: must look like an API (often has 'api' or '/v1/' or '.json')
      const url = m[0];
      if (
        url.includes("api") ||
        /\bv\d+\b/.test(url) ||
        url.endsWith(".json") ||
        url.includes("/$rpc/") ||
        url.includes("graphql")
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
      lower.includes("octet-stream")
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
      credentials: "include",
      headers,
    };

    if (msg.body != null) {
      opts.body =
        msg.bodyEncoding === "base64" ? base64ToUint8(msg.body) : msg.body;
    }

    try {
      const resp = await fetch(msg.url, opts);
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

  // Listen for messages from the background service worker
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === "PING") {
      sendResponse({ ok: true });
      return;
    }
    if (msg.type !== "PAGE_FETCH") return;
    handlePageFetch(msg).then(sendResponse);
    return true; // async sendResponse
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

  // ─── Mutation Observer (Dynamic Loading) ───────────────────────────────────

  let debounceTimer = null;
  const pendingKeys = new Set();
  const pendingEndpoints = new Set();

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
          }
          // Check other elements for text content (naive scan of innerHTML is too expensive)
          // tailored to common config patterns (e.g. JSON blobs in other tags)
          if (node.tagName === "DIV" || node.tagName === "SPAN") {
            // Optional: deep scan if needed, or specific attributes
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
  }
})();
