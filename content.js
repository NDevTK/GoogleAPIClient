// Content script: scans the page DOM for API keys and endpoint URLs,
// and acts as a fetch relay for the background service worker.
// Content scripts share the page's cookie jar so fetches here carry
// the same credentials as the page itself — no main-world injection needed.

(function () {
  const API_KEY_RE = /AIzaSy[\w-]{33}/g;
  const ENDPOINT_RE =
    /https?:\/\/[\w.-]+(?:googleapis\.com|clients6\.google\.com|sandbox\.googleapis\.com)\/[^\s"'<>)}\]]+/g;

  const ALLOWED_HOST_RE =
    /^[\w.-]+(googleapis\.com|clients6\.google\.com|sandbox\.googleapis\.com)$/;

  function scanText(text) {
    const keys = new Set();
    const endpoints = new Set();

    let m;
    API_KEY_RE.lastIndex = 0;
    while ((m = API_KEY_RE.exec(text)) !== null) keys.add(m[0]);
    ENDPOINT_RE.lastIndex = 0;
    while ((m = ENDPOINT_RE.exec(text)) !== null) endpoints.add(m[0]);

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
    // Validate URL is a Google API host
    try {
      const parsed = new URL(msg.url);
      if (!ALLOWED_HOST_RE.test(parsed.hostname)) {
        return { error: "blocked: not a Google API host" };
      }
    } catch (_) {
      return { error: "blocked: invalid URL" };
    }

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
