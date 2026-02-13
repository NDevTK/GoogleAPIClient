// Service worker: intercepts network requests to Google APIs,
// extracts API keys, endpoints, auth headers, and coordinates
// discovery document fetching + req2proto fallback probing.

importScripts("lib/protobuf.js", "lib/discovery.js", "lib/req2proto.js");

// ─── State ───────────────────────────────────────────────────────────────────

const state = {
  // Map<tabId, TabData>
  tabs: new Map(),
  // Map<tabId, boolean>
  attachedTabs: new Map(),
  // Map<requestId, url> for transient key scanning (scripts etc)
  tempRequestMap: new Map(),
};

// ─── Debugger Management ─────────────────────────────────────────────────────

const DebuggerManager = {
  async attach(tabId) {
    const status = state.attachedTabs.get(tabId);
    if (status === true || status === "pending") return;

    state.attachedTabs.set(tabId, "pending");
    try {
      await chrome.debugger.attach({ tabId }, "1.3");
      state.attachedTabs.set(tabId, true);
      await chrome.debugger.sendCommand({ tabId }, "Network.enable");
    } catch (err) {
      state.attachedTabs.delete(tabId);
      // Silence expected browser restricted errors
      const isExpectedError =
        err.message.includes("Another debugger is already attached") ||
        err.message.includes("Cannot access a chrome:// URL");

      if (!isExpectedError) {
        console.error(`[Debugger] Attach failed for ${tabId}:`, err);
      }
    }
  },

  async getResponseBody(tabId, requestId) {
    try {
      const result = await chrome.debugger.sendCommand(
        { tabId },
        "Network.getResponseBody",
        { requestId },
      );
      return result; // { body, base64Encoded }
    } catch (err) {
      console.warn("[Debugger] Get response body failed:", err);
      return null;
    }
  },
};

chrome.debugger.onEvent.addListener(async (source, method, params) => {
  const tabId = source.tabId;
  if (method === "Network.requestWillBeSent") {
    state.tempRequestMap.set(params.requestId, params.request.url);
  }

  if (method === "Network.responseReceived") {
    const { requestId, response } = params;
    const url = new URL(response.url);
    if (!isApiRequest(url, { method: response.method })) return;

    // Store response metadata
    const tab = getTab(tabId);
    const entry = tab.requestLog.find((r) => r.id === requestId);
    if (entry) {
      entry.responseHeaders = response.headers;
      entry.status = response.status;
      entry.mimeType = response.mimeType;
    }
  }

  if (method === "Network.loadingFinished") {
    const { requestId } = params;
    const tab = getTab(tabId);

    const bodyData = await DebuggerManager.getResponseBody(tabId, requestId);
    if (bodyData) {
      let textBody = bodyData.body;
      if (bodyData.base64Encoded) {
        try {
          const bytes = base64ToUint8(bodyData.body);
          textBody = new TextDecoder().decode(bytes);
        } catch (e) {
          textBody = null; // Truly binary
        }
      }

      const entry = tab.requestLog.find((r) => r.id === requestId);

      // Always scan for keys in captured bodies (scripts, JSON, etc)
      if (textBody) {
        let url = state.tempRequestMap.get(requestId);
        if (!url && entry) {
          url = entry.url;
        }
        extractKeysFromText(tabId, textBody, url, "response_body");
      }
      state.tempRequestMap.delete(requestId);

      if (entry) {
        entry.responseBody = bodyData.body;
        entry.responseBase64 = bodyData.base64Encoded;

        // Learn schema from the response!
        const service =
          entry.service || extractInterfaceName(new URL(entry.url));
        learnFromResponse(tabId, service, entry);
        notifyPopup(tabId);
      }
    }
  }
});

chrome.debugger.onDetach.addListener((source) => {
  state.attachedTabs.delete(source.tabId);
});

// Global persistent store — survives tab closes and SW restarts
const globalStore = {
  apiKeys: new Map(), // key → { origin, referer, firstSeen, ... }
  endpoints: new Map(), // endpointKey → endpoint data
  discoveryDocs: new Map(), // service → { status, url, method, apiKey, fetchedAt, summary }
  probeResults: new Map(), // endpointKey → probe result
  scopes: new Map(), // service → string[]
};

// ─── Key Extraction ──────────────────────────────────────────────────────────

const KEY_PATTERNS = [
  { name: "Google API Key", re: /AIzaSy[\w-]{33}/g },
  { name: "Firebase Key", re: /AIza[0-9A-Za-z-_]{35}/g },
  { name: "Bearer Token", re: /bearer\s+([a-zA-Z0-9-._~+/]+=*)/gi },
  {
    name: "Generic API Key",
    re: /(?:api[-_]?key|access[-_]?token|auth[-_]?token)['"]?\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{16,})['"]?/gi,
  },
  { name: "JWT", re: /ey[a-zA-Z0-9-_]+\.ey[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+/g },
  { name: "Mapbox Token", re: /pk\.[a-zA-Z0-9.]+/g },
  { name: "GitHub Token", re: /ghp_[a-zA-Z0-9]{36}/g },
  { name: "Stripe Key", re: /[sk|pk]_(?:test|live)_[0-9a-zA-Z]{24}/g },
];

// ─── batchexecute Decoding ──────────────────────────────────────────────────

function extractKeysFromText(tabId, text, sourceUrl, sourceContext, depth = 0) {
  if (!text || depth > 3) return; // Prevent infinite recursion
  const tab = getTab(tabId);
  const url = sourceUrl ? new URL(sourceUrl) : null;
  const service = url ? extractInterfaceName(url) : "unknown";

  // 1. Scan for direct key matches
  for (const pattern of KEY_PATTERNS) {
    pattern.re.lastIndex = 0;
    let m;
    while ((m = pattern.re.exec(text)) !== null) {
      const key = m[1] || m[0];
      if (key.length < 10) continue;

      if (!tab.apiKeys.has(key)) {
        tab.apiKeys.set(key, {
          name: pattern.name,
          origin: url ? url.origin : null,
          referer: url ? url.href : null,
          source: sourceContext || "network",
          firstSeen: Date.now(),
          lastSeen: Date.now(),
          services: new Set(),
          hosts: new Set(),
          endpoints: new Set(),
          requestCount: 0,
        });
      }

      const keyData = tab.apiKeys.get(key);
      keyData.lastSeen = Date.now();
      if (url) {
        keyData.services.add(service);
        keyData.hosts.add(url.hostname);
        keyData.endpoints.add(`${url.hostname}${url.pathname}`);
      }
    }
  }

  // 2. Scan for base64 blobs that might contain hidden keys
  // Heuristic: looking for strings > 20 chars that look like base64
  const B64_RE = /[a-zA-Z0-9+/]{20,}=*/g;
  let b64m;
  while ((b64m = B64_RE.exec(text)) !== null) {
    const candidate = b64m[0];
    try {
      // Don't try to decode if it's already a known key to avoid loops
      if (tab.apiKeys.has(candidate)) continue;

      // Ensure proper padding for atob
      const padded =
        candidate.length % 4 === 0
          ? candidate
          : candidate + "=".repeat(4 - (candidate.length % 4));
      const decoded = atob(padded);

      // Heuristic: If it looks like printable text or JSON, scan it recursively
      // Filter out non-printable garbage to avoid regex hangs
      const printable = decoded.replace(/[^\x20-\x7E\t\n\r]/g, "");
      if (printable.length > 10) {
        extractKeysFromText(
          tabId,
          printable,
          sourceUrl,
          sourceContext + " > b64",
          depth + 1,
        );
      }
    } catch (e) {
      // Not valid base64, ignore
    }
  }
}

function getTab(tabId) {
  if (!state.tabs.has(tabId)) {
    state.tabs.set(tabId, {
      apiKeys: new Map(), // key → { origin, referer, firstSeen }
      endpoints: new Map(), // endpointKey → { method, service, key, headers, firstSeen }
      authContext: null, // { sapisid, sapisidhash, cookies }
      discoveryDocs: new Map(), // service → discovery JSON or status
      probeResults: new Map(), // endpointKey → probe result
      scopes: new Map(), // service → string[] of required scopes
      requestLog: [], // Array of { id, url, method, service, timestamp, status, headers, responseHeaders, ... }
    });
  }
  return state.tabs.get(tabId);
}

// ─── Persistent Storage ─────────────────────────────────────────────────────

let _saveTimer = null;

function scheduleSave() {
  if (_saveTimer) clearTimeout(_saveTimer);
  _saveTimer = setTimeout(saveGlobalStore, 2000);
}

async function saveGlobalStore() {
  _saveTimer = null;
  const serialized = {
    apiKeys: Object.fromEntries(
      [...globalStore.apiKeys].map(([k, v]) => [
        k,
        {
          origin: v.origin,
          referer: v.referer,
          source: v.source,
          firstSeen: v.firstSeen,
          lastSeen: v.lastSeen,
          requestCount: v.requestCount || 0,
          services: [
            ...(v.services instanceof Set ? v.services : v.services || []),
          ],
          hosts: [...(v.hosts instanceof Set ? v.hosts : v.hosts || [])],
          endpoints: [
            ...(v.endpoints instanceof Set ? v.endpoints : v.endpoints || []),
          ],
        },
      ]),
    ),
    endpoints: Object.fromEntries(globalStore.endpoints),
    discoveryDocs: Object.fromEntries(
      [...globalStore.discoveryDocs].map(([k, v]) => [
        k,
        {
          status: v.status,
          url: v.url || null,
          method: v.method || null,
          apiKey: v.apiKey || null,
          fetchedAt: v.fetchedAt || null,
          summary: v.summary || (v.doc ? summarizeDiscovery(v.doc) : null),
          doc: v.doc, // Persist full doc (crucial for virtual docs)
        },
      ]),
    ),
    probeResults: Object.fromEntries(globalStore.probeResults),
    scopes: Object.fromEntries(globalStore.scopes),
    savedAt: Date.now(),
  };
  try {
    await chrome.storage.local.set({ gapiStore: serialized });
  } catch (_) {
    console.error("[Storage] Save failed:", _);
  }
}

async function loadGlobalStore() {
  try {
    const data = await chrome.storage.local.get("gapiStore");
    if (!data.gapiStore) return;
    const s = data.gapiStore;
    if (s.apiKeys) {
      for (const [k, v] of Object.entries(s.apiKeys)) {
        globalStore.apiKeys.set(k, {
          ...v,
          services: new Set(v.services || []),
          hosts: new Set(v.hosts || []),
          endpoints: new Set(v.endpoints || []),
        });
      }
    }
    if (s.endpoints) {
      for (const [k, v] of Object.entries(s.endpoints)) {
        globalStore.endpoints.set(k, v);
      }
    }
    if (s.discoveryDocs) {
      for (const [k, v] of Object.entries(s.discoveryDocs)) {
        globalStore.discoveryDocs.set(k, v);
      }
    }
    if (s.probeResults) {
      for (const [k, v] of Object.entries(s.probeResults)) {
        globalStore.probeResults.set(k, v);
      }
    }
    if (s.scopes) {
      for (const [k, v] of Object.entries(s.scopes)) {
        globalStore.scopes.set(k, v);
      }
    }
  } catch (_) {
    console.error("[Storage] Load failed:", _);
  }
}

function mergeToGlobal(tab) {
  for (const [k, v] of tab.apiKeys) {
    const existing = globalStore.apiKeys.get(k);
    if (existing) {
      existing.lastSeen = v.lastSeen;
      // Take the higher count — tab count is a running total, not a delta
      existing.requestCount = Math.max(
        existing.requestCount || 0,
        v.requestCount || 0,
      );
      const mergeSet = (target, source) => {
        if (source instanceof Set)
          source.forEach((s) => (target instanceof Set ? target.add(s) : null));
        else if (Array.isArray(source))
          source.forEach((s) => (target instanceof Set ? target.add(s) : null));
      };
      if (existing.services instanceof Set)
        mergeSet(existing.services, v.services);
      if (existing.hosts instanceof Set) mergeSet(existing.hosts, v.hosts);
      if (existing.endpoints instanceof Set)
        mergeSet(existing.endpoints, v.endpoints);
    } else {
      globalStore.apiKeys.set(k, {
        origin: v.origin,
        referer: v.referer,
        source: v.source,
        firstSeen: v.firstSeen,
        lastSeen: v.lastSeen,
        requestCount: v.requestCount || 0,
        services: new Set(v.services || []),
        hosts: new Set(v.hosts || []),
        endpoints: new Set(v.endpoints || []),
      });
    }
  }
  for (const [k, v] of tab.endpoints) {
    globalStore.endpoints.set(k, v);
  }
  for (const [k, v] of tab.discoveryDocs) {
    if (v.status === "found") {
      globalStore.discoveryDocs.set(k, {
        status: v.status,
        url: v.url,
        method: v.method,
        apiKey: v.apiKey,
        fetchedAt: v.fetchedAt,
        summary: v.doc ? summarizeDiscovery(v.doc) : v.summary || null,
        doc: v.doc, // keep in memory for schema resolution, won't be serialized
      });
    } else if (!globalStore.discoveryDocs.has(k)) {
      globalStore.discoveryDocs.set(k, { status: v.status });
    }
  }
  for (const [k, v] of tab.probeResults) {
    globalStore.probeResults.set(k, v);
  }
  for (const [k, v] of tab.scopes) {
    globalStore.scopes.set(k, v);
  }
  scheduleSave();
}

async function clearGlobalStore() {
  globalStore.apiKeys.clear();
  globalStore.endpoints.clear();
  globalStore.discoveryDocs.clear();
  globalStore.probeResults.clear();
  globalStore.scopes.clear();
  try {
    await chrome.storage.local.remove("gapiStore");
  } catch (_) {
    console.error("[Storage] Clear failed:", _);
  }
}

// Load persisted data on startup
loadGlobalStore();

// ─── Patterns ────────────────────────────────────────────────────────────────

const API_KEY_RE = /AIzaSy[\w-]{33}/g;

function isApiRequest(url, details, headers = {}) {
  // Ignore common non-API static assets
  const ext = url.pathname.split(".").pop().toLowerCase();
  const staticExts = [
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "css",
    "js",
    "woff",
    "woff2",
    "ttf",
    "otf",
    "ico",
    "map",
  ];
  if (staticExts.includes(ext)) return false;

  // batchexecute is always an API
  if (url.pathname.includes("batchexecute")) return true;

  // Ignore specific tracking/asset paths that aren't useful APIs
  const noisePaths = [
    "/gen_204",
    "/_/js/",
    "/_/ss/",
    "/xjs/",
    "/client_204",
    "/vt/",
    "/jserror",
    "/ulog",
    "/log",
    "/error",
    "/collect",
  ];
  if (noisePaths.some((p) => url.pathname.includes(p))) return false;

  // Look for API indicators in URL
  if (url.hostname.includes("api")) return true;
  if (/\bv\d+\b/.test(url.pathname)) return true; // versioning like /v1/
  if (url.pathname.includes("graphql")) return true;
  if (url.pathname.includes("$rpc")) return true;
  if (url.searchParams.has("alt") && url.searchParams.get("alt") === "json")
    return true;

  // Method indicator
  if (details.method !== "GET") return true;

  // Header indicators (if provided)
  if (
    headers["x-requested-with"] ||
    headers["authorization"] ||
    headers["x-api-key"] ||
    headers["x-goog-api-key"]
  ) {
    return true;
  }

  // Heuristic: If it's a GET, check if the path looks like a data endpoint
  const isDataPath = /json|data|query|search|async|rpc/.test(url.pathname);
  if (isDataPath) return true;

  return false;
}

// Extract interface name from URL with better granularity
function extractInterfaceName(urlObj) {
  const hostname = urlObj.hostname;
  const segments = urlObj.pathname.split("/").filter(Boolean);

  // batchexecute handling: /_/PlayStoreUi/data/batchexecute -> PlayStoreUi
  if (urlObj.pathname.includes("batchexecute")) {
    const dataIdx = segments.indexOf("data");
    if (dataIdx > 0) {
      return hostname + "/" + segments[dataIdx - 1];
    }
    const underscoreIdx = segments.indexOf("_");
    if (underscoreIdx !== -1 && segments.length > underscoreIdx + 1) {
      return hostname + "/" + segments[underscoreIdx + 1];
    }
  }

  // Special handling for Google (keep legacy support)
  if (
    hostname.endsWith(".googleapis.com") ||
    hostname.endsWith(".clients6.google.com")
  ) {
    const m = hostname.match(/^(?:staging-)?([^.]+)\./);
    return m ? m[1] : hostname;
  }

  // Common API root patterns
  const apiRoots = [
    "api",
    "v1",
    "v2",
    "v3",
    "rest",
    "graphql",
    "grpc",
    "async",
  ];

  // Find where the API "root" starts
  let rootIdx = -1;
  for (let i = 0; i < segments.length; i++) {
    if (apiRoots.includes(segments[i].toLowerCase())) {
      rootIdx = i;
      break;
    }
  }

  if (rootIdx !== -1) {
    // Interface is hostname + path up to the root (e.g. example.com/api/v1)
    return hostname + "/" + segments.slice(0, rootIdx + 1).join("/");
  }

  // Fallback: If it's a known non-API hostname but we're here,
  // it might be an internal app endpoint. Use 1 segment of path.
  if (segments.length > 0) {
    return hostname + "/" + segments[0];
  }

  return hostname;
}

// Parse $rpc/ paths: "/$rpc/google.internal.people.v2.InternalPeopleService/GetPeople"
// → { grpcPackage, grpcService, grpcMethod }
const RPC_PATH_RE = /^\/\$rpc\/(.+)\/([^/]+)$/;

function parseRpcPath(path) {
  const m = RPC_PATH_RE.exec(path);
  if (!m) return null;
  const fullService = m[1]; // "google.internal.people.v2.InternalPeopleService"
  const method = m[2]; // "GetPeople"
  // Split into package + service name
  const lastDot = fullService.lastIndexOf(".");
  return {
    grpcFullService: fullService,
    grpcPackage: lastDot > -1 ? fullService.slice(0, lastDot) : "",
    grpcService: lastDot > -1 ? fullService.slice(lastDot + 1) : fullService,
    grpcMethod: method,
  };
}

// ─── Request Interception ────────────────────────────────────────────────────

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const url = new URL(details.url);

    // Skip internal probe requests immediately
    if (url.hash.includes("_internal_probe")) return;

    // Auto-attach debugger for response capture on APIs and relevant scripts.
    const isScript =
      url.pathname.endsWith(".js") || url.pathname.includes("/xjs/");
    const isApi = isApiRequest(url, details);

    if (isApi || isScript) {
      DebuggerManager.attach(details.tabId);
      state.tempRequestMap.set(details.requestId, details.url);
      if (state.tempRequestMap.size > 500) {
        const firstKey = state.tempRequestMap.keys().next().value;
        state.tempRequestMap.delete(firstKey);
      }
    }

    if (!isApi) return;

    const tab = getTab(details.tabId);

    // Capture initiator as distinct from Origin header (more reliable for context)
    if (details.initiator) {
      tab.authContext = tab.authContext || {};
      if (!tab.authContext.origin) {
        tab.authContext.origin = details.initiator;
        scheduleSave();
      }
    }

    // We store raw request bytes if present (for Protobuf decoding)
    let rawBodyB64 = null;
    if (details.requestBody?.raw?.[0]?.bytes) {
      rawBodyB64 = uint8ToBase64(
        new Uint8Array(details.requestBody.raw[0].bytes),
      );
    } else if (details.requestBody?.formData) {
      // For application/x-www-form-urlencoded
      const params = new URLSearchParams();
      for (const [key, values] of Object.entries(
        details.requestBody.formData,
      )) {
        for (const val of values) {
          params.append(key, val);
        }
      }
      rawBodyB64 = uint8ToBase64(new TextEncoder().encode(params.toString()));
    }

    const entry = {
      id: details.requestId,
      url: details.url,
      method: details.method,
      service: extractInterfaceName(url),
      timestamp: Date.now(),
      status: "pending",
      requestBody: details.requestBody,
      rawBodyB64,
    };

    // Check if duplicate? (unlikely for new request)
    tab.requestLog.unshift(entry);
    if (tab.requestLog.length > 50) tab.requestLog.pop();
  },
  {
    urls: ["<all_urls>"],
  },
  ["requestBody"],
);

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const url = new URL(details.url);

    // Skip internal probe requests early
    if (url.hash.includes("_internal_probe")) return;

    // ─── CRITICAL: Universal Key Scanning ───
    // Scan EVERY request (scripts, assets, etc) for keys in URL and Headers
    // before any early exits.
    // before any early exits.
    extractKeysFromText(details.tabId, details.url, details.url, "url");
    for (const h of details.requestHeaders || []) {
      extractKeysFromText(
        details.tabId,
        `${h.name}: ${h.value}`,
        details.url,
        "header",
      );
    }

    const headerMap = {};
    for (const h of details.requestHeaders || []) {
      headerMap[h.name.toLowerCase()] = h.value;
    }

    if (!isApiRequest(url, details, headerMap)) return;

    // Skip internal probe requests
    if (url.searchParams.has("_probe")) return;

    const tab = getTab(details.tabId);

    // Capture initiator again in case onBeforeRequest didn't catch it
    if (details.initiator) {
      tab.authContext = tab.authContext || {};
      if (!tab.authContext.origin) {
        tab.authContext.origin = details.initiator;
        scheduleSave();
      }
    }

    let authorization = null;
    let cookie = null;
    let contentType = null;
    let origin = null;
    let referer = null;
    let apiKey = null;

    for (const h of details.requestHeaders || []) {
      const name = h.name.toLowerCase();

      if (name === "cookie") {
        cookie = "[PRESENT]";
        headerMap[name] = "[REDACTED]";
      }

      if (name === "authorization") authorization = h.value;
      if (name === "origin") origin = h.value;
      if (name === "referer") referer = h.value;
      if (name === "content-type") contentType = h.value;
      if (
        name === "x-goog-api-key" ||
        name === "x-api-key" ||
        name === "apikey"
      )
        apiKey = h.value;
    }

    // Store API key with service/host tracking
    const service = extractInterfaceName(url);
    const discoveryStatus = tab.discoveryDocs.get(service);

    // Update auth context
    if (authorization || cookie) {
      tab.authContext = tab.authContext || {};
      if (authorization) tab.authContext.hasAuthorization = true;
      if (cookie) tab.authContext.hasCookies = true;
      if (origin) tab.authContext.origin = origin;
    }

    // ─── Smart Learning (Virtual Discovery) ──────────────────────────────────

    // 1. Always learn from the current request to build the VDD immediately
    let entry = tab.requestLog.find((r) => r.id === details.requestId);
    if (!entry) {
      entry = {
        id: details.requestId,
        url: details.url,
        method: details.method,
        service: service,
        timestamp: Date.now(),
        status: "pending",
      };
      tab.requestLog.unshift(entry);
      if (tab.requestLog.length > 50) tab.requestLog.pop();
    }

    learnFromRequest(details.tabId, service, entry, headerMap);

    // 2. Proactive Active Probing for Protobuf
    // If it's a Protobuf request, check if we already have a detailed schema.
    // If not, trigger a probe to leak field names/numbers.
    const isProtobuf =
      (headerMap["content-type"] || "").includes("protobuf") ||
      url.pathname.includes("$rpc");
    if (isProtobuf && details.method === "POST") {
      const doc = discoveryStatus?.doc;
      const match = doc
        ? findDiscoveryMethod(doc, url.pathname, details.method)
        : null;

      // If no match OR method is in "learned" resource (meaning it lacks probed field numbers)
      const isLearnedOnly =
        match &&
        discoveryStatus.doc.resources?.learned?.methods[
          match.method.id.split(".").pop()
        ];

      if (!match || isLearnedOnly) {
        const keysForService = collectKeysForService(
          tab,
          service,
          url.hostname,
        );
        if (apiKey && !keysForService.includes(apiKey))
          keysForService.push(apiKey);
        performProbeAndPatch(
          details.tabId,
          service,
          details.url,
          apiKey || keysForService[0] || null,
        );
      }
    }

    // 3. Automatic Background Discovery
    // If we haven't tried to find an official discovery doc for this service yet, do it now.
    if (!discoveryStatus || discoveryStatus.status === "not_found") {
      if (!discoveryStatus) {
        tab.discoveryDocs.set(service, {
          status: "pending",
          seedUrl: details.url,
        });
      } else {
        discoveryStatus.status = "pending";
      }

      const keysForService = collectKeysForService(tab, service, url.hostname);
      if (apiKey && !keysForService.includes(apiKey))
        keysForService.push(apiKey);

      fetchDiscoveryForService(
        details.tabId,
        service,
        url.hostname,
        keysForService,
        details.url,
      );
    }

    mergeToGlobal(tab);

    // Log request for Response tab
    const logContentType = headerMap["content-type"] || "";

    if (!entry) {
      entry = {
        id: details.requestId,
        url: details.url,
        method: details.method,
        service: service,
        timestamp: Date.now(),
        status: "pending",
      };
      tab.requestLog.unshift(entry);
      if (tab.requestLog.length > 50) tab.requestLog.pop();
    }

    entry.requestHeaders = headerMap;
    entry.contentType = logContentType;
    entry.service = service;

    if (isProtobuf && entry.rawBodyB64) {
      try {
        const bytes = base64ToUint8(entry.rawBodyB64);
        if (
          logContentType.includes("json") ||
          logContentType.includes("text")
        ) {
          // Try JSPB (JSON array) parsing
          try {
            const text = new TextDecoder().decode(bytes);
            if (text.trim().startsWith("[")) {
              const json = JSON.parse(text);
              if (Array.isArray(json)) {
                entry.decodedBody = jspbToTree(json);
                entry.isJspb = true;
              }
            }
          } catch (e) {}
        } else {
          // Binary protobuf
          entry.decodedBody = pbDecodeTree(bytes, 8, (val) => {
            if (typeof val === "string") {
              extractKeysFromText(
                details.tabId,
                val,
                details.url,
                "protobuf_body",
              );
            }
          });
        }
      } catch (err) {}
    }

    notifyPopup(details.tabId);
  },
  {
    urls: ["<all_urls>"],
  },
  ["requestHeaders"],
);

// ─── Response Header Interception (scope extraction from 403) ────────────────

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return;

    const headerMap = {};
    for (const h of details.responseHeaders || []) {
      headerMap[h.name.toLowerCase()] = h.value;
    }

    const url = new URL(details.url);
    if (!isApiRequest(url, details, headerMap)) return;

    const tab = getTab(details.tabId);
    const service = extractInterfaceName(url);

    if (details.statusCode === 403) {
      for (const h of details.responseHeaders || []) {
        if (h.name.toLowerCase() === "www-authenticate" && h.value) {
          // Extract scopes: Bearer ... scope="scope1 scope2 ..."
          const scopeMatch = h.value.match(/scope="([^"]*)"/);
          if (scopeMatch) {
            const scopeList = scopeMatch[1].split(/\s+/).filter(Boolean);
            if (scopeList.length > 0) {
              tab.scopes.set(service, scopeList);

              // Also annotate the endpoint
              const endpointKey = `${details.method} ${url.hostname}${url.pathname}`;
              const ep = tab.endpoints.get(endpointKey);
              if (ep) ep.requiredScopes = scopeList;

              notifyPopup(details.tabId);
            }
          }
        }
      }
    }

    // Potential to learn from response body too, but we need to use debugger or another way
    // to get response body in MV3 reliably if we want it for all requests.
    // For now, we learn from the request side which is easier.
  },
  {
    urls: ["<all_urls>"],
  },
  ["responseHeaders"],
);

function calculateMethodMetadata(urlObj, interfaceName) {
  // batchexecute: use rpcids param
  if (urlObj.pathname.includes("batchexecute")) {
    const rpcids = urlObj.searchParams.get("rpcids") || "batch";
    return {
      methodName: rpcids,
      methodId: `${interfaceName.replace(/\//g, ".")}.${rpcids}`,
    };
  }

  const segments = urlObj.pathname.split("/").filter(Boolean);
  const interfaceParts = interfaceName.split("/");

  // Method segments are everything after the interface prefix
  // If interface is "example.com/api/v1" and path is "/api/v1/users/get"
  // startIdx should skip "api" and "v1".

  const hostname = urlObj.hostname;
  let startIdx = 0;
  if (interfaceName.startsWith(hostname)) {
    startIdx = interfaceParts.length - 1;
  }

  let methodSegments = segments.slice(startIdx);

  // Strip segments that look like hashes or long ID lists
  methodSegments = methodSegments.filter((s) => {
    if (s.length > 32) return false;
    if (s.includes("=") && s.includes(",")) return false;
    return true;
  });

  let methodName = methodSegments.join("_") || "root";

  // If it's a gRPC-style path, use the actual method name
  if (urlObj.pathname.includes("$rpc")) {
    methodName = segments[segments.length - 1];
  }

  const methodId = `${interfaceName.replace(/\//g, ".")}.${methodName}`;

  return { methodName, methodId };
}

// ─── Smart Learning ──────────────────────────────────────────────────────────

function learnFromRequest(tabId, interfaceName, entry, headers) {
  const tab = getTab(tabId);
  const url = new URL(entry.url);
  const method = entry.method;

  let docEntry = tab.discoveryDocs.get(interfaceName);
  if (!docEntry || !docEntry.doc) {
    docEntry = {
      status: "found",
      isVirtual: true,
      doc: {
        kind: "discovery#restDescription",
        name: interfaceName,
        title: `${interfaceName} (Learned)`,
        resources: {
          learned: { methods: {} },
        },
        schemas: {},
      },
    };
    tab.discoveryDocs.set(interfaceName, docEntry);
  }

  const doc = docEntry.doc;
  if (!doc.resources.learned) doc.resources.learned = { methods: {} };

  const { methodName, methodId } = calculateMethodMetadata(url, interfaceName);

  if (!doc.resources.learned.methods[methodName]) {
    doc.resources.learned.methods[methodName] = {
      id: methodId,
      path: url.pathname.substring(1),
      httpMethod: method,
      parameters: {},
      request: null,
    };
  }

  const m = doc.resources.learned.methods[methodName];

  // Learn parameters from URL
  if (!url.pathname.includes("batchexecute")) {
    url.searchParams.forEach((value, name) => {
      if (name === "key" || name === "api_key") return;
      if (!m.parameters[name]) {
        m.parameters[name] = {
          type: isNaN(value) ? "string" : "number",
          location: "query",
          description: `Learned from request`,
        };
      }
    });
  }

  // Learn request body if present
  if (entry.rawBodyB64) {
    const bytes = base64ToUint8(entry.rawBodyB64);
    const text = new TextDecoder().decode(bytes);
    const isBatch = url.pathname.includes("batchexecute");

    if (isBatch) {
      const calls = parseBatchExecuteRequest(text);
      if (calls) {
        for (const call of calls) {
          const callMethodId = `${interfaceName.replace(/\//g, ".")}.${call.rpcId}`;
          if (!doc.resources.learned.methods[call.rpcId]) {
            doc.resources.learned.methods[call.rpcId] = {
              id: callMethodId,
              path: url.pathname.substring(1),
              httpMethod: "POST",
              parameters: {},
              request: null,
            };
          }
          const callM = doc.resources.learned.methods[call.rpcId];
          const schemaName = `${call.rpcId}Request`;
          callM.request = { $ref: schemaName };
          doc.schemas[schemaName] = generateSchemaFromJson(
            call.data,
            schemaName,
            doc.schemas,
            true,
          );
        }
      }
    } else if (headers["content-type"]?.includes("json")) {
      try {
        const json = JSON.parse(text);
        const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Request`;
        m.request = { $ref: schemaName };
        doc.schemas[schemaName] = generateSchemaFromJson(
          json,
          schemaName,
          doc.schemas,
        );
      } catch (e) {}
    }
  }
}

function learnFromResponse(tabId, interfaceName, entry) {
  if (!entry.responseBody) return;

  const tab = getTab(tabId);
  const url = new URL(entry.url);
  const { methodName } = calculateMethodMetadata(url, interfaceName);

  const docEntry = tab.discoveryDocs.get(interfaceName);
  if (!docEntry || !docEntry.doc) return;
  const doc = docEntry.doc;
  const m = doc.resources.learned
    ? doc.resources.learned.methods[methodName]
    : null;
  // Also check probed methods
  const proM = doc.resources.probed
    ? doc.resources.probed.methods[methodName]
    : null;
  const targetM = m || proM;
  if (!targetM) return;

  // Decode base64 to text for JSON/Batch parsing
  let textBody = entry.responseBody;
  if (entry.responseBase64) {
    try {
      const bytes = base64ToUint8(entry.responseBody);
      textBody = new TextDecoder().decode(bytes);
    } catch (e) {
      textBody = null;
    }
  }
  if (!textBody) return;

  const mimeType = entry.mimeType || "";
  if (url.pathname.includes("batchexecute")) {
    const results = parseBatchExecuteResponse(textBody);
    if (results) {
      for (const res of results) {
        const callM = doc.resources.learned.methods[res.rpcId];
        if (callM) {
          const schemaName = `${res.rpcId}Response`;
          callM.response = { $ref: schemaName };
          doc.schemas[schemaName] = generateSchemaFromJson(
            res.data,
            schemaName,
            doc.schemas,
            true,
          );
        }
      }
    }
  } else if (mimeType.includes("json")) {
    try {
      const json = JSON.parse(textBody);
      const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Response`;
      targetM.response = { $ref: schemaName };
      doc.schemas[schemaName] = generateSchemaFromJson(
        json,
        schemaName,
        doc.schemas,
      );
    } catch (e) {}
  } else if (
    mimeType.includes("protobuf") ||
    entry.contentType?.includes("protobuf")
  ) {
    // Decode response protobuf heuristically
    try {
      const bytes = entry.responseBase64
        ? base64ToUint8(entry.responseBody)
        : new TextEncoder().encode(entry.responseBody);
      const tree = pbDecodeTree(bytes, 8, (val) => {
        if (typeof val === "string") {
          extractKeysFromText(tabId, val, entry.url, "response_protobuf");
        }
      });
      const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Response`;
      m.response = { $ref: schemaName };
      doc.schemas[schemaName] = generateSchemaFromPbTree(
        tree,
        schemaName,
        doc.schemas,
      );
    } catch (e) {}
  }
}

function generateSchemaFromPbTree(tree, name, schemas) {
  const properties = {};
  for (const node of tree) {
    const fieldKey = `field${node.field}`;
    const prop = {
      id: node.field,
      number: node.field,
      type:
        node.wire === 0
          ? "int64"
          : node.wire === 5
            ? "float"
            : node.wire === 1
              ? "double"
              : "string",
      description: `Discovered via response capture`,
    };

    if (node.message) {
      const nestedName = `${name}Field${node.field}`;
      prop.type = "message";
      prop.$ref = nestedName;
      schemas[nestedName] = generateSchemaFromPbTree(
        node.message,
        nestedName,
        schemas,
      );
    } else if (node.string) {
      prop.type = "string";
    }

    properties[fieldKey] = prop;
  }
  return { id: name, type: "object", properties };
}

function generateSchemaFromJson(json, name, schemas, isIndexed = false) {
  if (Array.isArray(json)) {
    if (isIndexed) {
      const properties = {};
      json.forEach((val, idx) => {
        const fieldNum = idx + 1;
        const fieldKey = `field${fieldNum}`;
        const nestedName = `${name}_f${fieldNum}`;

        if (val === null || val === undefined) {
          properties[fieldKey] = {
            id: fieldNum,
            number: fieldNum,
            type: "string",
            description: "Learned (null)",
          };
        } else if (Array.isArray(val)) {
          properties[fieldKey] = {
            id: fieldNum,
            number: fieldNum,
            $ref: nestedName,
          };
          schemas[nestedName] = generateSchemaFromJson(
            val,
            nestedName,
            schemas,
            true,
          );
        } else {
          properties[fieldKey] = {
            id: fieldNum,
            number: fieldNum,
            type: typeof val,
          };
        }
      });
      return { id: name, type: "object", properties };
    } else {
      const items =
        json.length > 0
          ? generateSchemaFromJson(json[0], name + "Item", schemas, false)
          : { type: "string" };
      return { type: "array", items };
    }
  } else if (typeof json === "object" && json !== null) {
    const properties = {};
    for (const key in json) {
      const val = json[key];
      const safeKey = key.replace(/[^a-zA-Z0-9]/g, "");
      if (Array.isArray(val)) {
        properties[key] = {
          type: "array",
          items:
            val.length > 0
              ? generateSchemaFromJson(val[0], name + safeKey + "Item", schemas)
              : { type: "string" },
        };
      } else if (typeof val === "object" && val !== null) {
        const nestedName =
          name + safeKey.charAt(0).toUpperCase() + safeKey.slice(1);
        properties[key] = { $ref: nestedName };
        schemas[nestedName] = generateSchemaFromJson(val, nestedName, schemas);
      } else {
        properties[key] = { type: typeof val };
      }
    }
    return { id: name, type: "object", properties };
  } else {
    return { type: typeof json };
  }
}

// ─── Page-Context Fetch Bridge ───────────────────────────────────────────────
// Routes fetch requests through the content script so they execute with the
// page's cookie jar and Origin. The content script shares the page's cookies,
// so the browser attaches them automatically.
//
// If the original tab is closed, a temporary background tab is opened to the
// request initiator origin so the content script loads and carries the right
// cookies + Origin.

/**
 * Send a PAGE_FETCH message to a tab's content script.
 */
async function sendPageFetch(tabId, url, opts) {
  return chrome.tabs.sendMessage(tabId, {
    type: "PAGE_FETCH",
    url,
    method: opts.method || "GET",
    headers: opts.headers || {},
    body: opts.body ?? null,
    bodyEncoding: opts.bodyEncoding || null,
  });
}

/**
 * Open a temporary hidden tab to `initiatorOrigin`, wait for content script
 * to load, and return its tabId. Caller must close via closeTempTab().
 */
// ─── Temp Tab Pooling ────────────────────────────────────────────────────────
// Reuses temporary tabs for the same origin to avoid opening multiple tabs
// during burst requests (like discovery). Keeps tab open for a short time
// after use to handle subsequent requests.

const tempTabPool = new Map(); // origin -> { tabId, promise, refCount, closeTimer }

async function acquireTempTab(origin) {
  let entry = tempTabPool.get(origin);

  if (entry) {
    // If pending close, cancel it
    if (entry.closeTimer) {
      clearTimeout(entry.closeTimer);
      entry.closeTimer = null;
    }
    entry.refCount++;
    return entry.promise;
  }

  // Create new entry

  const promise = (async () => {
    try {
      const tab = await chrome.tabs.create({ url: origin, active: false });

      // Wait for content script (max 15s)
      const deadline = Date.now() + 15000;
      while (Date.now() < deadline) {
        try {
          await chrome.tabs.sendMessage(tab.id, { type: "PING" });

          return tab.id;
        } catch (_) {
          await new Promise((r) => setTimeout(r, 500));
        }
      }

      // Timeout
      chrome.tabs.remove(tab.id).catch(() => {});
      throw new Error("Temp tab timeout");
    } catch (err) {
      // Clean up pool if creation failed
      tempTabPool.delete(origin);
      throw err;
    }
  })();

  entry = { tabId: null, promise, refCount: 1, closeTimer: null };
  tempTabPool.set(origin, entry);

  try {
    const tabId = await promise;
    entry.tabId = tabId;
    return tabId;
  } catch (err) {
    throw err;
  }
}

function releaseTempTab(origin) {
  const entry = tempTabPool.get(origin);
  if (!entry) return;

  entry.refCount--;
  if (entry.refCount <= 0) {
    // Debounce close (10s)
    if (entry.closeTimer) clearTimeout(entry.closeTimer);
    entry.closeTimer = setTimeout(() => {
      tempTabPool.delete(origin);
      if (entry.tabId) {
        chrome.tabs.remove(entry.tabId).catch(() => {});
        state.tabs.delete(entry.tabId);
      }
    }, 10000);
  }
}

/**
 * Fetch through a content script, with temp tab fallback.
 */
async function pageContextFetch(tabId, url, opts, initiatorOrigin) {
  // Validate URL is a valid API-like host
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { error: "blocked: invalid protocol" };
    }
  } catch (_) {
    return { error: "blocked: invalid URL" };
  }

  // Try the original tab first
  if (tabId != null) {
    try {
      const result = await sendPageFetch(tabId, url, opts);
      return result;
    } catch (_) {
      // Content script not reachable.
      // Check if the tab is actually on the correct origin (just loading?)
      // If so, we should wait for it rather than opening a temp tab.
      try {
        const tab = await chrome.tabs.get(tabId);
        // Requires "tabs" permission or activeTab for url to be visible
        if (tab && tab.url) {
          const tabOrigin = new URL(tab.url).origin;
          if (initiatorOrigin && tabOrigin === initiatorOrigin) {
            // It IS the correct context, just not ready. Wait for it.
            // Poll for up to 5s
            const deadline = Date.now() + 5000;
            while (Date.now() < deadline) {
              try {
                await new Promise((r) => setTimeout(r, 500));
                const res = await sendPageFetch(tabId, url, opts);
                return res; // Success!
              } catch (_) {
                // Keep waiting
              }
            }
            // If we timed out on the correct tab, we should NOT fall back to temp tab
            // because that would double-open.
            console.warn(`Relay failed on same-origin tab ${tabId} (timeout)`);
            return {
              error:
                "relay_failed: content script unreachable on same-origin tab",
            };
          }
        }
      } catch (e) {
        // Tab closed or no permission to see URL; fall through to temp tab
      }
    }
  }

  // Fall back: use pooled temp tab
  if (initiatorOrigin) {
    try {
      const tempTabId = await acquireTempTab(initiatorOrigin);
      const result = await sendPageFetch(tempTabId, url, opts);
      return result;
    } catch (err) {
      console.warn(`Relay failed for ${url} (temp tab error: ${err.message})`);
    } finally {
      releaseTempTab(initiatorOrigin);
    }
  }

  // Last resort: fail if relaying is impossible
  console.warn(
    `Relay failed for ${url} (no responsive content script and no initiatorOrigin)`,
  );
  return {
    error: "relay_failed: content script unreachable and no initiatorOrigin",
  };
}

/**
 * Create a fetchFn bound to a specific tab + initiator origin.
 */
function makePageFetchFn(tabId, initiatorOrigin) {
  return (url, opts) => pageContextFetch(tabId, url, opts, initiatorOrigin);
}

// ─── Discovery Document Fetching ─────────────────────────────────────────────

/**
 * Collect all API keys that have been seen with a specific service.
 */
function collectKeysForService(tab, service, hostname) {
  const keys = [];
  for (const [key, data] of tab.apiKeys) {
    if (data.services?.has(service) || data.hosts?.has(hostname)) {
      keys.push(key);
    }
  }
  return keys;
}

/**
 * Fetch discovery document for a service, trying multiple API keys.
 * Some discovery documents only load with the correct API key.
 *
 * @param {number} tabId
 * @param {string} service
 * @param {string} hostname
 * @param {string[]} apiKeys - All API keys to try for this service
 */
async function fetchDiscoveryForService(
  tabId,
  service,
  hostname,
  apiKeys,
  seedUrl,
) {
  const tab = getTab(tabId);

  // Find the initiator origin for this service
  let initiatorOrigin = tab.authContext?.origin || null;

  const fetchFn = makePageFetchFn(tabId, initiatorOrigin);
  const triedKeys = new Set();

  // Build a deduplicated candidate list across all keys
  // Try each key separately to track which one works
  const keysToTry = [...new Set(apiKeys || [])];

  // Also try without key if keys are empty/exhausted
  if (keysToTry.length === 0) keysToTry.push(null);

  for (const apiKey of keysToTry) {
    if (apiKey) triedKeys.add(apiKey);
    const candidates = buildDiscoveryUrls(hostname, apiKey);

    for (const { url, headers, method } of candidates) {
      try {
        const resp = await fetchFn(url, { method: method || "GET", headers });

        if (resp.error || !resp.ok) continue;

        let doc;
        try {
          doc = JSON.parse(resp.body);
        } catch (_) {
          continue;
        }

        if (
          doc &&
          (doc.discoveryVersion ||
            doc.kind === "discovery#restDescription" ||
            doc.openapi ||
            doc.swagger)
        ) {
          let unifiedDoc = doc;
          // If it's OpenAPI/Swagger, convert it to our internal Discovery-like format
          if (doc.openapi || doc.swagger) {
            unifiedDoc = convertOpenApiToDiscovery(doc, url);
          }

          const existingEntry = tab.discoveryDocs.get(service);
          const mergedDoc = mergeVirtualParts(unifiedDoc, existingEntry?.doc);

          tab.discoveryDocs.set(service, {
            status: "found",
            doc: mergedDoc,
            url,
            method: method || "GET",
            apiKey: apiKey || null,
            fetchedAt: Date.now(),
          });
          mergeToGlobal(tab);

          // Check if the seedUrl method is actually in the doc.
          // If not, trigger immediate hybrid probe to patch it.
          if (seedUrl) {
            const seedUrlObj = new URL(seedUrl);
            // We can assume POST for gRPC-Web usually, or just check path coverage
            const match = findDiscoveryMethod(doc, seedUrlObj.pathname, "POST");
            if (!match) {
              // We need to wait for this probe to finish before notifying popup?
              // Or notify now (partial) and then notify again after patch?
              // Better to patch first if fast, but probing takes time.
              // Let's notify partial first so user sees *something* (service name), then patch.
              notifyPopup(tabId);

              await performProbeAndPatch(tabId, service, seedUrl, apiKey);
              return;
            }
          }

          notifyPopup(tabId);
          return;
        } else {
        }
      } catch (err) {
        // continue to next candidate
      }
    }
  }

  // Also try without any API key (some public APIs don't need one)
  // ... (Removed explicit null check here since we added it to keysToTry list above if empty,
  //      but strictly speaking we should try it if it wasn't in keysToTry)
  // [Code simplifies to just letting execution flows below if nothing returning]

  // Also try without any API key (some public APIs don't need one)
  const candidates = buildDiscoveryUrls(hostname, null);
  for (const { url, headers, method } of candidates) {
    try {
      const resp = await fetchFn(url, { method: method || "GET", headers });
      if (resp.error || !resp.ok) continue;

      let doc;
      try {
        doc = JSON.parse(resp.body);
      } catch (_) {
        continue;
      }

      if (
        doc &&
        (doc.discoveryVersion ||
          doc.kind === "discovery#restDescription" ||
          doc.openapi ||
          doc.swagger)
      ) {
        let unifiedDoc = doc;
        if (doc.openapi || doc.swagger) {
          unifiedDoc = convertOpenApiToDiscovery(doc, url);
        }

        const existingEntry = tab.discoveryDocs.get(service);
        const mergedDoc = mergeVirtualParts(unifiedDoc, existingEntry?.doc);

        tab.discoveryDocs.set(service, {
          status: "found",
          doc: mergedDoc,
          url,
          method: method || "GET",
          apiKey: null,
          fetchedAt: Date.now(),
        });
        mergeToGlobal(tab);
        notifyPopup(tabId);
        return;
      }
    } catch (_) {}
  }

  // All keys failed (or no keys).
  // FALLBACK: Try req2proto probing if we have a seed URL.
  const currentStatus = tab.discoveryDocs.get(service);
  const finalSeedUrl = seedUrl || currentStatus?.seedUrl;

  if (finalSeedUrl) {
    // Pick a key to try probing with (use the first available one if any)
    const probeKey = keysToTry[0] || null;
    await performProbeAndPatch(tabId, service, finalSeedUrl, probeKey);
  } else {
    // If we get here, truly not found
    tab.discoveryDocs.set(service, {
      status: "not_found",
      _triedKeys: triedKeys,
    });
    mergeToGlobal(tab);
    notifyPopup(tabId);
  }
}

/**
 * Perform req2proto probing and patch the discovery document.
 */
async function performProbeAndPatch(tabId, service, targetUrl, apiKey) {
  const tab = getTab(tabId);

  if (typeof probeApiEndpoint === "undefined") {
    console.error("[Debug] CRITICAL: probeApiEndpoint is not defined!");
    return;
  }

  //Find initiator for fetch context
  const initiatorOrigin = tab.authContext?.origin || null;
  const fetchFn = makePageFetchFn(tabId, initiatorOrigin);

  const probeHeader = apiKey ? { "x-goog-api-key": apiKey } : {};

  // Add #_internal_probe fragment to avoid interception loop
  const safeTargetUrl = targetUrl + "#_internal_probe";

  try {
    const probeResult = await probeApiEndpoint(safeTargetUrl, probeHeader, {
      fetchFn,
    });

    if (probeResult && probeResult.fields) {
      // Convert probe result to a "Virtual" Discovery Doc
      // Merge with existing if available
      const currentStatus = tab.discoveryDocs.get(service);
      const existingDoc = currentStatus?.doc ? currentStatus.doc : null;

      const virtualDoc = updateOrCreateVirtualDoc(
        service,
        targetUrl,
        probeResult,
        existingDoc,
      );

      if (virtualDoc.schemas) {
        for (const sName of Object.keys(virtualDoc.schemas)) {
        }
      }

      tab.discoveryDocs.set(service, {
        status: "found", // Treat as found so it shows up in UI
        doc: virtualDoc,
        summary: summarizeDiscovery(virtualDoc),
        apiKey: apiKey,
        fetchedAt: Date.now(),
        method: existingDoc ? currentStatus.method || "HYBRID" : "PROBE",
        isVirtual: existingDoc ? currentStatus.isVirtual || false : true,
        // Note: if we patch a real doc, we don't necessarily mark it full virtual,
        // but maybe we should track it has probed parts.
      });
      mergeToGlobal(tab);
      notifyPopup(tabId);
    }
  } catch (probeErr) {
    console.error("Probe fallback failed:", probeErr);
  }
}

function updateOrCreateVirtualDoc(service, seedUrl, probeResult, existingDoc) {
  const u = new URL(seedUrl);
  const origin = `${u.protocol}//${u.host}`;
  const fullPath = u.pathname.substring(1); // remove leading /

  const { methodName, methodId } = calculateMethodMetadata(u, service);
  const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Request`;
  const responseSchemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Response`;

  let doc = existingDoc
    ? JSON.parse(JSON.stringify(existingDoc))
    : {
        kind: "discovery#restDescription",
        name: service,
        version: "v1",
        title: `${service} (Probed)`,
        description: "Auto-generated from req2proto probe",
        rootUrl: origin + "/",
        servicePath: "",
        baseUrl: origin + "/", // We use root as base, and full paths for methods
        resources: {},
        schemas: {},
      };

  // Ensure resources structure
  if (!doc.resources) doc.resources = {};
  if (!doc.resources.probed) {
    doc.resources.probed = { methods: {} };
  }

  // Ensure schemas structure
  if (!doc.schemas) doc.schemas = {};

  // Heuristic for response schema: try GetAsyncDataResponse, AsyncDataResponse, etc.
  const responseCandidates = [
    responseSchemaName,
    schemaName.replace("Request", "Response"),
    methodName.charAt(0).toUpperCase() + methodName.slice(1) + "Response",
    methodName.replace(/^Get/, "") + "Response",
    methodName.replace(/^BatchGet/, "") + "Response",
  ];

  let actualResponseRef = responseSchemaName;
  if (doc.schemas) {
    for (const cand of responseCandidates) {
      if (doc.schemas[cand]) {
        actualResponseRef = cand;

        break;
      }
    }
  }

  // Add/Update Method
  doc.resources.probed.methods[methodName] = {
    id: methodId,
    path: fullPath,
    httpMethod: "POST", // Assumed
    description: `Probed endpoint: ${fullPath}`,
    parameters: {},
    request: { $ref: schemaName },
    response: { $ref: actualResponseRef },
  };

  // Create/Merge Schema for Request recursively
  const newProperties = convertProbeFieldsToSchema(
    probeResult.fields,
    doc.schemas,
    schemaName,
  );

  if (!doc.schemas[schemaName]) {
    doc.schemas[schemaName] = {
      id: schemaName,
      type: "object",
      properties: newProperties,
    };
  } else {
    // Merge: only add missing properties
    doc.schemas[schemaName].properties = {
      ...newProperties,
      ...doc.schemas[schemaName].properties,
    };
  }

  if (!doc.schemas[actualResponseRef]) {
    doc.schemas[actualResponseRef] = {
      id: actualResponseRef,
      type: "object",
      properties: newProperties,
    };
  } else {
    // Merge: only add missing properties
    doc.schemas[actualResponseRef].properties = {
      ...newProperties,
      ...doc.schemas[actualResponseRef].properties,
    };
  }

  // Preserve IDs in request AND response schemas
  for (const [key, prop] of Object.entries(newProperties)) {
    // Request side
    if (
      doc.schemas[schemaName].properties[key] &&
      doc.schemas[schemaName].properties[key].id == null
    ) {
      doc.schemas[schemaName].properties[key].id = prop.id;
      doc.schemas[schemaName].properties[key].number = prop.id;
    }
    // Response side (Crucial for manual send results!)
    if (
      doc.schemas[actualResponseRef].properties[key] &&
      doc.schemas[actualResponseRef].properties[key].id == null
    ) {
      doc.schemas[actualResponseRef].properties[key].id = prop.id;
      doc.schemas[actualResponseRef].properties[key].number = prop.id;
    }
  }

  return doc;
}

function convertProbeFieldsToSchema(fieldsObj, schemas, prefix = "") {
  const properties = {};
  const fields = Array.isArray(fieldsObj)
    ? fieldsObj
    : fieldsObj instanceof Map
      ? [...fieldsObj.values()]
      : Object.values(fieldsObj || {});

  for (const field of fields) {
    // Discovery format property
    const prop = {
      id: field.number,
      number: field.number,
      name: field.name,
      type: field.type || "string",
      description: `Field ${field.number} (${field.type || "unknown"})`,
    };

    if (field.label === "repeated") {
      prop.type = "array";
      prop.items = { type: field.type || "string" };

      if (field.type === "message" && field.children) {
        // Use messageType as key if available, otherwise generate
        const nestedName =
          field.messageType ||
          `${prefix}${field.name.charAt(0).toUpperCase() + field.name.slice(1)}Entry`;

        if (!schemas[nestedName]) {
          const nestedProperties = convertProbeFieldsToSchema(
            field.children,
            schemas,
            nestedName,
          );
          schemas[nestedName] = {
            id: nestedName,
            type: "object",
            properties: nestedProperties,
          };
        }
        prop.items.$ref = nestedName;
        prop.items.children = schemas[nestedName].properties;
        delete prop.items.type;
      }
    } else if (field.type === "message" && field.children) {
      const nestedName =
        field.messageType ||
        `${prefix}${field.name.charAt(0).toUpperCase() + field.name.slice(1)}`;

      if (!schemas[nestedName]) {
        const nestedProperties = convertProbeFieldsToSchema(
          field.children,
          schemas,
          nestedName,
        );
        schemas[nestedName] = {
          id: nestedName,
          type: "object",
          properties: nestedProperties,
        };
      }
      prop.$ref = nestedName;
      prop.children = schemas[nestedName].properties;
      delete prop.type;
    }

    const fieldKey = field.name || `field_${field.number}`;
    properties[fieldKey] = prop;
  }
  return properties;
}

// ─── req2proto Fallback Probing ──────────────────────────────────────────────

async function probeEndpoint(tabId, endpointKey) {
  const tab = getTab(tabId);
  const ep = tab.endpoints.get(endpointKey);
  if (!ep || ep.method !== "POST") return null;

  // Pass the API key the same way it was originally sent (URL param vs header).
  // Cookie, Origin, Referer are handled by the browser via the content script relay.
  const headers = {};
  const probeUrl = new URL(ep.url);
  probeUrl.searchParams.delete("key");

  if (ep.apiKey) {
    if (ep.apiKeySource === "url") {
      probeUrl.searchParams.set("key", ep.apiKey);
    } else {
      headers["X-Goog-Api-Key"] = ep.apiKey;
    }
  }

  const fetchFn = makePageFetchFn(tabId, ep.origin || ep.referer);
  const result = await probeApiEndpoint(probeUrl.toString(), headers, {
    fetchFn,
  });
  tab.probeResults.set(endpointKey, result);

  // Store scopes if the probe discovered them
  if (result.scopes?.length) {
    const svc = ep.service || extractInterfaceName(new URL(ep.url));
    tab.scopes.set(svc, result.scopes);
  }

  mergeToGlobal(tab);
  notifyPopup(tabId);
  return result;
}

// ─── Message Handling ────────────────────────────────────────────────────────

// Content scripts only handle CONTENT_KEYS and CONTENT_ENDPOINTS.
// Manifest "matches" already restricts which pages they run on.
function handleContentMessage(msg, sender) {
  if (!sender.tab || !Array.isArray(msg.keys || msg.endpoints)) return;
  const tabId = sender.tab.id;
  const tab = getTab(tabId);

  if (msg.type === "CONTENT_KEYS") {
    for (const key of msg.keys) {
      API_KEY_RE.lastIndex = 0;
      if (!API_KEY_RE.test(key)) continue;
      if (!tab.apiKeys.has(key)) {
        tab.apiKeys.set(key, {
          origin: sender.origin,
          referer: sender.origin,
          source: "page_source",
          firstSeen: Date.now(),
          lastSeen: Date.now(),
          services: new Set(),
          hosts: new Set(),
          endpoints: new Set(),
          requestCount: 0,
        });
      }
    }
    mergeToGlobal(tab);
    notifyPopup(tabId);
  }

  if (msg.type === "CONTENT_ENDPOINTS") {
    for (const ep of msg.endpoints) {
      const key = `SOURCE ${ep}`;
      if (!tab.endpoints.has(key)) {
        try {
          const url = new URL(ep);
          const rpcInfo = parseRpcPath(url.pathname);
          tab.endpoints.set(key, {
            url: ep,
            method: "?",
            host: url.hostname,
            path: url.pathname,
            service: extractInterfaceName(url),
            origin: sender.origin,
            rpc: rpcInfo,
            source: "page_source",
            firstSeen: Date.now(),
          });
        } catch (_) {}
      }
    }
    mergeToGlobal(tab);
    notifyPopup(tabId);
  }
}

// Popup messages — sender.tab is absent for popup contexts.
function handlePopupMessage(msg, _sender, sendResponse) {
  const tabId = msg.tabId;

  switch (msg.type) {
    case "GET_STATE": {
      const tab = tabId != null ? getTab(tabId) : null;
      sendResponse(tab ? serializeTabData(tab) : null);
      return;
    }

    case "PROBE_ENDPOINT": {
      if (tabId == null) return;
      probeEndpoint(tabId, msg.endpointKey).then((result) => {
        sendResponse(result);
      });
      return true;
    }

    case "DISCOVER_SERVICE": {
      if (tabId == null) return;
      const tab = getTab(tabId);
      const ep = tab.endpoints.get(msg.endpointKey);
      if (!ep) {
        sendResponse(null);
        return;
      }

      const headers = {};
      const discoverUrl = new URL(ep.url);
      discoverUrl.searchParams.delete("key");
      if (ep.apiKey) {
        if (ep.apiKeySource === "url") {
          discoverUrl.searchParams.set("key", ep.apiKey);
        } else {
          headers["X-Goog-Api-Key"] = ep.apiKey;
        }
      }
      const fetchFn = makePageFetchFn(tabId, ep.origin || ep.referer);
      discoverServiceInfo(discoverUrl.toString(), headers, { fetchFn }).then(
        (result) => {
          tab.probeResults.set(`svc:${msg.endpointKey}`, result);
          if (result.scopes?.length) {
            const svc = ep.service || extractInterfaceName(new URL(ep.url));
            tab.scopes.set(svc, result.scopes);
          }
          mergeToGlobal(tab);
          notifyPopup(tabId);
          sendResponse(result);
        },
      );
      return true;
    }

    case "FETCH_DISCOVERY": {
      if (tabId == null) return;
      const tab = getTab(tabId);
      const ep = tab.endpoints.values().next().value;
      const hostname =
        msg.hostname || (ep?.host ?? `${msg.service}.googleapis.com`);
      const apiKeys = collectKeysForService(tab, msg.service, hostname);
      if (msg.apiKey && !apiKeys.includes(msg.apiKey)) apiKeys.push(msg.apiKey);
      if (ep?.apiKey && !apiKeys.includes(ep.apiKey)) apiKeys.push(ep.apiKey);
      fetchDiscoveryForService(tabId, msg.service, hostname, apiKeys).then(
        () => {
          sendResponse(serializeTabData(getTab(tabId)));
        },
      );
      return true;
    }

    case "CLEAR_TAB": {
      if (tabId != null) state.tabs.delete(tabId);
      clearGlobalStore();
      sendResponse({ ok: true });
      return;
    }

    case "GET_ENDPOINT_SCHEMA": {
      if (tabId == null) return;
      // Pass service/methodId if available (for virtual endpoints)
      const result = resolveEndpointSchema(
        tabId,
        msg.endpointKey,
        msg.service,
        msg.methodId,
      );
      sendResponse(result);
      return;
    }

    case "SEND_REQUEST": {
      if (tabId == null) return;
      executeSendRequest(tabId, msg).then((result) => {
        sendResponse(result);
      });
      return true;
    }

    case "EXECUTE_FUZZ": {
      if (tabId == null) return;
      executeFuzzing(tabId, msg);
      sendResponse({ ok: true });
      return;
    }

    case "RENAME_FIELD": {
      if (tabId == null) return;
      const tab = getTab(tabId);
      const { service, schemaName, fieldKey, newName } = msg;
      const docEntry =
        tab.discoveryDocs.get(service) ||
        globalStore.discoveryDocs.get(service);

      if (!docEntry || !docEntry.doc) return;
      const doc = docEntry.doc;

      if (schemaName === "params") {
        // Find method and rename its parameter
        let m = null;
        console.log("[BG] RENAME_FIELD: Starting for params", {
          service,
          methodId: msg.methodId,
          fieldKey,
          newName,
        });
        if (msg.methodId) {
          // Direct lookup by ID (reliable)
          const match = findMethodById(doc, msg.methodId);
          if (match) {
            m = match.method;
            console.log("[BG] Found method by ID:", m.id);
          } else {
            console.warn(
              "[BG] Method ID provided but not found:",
              msg.methodId,
            );
          }
        }

        if (!m) {
          // Fallback: Calculate from URL (less reliable)
          const { methodName } = calculateMethodMetadata(
            new URL(msg.url || ""),
            service,
          );
          console.log("[BG] Fallback to URL method name:", methodName);
          m =
            doc.resources.learned?.methods[methodName] ||
            doc.resources.probed?.methods[methodName];
        }

        if (m) {
          if (m.parameters?.[fieldKey]) {
            console.log("[BG] Renaming param:", fieldKey, "to", newName);
            m.parameters[fieldKey].name = newName;
            m.parameters[fieldKey].customName = true;
            mergeToGlobal(tab);
            sendResponse({ ok: true });
          } else {
            console.warn("[BG] Param not found in method:", fieldKey);
          }
        } else {
          console.warn("[BG] Method not found for rename.");
        }
      } else if (doc.schemas?.[schemaName]) {
        const schema = doc.schemas[schemaName];
        if (schema.properties?.[fieldKey]) {
          const prop = schema.properties[fieldKey];
          prop.name = newName;
          prop.customName = true;
          mergeToGlobal(tab);
          sendResponse({ ok: true });
        }
      }
      return;
    }
  }
}

// ─── Fuzzing Engine ──────────────────────────────────────────────────────────

async function executeFuzzing(tabId, msg) {
  const schema = resolveEndpointSchema(tabId, null, msg.service, msg.methodId);
  if (!schema || !schema.requestBody) return;

  const fields = schema.requestBody.fields;
  const url =
    schema.endpoint?.url ||
    (schema.method
      ? new URL(
          schema.method.path,
          "https://" + msg.service + ".googleapis.com",
        ).toString()
      : null);
  if (!url) return;

  const payloads = [];
  if (msg.config.strings) {
    payloads.push(
      "",
      "A".repeat(1000),
      "' OR 1=1 --",
      "<script>alert(1)</script>",
      "\0",
      "NaN",
      "undefined",
    );
  }
  if (msg.config.numbers) {
    payloads.push(0, -1, 2147483648, 9007199254740991, 1.1e38, -1.1e38);
  }
  if (msg.config.objects) {
    payloads.push(null, [], {});
  }

  for (const field of fields) {
    for (const payload of payloads) {
      // Create a copy of default fields with one fuzzed field
      const fuzzedFields = fields.map((f) => {
        if (f.name === field.name) {
          return { ...f, value: payload };
        }
        // Use a safe default value for other fields
        return {
          ...f,
          value: f.type === "string" ? "test" : f.type === "bool" ? false : 1,
        };
      });

      const result = await executeSendRequest(tabId, {
        service: msg.service,
        methodId: msg.methodId,
        url: url + "#_internal_probe",
        httpMethod: schema.method?.httpMethod || "POST",
        contentType: schema.contentTypes[0],
        body: {
          mode: "form",
          formData: { fields: fuzzedFields },
        },
      });

      chrome.runtime.sendMessage({
        type: "FUZZ_UPDATE",
        tabId,
        update: {
          field: field.name,
          payload: payload,
          status: result.status,
          error: result.error,
        },
      });

      // Small delay to avoid rate limiting
      await new Promise((r) => setTimeout(r, 200));
    }
  }
}

const EXTENSION_ORIGIN = `chrome-extension://${chrome.runtime.id}`;
const CONTENT_TYPES = new Set(["CONTENT_KEYS", "CONTENT_ENDPOINTS"]);

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;

  const isExtensionPage =
    sender.url && sender.url.startsWith(EXTENSION_ORIGIN + "/");

  if (isExtensionPage) {
    // Popup / extension pages — reject content-script message types
    if (CONTENT_TYPES.has(msg.type)) return;
    return handlePopupMessage(msg, sender, sendResponse);
  }

  // Content script — only allow CONTENT_KEYS and CONTENT_ENDPOINTS
  if (!CONTENT_TYPES.has(msg.type)) return;
  handleContentMessage(msg, sender);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  state.tabs.delete(tabId);
});

// ─── Send Request: Schema Resolution ─────────────────────────────────────────

/**
 * Resolve the full schema for an endpoint by merging discovery doc + probe data.
 * Returns a unified schema the popup can use to build a form.
 */
function resolveEndpointSchema(tabId, endpointKey, service, methodId) {
  const tab = getTab(tabId);
  const ep = endpointKey
    ? tab.endpoints.get(endpointKey) || globalStore.endpoints.get(endpointKey)
    : null;

  // If no endpoint but we have service+methodId (virtual), create a dummy ep object for context
  if (!ep && (!service || !methodId)) return { source: "none", endpoint: null };

  const targetService = ep?.service || service;

  let source = "none";
  let discoveryMethod = null;
  let parameters = null;
  let bodyFields = null;
  let bodySchemaName = null;
  let contentTypes = [];

  // 1. Try discovery doc (tab-specific first, then global store fallback)
  let discoveryEntry = tab.discoveryDocs.get(targetService);
  if (discoveryEntry?.status === "found" && !discoveryEntry.doc) {
    // Tab has a found entry but no full doc — check global store for in-memory doc
    const globalEntry = globalStore.discoveryDocs.get(targetService);
    if (globalEntry?.doc) discoveryEntry = globalEntry;
  }
  if (!discoveryEntry?.doc) {
    // Also try global store directly if tab has no entry
    const globalEntry = globalStore.discoveryDocs.get(targetService);
    if (globalEntry?.status === "found" && globalEntry.doc)
      discoveryEntry = globalEntry;
  }
  if (discoveryEntry?.status === "found" && discoveryEntry.doc) {
    const doc = discoveryEntry.doc;
    let match = null;

    if (methodId) {
      // Direct lookup by ID (virtual endpoint)
      match = findMethodById(doc, methodId);
    } else if (ep) {
      // Path matching (captured endpoint)
      match = findDiscoveryMethod(doc, ep.path, ep.method || "POST");
    }

    if (match) {
      source = "discovery";
      discoveryMethod = {
        id: match.method.id,
        httpMethod: match.method.httpMethod,
        path: match.method.path || match.method.flatPath,
        description: match.method.description,
        scopes: match.method.scopes || [],
        resourceName: match.resourceName,
      };

      // Resolve parameters
      if (match.method.parameters) {
        parameters = {};
        for (const [pName, pDef] of Object.entries(match.method.parameters)) {
          parameters[pName] = {
            name: pDef.name || pName, // Add name property!
            customName: !!pDef.customName, // Add customName flag!
            type: pDef.type || "string",
            location: pDef.location || "query",
            required: !!pDef.required,
            description: pDef.description || "",
            format: pDef.format || null,
            enum: pDef.enum || null,
          };
        }
      }

      // Resolve request body schema
      if (match.method.request?.$ref) {
        bodySchemaName = match.method.request.$ref;
        bodyFields = resolveDiscoverySchema(doc, bodySchemaName);
      }
    }
  }

  // 2. Try probe results (only if we have a real endpoint key)
  const probeResult = endpointKey
    ? tab.probeResults.get(endpointKey) ||
      globalStore.probeResults.get(endpointKey)
    : null;
  if (probeResult?.fields) {
    const probeFields = Object.entries(probeResult.fields).map(([name, f]) => ({
      name,
      type: f.type || "string",
      number: f.number || null,
      required: !!f.required,
      label: f.label || "optional",
      messageType: f.messageType || null,
      description: null,
      children: f.children || null,
    }));

    if (!bodyFields || bodyFields.length === 0) {
      // No discovery body fields — use probe fields directly
      source = source === "discovery" ? "merged" : "probe";
      bodyFields = probeFields;
    } else {
      // Merge: overlay probe field numbers onto discovery fields
      source = "merged";
      for (const pf of probeFields) {
        const match = bodyFields.find(
          (df) => df.name.toLowerCase() === pf.name.toLowerCase(),
        );
        if (match) {
          if (pf.number) match.number = pf.number;
          if (pf.type !== "unknown" && match.type === "string")
            match.type = pf.type;
          if (pf.label === "repeated") match.label = "repeated";
          if (pf.children && !match.children) match.children = pf.children;
        } else {
          bodyFields.push(pf);
        }
      }
    }
  }

  // 3. Content type suggestions
  if (ep?.contentType) contentTypes.push(ep.contentType);
  if (probeResult?.probeDetails) {
    for (const pd of probeResult.probeDetails) {
      if (
        pd.fieldCount > 0 &&
        pd.contentType &&
        !contentTypes.includes(pd.contentType)
      ) {
        contentTypes.push(pd.contentType);
      }
    }
  }
  if (!contentTypes.length) {
    contentTypes = [
      "application/json",
      "application/json+protobuf",
      "application/x-protobuf",
    ];
  }

  return {
    source,
    method: discoveryMethod,
    parameters,
    requestBody: bodyFields?.length
      ? { schemaName: bodySchemaName, fields: bodyFields }
      : null,
    contentTypes,
    endpoint: ep
      ? {
          url: ep.url,
          method: ep.method,
          host: ep.host,
          path: ep.path,
          service: ep.service,
          apiKey: ep.apiKey,
          apiKeySource: ep.apiKeySource,
          origin: ep.origin,
          referer: ep.referer,
          contentType: ep.contentType,
        }
      : null,
  };
}

// ─── Send Request: Body Encoding ─────────────────────────────────────────────

/**
 * Encode form fields as a JSON object (field names as keys).
 */
function encodeFormToJson(fields) {
  const obj = {};
  for (const f of fields) {
    if (f.value == null && !f.children?.length) continue;
    if (f.type === "message" && f.children?.length) {
      obj[f.name] = encodeFormToJson(f.children);
    } else if (f.label === "repeated" && Array.isArray(f.value)) {
      obj[f.name] = f.value.map((v) => coerceValue(v, f.type));
    } else {
      obj[f.name] = coerceValue(f.value, f.type);
    }
  }
  return obj;
}

/**
 * Encode form fields as a JSPB array (indexed by field number).
 */
function encodeFormToJspb(fields) {
  let maxNum = 0;
  for (const f of fields) {
    if (f.number > maxNum) maxNum = f.number;
  }
  if (maxNum === 0) return encodeFormToJson(fields); // fallback if no field numbers

  // JSPB uses 0-based indexing for field 1 (i.e. index 0 is field 1)
  const arr = new Array(maxNum).fill(null);
  for (const f of fields) {
    if (!f.number) continue;
    if (f.value == null && !f.children?.length) continue;

    const targetIdx = f.number - 1;
    if (f.type === "message" && f.children?.length) {
      arr[targetIdx] = encodeFormToJspb(f.children);
    } else if (f.label === "repeated" && Array.isArray(f.value)) {
      arr[targetIdx] = f.value.map((v) => coerceValue(v, f.type));
    } else {
      arr[targetIdx] = coerceValue(f.value, f.type);
    }
  }
  return arr;
}

/**
 * Encode form fields as binary protobuf.
 */
function encodeFormToProtobuf(fields) {
  const parts = [];
  for (const f of fields) {
    if (!f.number) continue;
    if (f.value == null && !f.children?.length) continue;
    if (f.label === "repeated" && Array.isArray(f.value)) {
      for (const v of f.value) {
        parts.push(encodeSinglePbField(f.number, f.type, v, null));
      }
    } else {
      parts.push(encodeSinglePbField(f.number, f.type, f.value, f.children));
    }
  }
  return concatBytes.apply(null, parts.length ? parts : [new Uint8Array(0)]);
}

function encodeSinglePbField(num, type, value, children) {
  if (type === "message" && children?.length) {
    const inner = encodeFormToProtobuf(children);
    return pbEncodeLenField(num, inner);
  }
  switch (type) {
    case "string":
      return pbEncodeLenField(num, String(value));
    case "bytes":
      return pbEncodeLenField(num, base64ToUint8(String(value)));
    case "bool":
      return pbEncodeVarintField(num, value ? 1 : 0);
    case "enum":
    case "int32":
    case "int64":
    case "uint32":
    case "uint64":
      return pbEncodeVarintField(num, Number(value) || 0);
    case "sint32":
    case "sint64": {
      const n = Number(value) || 0;
      return pbEncodeVarintField(num, (n << 1) ^ (n >> 31));
    }
    case "float":
    case "fixed32":
    case "sfixed32": {
      const buf = new Uint8Array(4);
      if (type === "float")
        new DataView(buf.buffer).setFloat32(0, Number(value) || 0, true);
      else new DataView(buf.buffer).setUint32(0, Number(value) || 0, true);
      return concatBytes(pbTag(num, PB_32BIT), buf);
    }
    case "double":
    case "fixed64":
    case "sfixed64": {
      const buf = new Uint8Array(8);
      new DataView(buf.buffer).setFloat64(0, Number(value) || 0, true);
      return concatBytes(pbTag(num, PB_64BIT), buf);
    }
    default:
      return pbEncodeLenField(num, String(value));
  }
}

function coerceValue(value, type) {
  if (value == null) return null;
  if (type === "bool") return value === true || value === "true";
  if (
    [
      "int32",
      "int64",
      "uint32",
      "uint64",
      "double",
      "float",
      "enum",
      "sint32",
      "sint64",
      "fixed32",
      "fixed64",
      "sfixed32",
      "sfixed64",
    ].includes(type)
  ) {
    return Number(value);
  }
  return String(value);
}

// ─── Send Request: Execute ───────────────────────────────────────────────────

/**
 * Execute a request from the Send panel.
 * Encodes form data, sends via pageContextFetch, decodes response.
 */
async function executeSendRequest(tabId, msg) {
  const startTime = Date.now();
  const service = msg.service;
  const methodId = msg.methodId;

  // Validate URL
  let parsedUrl;
  try {
    parsedUrl = new URL(msg.url);
    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      return { error: "blocked: invalid protocol" };
    }
  } catch (_) {
    return { error: "invalid URL" };
  }

  // Build headers
  const headers = { ...(msg.headers || {}) };
  if (
    msg.contentType &&
    msg.httpMethod !== "GET" &&
    msg.httpMethod !== "DELETE"
  ) {
    headers["Content-Type"] = msg.contentType;
  }

  // API key from endpoint
  const tab = getTab(tabId);
  const epKey = msg.endpointKey;
  const ep = epKey ? tab.endpoints.get(epKey) : null;
  if (ep?.apiKey) {
    if (ep.apiKeySource === "url") {
      parsedUrl.searchParams.set("key", ep.apiKey);
    } else {
      headers["X-Goog-Api-Key"] = ep.apiKey;
    }
  }

  const url = parsedUrl.toString();

  // Encode body
  let body = null;
  let bodyEncoding = null;

  if (msg.httpMethod !== "GET" && msg.httpMethod !== "DELETE" && msg.body) {
    if (url.includes("batchexecute") && msg.body.mode === "form") {
      // Special handling for batchexecute: wrap in f.req envelope
      const fields = msg.body.formData?.fields || [];
      const argsArray = encodeFormToJspb(fields); // Convert fields back to positional array
      const innerJson = JSON.stringify(argsArray);

      // Extract RPC ID from methodId (e.g. "Google.Photos.p1Takd" -> "p1Takd")
      const rpcId = methodId ? methodId.split(".").pop() : "unknown";

      const envelope = [[[rpcId, innerJson, null, "generic"]]];
      const params = new URLSearchParams();
      params.set("f.req", JSON.stringify(envelope));

      body = params.toString();
      headers["Content-Type"] =
        "application/x-www-form-urlencoded;charset=UTF-8";
    } else if (msg.body.mode === "raw" && msg.body.rawBody) {
      if (msg.contentType === "application/x-protobuf") {
        body = msg.body.rawBody;
        bodyEncoding = "base64";
      } else {
        body = msg.body.rawBody;
      }
    } else if (msg.body.mode === "form" && msg.body.formData?.fields?.length) {
      const fields = msg.body.formData.fields;
      if (msg.contentType === "application/x-protobuf") {
        const encoded = encodeFormToProtobuf(fields);
        body = uint8ToBase64(encoded);
        bodyEncoding = "base64";
      } else if (msg.contentType === "application/json+protobuf") {
        body = JSON.stringify(encodeFormToJspb(fields));
      } else {
        body = JSON.stringify(encodeFormToJson(fields));
      }
    }
  }

  // Resolve initiator origin
  const initiatorOrigin =
    ep?.origin || ep?.referer || tab.authContext?.origin || null;

  // Send request
  const resp = await pageContextFetch(
    tabId,
    url,
    {
      method: msg.httpMethod || "POST",
      headers,
      body,
      bodyEncoding,
    },
    initiatorOrigin,
  );

  const timing = Date.now() - startTime;

  if (resp.error) {
    return { error: resp.error, timing };
  }

  // Decode response
  const respCt = resp.headers?.["content-type"] || "";
  let bodyResult;

  if (resp.bodyEncoding === "base64" || isBinaryContentType(respCt)) {
    // Binary protobuf response
    try {
      const bytes =
        resp.bodyEncoding === "base64"
          ? base64ToUint8(resp.body)
          : new TextEncoder().encode(resp.body);
      const tree = pbDecodeTree(bytes, 8, (val) => {
        if (typeof val === "string") {
          extractKeysFromText(tabId, val, url, "send_response_protobuf");
        }
      });
      bodyResult = {
        format: "protobuf_tree",
        parsed: tree,
        raw: resp.body,
        size: bytes.length,
      };
    } catch (_) {
      bodyResult = {
        format: "binary",
        parsed: null,
        raw: resp.body,
        size: (resp.body || "").length,
      };
    }
  } else {
    // Try JSON parse
    try {
      const parsed = JSON.parse(resp.body);
      if (
        Array.isArray(parsed) &&
        (respCt.includes("json+protobuf") || respCt.includes("text/"))
      ) {
        // JSPB format found in manual send
        bodyResult = {
          format: "protobuf_tree",
          parsed: jspbToTree(parsed),
          raw: resp.body,
          size: (resp.body || "").length,
          isJspb: true,
        };
      } else {
        bodyResult = {
          format: "json",
          parsed,
          raw: resp.body,
          size: (resp.body || "").length,
        };
      }
    } catch (_) {
      bodyResult = {
        format: "text",
        parsed: null,
        raw: resp.body || "",
        size: (resp.body || "").length,
      };
    }
  }

  // Include latest discovery info in result
  const discovery = tab.discoveryDocs.get(msg.service);

  return {
    ok: resp.ok,
    status: resp.status,
    statusText: resp.statusText || "",
    headers: resp.headers || {},
    body: bodyResult,
    timing,
    discovery, // Pass back latest doc (+ summary/apiKey)
    service, // Echo back metadata
    methodId,
    error: null,
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function notifyPopup(tabId) {
  chrome.runtime.sendMessage({ type: "STATE_UPDATED", tabId }).catch(() => {});
}

function mergeVirtualParts(newDoc, oldDoc) {
  if (!oldDoc || !newDoc) return newDoc;

  // Preserve "learned" methods
  if (oldDoc.resources?.learned) {
    if (!newDoc.resources) newDoc.resources = {};
    newDoc.resources.learned = oldDoc.resources.learned;
  }

  // Preserve "probed" methods
  if (oldDoc.resources?.probed) {
    if (!newDoc.resources) newDoc.resources = {};
    newDoc.resources.probed = oldDoc.resources.probed;
  }

  // Preserve learned schemas
  if (oldDoc.schemas) {
    for (const [name, schema] of Object.entries(oldDoc.schemas)) {
      if (!newDoc.schemas[name]) {
        newDoc.schemas[name] = schema;
      }
    }
  }

  return newDoc;
}

function serializeApiKeyEntry(v) {
  return {
    name: v.name,
    origin: v.origin,
    referer: v.referer,
    source: v.source,
    firstSeen: v.firstSeen,
    lastSeen: v.lastSeen,
    requestCount: v.requestCount || 0,
    services: [...(v.services instanceof Set ? v.services : v.services || [])],
    hosts: [...(v.hosts instanceof Set ? v.hosts : v.hosts || [])],
    endpoints: [
      ...(v.endpoints instanceof Set ? v.endpoints : v.endpoints || []),
    ],
  };
}

function serializeTabData(tab) {
  // Merge global store (base) with tab data (tab wins on conflict)

  // API keys: global base, tab overwrites
  const mergedKeys = {};
  for (const [k, v] of globalStore.apiKeys) {
    mergedKeys[k] = serializeApiKeyEntry(v);
  }
  for (const [k, v] of tab.apiKeys) {
    mergedKeys[k] = serializeApiKeyEntry(v);
  }

  // Endpoints: global base, tab overwrites
  const mergedEndpoints = {};
  for (const [k, v] of globalStore.endpoints) {
    mergedEndpoints[k] = v;
  }
  for (const [k, v] of tab.endpoints) {
    mergedEndpoints[k] = v;
  }

  // Scopes: global base, tab overwrites
  const mergedScopes = {};
  for (const [k, v] of globalStore.scopes) {
    mergedScopes[k] = v;
  }
  for (const [k, v] of tab.scopes) {
    mergedScopes[k] = v;
  }

  // Discovery docs: global base (summaries), tab overwrites with full doc
  const mergedDiscovery = {};
  for (const [k, v] of globalStore.discoveryDocs) {
    if (v.status === "found") {
      mergedDiscovery[k] = {
        status: v.status,
        url: v.url,
        method: v.method,
        apiKey: v.apiKey || null,
        fetchedAt: v.fetchedAt,
        summary: v.summary || (v.doc ? summarizeDiscovery(v.doc) : null),
      };
    } else {
      mergedDiscovery[k] = { status: v.status };
    }
  }
  for (const [k, v] of tab.discoveryDocs) {
    if (v.status === "found") {
      mergedDiscovery[k] = {
        status: v.status,
        url: v.url,
        method: v.method,
        apiKey: v.apiKey || null,
        fetchedAt: v.fetchedAt,
        summary: v.doc ? summarizeDiscovery(v.doc) : v.summary || null,
        doc: v.doc || null,
        isVirtual: v.isVirtual || false,
      };
    } else {
      mergedDiscovery[k] = { status: v.status };
    }
  }

  // Probe results: global base, tab overwrites
  const mergedProbe = {};
  for (const [k, v] of globalStore.probeResults) {
    mergedProbe[k] = v;
  }
  for (const [k, v] of tab.probeResults) {
    mergedProbe[k] = v;
  }

  return {
    apiKeys: mergedKeys,
    endpoints: mergedEndpoints,
    authContext: tab.authContext,
    scopes: mergedScopes,
    discoveryDocs: mergedDiscovery,
    probeResults: mergedProbe,
    requestLog: tab.requestLog || [],
  };
}

// ─── Request Completion Tracking ─────────────────────────────────────────────

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const tab = state.tabs.get(details.tabId);
    if (!tab) return;

    const entry = tab.requestLog.find((r) => r.id === details.requestId);
    if (entry) {
      entry.status = details.statusCode;
      entry.completedAt = Date.now();
      notifyPopup(details.tabId);
    }
  },
  { urls: ["<all_urls>"] },
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const tab = state.tabs.get(details.tabId);
    if (!tab) return;

    const entry = tab.requestLog.find((r) => r.id === details.requestId);
    if (entry) {
      entry.status = "error";
      entry.error = details.error;
      entry.completedAt = Date.now();
      notifyPopup(details.tabId);
    }
  },
  { urls: ["<all_urls>"] },
);
