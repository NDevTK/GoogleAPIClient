// Service worker: intercepts network requests, extracts API keys,
// endpoints, auth headers, coordinates discovery document fetching,
// req2proto fallback probing, and stores AST security findings.

importScripts("lib/protobuf.js", "lib/discovery.js", "lib/req2proto.js", "lib/stats.js", "lib/chains.js");

// ─── Offscreen AST Worker ────────────────────────────────────────────────────
// Heavy libs (babel-bundle.js, ast.js, sourcemap.js) run in an offscreen
// document so the service worker stays responsive during analysis.

var _offscreenReady = null;

async function ensureOffscreen() {
  if (_offscreenReady) return _offscreenReady;
  _offscreenReady = (async () => {
    var contexts = await chrome.runtime.getContexts({
      contextTypes: ["OFFSCREEN_DOCUMENT"]
    });
    if (contexts.length > 0) return;
    await chrome.offscreen.createDocument({
      url: "ast-worker.html",
      reasons: ["WORKERS"],
      justification: "AST analysis of JavaScript bundles"
    });
  })();
  return _offscreenReady;
}

async function sendToOffscreen(msg) {
  await ensureOffscreen();
  return chrome.runtime.sendMessage(msg);
}

// Inlined from ast.js — extracts sourceMappingURL from the last 500 chars.
// Runs synchronously in the service worker (no Babel needed).
function extractSourceMapUrl(code) {
  var tail = code.length > 500 ? code.slice(-500) : code;
  var marker = "sourceMappingURL=";
  var idx = tail.indexOf(marker);
  if (idx === -1) return null;
  var start = idx + marker.length;
  while (start < tail.length && (tail.charCodeAt(start) === 32 || tail.charCodeAt(start) === 9)) start++;
  var end = start;
  while (end < tail.length && tail.charCodeAt(end) > 32) end++;
  return end > start ? tail.substring(start, end) : null;
}

// ─── State ───────────────────────────────────────────────────────────────────

const state = {
  // Map<tabId, TabData>
  tabs: new Map(),
};

// Session storage for request logs — survives SW restarts, clears on browser close
const _sessionSaveTimers = new Map(); // tabId → timeoutId
const _tabMeta = new Map(); // tabId → { title, url, closed? }
const _wsConnState = new Map(); // tabId → Map<wsId, { url, readyState }>

// Cross-script AST analysis: buffer scripts per tab, debounce, concatenate + analyze
const _scriptBuffers = new Map(); // tabId → { scripts: [{url, code}], timer: null }

// Global persistent store — survives tab closes and SW restarts
const globalStore = {
  apiKeys: new Map(), // key → { origin, referer, firstSeen, ... }
  endpoints: new Map(), // endpointKey → endpoint data
  discoveryDocs: new Map(), // service → { status, url, method, apiKey, fetchedAt, doc }
  probeResults: new Map(), // endpointKey → probe result
  scopes: new Map(), // service → string[]
  securityFindings: new Map(), // sourceUrl → { sourceUrl, securitySinks[], dangerousPatterns[] }
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
  // Heuristic: looking for strings 20-2000 chars that look like base64.
  // Cap at 2000 to avoid decoding huge binary blobs (images, protobuf payloads).
  // Also limit to first 50 matches per text to bound CPU time.
  const B64_RE = /[a-zA-Z0-9+/]{20,2000}=*/g;
  let b64m;
  let b64Count = 0;
  while ((b64m = B64_RE.exec(text)) !== null && b64Count < 50) {
    b64Count++;
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
      _valueIndex: createValueIndex(), // Chain engine: response value → source tracking
    });
    captureTabMeta(tabId);
  }
  return state.tabs.get(tabId);
}

async function captureTabMeta(tabId) {
  if (_tabMeta.has(tabId)) return;
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab) {
      _tabMeta.set(tabId, { title: tab.title || `Tab ${tabId}`, url: tab.url || "" });
    }
  } catch (_) {
    _tabMeta.set(tabId, { title: `Tab ${tabId}`, url: "" });
  }
}

// ─── Persistent Storage (IndexedDB) ─────────────────────────────────────────

const _IDB_NAME = "uasr_store";
const _IDB_VERSION = 1;
const _IDB_STORE = "global";

function _openIDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(_IDB_NAME, _IDB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(_IDB_STORE)) {
        db.createObjectStore(_IDB_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function _idbGet(key) {
  return _openIDB().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(_IDB_STORE, "readonly");
        const store = tx.objectStore(_IDB_STORE);
        const req = store.get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
        tx.oncomplete = () => db.close();
      }),
  );
}

function _idbSet(key, value) {
  return _openIDB().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(_IDB_STORE, "readwrite");
        const store = tx.objectStore(_IDB_STORE);
        store.put(value, key);
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error);
        };
      }),
  );
}

function _idbClear() {
  return _openIDB().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(_IDB_STORE, "readwrite");
        const store = tx.objectStore(_IDB_STORE);
        store.clear();
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error);
        };
      }),
  );
}

let _saveTimer = null;

function scheduleSave() {
  if (_saveTimer) clearTimeout(_saveTimer);
  _saveTimer = setTimeout(saveGlobalStore, 2000);
}

function _serializeGlobalStore() {
  return {
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
          doc: v.doc || null,
        },
      ]),
    ),
    probeResults: Object.fromEntries(globalStore.probeResults),
    scopes: Object.fromEntries(globalStore.scopes),
    securityFindings: Object.fromEntries(globalStore.securityFindings),
    savedAt: Date.now(),
  };
}

function _deserializeIntoGlobalStore(s) {
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
    for (const [k, v] of Object.entries(s.endpoints))
      globalStore.endpoints.set(k, v);
  }
  if (s.discoveryDocs) {
    for (const [k, v] of Object.entries(s.discoveryDocs))
      globalStore.discoveryDocs.set(k, v);
  }
  if (s.probeResults) {
    for (const [k, v] of Object.entries(s.probeResults))
      globalStore.probeResults.set(k, v);
  }
  if (s.scopes) {
    for (const [k, v] of Object.entries(s.scopes))
      globalStore.scopes.set(k, v);
  }
  if (s.securityFindings) {
    for (const [k, v] of Object.entries(s.securityFindings))
      globalStore.securityFindings.set(k, v);
  }
}

async function saveGlobalStore() {
  _saveTimer = null;
  try {
    await _idbSet("gapiStore", _serializeGlobalStore());
  } catch (_) {
    console.error("[Storage] Save failed:", _);
  }
}

async function loadGlobalStore() {
  try {
    // Migrate from chrome.storage.local if data exists there (one-time)
    const legacy = await chrome.storage.local.get("gapiStore");
    if (legacy.gapiStore) {
      _deserializeIntoGlobalStore(legacy.gapiStore);
      await _idbSet("gapiStore", _serializeGlobalStore());
      await chrome.storage.local.remove("gapiStore");
      return;
    }
    // Normal load from IndexedDB
    const s = await _idbGet("gapiStore");
    if (s) _deserializeIntoGlobalStore(s);
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
        doc: v.doc || null,
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
  if (tab._securityFindings) {
    for (var sf = 0; sf < tab._securityFindings.length; sf++) {
      var finding = tab._securityFindings[sf];
      globalStore.securityFindings.set(finding.sourceUrl || ("unknown_" + sf), finding);
    }
  }
  scheduleSave();
}

async function clearGlobalStore() {
  globalStore.apiKeys.clear();
  globalStore.endpoints.clear();
  globalStore.discoveryDocs.clear();
  globalStore.probeResults.clear();
  globalStore.scopes.clear();
  globalStore.securityFindings.clear();
  try {
    await _idbClear();
  } catch (_) {
    console.error("[Storage] Clear failed:", _);
  }
}

// Load persisted data on startup — handlers must await this before reading globalStore
const _globalStoreReady = loadGlobalStore();

// ─── Session Storage (Request Logs) ─────────────────────────────────────────

function serializeLogEntry(entry) {
  const clone = { ...entry };
  delete clone.requestBody; // Chrome requestBody object, redundant with rawBodyB64
  delete clone.decodedBody; // Parsed protobuf tree, regenerable
  return clone;
}

function scheduleSessionSave(tabId) {
  if (_sessionSaveTimers.has(tabId)) {
    clearTimeout(_sessionSaveTimers.get(tabId));
  }
  _sessionSaveTimers.set(
    tabId,
    setTimeout(() => {
      _sessionSaveTimers.delete(tabId);
      saveTabSessionLog(tabId);
    }, 1000),
  );
}

async function saveTabSessionLog(tabId) {
  const tab = state.tabs.get(tabId);
  if (!tab) return;
  try {
    const serialized = tab.requestLog.map(serializeLogEntry);
    await chrome.storage.session.set({ [`reqLog_${tabId}`]: serialized });
    await saveSessionIndex();
  } catch (e) {
    console.error("[Session] Save failed for tab", tabId, e);
  }
}

async function saveSessionIndex() {
  const index = {};
  for (const [tabId, meta] of _tabMeta) {
    const tab = state.tabs.get(tabId);
    const count = tab ? tab.requestLog.length : 0;
    if (count > 0 || meta.closed) {
      index[tabId] = { ...meta, count };
    }
  }
  try {
    await chrome.storage.session.set({ reqLog_index: index });
  } catch (e) {
    console.error("[Session] Index save failed:", e);
  }
}

async function loadSessionLogs() {
  try {
    const data = await chrome.storage.session.get(null);
    for (const [key, value] of Object.entries(data)) {
      if (key === "reqLog_index") {
        for (const [tidStr, meta] of Object.entries(value)) {
          const tid = parseInt(tidStr, 10);
          if (!isNaN(tid)) _tabMeta.set(tid, meta);
        }
        continue;
      }
      if (key.startsWith("reqLog_")) {
        const tabId = parseInt(key.slice(7), 10);
        if (isNaN(tabId) || !Array.isArray(value)) continue;
        const tab = getTab(tabId);
        if (tab.requestLog.length === 0) {
          tab.requestLog = value;
        }
      }
    }
  } catch (e) {
    console.error("[Session] Load failed:", e);
  }
}

loadSessionLogs();

// ─── Patterns ────────────────────────────────────────────────────────────────

const API_KEY_RE = /AIzaSy[\w-]{33}/g;

function isApiRequest(url, details) {
  // Use the browser's own resource type classification
  // xmlhttprequest covers both fetch() and XMLHttpRequest calls
  if (details.type !== "xmlhttprequest") return false;

  // Ignore tracking/telemetry noise
  const noisePaths = [
    "/gen_204",
    "/client_204",
    "/jserror",
    "/ulog",
    "/log",
    "/error",
    "/collect",
  ];
  if (noisePaths.some((p) => url.pathname.includes(p))) return false;

  return true;
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

  // Special handling for Google API hosts
  if (
    hostname.endsWith(".googleapis.com") ||
    hostname.endsWith(".clients6.google.com")
  ) {
    const m = hostname.match(/^(?:staging-)?([^.]+)\./);
    return m ? m[1] : hostname;
  }

  // Google-specific: /async/ is an API root on Google properties only
  const isGoogleHost =
    hostname.endsWith(".google.com") || hostname.includes("google");

  // API root keywords — segments that mark where the API namespace begins
  const apiRootKeywords = [
    "api",
    "_api",
    "__api",
    "rest",
    "graphql",
    "gql",
    "grpc",
    "rpc",
    "wp-json",
    "services",
    "gateway",
  ];
  if (isGoogleHost) apiRootKeywords.push("async");

  const isVersionSeg = (s) => /^v\d+\w*$/i.test(s);

  // Find where the API "root" starts — match keyword roots first
  let rootIdx = -1;
  for (let i = 0; i < segments.length; i++) {
    if (apiRootKeywords.includes(segments[i].toLowerCase())) {
      rootIdx = i;
      // Also include a following version segment (e.g. api/v2 → rootIdx covers both)
      if (i + 1 < segments.length && isVersionSeg(segments[i + 1])) {
        rootIdx = i + 1;
      }
      break;
    }
  }

  // If no keyword root, find the first version segment anywhere in the path
  if (rootIdx === -1) {
    for (let i = 0; i < segments.length; i++) {
      if (isVersionSeg(segments[i])) {
        rootIdx = i;
        break;
      }
    }
  }

  if (rootIdx !== -1) {
    return hostname + "/" + segments.slice(0, rootIdx + 1).join("/");
  }

  // Fallback: group under hostname alone — most sites have one API,
  // and the first path segment is typically a resource, not a service boundary
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

    // Skip internal requests immediately
    if (url.hash.includes("_internal_probe")) return;
    if (url.hash.includes("_uasr_send")) return;

    if (!isApiRequest(url, details)) return;

    const tab = getTab(details.tabId);

    // Capture initiator as distinct from Origin header (more reliable for context)
    if (details.initiator) {
      tab.authContext = tab.authContext || {};
      if (!tab.authContext.origin) {
        tab.authContext.origin = details.initiator;
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
      frameId: details.frameId,
      documentId: details.documentId,
    };

    // Check if duplicate? (unlikely for new request)
    tab.requestLog.unshift(entry);
    if (tab.requestLog.length > 50) tab.requestLog.pop();
    scheduleSessionSave(details.tabId);
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

    // Skip internal requests early
    if (url.hash.includes("_internal_probe")) return;
    if (url.hash.includes("_uasr_send")) return;

    // ─── CRITICAL: Universal Key Scanning ───
    // Scan EVERY request (scripts, assets, etc) for keys in URL and Headers
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

    if (!isApiRequest(url, details)) return;

    // Skip internal probe requests
    if (url.searchParams.has("_probe")) return;

    const tab = getTab(details.tabId);

    // Capture initiator again in case onBeforeRequest didn't catch it
    if (details.initiator) {
      tab.authContext = tab.authContext || {};
      if (!tab.authContext.origin) {
        tab.authContext.origin = details.initiator;
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
      scheduleSessionSave(details.tabId);
    }

    learnFromRequest(details.tabId, service, entry, headerMap);

    // Sync learned data to globalStore immediately so it survives SW restarts
    mergeToGlobal(tab);

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
    // Cooldown: don't retry not_found within 5 minutes to avoid flooding.
    const notFoundCooldown = discoveryStatus?.status === "not_found" &&
      discoveryStatus._failedAt && (Date.now() - discoveryStatus._failedAt < 300000);
    if (!notFoundCooldown && (!discoveryStatus || discoveryStatus.status === "not_found")) {
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

    const logContentType = headerMap["content-type"] || "";

    entry.requestHeaders = headerMap;
    entry.contentType = logContentType;
    entry.service = service;

    if (entry.rawBodyB64) {
      try {
        const bytes = base64ToUint8(entry.rawBodyB64);
        if (isProtobuf) {
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
        } else if (logContentType.includes("x-www-form-urlencoded")) {
          // Form-urlencoded with f.req JSPB (e.g. browserinfo)
          try {
            const text = new TextDecoder().decode(bytes);
            const params = new URLSearchParams(text);
            const fReq = params.get("f.req");
            if (fReq) {
              const json = JSON.parse(fReq);
              if (Array.isArray(json)) {
                entry.decodedBody = jspbToTree(json);
                entry.isJspb = true;
              }
            }
          } catch (e) {}
        } else if (logContentType.includes("json")) {
          // JSON body — store parsed object for replay pre-fill
          try {
            const text = new TextDecoder().decode(bytes);
            const json = JSON.parse(text);
            if (json && typeof json === "object") {
              entry.decodedBody = json;
              entry.isJson = true;
            }
          } catch (e) {}
        }
      } catch (err) {}
    }

    scheduleSessionSave(details.tabId);
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
    if (!isApiRequest(url, details)) return;

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

    // Response body learning is handled by the RESPONSE_BODY message from
    // the main-world intercept script (intercept.js → content.js relay).
  },
  {
    urls: ["<all_urls>"],
  },
  ["responseHeaders"],
);

/** Detect path segments that look like dynamic IDs rather than resource names. */
function looksLikeDynamicSegment(s) {
  if (/^\d+$/.test(s)) return true; // Pure numeric
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(s)) return true; // UUID prefix
  if (/^[0-9a-f]{24}$/i.test(s)) return true; // MongoDB ObjectId
  // Base64-like tokens: 16+ chars, must contain a digit (avoids camelCase names)
  if (
    s.length >= 16 &&
    /^[A-Za-z0-9_-]+$/.test(s) &&
    /\d/.test(s) &&
    !/^[a-z]+$/.test(s)
  )
    return true;
  return false;
}

function calculateMethodMetadata(urlObj, interfaceName) {
  // batchexecute: use first rpcid from URL param (individual calls registered by learnFromRequest)
  if (urlObj.pathname.includes("batchexecute")) {
    const rpcids = urlObj.searchParams.get("rpcids") || "batch";
    const primaryRpcId = rpcids.split(",")[0].trim();
    return {
      methodName: primaryRpcId,
      methodId: `${interfaceName.replace(/\//g, ".")}.${primaryRpcId}`,
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

  // Strip segments that look like hashes, long ID lists, or path-style params
  methodSegments = methodSegments.filter((s) => {
    if (s.length > 32) return false;
    if (s.includes("=")) return false; // path-style parameter (e.g. name=foo)
    return true;
  });

  // Normalize dynamic segments (IDs, UUIDs, tokens) to prevent method proliferation
  methodSegments = methodSegments.map((s) =>
    looksLikeDynamicSegment(s) ? "_id" : s,
  );

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
        rootUrl: url.origin + "/",
        baseUrl: url.origin + "/",
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

  const { methodName: baseMethodName } = calculateMethodMetadata(url, interfaceName);
  const qualifiedName = method.toLowerCase() + "_" + baseMethodName;

  // If this method was already probed with richer schema, update it there instead
  const probedMethod = doc.resources.probed?.methods?.[baseMethodName];

  // Resolve method name — disambiguate when different HTTP methods hit the same path
  let methodName;
  const existingBase = doc.resources.learned.methods[baseMethodName];
  const existingQualified = doc.resources.learned.methods[qualifiedName];

  if (existingQualified) {
    // Already disambiguated from a prior collision — use qualified name
    methodName = qualifiedName;
  } else if (existingBase && existingBase.httpMethod !== method && !probedMethod) {
    // Collision: different HTTP method to same path — rename existing, qualify new
    const existQualName = existingBase.httpMethod.toLowerCase() + "_" + baseMethodName;
    if (!doc.resources.learned.methods[existQualName]) {
      existingBase.id = `${interfaceName.replace(/\//g, ".")}.${existQualName}`;
      doc.resources.learned.methods[existQualName] = existingBase;
    }
    delete doc.resources.learned.methods[baseMethodName];
    methodName = qualifiedName;
  } else {
    // No collision — use base name
    methodName = baseMethodName;
  }

  const methodId = `${interfaceName.replace(/\//g, ".")}.${methodName}`;
  entry.methodId = methodId;

  if (!doc.resources.learned.methods[methodName] && !probedMethod) {
    doc.resources.learned.methods[methodName] = {
      id: methodId,
      path: url.pathname.substring(1),
      httpMethod: method,
      parameters: {},
      request: null,
    };
  }

  const m = probedMethod || doc.resources.learned.methods[methodName];

  // Learn query parameters from URL
  if (!url.pathname.includes("batchexecute")) {
    url.searchParams.forEach((value, name) => {
      if (name === "key" || name === "api_key") return;
      if (!m.parameters[name]) {
        m.parameters[name] = {
          type: isNaN(value) ? "string" : "number",
          location: "query",
          description: "Learned from request",
        };
      }
    });

    // Learn path parameters by comparing URL to stored template AND
    // by detecting ID-like segments on first observation.
    const segments = url.pathname.split("/").filter(Boolean);
    const templateParts = (m.path || "").split("/").filter(Boolean);
    if (templateParts.length === segments.length) {
      let changed = false;
      for (let i = 0; i < segments.length; i++) {
        if (templateParts[i].startsWith("{")) continue; // Already templated
        if (templateParts[i] !== segments[i]) {
          // Segment differs from template — definitely a parameter
          const paramName = `path_${templateParts[i] || "param" + i}`;
          templateParts[i] = `{${paramName}}`;
          if (!m.parameters[paramName]) {
            m.parameters[paramName] = {
              type: "string",
              location: "path",
              description: "Inferred path parameter",
            };
          }
          changed = true;
        } else if (looksLikeDynamicSegment(segments[i])) {
          // First observation but segment looks like an ID/UUID/token
          const paramName = `path_param${i}`;
          templateParts[i] = `{${paramName}}`;
          if (!m.parameters[paramName]) {
            m.parameters[paramName] = {
              type: "string",
              location: "path",
              description: "Inferred path parameter (pattern-detected)",
            };
          }
          changed = true;
        }
      }
      if (changed) m.path = templateParts.join("/");
    }
  }

  // Record the observed Content-Type on the method for replay fidelity
  if (headers["content-type"]) {
    const ct = headers["content-type"].split(";")[0].trim();
    if (!m.contentTypes) m.contentTypes = [];
    if (!m.contentTypes.includes(ct)) m.contentTypes.unshift(ct);
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
          const newSchema = generateSchemaFromJson(
            call.data,
            schemaName,
            doc.schemas,
            true,
          );
          mergeSchemaInto(doc, schemaName, newSchema);
        }
      }
    } else if (
      headers["content-type"]?.includes("grpc-web") ||
      headers["content-type"]?.includes("grpc+proto")
    ) {
      // gRPC-Web request body: 5-byte frame header + protobuf payload
      try {
        const parsed = parseGrpcWebFrames(bytes);
        if (parsed) {
          for (const frame of parsed.frames) {
            if (frame.type !== "data") continue;
            const tree = pbDecodeTree(frame.data, 8);
            if (tree && tree.length > 0) {
              const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Request`;
              m.request = { $ref: schemaName };
              const newSchema = generateSchemaFromPbTree(tree, schemaName, doc.schemas);
              mergeSchemaInto(doc, schemaName, newSchema);
            }
          }
        }
      } catch (e) {}
    } else if (headers["content-type"]?.includes("json+protobuf")) {
      // JSPB body — positional array encoding
      try {
        const json = JSON.parse(text);
        if (Array.isArray(json)) {
          const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Request`;
          m.request = { $ref: schemaName };
          const newSchema = generateSchemaFromJson(json, schemaName, doc.schemas, true);
          mergeSchemaInto(doc, schemaName, newSchema);
        }
      } catch (e) {}
    } else if (
      headers["content-type"]?.includes("x-protobuf") ||
      headers["content-type"]?.includes("application/protobuf")
    ) {
      // Binary protobuf body
      try {
        const tree = pbDecodeTree(bytes, 8);
        if (tree && tree.length > 0) {
          const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Request`;
          m.request = { $ref: schemaName };
          const newSchema = generateSchemaFromPbTree(tree, schemaName, doc.schemas);
          mergeSchemaInto(doc, schemaName, newSchema);
        }
      } catch (e) {}
    } else if (headers["content-type"]?.includes("json")) {
      try {
        const json = JSON.parse(text);
        const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Request`;
        m.request = { $ref: schemaName };
        const newSchema = generateSchemaFromJson(json, schemaName, doc.schemas);
        mergeSchemaInto(doc, schemaName, newSchema);
      } catch (e) {}
    } else if (headers["content-type"]?.includes("x-www-form-urlencoded")) {
      // Form-urlencoded with f.req JSPB (non-batchexecute, e.g. browserinfo)
      try {
        const params = new URLSearchParams(text);
        const fReq = params.get("f.req");
        if (fReq) {
          const json = JSON.parse(fReq);
          if (Array.isArray(json)) {
            const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Request`;
            m.request = { $ref: schemaName };
            const newSchema = generateSchemaFromJson(json, schemaName, doc.schemas, true);
            mergeSchemaInto(doc, schemaName, newSchema);
          }
        }
      } catch (e) {}
    }
  }

  // ─── Statistics collection ───────────────────────────────────────────────
  if (!m._stats) m._stats = { requestCount: 0, params: {}, bodyFields: {} };
  m._stats.requestCount++;

  // Track query param values
  if (!url.pathname.includes("batchexecute")) {
    url.searchParams.forEach((value, name) => {
      if (name === "key" || name === "api_key") return;
      if (!m._stats.params[name]) m._stats.params[name] = createParamStats();
      updateParamStats(m._stats.params[name], value);
    });
  }

  // Track body field values (JSON bodies only)
  if (entry.isJson && entry.decodedBody && typeof entry.decodedBody === "object") {
    const flat = flattenObjectValues(entry.decodedBody);
    for (const [fieldPath, value] of Object.entries(flat)) {
      if (typeof value === "string" || typeof value === "number") {
        if (!m._stats.bodyFields[fieldPath]) m._stats.bodyFields[fieldPath] = createParamStats();
        updateParamStats(m._stats.bodyFields[fieldPath], String(value));
      }
    }
  }

  // Apply stats-derived metadata back to parameters
  applyStatsToMethod(m);

  // ─── Chain detection ────────────────────────────────────────────────────
  if (tab._valueIndex) {
    const requestParams = {};
    url.searchParams.forEach((v, k) => { requestParams[k] = v; });
    // Extract body values for chain matching: use JSON body if available
    let chainBody = {};
    if (entry.isJson && entry.decodedBody) {
      chainBody = entry.decodedBody;
    } else if (entry.rawBodyB64) {
      try {
        const _cbText = new TextDecoder().decode(base64ToUint8(entry.rawBodyB64));
        chainBody = JSON.parse(_cbText);
      } catch (_) {}
    }
    const bodyValues = flattenObjectValues(chainBody);
    const links = findChainLinks(tab._valueIndex, requestParams, bodyValues, methodId);
    if (links.length) {
      m._chains = mergeChainLinks(m._chains, links);
      // Update outgoing chains on source methods
      for (var li = 0; li < links.length; li++) {
        var srcMethod = findMethodInDoc(doc, links[li].sourceMethodId);
        if (srcMethod) {
          if (!srcMethod._chains) srcMethod._chains = { incoming: [], outgoing: [] };
          var outLink = {
            targetMethodId: methodId,
            paramName: links[li].paramName,
            sourceFieldPath: links[li].sourceFieldPath,
            lastSeen: links[li].lastSeen,
          };
          var outDupe = false;
          for (var oi = 0; oi < srcMethod._chains.outgoing.length; oi++) {
            var o = srcMethod._chains.outgoing[oi];
            if (o.targetMethodId === methodId && o.paramName === links[li].paramName && o.sourceFieldPath === links[li].sourceFieldPath) {
              o.observedCount = (o.observedCount || 1) + 1;
              o.lastSeen = links[li].lastSeen;
              outDupe = true;
              break;
            }
          }
          if (!outDupe) {
            outLink.observedCount = 1;
            srcMethod._chains.outgoing.push(outLink);
          }
        }
      }
    }
  }
}

function applyStatsToMethod(m) {
  if (!m._stats || m._stats.requestCount < STATS_MIN_OBS_FOR_REQUIRED) return;
  const stats = m._stats;

  for (const [name, paramStats] of Object.entries(stats.params)) {
    if (!m.parameters[name]) continue;
    const param = m.parameters[name];

    // Required detection
    const reqAnalysis = analyzeRequired(paramStats, stats.requestCount);
    if (!param.customRequired) {
      param.required = reqAnalysis.required;
      param._requiredConfidence = reqAnalysis.confidence;
    }

    // Enum detection
    const enumAnalysis = analyzeEnum(paramStats);
    if (enumAnalysis.isEnum && !param.customEnum) {
      param.enum = enumAnalysis.values;
      param._detectedEnum = true;
    }

    // Default detection
    const defaultAnalysis = analyzeDefault(paramStats);
    if (defaultAnalysis.hasDefault) {
      param._defaultValue = defaultAnalysis.value;
      param._defaultConfidence = defaultAnalysis.confidence;
    }

    // Type narrowing
    const narrowedFormat = analyzeFormat(paramStats);
    if (narrowedFormat && param.type === "string") {
      param.format = narrowedFormat;
    }

    // Numeric range
    const range = analyzeRange(paramStats);
    if (range) {
      param._range = range;
    }
  }

  // Correlations
  stats.correlations = detectCorrelations(stats);
}

function findMethodInDoc(doc, methodId) {
  if (!doc || !doc.resources) return null;
  for (const rKey of Object.keys(doc.resources)) {
    var methods = doc.resources[rKey]?.methods;
    if (methods) {
      for (var mKey in methods) {
        if (methods[mKey].id === methodId) return methods[mKey];
      }
    }
  }
  return null;
}

function learnFromResponse(tabId, interfaceName, entry) {
  if (!entry.responseBody) return;

  const tab = getTab(tabId);
  const url = new URL(entry.url);
  const { methodName } = calculateMethodMetadata(url, interfaceName);
  // Check tab-level first, then fall back to globalStore (survives SW restarts)
  let docEntry = tab.discoveryDocs.get(interfaceName);
  if (!docEntry?.doc) {
    const globalEntry = globalStore.discoveryDocs.get(interfaceName);
    if (globalEntry?.doc) {
      docEntry = globalEntry;
      // Also set on tab so subsequent lookups are fast
      tab.discoveryDocs.set(interfaceName, docEntry);
    }
  }
  if (!docEntry || !docEntry.doc) return;
  const doc = docEntry.doc;
  // Find method — try base name first, then HTTP-qualified name (from disambiguation)
  const qualifiedName = entry.method ? entry.method.toLowerCase() + "_" + methodName : null;
  const learned = doc.resources.learned?.methods;
  const m = learned
    ? (learned[methodName] || (qualifiedName ? learned[qualifiedName] : null))
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
  if (isAsyncChunkedResponse(textBody)) {
    const chunks = parseAsyncChunkedResponse(textBody);
    if (chunks) {
      if (!doc.resources.learned) doc.resources.learned = { methods: {} };
      // Use endpoint path as the method key (e.g. "hpba" from /async/hpba)
      const asyncPath = url.pathname.split("/").filter(Boolean).pop() || methodName;
      for (let i = 0; i < chunks.length; i++) {
        const chunk = chunks[i];
        if (chunk.type !== "jspb" || !Array.isArray(chunk.data)) continue;

        const chunkKey = `${asyncPath}_chunk${i}`;
        let callM =
          doc.resources.learned.methods[chunkKey] ||
          doc.resources.probed?.methods[chunkKey];
        if (!callM) {
          doc.resources.learned.methods[chunkKey] = {
            id: `${interfaceName.replace(/\//g, ".")}.${chunkKey}`,
            path: url.pathname.substring(1),
            httpMethod: entry.method || "GET",
            parameters: {},
            request: null,
            response: null,
          };
          callM = doc.resources.learned.methods[chunkKey];
        }

        const schemaName = `${chunkKey}Response`;
        callM.response = { $ref: schemaName };
        const newSchema = generateSchemaFromJson(
          chunk.data,
          schemaName,
          doc.schemas,
          true,
        );
        mergeSchemaInto(doc, schemaName, newSchema);
      }
    }
  } else if (isBatchExecuteResponse(textBody)) {
    const results = parseBatchExecuteResponse(textBody);
    if (results) {
      if (!doc.resources.learned) doc.resources.learned = { methods: {} };
      for (const res of results) {
        let callM =
          doc.resources.learned.methods[res.rpcId] ||
          doc.resources.probed?.methods[res.rpcId];
        // Create method entry if response arrived before request was learned
        if (!callM) {
          doc.resources.learned.methods[res.rpcId] = {
            id: `${interfaceName.replace(/\//g, ".")}.${res.rpcId}`,
            path: url.pathname.substring(1),
            httpMethod: "POST",
            parameters: {},
            request: null,
            response: null,
          };
          callM = doc.resources.learned.methods[res.rpcId];
        }

        const schemaName = `${res.rpcId}Response`;
        callM.response = { $ref: schemaName };
        const newSchema = generateSchemaFromJson(
          res.data,
          schemaName,
          doc.schemas,
          true,
        );
        mergeSchemaInto(doc, schemaName, newSchema);
      }
    }
  } else if (isGrpcWeb(mimeType)) {
    // gRPC-Web: unwrap frames, decode protobuf payload
    try {
      let bytes;
      if (isGrpcWebText(mimeType)) {
        // grpc-web-text uses base64 encoding
        bytes = base64ToUint8(
          entry.responseBase64 ? entry.responseBody : btoa(entry.responseBody),
        );
      } else {
        bytes = entry.responseBase64
          ? base64ToUint8(entry.responseBody)
          : new TextEncoder().encode(entry.responseBody);
      }
      const parsed = parseGrpcWebFrames(bytes);
      if (parsed) {
        for (const frame of parsed.frames) {
          if (frame.type !== "data") continue;
          const tree = pbDecodeTree(frame.data, 8, (val) => {
            if (typeof val === "string") {
              extractKeysFromText(tabId, val, entry.url, "response_grpc");
            }
          });
          const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Response`;
          targetM.response = { $ref: schemaName };
          const newSchema = generateSchemaFromPbTree(
            tree,
            schemaName,
            doc.schemas,
          );
          mergeSchemaInto(doc, schemaName, newSchema);
        }
      }
    } catch (e) {}
  } else if (isSSE(mimeType)) {
    // Server-Sent Events: learn schema from JSON data payloads
    try {
      const events = parseSSE(textBody);
      if (events) {
        for (const evt of events) {
          if (typeof evt.data === "object" && evt.data !== null) {
            const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Event`;
            targetM.response = { $ref: schemaName };
            const newSchema = generateSchemaFromJson(
              evt.data,
              schemaName,
              doc.schemas,
            );
            mergeSchemaInto(doc, schemaName, newSchema);
            break; // Schema from first JSON event is representative
          }
        }
      }
    } catch (e) {}
  } else if (isNDJSON(mimeType)) {
    // NDJSON: learn schema from first object
    try {
      const objects = parseNDJSON(textBody);
      if (objects && objects.length > 0) {
        const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Response`;
        targetM.response = { $ref: schemaName };
        const newSchema = generateSchemaFromJson(
          objects[0],
          schemaName,
          doc.schemas,
        );
        mergeSchemaInto(doc, schemaName, newSchema);
      }
    } catch (e) {}
  } else if (isMultipartBatch(mimeType)) {
    // Multipart batch: learn schema from each part's body
    try {
      const parts = parseMultipartBatch(textBody, mimeType);
      if (parts) {
        for (let i = 0; i < parts.length; i++) {
          const part = parts[i];
          if (!part.body) continue;
          try {
            const json = JSON.parse(part.body);
            const partKey = `${methodName}_part${i}`;
            if (!doc.resources.learned) doc.resources.learned = { methods: {} };
            let partM = doc.resources.learned.methods[partKey];
            if (!partM) {
              doc.resources.learned.methods[partKey] = {
                id: `${interfaceName.replace(/\//g, ".")}.${partKey}`,
                path: url.pathname.substring(1),
                httpMethod: entry.method || "POST",
                parameters: {},
                request: null,
                response: null,
              };
              partM = doc.resources.learned.methods[partKey];
            }
            const schemaName = `${partKey}Response`;
            partM.response = { $ref: schemaName };
            const newSchema = generateSchemaFromJson(
              json,
              schemaName,
              doc.schemas,
            );
            mergeSchemaInto(doc, schemaName, newSchema);
          } catch (_) {}
        }
      }
    } catch (e) {}
  } else if (isGraphQLUrl(url.href) && mimeType.includes("json")) {
    // GraphQL response: extract data/errors structure
    try {
      const gqlResp = parseGraphQLResponse(textBody);
      if (gqlResp && gqlResp.data) {
        const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Response`;
        targetM.response = { $ref: schemaName };
        const newSchema = generateSchemaFromJson(
          gqlResp.data,
          schemaName,
          doc.schemas,
        );
        mergeSchemaInto(doc, schemaName, newSchema);
      }
    } catch (e) {}
  } else if (mimeType.includes("json")) {
    try {
      const json = JSON.parse(textBody);
      const schemaName = `${methodName.replace(/[^a-zA-Z0-9]/g, "")}Response`;
      targetM.response = { $ref: schemaName };
      const newSchema = generateSchemaFromJson(json, schemaName, doc.schemas);
      mergeSchemaInto(doc, schemaName, newSchema);
    } catch (e) {}
  } else if (
    mimeType.includes("protobuf") ||
    entry.contentType?.includes("protobuf") ||
    mimeType.includes("octet-stream") ||
    entry.contentType?.includes("octet-stream")
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
      targetM.response = { $ref: schemaName };
      const newSchema = generateSchemaFromPbTree(tree, schemaName, doc.schemas);
      mergeSchemaInto(doc, schemaName, newSchema);
    } catch (e) {}
  }

  // ─── Chain value indexing ─────────────────────────────────────────────────
  // Index response values so subsequent requests can detect chains
  if (tab._valueIndex && textBody) {
    const methodId = targetM.id || `${interfaceName.replace(/\//g, ".")}.${methodName}`;
    try {
      const parsed = JSON.parse(textBody);
      indexResponseValues(tab._valueIndex, parsed, methodId);
    } catch (_) {
      // Not JSON — index the raw text body if it looks like a useful value
      if (textBody.length >= 4 && textBody.length <= 500) {
        indexResponseValues(tab._valueIndex, textBody, methodId);
      }
    }
  }
}

function generateSchemaFromPbTree(tree, name, schemas) {
  // First pass: count field occurrences to detect repeated fields
  const fieldCounts = {};
  for (const node of tree) {
    fieldCounts[node.field] = (fieldCounts[node.field] || 0) + 1;
  }

  const properties = {};
  const seen = new Set();
  for (const node of tree) {
    const fieldKey = `field${node.field}`;
    if (seen.has(node.field)) {
      // Merge nested schemas from additional occurrences of repeated message fields
      if (node.message) {
        const nestedName = `${name}Field${node.field}`;
        if (schemas[nestedName]) {
          const additionalSchema = generateSchemaFromPbTree(node.message, nestedName, schemas);
          const existing = schemas[nestedName];
          if (!existing.properties) existing.properties = {};
          for (const [k, v] of Object.entries(additionalSchema.properties || {})) {
            if (!existing.properties[k]) {
              existing.properties[k] = v;
            }
          }
        }
      }
      continue;
    }
    seen.add(node.field);

    const isRepeated = fieldCounts[node.field] > 1 || !!node.isRepeatedScalar || !!node.packed;
    let wireType;

    // For JSPB-sourced nodes, infer type from the actual JS value
    // since wire codes are synthetic and less reliable
    if (node.isJspb) {
      const val = node.value;
      if (typeof val === "boolean") wireType = "bool";
      else if (typeof val === "number") wireType = Number.isInteger(val) ? "int64" : "double";
      else if (typeof val === "string") wireType = "string";
      else if (node.isRepeatedScalar && Array.isArray(val) && val.length > 0) {
        // Infer from first non-null element of repeated scalar
        const sample = val.find((v) => v != null);
        if (typeof sample === "boolean") wireType = "bool";
        else if (typeof sample === "number") wireType = Number.isInteger(sample) ? "int64" : "double";
        else wireType = "string";
      } else wireType = "string";
    } else if (node.packed) {
      // Packed repeated: values are varint-decoded numbers
      wireType = "int64";
    } else {
      // Binary protobuf wire type inference
      if (node.wire === 0) wireType = "int64";
      else if (node.wire === 5) wireType = "float";
      else if (node.wire === 1) wireType = "double";
      else if (node.string !== undefined) wireType = "string";
      else if (node.hex) wireType = "bytes";
      else wireType = "string";
    }

    const prop = {
      id: node.field,
      number: node.field,
      type: wireType,
      description: "Discovered via response capture",
    };

    if (isRepeated) {
      prop.type = "array";
      prop.items = { type: wireType };
    }

    if (node.message) {
      const nestedName = `${name}Field${node.field}`;
      if (isRepeated) {
        prop.items = { $ref: nestedName };
      } else {
        prop.type = "message";
        prop.$ref = nestedName;
      }
      schemas[nestedName] = generateSchemaFromPbTree(
        node.message,
        nestedName,
        schemas,
      );
    } else if (node.string !== undefined) {
      if (!isRepeated) prop.type = "string";
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
          // Distinguish repeated scalars from nested JSPB messages:
          // - All primitives (string/number/bool/null) → repeated scalar
          // - Contains sub-arrays or objects → nested message
          const allPrim =
            val.length > 0 &&
            val.every(
              (v) =>
                v === null ||
                v === undefined ||
                typeof v === "string" ||
                typeof v === "number" ||
                typeof v === "boolean",
            );
          if (allPrim) {
            const itemType = inferRepeatedItemType(val);
            properties[fieldKey] = {
              id: fieldNum,
              number: fieldNum,
              type: itemType,
              label: "repeated",
            };
          } else {
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
          }
        } else if (typeof val === "object") {
          // Object within indexed array → nested named-key message
          properties[fieldKey] = {
            id: fieldNum,
            number: fieldNum,
            $ref: nestedName,
          };
          schemas[nestedName] = generateSchemaFromJson(
            val,
            nestedName,
            schemas,
            false,
          );
        } else {
          properties[fieldKey] = {
            id: fieldNum,
            number: fieldNum,
            type: inferJsonType(val),
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
        properties[key] = { type: inferJsonType(val) };
      }
    }
    return { id: name, type: "object", properties };
  } else {
    return { type: inferJsonType(json) };
  }
}

/**
 * Infer a protobuf-style type from a JS value.
 * More precise than raw `typeof` — distinguishes int vs float, bool, etc.
 */
function inferJsonType(val) {
  if (val === null || val === undefined) return "string";
  if (typeof val === "boolean") return "bool";
  if (typeof val === "number") {
    return Number.isInteger(val) ? "int64" : "double";
  }
  if (typeof val === "string") return "string";
  return "string";
}

/** Infer the best scalar type for a repeated field from sample values. */
function inferRepeatedItemType(arr) {
  for (const v of arr) {
    if (v === null || v === undefined) continue;
    return inferJsonType(v);
  }
  return "string";
}

/**
 * Merge new schema properties into an existing schema, preserving custom renames
 * and enriching with new fields. Existing fields keep customName/name if set;
 * new fields or missing type info gets filled in from the new observation.
 */
function mergeSchemaInto(doc, schemaName, newSchema) {
  if (!doc.schemas[schemaName]) {
    doc.schemas[schemaName] = newSchema;
    return;
  }
  const existing = doc.schemas[schemaName];
  if (!existing.properties) existing.properties = {};
  const newProps = newSchema.properties || {};

  // Build field-number → key index for deduplication
  const numToKey = {};
  for (const [k, p] of Object.entries(existing.properties)) {
    const n = p.number ?? p.id;
    if (n != null) numToKey[n] = k;
  }

  for (const [key, newProp] of Object.entries(newProps)) {
    // Match by key first, then fall back to field number
    const fieldNum = newProp.number ?? newProp.id;
    const matchKey = existing.properties[key] ? key
      : (fieldNum != null && numToKey[fieldNum]) ? numToKey[fieldNum]
      : null;
    const old = matchKey ? existing.properties[matchKey] : null;

    if (!old) {
      // Brand new field — add it
      existing.properties[key] = newProp;
      if (fieldNum != null) numToKey[fieldNum] = key;
    } else {
      // Re-key if matched by field number and the new key has a real name
      if (matchKey !== key && !old.customName && !/^field\d+$/.test(key)) {
        existing.properties[key] = old;
        delete existing.properties[matchKey];
        numToKey[fieldNum] = key;
      }
      // Merge: preserve custom names, upgrade types
      if (old.customName) {
        // Keep the user's rename
      } else if (newProp.name && !old.name) {
        old.name = newProp.name;
      }
      // Upgrade generic types with more specific ones
      if (newProp.type && newProp.type !== old.type) {
        if (old.type === "string" && newProp.type !== "string") {
          old.type = newProp.type;
        }
        // int → double/float (observed fractional value refines integer assumption)
        else if (
          (old.type === "int64" || old.type === "int32") &&
          (newProp.type === "double" || newProp.type === "float")
        ) {
          old.type = newProp.type;
        }
      }
      // Upgrade array item types
      if (old.type === "array" && newProp.items) {
        if (!old.items) {
          old.items = newProp.items;
        } else {
          if (old.items.type === "string" && newProp.items.type && newProp.items.type !== "string") {
            old.items.type = newProp.items.type;
          }
          if (newProp.items.$ref && !old.items.$ref) {
            old.items.$ref = newProp.items.$ref;
          }
        }
      }
      if (newProp.id != null && old.id == null) old.id = newProp.id;
      if (newProp.number != null && old.number == null)
        old.number = newProp.number;
      if (newProp.$ref && !old.$ref) {
        old.$ref = newProp.$ref;
        old.type = "message";
      }
      if (newProp.children && !old.children) old.children = newProp.children;
      if (newProp.description && !old.description) old.description = newProp.description;
      // Merge nested schema recursively
      if (newProp.$ref && doc.schemas[newProp.$ref]) {
        mergeSchemaInto(doc, newProp.$ref, doc.schemas[newProp.$ref]);
      }
    }
  }
}

// ─── Page-Context Fetch Bridge ───────────────────────────────────────────────
// Routes fetch requests through the content script so they execute with the
// page's cookie jar and Origin. The content script shares the page's cookies,
// so the browser attaches them automatically. Targets a specific frameId when
// the request originated from an iframe (e.g. proxy.html).
//
// If the original tab/frame is unreachable, a minimized background window is
// opened to the initiator origin so the content script loads and carries the
// right cookies + Origin.

/**
 * Send a PAGE_FETCH message to a tab's content script.
 */
async function sendPageFetch(tabId, url, opts, frameId = 0) {
  return chrome.tabs.sendMessage(
    tabId,
    {
      type: "PAGE_FETCH",
      url,
      method: opts.method || "GET",
      headers: opts.headers || {},
      body: opts.body ?? null,
      bodyEncoding: opts.bodyEncoding || null,
    },
    { frameId: frameId ?? 0 },
  );
}

/**
 * Open a temporary hidden tab to `initiatorOrigin`, wait for content script
 * to load, and return its tabId. Caller must close via closeTempTab().
 */
// ─── Temp Tab Pooling ────────────────────────────────────────────────────────
// Reuses temporary tabs for the same origin to avoid opening multiple tabs
// during burst requests (like discovery). Keeps tab open for a short time
// after use to handle subsequent requests.

const tempTabPool = new Map(); // origin -> { tabId, windowId, promise, refCount, closeTimer }

// Track temp window IDs in session storage so we can clean up after SW restart.
async function _saveTempWindowIds() {
  const ids = [];
  for (const entry of tempTabPool.values()) {
    if (entry.windowId) ids.push(entry.windowId);
  }
  try { await chrome.storage.session.set({ _tempWinIds: ids }); } catch (_) {}
}
// On startup, close any temp windows leaked from a previous SW lifetime.
(async () => {
  try {
    const data = await chrome.storage.session.get("_tempWinIds");
    const ids = data?._tempWinIds;
    if (Array.isArray(ids)) {
      for (const wid of ids) chrome.windows.remove(wid).catch(() => {});
      await chrome.storage.session.remove("_tempWinIds");
    }
  } catch (_) {}
})();

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

  // Create new entry — use a minimized background window (invisible to user)

  const promise = (async () => {
    try {
      const win = await chrome.windows.create({
        url: origin,
        state: "minimized",
        focused: false,
      });

      const tabId = win.tabs[0].id;

      // Wait for content script (max 15s)
      const deadline = Date.now() + 15000;
      while (Date.now() < deadline) {
        try {
          await chrome.tabs.sendMessage(
            tabId,
            { type: "PING" },
            { frameId: 0 },
          );

          return { tabId, windowId: win.id };
        } catch (_) {
          await new Promise((r) => setTimeout(r, 500));
        }
      }

      // Timeout
      chrome.windows.remove(win.id).catch(() => {});
      throw new Error("Temp tab timeout");
    } catch (err) {
      // Clean up pool if creation failed
      tempTabPool.delete(origin);
      throw err;
    }
  })();

  entry = { tabId: null, windowId: null, promise, refCount: 1, closeTimer: null };
  tempTabPool.set(origin, entry);

  try {
    const result = await promise;
    entry.tabId = result.tabId;
    entry.windowId = result.windowId;
    _saveTempWindowIds();
    return result.tabId;
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
      if (entry.windowId) {
        chrome.windows.remove(entry.windowId).catch(() => {});
      } else if (entry.tabId) {
        chrome.tabs.remove(entry.tabId).catch(() => {});
      }
      if (entry.tabId) state.tabs.delete(entry.tabId);
      _saveTempWindowIds();
    }, 10000);
  }
}

/**
 * Resolve the best frameId for a given initiatorOrigin on a tab.
 * Uses webNavigation.getAllFrames to find a frame matching the origin.
 * Returns 0 (main frame) if no match or if initiatorOrigin is null.
 */
async function _resolveFrameForOrigin(tabId, initiatorOrigin) {
  if (!initiatorOrigin) return 0;
  try {
    const frames = await chrome.webNavigation.getAllFrames({ tabId });
    if (!frames) return 0;
    // Prefer non-main frames matching the origin (iframe proxy scenario)
    for (const f of frames) {
      if (f.frameId === 0) continue; // check sub-frames first
      try {
        if (new URL(f.url).origin === initiatorOrigin) return f.frameId;
      } catch (_) {}
    }
    // Fall back to main frame if its origin matches
    for (const f of frames) {
      if (f.frameId !== 0) continue;
      try {
        if (new URL(f.url).origin === initiatorOrigin) return 0;
      } catch (_) {}
    }
  } catch (_) {}
  return 0;
}

/**
 * Fetch through a content script, with temp window fallback.
 * Dynamically resolves the correct frame by matching initiatorOrigin
 * against the tab's current frames (frameIds are ephemeral).
 */
async function pageContextFetch(tabId, url, opts, initiatorOrigin) {
  // Validate URL
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { error: "blocked: invalid protocol" };
    }
  } catch (_) {
    return { error: "blocked: invalid URL" };
  }

  // Try the original tab — resolve the right frame dynamically
  if (tabId != null) {
    const frameId = await _resolveFrameForOrigin(tabId, initiatorOrigin);
    try {
      return await sendPageFetch(tabId, url, opts, frameId);
    } catch (_) {
      // If we targeted a sub-frame and it failed, fall back to main frame
      if (frameId !== 0) {
        try {
          return await sendPageFetch(tabId, url, opts, 0);
        } catch (__) {}
      }

      // Tab might still be loading — poll briefly if origin matches
      try {
        const tab = await chrome.tabs.get(tabId);
        if (tab && tab.url) {
          const tabOrigin = new URL(tab.url).origin;
          if (initiatorOrigin && tabOrigin === initiatorOrigin) {
            const deadline = Date.now() + 5000;
            while (Date.now() < deadline) {
              try {
                await new Promise((r) => setTimeout(r, 500));
                return await sendPageFetch(tabId, url, opts, 0);
              } catch (___) {}
            }
          }
        }
      } catch (_) {}
    }
  }

  // Fall back: use pooled minimized background window
  if (initiatorOrigin) {
    try {
      const tempTabId = await acquireTempTab(initiatorOrigin);
      return await sendPageFetch(tempTabId, url, opts);
    } catch (err) {
      console.warn(`Relay failed for ${url} (temp window error: ${err.message})`);
    } finally {
      releaseTempTab(initiatorOrigin);
    }
  }

  // Last resort
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

  // Always try without key as a fallback (some public APIs don't need one)
  if (!keysToTry.includes(null)) keysToTry.push(null);

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
            const match = findDiscoveryMethod(doc, seedUrlObj.pathname, "POST");
            if (!match) {
              notifyPopup(tabId);
              await performProbeAndPatch(tabId, service, seedUrl, apiKey);
              return;
            }
          }

          notifyPopup(tabId);
          return;
        }
      } catch (err) {
        // continue to next candidate
      }
    }
  }

  // All keys (including null) failed.
  // FALLBACK: Try req2proto probing if we have a seed URL.
  const currentStatus = tab.discoveryDocs.get(service);
  const finalSeedUrl = seedUrl || currentStatus?.seedUrl;

  if (finalSeedUrl) {
    // Pick a key to try probing with (use the first available one if any)
    const probeKey = keysToTry[0] || null;
    await performProbeAndPatch(tabId, service, finalSeedUrl, probeKey);
  } else {
    // If we get here, truly not found — record timestamp for cooldown
    tab.discoveryDocs.set(service, {
      status: "not_found",
      _triedKeys: triedKeys,
      _failedAt: Date.now(),
    });
    mergeToGlobal(tab);
    notifyPopup(tabId);
  }
}

// Track in-flight probes to prevent concurrent duplicates
const _inflight = new Set();

/**
 * Perform req2proto probing and patch the discovery document.
 */
async function performProbeAndPatch(tabId, service, targetUrl, apiKey) {
  // Deduplicate: skip if already probing this service+url combo
  const probeKey = `${service}::${targetUrl}`;
  if (_inflight.has(probeKey)) return;
  _inflight.add(probeKey);

  const tab = getTab(tabId);

  if (typeof probeApiEndpoint === "undefined") {
    console.error("[Debug] CRITICAL: probeApiEndpoint is not defined!");
    _inflight.delete(probeKey);
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

      tab.discoveryDocs.set(service, {
        status: "found", // Treat as found so it shows up in UI
        doc: virtualDoc,
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
  } finally {
    _inflight.delete(probeKey);
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

  // Merge probe properties into request and response schemas.
  // Probe data has verified field numbers/types — prefer it over learned data,
  // but always preserve user's customName renames.
  function mergeProbeInto(target, probeProps) {
    if (!target.properties) target.properties = {};
    // Build field-number → key index for deduplication
    const numToKey = {};
    for (const [k, p] of Object.entries(target.properties)) {
      const n = p.number ?? p.id;
      if (n != null) numToKey[n] = k;
    }
    for (const [key, probeProp] of Object.entries(probeProps)) {
      const fieldNum = probeProp.number ?? probeProp.id;
      const matchKey = target.properties[key] ? key
        : (fieldNum != null && numToKey[fieldNum]) ? numToKey[fieldNum]
        : null;
      const existing = matchKey ? target.properties[matchKey] : null;
      if (!existing) {
        target.properties[key] = probeProp;
        if (fieldNum != null) numToKey[fieldNum] = key;
      } else {
        // Re-key: probe has the real name, replace generic fieldN key
        if (matchKey !== key && !existing.customName && !/^field\d+$/.test(key)) {
          target.properties[key] = existing;
          delete target.properties[matchKey];
          numToKey[fieldNum] = key;
        }
        // Probe has authoritative field numbers and types
        if (probeProp.id != null) existing.id = probeProp.id;
        if (probeProp.number != null) existing.number = probeProp.number;
        if (probeProp.type && existing.type === "string" && probeProp.type !== "string") {
          existing.type = probeProp.type;
        }
        if (probeProp.$ref && !existing.$ref) existing.$ref = probeProp.$ref;
        if (probeProp.children && !existing.children) existing.children = probeProp.children;
        if (probeProp.description && !existing.description) existing.description = probeProp.description;
        // Preserve user renames
        if (existing.customName) {
          // keep existing.name
        } else if (probeProp.name) {
          existing.name = probeProp.name;
        }
      }
    }
  }

  if (!doc.schemas[schemaName]) {
    doc.schemas[schemaName] = {
      id: schemaName,
      type: "object",
      properties: newProperties,
    };
  } else {
    mergeProbeInto(doc.schemas[schemaName], newProperties);
  }

  if (!doc.schemas[actualResponseRef]) {
    doc.schemas[actualResponseRef] = {
      id: actualResponseRef,
      type: "object",
      properties: newProperties,
    };
  } else {
    mergeProbeInto(doc.schemas[actualResponseRef], newProperties);
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

// ─── Response Body Handling (from intercept.js via content.js relay) ─────────

async function handleResponseBody(tabId, msg) {
  if (!msg.url) return;
  await _globalStoreReady;

  // WebSocket lifecycle events — track state, no log entry
  if (msg.method === "WS_OPEN") {
    if (!_wsConnState.has(tabId)) _wsConnState.set(tabId, new Map());
    _wsConnState.get(tabId).set(msg.wsId, { url: msg.url, readyState: 1 });
    notifyPopup(tabId);
    return;
  }
  if (msg.method === "WS_CLOSE") {
    const conns = _wsConnState.get(tabId);
    if (conns) {
      const conn = conns.get(msg.wsId);
      if (conn) conn.readyState = 3;
    }
    notifyPopup(tabId);
    return;
  }

  if (!msg.body) return;

  const tab = getTab(tabId);

  // Decode body to text for key scanning
  let textBody = msg.body;
  if (msg.base64Encoded) {
    try {
      const bytes = base64ToUint8(msg.body);
      textBody = new TextDecoder().decode(bytes);
    } catch (e) {
      textBody = null;
    }
  }

  // Scan for keys in every captured response body
  if (textBody) {
    extractKeysFromText(tabId, textBody, msg.url, "response_body");
  }

  // Match to request log entry — most recent entry for this URL without a body
  let entry = tab.requestLog.find(
    (r) => r.url === msg.url && !r.responseBody,
  );

  // For transports not captured by webRequest (WebSocket, EventSource, sendBeacon),
  // create a log entry on the fly
  const isAltTransport = msg.method === "WS_SEND" || msg.method === "WS_RECV" ||
    msg.method === "SSE" || msg.method === "BEACON";
  if (!entry && isAltTransport) {
    entry = {
      id: "alt_" + Date.now() + "_" + Math.random().toString(36).slice(2, 8),
      url: msg.url,
      method: msg.method,
      service: extractInterfaceName(new URL(msg.url)),
      timestamp: Date.now(),
      status: msg.status || 0,
      wsId: msg.wsId || null,
    };
    tab.requestLog.unshift(entry);
    if (tab.requestLog.length > 50) tab.requestLog.pop();
  }

  if (entry) {
    entry.responseBody = msg.body;
    entry.responseBase64 = msg.base64Encoded || false;
    entry.mimeType = msg.contentType || "";
    entry.responseHeaders = msg.responseHeaders || {};

    const service =
      entry.service || extractInterfaceName(new URL(entry.url));
    learnFromResponse(tabId, service, entry);
    scheduleSessionSave(tabId);
    notifyPopup(tabId);
  }
}

// ─── Cross-Script AST Buffering ──────────────────────────────────────────────

function _bufferScript(tabId, scriptUrl, code, pageUrl) {
  var buf = _scriptBuffers.get(tabId);
  if (!buf) {
    buf = { scripts: [], timer: null, pageUrl: pageUrl };
    _scriptBuffers.set(tabId, buf);
  }

  // Detect navigation: if page URL changed, clear old buffer
  if (pageUrl && buf.pageUrl && pageUrl !== buf.pageUrl) {
    if (buf.timer) clearTimeout(buf.timer);
    buf.scripts = [];
    buf.pageUrl = pageUrl;
    console.debug("[AST:buffer] Navigation detected, cleared buffer for tab=%d", tabId);
  }
  if (pageUrl) buf.pageUrl = pageUrl;

  // Deduplicate by URL or content hash
  var key = scriptUrl || _hashScriptCode(code);
  for (var i = 0; i < buf.scripts.length; i++) {
    if (buf.scripts[i].key === key) return; // already buffered
  }

  buf.scripts.push({ url: scriptUrl, code: code, key: key });
  console.debug("[AST:buffer] Buffered script %s (%d chars) tab=%d — %d scripts pending",
    scriptUrl || "(inline)", code.length, tabId, buf.scripts.length);

  // Reset debounce timer — wait for more scripts before combined analysis
  if (buf.timer) clearTimeout(buf.timer);
  buf.timer = setTimeout(function() {
    buf.timer = null;
    _analyzeCombinedScripts(tabId);
  }, 1500);
}

function _fetchAndBufferScript(tabId, scriptUrl, pageUrl) {
  // Check if already buffered
  var buf = _scriptBuffers.get(tabId);
  if (buf) {
    for (var i = 0; i < buf.scripts.length; i++) {
      if (buf.scripts[i].key === scriptUrl) return;
    }
  }

  fetch(scriptUrl).then(function(resp) {
    if (!resp.ok) {
      console.debug("[AST:buffer] Fetch failed for %s: %d %s", scriptUrl, resp.status, resp.statusText);
      return;
    }
    var ct = resp.headers.get("content-type") || "";
    // Skip non-JS responses (images, CSS, etc. that might share .open() URLs)
    if (ct && !ct.includes("javascript") && !ct.includes("ecmascript") && !ct.includes("text/plain") && !ct.includes("application/x-javascript")) {
      console.debug("[AST:buffer] Skipping non-JS content-type for %s: %s", scriptUrl, ct);
      return;
    }
    return resp.text();
  }).then(function(code) {
    if (code && code.length >= 50) {
      _bufferScript(tabId, scriptUrl, code, pageUrl);
    }
  }).catch(function(err) {
    console.debug("[AST:buffer] Fetch error for %s: %s", scriptUrl, err.message || err);
  });
}

function _hashScriptCode(code) {
  var h = 0;
  for (var i = 0; i < Math.min(code.length, 500); i++) {
    h = ((h << 5) - h + code.charCodeAt(i)) | 0;
  }
  return "inline:" + h;
}

async function _analyzeCombinedScripts(tabId) {
  var buf = _scriptBuffers.get(tabId);
  if (!buf || buf.scripts.length === 0) return;

  var tab = getTab(tabId);
  var scripts = buf.scripts;
  var totalChars = 0;
  for (var i = 0; i < scripts.length; i++) totalChars += scripts[i].code.length;

  console.debug("[AST:combined] Analyzing %d scripts (%d total chars) for tab=%d",
    scripts.length, totalChars, tabId);

  // Extract source map URLs from individual scripts before concatenation
  var sourceMapScripts = []; // [{url, smUrl}]
  for (var si = 0; si < scripts.length; si++) {
    var smUrl = extractSourceMapUrl(scripts[si].code);
    if (smUrl) {
      sourceMapScripts.push({ scriptUrl: scripts[si].url, smUrl: smUrl });
    }
  }

  // Clear previous AST-derived endpoints (in case of re-analysis due to late scripts)
  var keysToDelete = [];
  tab.endpoints.forEach(function(val, key) {
    if (key.startsWith("AST ") || key.startsWith("AST DYN ")) {
      keysToDelete.push(key);
    }
  });
  for (var di = 0; di < keysToDelete.length; di++) {
    tab.endpoints.delete(keysToDelete[di]);
  }
  tab._astResults = [];
  tab._securityFindings = [];

  // Concatenate all scripts with semicolons (safe delimiter for script mode)
  var combined = "";
  for (var ci = 0; ci < scripts.length; ci++) {
    if (ci > 0) combined += ";\n";
    combined += scripts[ci].code;
  }

  // Determine source URL for the combined analysis (use tab URL or first script URL)
  var tabUrl = "";
  var meta = _tabMeta.get(tabId);
  if (meta && meta.url) tabUrl = meta.url;
  else if (buf.pageUrl) tabUrl = buf.pageUrl;
  else if (scripts[0].url) tabUrl = scripts[0].url;

  // Analyze combined in offscreen document (non-blocking)
  var analysis;
  var response;
  try {
    response = await sendToOffscreen({
      type: "AST_ANALYZE", code: combined, sourceUrl: tabUrl, forceScript: true
    });
  } catch (e) {
    console.debug("[AST:combined] sendToOffscreen failed for tab=%d: %s", tabId, e.message || e);
    return;
  }
  if (!response || !response.success) {
    console.debug("[AST:combined] analyzeJSBundle failed for tab=%d: %s", tabId,
      response ? response.error : "no response");
    // Fallback: analyze scripts individually
    for (var fi = 0; fi < scripts.length; fi++) {
      analyzeScript(tabId, scripts[fi].url, scripts[fi].code);
    }
    return;
  }
  analysis = response.result;

  var hasFindings = analysis.protoEnums.length || analysis.protoFieldMaps.length ||
    analysis.fetchCallSites.length || analysis.sourceMapUrl ||
    (analysis.securitySinks && analysis.securitySinks.length) ||
    (analysis.dangerousPatterns && analysis.dangerousPatterns.length);
  if (!hasFindings && sourceMapScripts.length === 0) {
    console.debug("[AST:combined] No findings for tab=%d", tabId);
    return;
  }

  if (hasFindings) {
    console.debug("[AST:combined] Findings for tab=%d: %d protoEnums, %d fieldMaps, %d fetchSites, %d secSinks, %d dangerousPatterns",
      tabId, analysis.protoEnums.length, analysis.protoFieldMaps.length, analysis.fetchCallSites.length,
      (analysis.securitySinks ? analysis.securitySinks.length : 0),
      (analysis.dangerousPatterns ? analysis.dangerousPatterns.length : 0));

    tab._astResults.push(analysis);
    mergeASTResultsIntoVDD(tab, [analysis], tabId);
    mergeToGlobal(tab);
    notifyPopup(tabId);
  }

  // Fetch source maps for individual scripts (each has its own source map)
  for (var smi = 0; smi < sourceMapScripts.length; smi++) {
    _fetchSourceMapForScript(tabId, tab, analysis, sourceMapScripts[smi].scriptUrl, sourceMapScripts[smi].smUrl);
  }
}

function _fetchSourceMapForScript(tabId, tab, analysis, scriptUrl, smUrl) {
  try {
    if (!/^https?:\/\//i.test(smUrl)) {
      smUrl = new URL(smUrl, new URL(scriptUrl)).href;
    }
  } catch (_) {
    console.debug("[AST:sourcemap] Failed to resolve URL: %s (base: %s)", smUrl, scriptUrl);
    return;
  }
  console.debug("[AST:sourcemap] Fetching: %s (from %s)", smUrl, scriptUrl);
  pageContextFetch(tabId, smUrl, { method: "GET" }, new URL(smUrl).origin)
    .then(async function(smResp) {
      if (!smResp.body || smResp.error) {
        console.debug("[AST:sourcemap] Fetch failed for %s: %s", smUrl, smResp.error || "empty body");
        return;
      }
      try {
        var smJson = JSON.parse(smResp.body);
        var smResp2 = await sendToOffscreen({ type: "AST_PARSE_SOURCEMAP", sourceMapJson: smJson });
        if (!smResp2 || !smResp2.success) {
          console.debug("[AST:sourcemap] parseSourceMap failed for %s: %s", smUrl, smResp2 ? smResp2.error : "no response");
          return;
        }
        var smData = smResp2.result;
        analysis.sourceMap = smData;
        console.debug("[AST:sourcemap] Parsed: %d sources, %d names, %d proto files, %d API client files",
          smData.sources.length, smData.names.length, smData.protoFileNames.length, smData.apiClientFiles.length);
        if (smData.sourcesContent && smData.sourcesContent.length) {
          var typesResp = await sendToOffscreen({
            type: "AST_EXTRACT_TYPES",
            sourcesContent: smData.sourcesContent,
            sources: smData.sources
          });
          if (typesResp && typesResp.success) {
            analysis.sourceMapTypes = typesResp.result;
            if (analysis.sourceMapTypes.length) {
              console.debug("[AST:sourcemap] Extracted %d types", analysis.sourceMapTypes.length);
            }
          }
          // Run security analysis on original (unminified) source files via batch offscreen call.
          // Build a set of existing finding keys to deduplicate against the combined analysis.
          var _existingKeys = new Set();
          if (tab._securityFindings) {
            for (var _efi = 0; _efi < tab._securityFindings.length; _efi++) {
              var _efEntry = tab._securityFindings[_efi];
              var _efSinks = _efEntry.securitySinks || [];
              for (var _esi = 0; _esi < _efSinks.length; _esi++) {
                var _es = _efSinks[_esi];
                _existingKeys.add(_es.type + ":" + _es.sink + ":" + _es.location.line + ":" + _es.location.column);
              }
              var _efDangs = _efEntry.dangerousPatterns || [];
              for (var _edi = 0; _edi < _efDangs.length; _edi++) {
                var _ed = _efDangs[_edi];
                _existingKeys.add(_ed.type + ":" + _ed.location.line + ":" + _ed.location.column);
              }
            }
          }
          // Collect files eligible for security analysis
          var batchFiles = [];
          for (var _ssi = 0; _ssi < smData.sourcesContent.length; _ssi++) {
            var _srcContent = smData.sourcesContent[_ssi];
            var _srcName = smData.sources[_ssi] || "source_" + _ssi;
            if (!_srcContent || _srcContent.length < 100) continue;
            if (!/\.(js|ts|jsx|tsx|mjs)$/i.test(_srcName) && !/^[^.]+$/.test(_srcName)) continue;
            batchFiles.push({ code: _srcContent, name: _srcName });
          }
          if (batchFiles.length > 0) {
            var batchResp = await sendToOffscreen({ type: "AST_ANALYZE_BATCH", files: batchFiles });
            if (batchResp && batchResp.success) {
              var smSecFindings = 0;
              for (var _bi = 0; _bi < batchResp.result.length; _bi++) {
                var _bResult = batchResp.result[_bi];
                if (!_bResult.success) continue;
                var _srcSinks = (_bResult.securitySinks || []).filter(function(s) {
                  return !_existingKeys.has(s.type + ":" + s.sink + ":" + s.location.line + ":" + s.location.column);
                });
                var _srcDangerous = (_bResult.dangerousPatterns || []).filter(function(d) {
                  return !_existingKeys.has(d.type + ":" + d.location.line + ":" + d.location.column);
                });
                if (_srcSinks.length || _srcDangerous.length) {
                  if (!tab._securityFindings) tab._securityFindings = [];
                  tab._securityFindings.push({
                    sourceUrl: batchFiles[_bi].name,
                    securitySinks: _srcSinks,
                    dangerousPatterns: _srcDangerous,
                  });
                  smSecFindings += _srcSinks.length + _srcDangerous.length;
                }
              }
              if (smSecFindings > 0) {
                console.debug("[AST:sourcemap] Security analysis of original sources: %d additional findings", smSecFindings);
              }
            }
          }
        }
        mergeASTResultsIntoVDD(tab, [analysis], tabId);
        mergeToGlobal(tab);
        notifyPopup(tabId);
      } catch (e) {
        console.debug("[AST:sourcemap] Parse error for %s: %s", smUrl, e.message);
      }
    }).catch(function(e) {
      console.debug("[AST:sourcemap] Network error for %s: %s", smUrl, e.message || e);
    });
}

// ─── AST Bundle Analysis ─────────────────────────────────────────────────────

async function analyzeScript(tabId, scriptUrl, code) {
  var tab = getTab(tabId);
  console.debug("[AST] Received script: %s (%d chars) tab=%d", scriptUrl || "(inline)", code.length, tabId);
  var analysis;
  var response;
  try {
    response = await sendToOffscreen({
      type: "AST_ANALYZE", code: code, sourceUrl: scriptUrl
    });
  } catch (e) {
    console.debug("[AST] sendToOffscreen failed for %s: %s", scriptUrl, e.message || e);
    return;
  }
  if (!response || !response.success) {
    console.debug("[AST] analyzeJSBundle failed for %s: %s", scriptUrl,
      response ? response.error : "no response");
    return;
  }
  analysis = response.result;

  var hasFindings = analysis.protoEnums.length || analysis.protoFieldMaps.length ||
    analysis.fetchCallSites.length || analysis.sourceMapUrl ||
    (analysis.securitySinks && analysis.securitySinks.length) ||
    (analysis.dangerousPatterns && analysis.dangerousPatterns.length);
  if (!hasFindings) {
    console.debug("[AST] No findings for %s", scriptUrl || "(inline)");
    return;
  }

  console.debug("[AST] Findings for %s: %d protoEnums, %d fieldMaps, %d fetchSites, %d secSinks, %d dangerousPatterns, sourceMap=%s",
    scriptUrl || "(inline)", analysis.protoEnums.length, analysis.protoFieldMaps.length,
    analysis.fetchCallSites.length,
    (analysis.securitySinks ? analysis.securitySinks.length : 0),
    (analysis.dangerousPatterns ? analysis.dangerousPatterns.length : 0),
    analysis.sourceMapUrl || "none");

  if (!tab._astResults) tab._astResults = [];
  tab._astResults.push(analysis);
  mergeASTResultsIntoVDD(tab, [analysis], tabId);
  mergeToGlobal(tab);
  notifyPopup(tabId);

  // Source map recovery (async, fires after initial merge)
  if (analysis.sourceMapUrl) {
    var smUrl = analysis.sourceMapUrl;
    try {
      if (!/^https?:\/\//i.test(smUrl)) {
        smUrl = new URL(smUrl, new URL(scriptUrl)).href;
      }
    } catch (_) {
      console.debug("[AST:sourcemap] Failed to resolve URL: %s (base: %s)", analysis.sourceMapUrl, scriptUrl);
      return;
    }
    console.debug("[AST:sourcemap] Fetching: %s", smUrl);
    pageContextFetch(tabId, smUrl, { method: "GET" }, new URL(smUrl).origin)
      .then(async function(smResp) {
        if (!smResp.body || smResp.error) {
          console.debug("[AST:sourcemap] Fetch failed for %s: %s", smUrl, smResp.error || "empty body");
          return;
        }
        try {
          var smJson = JSON.parse(smResp.body);
          var smResp2 = await sendToOffscreen({ type: "AST_PARSE_SOURCEMAP", sourceMapJson: smJson });
          if (!smResp2 || !smResp2.success) {
            console.debug("[AST:sourcemap] parseSourceMap failed for %s: %s", smUrl, smResp2 ? smResp2.error : "no response");
            return;
          }
          var smData = smResp2.result;
          analysis.sourceMap = smData;
          console.debug("[AST:sourcemap] Parsed: %d sources, %d names, %d proto files, %d API client files, %d sourcesContent",
            smData.sources.length, smData.names.length, smData.protoFileNames.length,
            smData.apiClientFiles.length, (smData.sourcesContent || []).length);
          if (smData.protoFileNames.length) {
            console.debug("[AST:sourcemap] Proto files: %s", smData.protoFileNames.join(", "));
          }
          if (smData.apiClientFiles.length) {
            console.debug("[AST:sourcemap] API client files: %s", smData.apiClientFiles.join(", "));
          }
          if (smData.sourcesContent && smData.sourcesContent.length) {
            var typesResp = await sendToOffscreen({
              type: "AST_EXTRACT_TYPES",
              sourcesContent: smData.sourcesContent,
              sources: smData.sources
            });
            if (typesResp && typesResp.success) {
              analysis.sourceMapTypes = typesResp.result;
              if (analysis.sourceMapTypes.length) {
                console.debug("[AST:sourcemap] Extracted %d types: %s", analysis.sourceMapTypes.length,
                  analysis.sourceMapTypes.map(function(t) { return t.kind + " " + t.name; }).slice(0, 10).join(", "));
              }
            }
          }
          mergeASTResultsIntoVDD(tab, [analysis], tabId);
          mergeToGlobal(tab);
          notifyPopup(tabId);
        } catch (e) {
          console.debug("[AST:sourcemap] Parse error for %s: %s", smUrl, e.message);
        }
      }).catch(function(e) {
        console.debug("[AST:sourcemap] Network error for %s: %s", smUrl, e.message || e);
      });
  }
}

function mergeASTResultsIntoVDD(tab, results, tabId) {
  for (var r = 0; r < results.length; r++) {
    var analysis = results[r];
    var sourceHost = "";
    try { sourceHost = new URL(analysis.sourceUrl).hostname; } catch (_) {}

    // Find matching discovery doc for this host (optional — endpoint registration works without it)
    var doc = null;
    var matchedSvc = null;
    tab.discoveryDocs.forEach(function(entry, svc) {
      if (entry.doc && svc.includes(sourceHost)) { doc = entry.doc; matchedSvc = svc; }
    });
    if (!doc) {
      globalStore.discoveryDocs.forEach(function(entry, svc) {
        if (entry.doc && svc.includes(sourceHost)) { doc = entry.doc; matchedSvc = svc; }
      });
    }

    // Proto field/enum merge — requires a matching doc
    if (doc) {
      console.debug("[AST:merge] Matched doc %s for host=%s", matchedSvc, sourceHost);

      // Merge proto field maps: match by field number to existing schema properties
      if (analysis.protoFieldMaps.length && doc.schemas) {
        var fieldMapMatches = 0;
        var fieldMapUnmatched = [];
        var matchedFieldNums = new Set();
        for (var schemaName in doc.schemas) {
          var schema = doc.schemas[schemaName];
          if (!schema.properties) continue;
          for (var propName in schema.properties) {
            var prop = schema.properties[propName];
            if (!prop["x-field-number"]) continue;
            for (var fm = 0; fm < analysis.protoFieldMaps.length; fm++) {
              var fieldMap = analysis.protoFieldMaps[fm];
              if (fieldMap.fieldNumber === prop["x-field-number"] && !prop.customName) {
                prop._astName = fieldMap.fieldName;
                prop._astAccessor = fieldMap.accessorName;
                fieldMapMatches++;
                matchedFieldNums.add(fieldMap.fieldNumber);
                console.debug("[AST:merge] Field #%d → %s.%s renamed to '%s'", fieldMap.fieldNumber, schemaName, propName, fieldMap.fieldName);
              }
            }
          }
        }
        for (var fmu = 0; fmu < analysis.protoFieldMaps.length; fmu++) {
          if (!matchedFieldNums.has(analysis.protoFieldMaps[fmu].fieldNumber)) {
            fieldMapUnmatched.push("#" + analysis.protoFieldMaps[fmu].fieldNumber + "=" + analysis.protoFieldMaps[fmu].fieldName);
          }
        }
        console.debug("[AST:merge] Field maps: %d matched, %d unmatched [%s]", fieldMapMatches, fieldMapUnmatched.length,
          fieldMapUnmatched.slice(0, 10).join(", ") + (fieldMapUnmatched.length > 10 ? ", ..." : ""));
      }

      // Merge proto enums: enrich existing enum-type fields
      if (analysis.protoEnums.length && doc.schemas) {
        var enumMatches = 0;
        for (var eName in doc.schemas) {
          var eSchema = doc.schemas[eName];
          if (!eSchema.properties) continue;
          for (var ePropName in eSchema.properties) {
            var eProp = eSchema.properties[ePropName];
            if (eProp.enum && !eProp.customEnum) {
              for (var pe = 0; pe < analysis.protoEnums.length; pe++) {
                var protoEnum = analysis.protoEnums[pe];
                if (!protoEnum.isReverseMap) {
                  var enumKeys = Object.keys(protoEnum.values);
                  if (enumKeys.length === eProp.enum.length) {
                    eProp._astEnum = protoEnum.values;
                    enumMatches++;
                    console.debug("[AST:merge] Enum matched: %s.%s ← {%s} (%d values)", eName, ePropName,
                      enumKeys.slice(0, 5).join(", ") + (enumKeys.length > 5 ? ", ..." : ""), enumKeys.length);
                    break;
                  }
                }
              }
            }
          }
        }
        if (analysis.protoEnums.length > enumMatches) {
          console.debug("[AST:merge] %d/%d proto enums unmatched (no schema field with same value count)", analysis.protoEnums.length - enumMatches, analysis.protoEnums.length);
        }
      }
      // Merge value constraints: enrich VDD method parameters with AST-discovered valid values
      if (analysis.valueConstraints && analysis.valueConstraints.length && doc.resources && doc.resources.learned) {
        var vcMatches = 0;
        var methods = doc.resources.learned.methods || {};
        for (var mName in methods) {
          var method = methods[mName];
          if (!method.parameters) continue;
          for (var pName in method.parameters) {
            var param = method.parameters[pName];
            if (param.customEnum) continue; // don't override manual enums
            for (var vci = 0; vci < analysis.valueConstraints.length; vci++) {
              var vc = analysis.valueConstraints[vci];
              // Match by parameter name or constraint variable name
              if (vc.variable === pName && vc.values.length >= 2 && vc.values.length <= 50) {
                param._astValidValues = vc.values;
                param._astValueSource = vc.sources.join(",");
                if (!param.enum || !param.customEnum) {
                  param.enum = vc.values.map(String);
                  param._detectedEnum = true;
                }
                vcMatches++;
                console.debug("[AST:merge] Value constraint: %s.%s ← [%s] (%d values, source: %s)",
                  mName, pName, vc.values.slice(0, 5).join(", ") + (vc.values.length > 5 ? ", ..." : ""),
                  vc.values.length, vc.sources.join(","));
                break;
              }
            }
          }
        }
        if (vcMatches > 0) {
          console.debug("[AST:merge] Value constraints: %d matched to VDD parameters", vcMatches);
        }
      }
      // Merge sourceMap TypeScript types: enrich VDD parameters with type info from original sources
      if (analysis.sourceMapTypes && analysis.sourceMapTypes.length) {
        var typeMatches = 0;
        var tsMethods = doc.resources && doc.resources.learned ? doc.resources.learned.methods || {} : {};
        for (var _tmName in tsMethods) {
          var _tmMethod = tsMethods[_tmName];
          if (!_tmMethod.parameters) continue;
          for (var _tpName in _tmMethod.parameters) {
            var _tpParam = _tmMethod.parameters[_tpName];
            if (_tpParam._tsType) continue; // already enriched
            for (var _sti = 0; _sti < analysis.sourceMapTypes.length; _sti++) {
              var _smType = analysis.sourceMapTypes[_sti];
              for (var _stf = 0; _stf < _smType.fields.length; _stf++) {
                if (_smType.fields[_stf].name === _tpName) {
                  _tpParam._tsType = _smType.fields[_stf].type;
                  _tpParam._tsInterface = _smType.name;
                  _tpParam._tsOptional = _smType.fields[_stf].optional || false;
                  if (!_tpParam.type) _tpParam.type = _smType.fields[_stf].type;
                  typeMatches++;
                  break;
                }
              }
              if (_tpParam._tsType) break;
            }
          }
        }
        // Enrich proto field maps with human-readable names from TypeScript .pb.ts interfaces
        if (analysis.protoFieldMaps && analysis.protoFieldMaps.length) {
          for (var _fmi = 0; _fmi < analysis.protoFieldMaps.length; _fmi++) {
            var _fm = analysis.protoFieldMaps[_fmi];
            for (var _sti2 = 0; _sti2 < analysis.sourceMapTypes.length; _sti2++) {
              var _pbType = analysis.sourceMapTypes[_sti2];
              if (_pbType.kind !== "interface" && _pbType.kind !== "type") continue;
              // Match by field count similarity — proto field maps and TypeScript interfaces
              // from the same proto definition should have similar field counts
              if (_pbType.fields.length === _fm.fields.length ||
                  Math.abs(_pbType.fields.length - _fm.fields.length) <= 2) {
                // Check if it looks proto-related (from .pb.ts file or has matching structure)
                var _isPbType = /\.pb\.|_pb\.|proto/i.test(_pbType.source || "");
                if (_isPbType) {
                  if (!_fm._tsNames) _fm._tsNames = {};
                  for (var _pfi = 0; _pfi < _pbType.fields.length; _pfi++) {
                    var _pbField = _pbType.fields[_pfi];
                    // Map by position: TypeScript interface field order matches proto field order
                    _fm._tsNames[_pfi + 1] = _pbField.name;
                  }
                  _fm._tsInterface = _pbType.name;
                  typeMatches++;
                  break;
                }
              }
            }
          }
        }
        if (typeMatches > 0) {
          console.debug("[AST:merge] TypeScript type enrichment: %d matches", typeMatches);
        }
      }
    } else {
      console.debug("[AST:merge] No doc for host=%s — registering endpoints only (script: %s)", sourceHost, analysis.sourceUrl);
    }

    // Feed fetch call sites through the same learning pipeline as network requests
    var newEndpoints = 0;
    for (var fc = 0; fc < analysis.fetchCallSites.length; fc++) {
      var callSite = analysis.fetchCallSites[fc];
      try {
        // --- Resolve URL ---
        var isDynamic = /^\$\{|^\(dynamic\)|^\{[a-zA-Z]/.test(callSite.url);
        var csUrl = null;
        var interfaceName = null;

        if (isDynamic) {
          if (!sourceHost) continue;
          interfaceName = sourceHost;
        } else if (/^https?:\/\//i.test(callSite.url)) {
          csUrl = new URL(callSite.url);
          interfaceName = extractInterfaceName(csUrl);
        } else {
          csUrl = new URL(callSite.url, analysis.sourceUrl);
          interfaceName = extractInterfaceName(csUrl);
        }

        // --- Build synthetic URL with query params from AST ---
        var syntheticUrl = csUrl ? csUrl.href : "https://" + sourceHost + "/dynamic_" + fc;
        if (callSite.params) {
          var urlObj = new URL(syntheticUrl);
          for (var pi = 0; pi < callSite.params.length; pi++) {
            var p = callSite.params[pi];
            if ((p.location || "query") === "query") {
              urlObj.searchParams.set(p.name, p.defaultValue !== undefined ? String(p.defaultValue)
                : (p.validValues && p.validValues.length > 0 ? String(p.validValues[0]) : ""));
            }
          }
          syntheticUrl = urlObj.href;
        }

        // --- Build synthetic body from body params ---
        var syntheticHeaders = {};
        if (callSite.headers) {
          for (var hk in callSite.headers) {
            syntheticHeaders[hk.toLowerCase()] = callSite.headers[hk];
          }
        }
        var syntheticBody = null;
        if (callSite.params) {
          var bodyJson = {};
          var hasBody = false;
          for (var bi = 0; bi < callSite.params.length; bi++) {
            var bp = callSite.params[bi];
            if ((bp.location || "query") === "body") {
              bodyJson[bp.name] = bp.defaultValue !== undefined ? bp.defaultValue
                : (bp.validValues && bp.validValues.length > 0 ? bp.validValues[0] : "");
              hasBody = true;
            }
          }
          if (hasBody) {
            var bodyStr = JSON.stringify(bodyJson);
            syntheticBody = btoa(bodyStr);
            if (!syntheticHeaders["content-type"]) {
              syntheticHeaders["content-type"] = "application/json";
            }
          }
        }

        // --- Build entry matching what learnFromRequest expects ---
        var syntheticEntry = {
          url: syntheticUrl,
          method: callSite.method,
          source: isDynamic ? "ast_dynamic" : "ast_analysis",
        };
        if (syntheticBody) {
          syntheticEntry.rawBodyB64 = syntheticBody;
        }

        // --- Call the same learning function used for real network traffic ---
        learnFromRequest(tabId, interfaceName, syntheticEntry, syntheticHeaders);

        // --- Layer on AST-only extras: value constraints as enums ---
        var vddDocEntry = tab.discoveryDocs.get(interfaceName);
        if (vddDocEntry && vddDocEntry.doc && callSite.params) {
          var vddUrl = new URL(syntheticUrl);
          var meta = calculateMethodMetadata(vddUrl, interfaceName);
          var qualName = callSite.method ? callSite.method.toLowerCase() + "_" + meta.methodName : null;
          var vddLearned = vddDocEntry.doc.resources.learned;
          var vddProbed = vddDocEntry.doc.resources.probed;
          var vddM = (vddProbed && vddProbed.methods && vddProbed.methods[meta.methodName])
            || (vddLearned && vddLearned.methods && (vddLearned.methods[meta.methodName] || (qualName ? vddLearned.methods[qualName] : null)));
          if (vddM) {
            // Enrich URL parameters with valid values
            for (var vi = 0; vi < callSite.params.length; vi++) {
              var vp = callSite.params[vi];
              if (vp.validValues && vp.validValues.length > 0 && vddM.parameters[vp.name]) {
                var ep = vddM.parameters[vp.name];
                if (!ep.customEnum && !ep.enum) {
                  ep.enum = vp.validValues.map(String);
                }
              }
            }
            // Enrich body schema properties with valid values
            if (vddM.request && vddM.request.$ref) {
              var bodySchemaObj = vddDocEntry.doc.schemas[vddM.request.$ref];
              if (bodySchemaObj && bodySchemaObj.properties) {
                for (var bvi = 0; bvi < callSite.params.length; bvi++) {
                  var bvp = callSite.params[bvi];
                  if (bvp.validValues && bvp.validValues.length > 0 && (bvp.location || "query") === "body") {
                    var schemaProp = bodySchemaObj.properties[bvp.name];
                    if (schemaProp && !schemaProp.enum) {
                      schemaProp.enum = bvp.validValues.map(String);
                    }
                  }
                }
              }
            }
          }
        }

        // --- Register endpoint for popup display ---
        var bundleId = analysis.sourceUrl ? analysis.sourceUrl.replace(/^https?:\/\//, "").slice(-60) : "";
        var epKey = isDynamic
          ? "AST DYN " + bundleId + " " + (callSite.enclosingFunction || "anon") + " " + callSite.method + " " + fc
          : "AST " + callSite.method + " " + csUrl.pathname;
        if (!tab.endpoints.has(epKey)) {
          tab.endpoints.set(epKey, {
            url: isDynamic ? callSite.url : csUrl.href,
            method: callSite.method,
            host: isDynamic ? sourceHost : csUrl.hostname,
            path: isDynamic ? callSite.url : csUrl.pathname,
            service: interfaceName,
            source: isDynamic ? "ast_dynamic" : "ast_analysis",
            firstSeen: Date.now(),
          });
          newEndpoints++;
        }
      } catch (mergeErr) {
        console.debug("[AST:merge] Error processing fetch site %d (%s %s): %s", fc, callSite.method, callSite.url, mergeErr.message || mergeErr);
      }
    }
    if (analysis.fetchCallSites.length) {
      console.debug("[AST:merge] Fetch sites: %d call sites processed, %d endpoints registered",
        analysis.fetchCallSites.length, newEndpoints);
    }

    // Store security findings on tab state (only once per analysis — skip if already merged)
    var secSinks = analysis.securitySinks || [];
    var dangerousPats = analysis.dangerousPatterns || [];
    if ((secSinks.length || dangerousPats.length) && !analysis._securityMerged) {
      analysis._securityMerged = true;
      if (!tab._securityFindings) tab._securityFindings = [];
      tab._securityFindings.push({
        sourceUrl: analysis.sourceUrl,
        securitySinks: secSinks,
        dangerousPatterns: dangerousPats,
      });
      console.debug("[AST:merge] Security findings for %s: %d sinks, %d dangerous patterns",
        analysis.sourceUrl, secSinks.length, dangerousPats.length);
    }
  }
}

// ─── Message Handling ────────────────────────────────────────────────────────

// Content scripts handle CONTENT_KEYS, CONTENT_ENDPOINTS, RESPONSE_BODY, and SCRIPT_SOURCE.
// Manifest "matches" already restricts which pages they run on.
function handleContentMessage(msg, sender) {
  if (!sender.tab) return;
  const tabId = sender.tab.id;

  // RESPONSE_BODY comes from intercept.js via content.js relay
  if (msg.type === "RESPONSE_BODY") {
    handleResponseBody(tabId, msg);
    return;
  }

  // SCRIPT_SOURCE comes from content.js script extraction — buffer for cross-script analysis
  if (msg.type === "SCRIPT_SOURCE") {
    var pageUrl = (sender.tab && sender.tab.url) || "";
    if (msg.code && typeof msg.code === "string") {
      // Inline script — code sent directly
      _bufferScript(tabId, msg.url || "", msg.code, pageUrl);
    } else if (msg.url && !msg.code) {
      // External script — content script sent URL only (avoids CORS issues)
      // Background has host_permissions: <all_urls>, so fetch is unrestricted
      _fetchAndBufferScript(tabId, msg.url, pageUrl);
    }
    return;
  }

  if (!Array.isArray(msg.keys || msg.endpoints)) return;
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
async function handlePopupMessage(msg, _sender, sendResponse) {
  await _globalStoreReady;
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

    case "CLEAR_LOG": {
      if (msg.clearAll) {
        for (const [tid, t] of state.tabs) {
          t.requestLog = [];
          chrome.storage.session.remove(`reqLog_${tid}`).catch(() => {});
        }
        saveSessionIndex();
      } else {
        if (tabId == null) return;
        const tab = getTab(tabId);
        tab.requestLog = [];
        chrome.storage.session.remove(`reqLog_${tabId}`).catch(() => {});
        saveSessionIndex();
      }
      sendResponse({ ok: true });
      return;
    }

    case "GET_TAB_LIST": {
      const tabs = [];
      for (const [tid, t] of state.tabs) {
        if (t.requestLog.length === 0) continue;
        const meta = _tabMeta.get(tid) || { title: `Tab ${tid}`, url: "" };
        tabs.push({ tabId: tid, title: meta.title, url: meta.url, count: t.requestLog.length, closed: !!meta.closed });
      }
      // Also include closed tabs from metadata that still have session storage
      for (const [tid, meta] of _tabMeta) {
        if (meta.closed && !state.tabs.has(tid)) {
          tabs.push({ tabId: tid, title: meta.title, url: meta.url, count: meta.count || 0, closed: true });
        }
      }
      sendResponse(tabs);
      return;
    }

    case "GET_ALL_LOGS": {
      const result = {};
      const filter = msg.filter; // "all" | tabId (number)
      for (const [tid, t] of state.tabs) {
        if (t.requestLog.length === 0) continue;
        if (filter !== "all" && filter !== tid) continue;
        const meta = _tabMeta.get(tid) || { title: `Tab ${tid}`, url: "" };
        result[tid] = { meta, requestLog: t.requestLog };
      }
      sendResponse(result);
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

    case "WS_SEND_MSG": {
      if (tabId == null) return;
      chrome.tabs.sendMessage(tabId, {
        type: "WS_SEND_MSG",
        wsId: msg.wsId,
        data: msg.data,
        binary: msg.binary || false,
      }).then(() => sendResponse({ ok: true }))
        .catch((err) => sendResponse({ error: err.message }));
      return true;
    }

    case "WS_GET_STATUS": {
      if (tabId == null) return;
      const conns = _wsConnState.get(tabId);
      const conn = conns?.get(msg.wsId);
      if (!conn || conn.readyState === 3) {
        sendResponse({ readyState: 3, url: conn?.url || null });
        return;
      }
      chrome.tabs.sendMessage(tabId, {
        type: "WS_QUERY_STATUS",
        wsId: msg.wsId,
      }).then((result) => {
        conn.readyState = result.readyState;
        sendResponse({ readyState: result.readyState, url: conn.url });
      }).catch(() => {
        conn.readyState = 3;
        sendResponse({ readyState: 3, url: conn.url });
      });
      return true;
    }

    case "BUILD_REQUEST": {
      if (tabId == null) return;
      buildExportRequest(tabId, msg).then((result) => {
        sendResponse(result);
      });
      return true;
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
        if (msg.methodId) {
          const match = findMethodById(doc, msg.methodId);
          if (match) m = match.method;
        }

        if (!m) {
          // Fallback: Calculate from URL (less reliable)
          const { methodName } = calculateMethodMetadata(
            new URL(msg.url || ""),
            service,
          );
          m =
            doc.resources.learned?.methods[methodName] ||
            doc.resources.probed?.methods[methodName];
        }

        if (m && m.parameters?.[fieldKey]) {
          m.parameters[fieldKey].name = newName;
          m.parameters[fieldKey].customName = true;
          mergeToGlobal(tab);
          sendResponse({ ok: true });
        }
      } else {
        // Handle schema properties or create virtual schema for raw fields
        if (!doc.schemas) doc.schemas = {};
        if (!doc.schemas[schemaName]) {
          doc.schemas[schemaName] = { id: schemaName, type: "object", properties: {} };
        }

        const schema = doc.schemas[schemaName];
        if (!schema.properties) schema.properties = {};

        if (schema.properties[fieldKey]) {
          const prop = schema.properties[fieldKey];
          prop.name = newName;
          prop.customName = true;
        } else {
          // Create a virtual property for a raw field number
          schema.properties[fieldKey] = {
            id: fieldKey,
            number: parseInt(fieldKey) || null,
            name: newName,
            customName: true,
            type: "any"
          };
        }
        mergeToGlobal(tab);
        sendResponse({ ok: true });
      }
      return;
    }

    case "EXPORT_OPENAPI": {
      if (tabId == null) return;
      const tab = getTab(tabId);
      const svc = msg.service;
      const docEntry =
        tab.discoveryDocs.get(svc) || globalStore.discoveryDocs.get(svc);
      if (!docEntry?.doc) {
        sendResponse({ error: "No discovery document found for " + svc });
        return;
      }
      const openapi = convertDiscoveryToOpenApi(docEntry.doc, svc);
      sendResponse({ ok: true, spec: openapi });
      return;
    }

    case "IMPORT_OPENAPI": {
      if (tabId == null) return;
      const tab = getTab(tabId);
      try {
        const spec = msg.spec;
        if (!spec || typeof spec !== "object") {
          sendResponse({ error: "Invalid OpenAPI spec: not an object" });
          return;
        }
        if (!spec.paths || typeof spec.paths !== "object") {
          sendResponse({ error: "Invalid OpenAPI spec: missing or invalid paths" });
          return;
        }
        // Validate OpenAPI version — only 3.0.x and 3.1.x supported
        if (spec.openapi) {
          if (!/^3\.\d+\.\d+/.test(spec.openapi)) {
            sendResponse({ error: "Unsupported OpenAPI version: " + spec.openapi + ". Only 3.x is supported." });
            return;
          }
        } else if (spec.swagger) {
          // Swagger 2.0 — not supported by convertOpenApiToDiscovery
          sendResponse({ error: "Swagger 2.0 is not supported. Please convert to OpenAPI 3.x first." });
          return;
        }
        // Determine service name from server URL or info.title
        let svcName;
        if (spec.servers?.[0]?.url) {
          try {
            svcName = new URL(spec.servers[0].url).hostname;
          } catch (_) {}
        }
        if (!svcName) {
          svcName = (spec.info?.title || "imported")
            .toLowerCase().replace(/[^a-z0-9.]/g, "_");
        }

        // Convert to internal Discovery format
        const sourceUrl = spec.servers?.[0]?.url || "https://" + svcName;
        const doc = convertOpenApiToDiscovery(spec, sourceUrl);

        // Merge with existing doc if present
        const existing = tab.discoveryDocs.get(svcName) ||
          globalStore.discoveryDocs.get(svcName);
        if (existing?.doc) {
          // Merge imported methods into existing doc
          for (const [rName, resource] of Object.entries(doc.resources)) {
            if (!existing.doc.resources[rName]) {
              existing.doc.resources[rName] = resource;
            } else {
              for (const [mName, method] of Object.entries(resource.methods || {})) {
                if (!existing.doc.resources[rName].methods[mName]) {
                  existing.doc.resources[rName].methods[mName] = method;
                }
              }
            }
          }
          // Merge schemas (imported fills gaps, doesn't overwrite)
          for (const [sName, schema] of Object.entries(doc.schemas)) {
            if (!existing.doc.schemas[sName]) {
              existing.doc.schemas[sName] = schema;
            }
          }
        } else {
          // Store as new discovery doc
          const entry = {
            status: "found",
            url: sourceUrl,
            method: "IMPORT",
            apiKey: null,
            fetchedAt: Date.now(),
            doc,
            isVirtual: false,
          };
          tab.discoveryDocs.set(svcName, entry);
          globalStore.discoveryDocs.set(svcName, entry);
        }
        mergeToGlobal(tab);
        scheduleSave();
        sendResponse({ ok: true, service: svcName });
      } catch (err) {
        sendResponse({ error: "Import failed: " + err.message });
      }
      return;
    }
  }
}

// ─── Export Request Builder ──────────────────────────────────────────────────

/**
 * Build a fully-encoded request (URL, headers, body) for export.
 * Reuses the same encoding logic as executeSendRequest but returns the
 * request instead of sending it.
 */
async function buildExportRequest(tabId, msg) {
  let parsedUrl;
  try {
    parsedUrl = new URL(msg.url);
  } catch (_) {
    return { error: "invalid URL" };
  }

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
  const ep = msg.endpointKey ? tab.endpoints.get(msg.endpointKey) : null;
  if (ep?.apiKey) {
    if (ep.apiKeySource === "url") {
      parsedUrl.searchParams.set("key", ep.apiKey);
    } else {
      headers["X-Goog-Api-Key"] = ep.apiKey;
    }
  }

  const url = parsedUrl.toString();

  let body = null;
  if (msg.httpMethod !== "GET" && msg.httpMethod !== "DELETE" && msg.body) {
    if (url.includes("batchexecute") && msg.body.mode === "form") {
      const fields = msg.body.formData?.fields || [];
      const argsArray = encodeFormToJspb(fields);
      const innerJson = JSON.stringify(argsArray);
      const rpcId = msg.methodId ? msg.methodId.split(".").pop() : "unknown";
      const envelope = [[[rpcId, innerJson, null, "generic"]]];
      const params = new URLSearchParams();
      params.set("f.req", JSON.stringify(envelope));
      body = params.toString();
      headers["Content-Type"] =
        "application/x-www-form-urlencoded;charset=UTF-8";
    } else if (msg.body.mode === "raw" && msg.body.rawBody) {
      body = msg.body.rawBody;
    } else if (msg.body.mode === "form" && msg.body.formData?.fields?.length) {
      const fields = msg.body.formData.fields;
      if (
        msg.contentType === "application/grpc-web+proto" ||
        msg.contentType === "application/grpc-web-text+proto"
      ) {
        // gRPC-Web: encode protobuf, wrap in frame
        const pbBytes = encodeFormToProtobuf(fields);
        const framed = encodeGrpcWebFrame(pbBytes);
        body = uint8ToBase64(framed);
      } else if (msg.contentType === "application/x-protobuf") {
        const encoded = encodeFormToProtobuf(fields);
        body = uint8ToBase64(encoded);
      } else if (msg.contentType === "application/json+protobuf") {
        body = JSON.stringify(encodeFormToJspb(fields));
      } else if (msg.contentType?.startsWith("application/x-www-form-urlencoded")) {
        const argsArray = encodeFormToJspb(fields);
        const params = new URLSearchParams();
        params.set("f.req", JSON.stringify(argsArray));
        body = params.toString();
      } else {
        body = JSON.stringify(encodeFormToJson(fields));
      }
    }
  }

  // GraphQL: wrap query/variables in standard envelope
  if (isGraphQLUrl(url) && msg.body?.mode === "graphql") {
    const gqlBody = {
      query: msg.body.query || "",
    };
    if (msg.body.variables) {
      try {
        gqlBody.variables = JSON.parse(msg.body.variables);
      } catch (_) {
        gqlBody.variables = msg.body.variables;
      }
    }
    if (msg.body.operationName) {
      gqlBody.operationName = msg.body.operationName;
    }
    body = JSON.stringify(gqlBody);
    headers["Content-Type"] = "application/json";
  }

  return { url, method: msg.httpMethod || "POST", headers, body };
}

const EXTENSION_ORIGIN = `chrome-extension://${chrome.runtime.id}`;
const CONTENT_TYPES = new Set([
  "CONTENT_KEYS",
  "CONTENT_ENDPOINTS",
  "RESPONSE_BODY",
  "SCRIPT_SOURCE",
]);

// Threat model: Content scripts run in web page renderer processes. A compromised
// renderer has our extension's sender.id (since we inject into every page), so
// sender.id only rejects other extensions. The real security gate is sender.url —
// set by the browser process, unforgeable by the renderer. This router enforces:
//   1. sender.id must match our extension (rejects other extensions)
//   2. sender.url origin check (extension page vs content script — unforgeable)
//   3. Extension pages → handlePopupMessage (rejects CONTENT_TYPES)
//   4. Content scripts → handleContentMessage (rejects everything except CONTENT_TYPES)
// Data-returning types (GET_STATE, GET_ALL_LOGS, GET_TAB_LIST) are only reachable
// from extension pages, never from content scripts. See SECURITY.md.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;

  const isExtensionPage =
    sender.url && sender.url.startsWith(EXTENSION_ORIGIN + "/");

  if (isExtensionPage) {
    if (CONTENT_TYPES.has(msg.type)) return;
    handlePopupMessage(msg, sender, sendResponse);
    return true; // keep sendResponse alive for async handlePopupMessage
  }

  if (!CONTENT_TYPES.has(msg.type)) return;
  handleContentMessage(msg, sender);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  // Keep session storage logs so closed tab requests remain viewable
  const meta = _tabMeta.get(tabId);
  if (meta) {
    const tab = state.tabs.get(tabId);
    meta.closed = true;
    meta.closedAt = Date.now();
    meta.count = tab ? tab.requestLog.length : meta.count || 0;
  }
  state.tabs.delete(tabId);
  _wsConnState.delete(tabId);
  // Clean up script buffer and cancel pending analysis
  var buf = _scriptBuffers.get(tabId);
  if (buf && buf.timer) clearTimeout(buf.timer);
  _scriptBuffers.delete(tabId);
  saveSessionIndex();
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
        contentTypes: match.method.contentTypes || [],
      };

      // Resolve parameters
      if (match.method.parameters) {
        parameters = {};
        for (const [pName, pDef] of Object.entries(match.method.parameters)) {
          parameters[pName] = {
            name: pDef.name || pName,
            customName: !!pDef.customName,
            type: pDef.type || "string",
            location: pDef.location || "query",
            required: !!pDef.required,
            description: pDef.description || "",
            format: pDef.format || null,
            enum: pDef.enum || null,
            // Stats-derived metadata
            _requiredConfidence: pDef._requiredConfidence ?? null,
            _detectedEnum: !!pDef._detectedEnum,
            _defaultValue: pDef._defaultValue ?? null,
            _defaultConfidence: pDef._defaultConfidence ?? null,
            _range: pDef._range || null,
            // AST-discovered valid values
            _astValidValues: pDef._astValidValues || null,
            _astValueSource: pDef._astValueSource || null,
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

  // 3. Content type suggestions — prefer method-level observed CTs
  if (discoveryMethod?.contentTypes?.length) {
    for (const ct of discoveryMethod.contentTypes) {
      if (!contentTypes.includes(ct)) contentTypes.push(ct);
    }
  }
  if (ep?.contentType && !contentTypes.includes(ep.contentType)) {
    contentTypes.push(ep.contentType);
  }
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

  // 4. Collect chain data from the raw method object
  let chains = null;
  if (discoveryEntry?.doc && methodId) {
    const rawMatch = findMethodById(discoveryEntry.doc, methodId);
    if (rawMatch?.method?._chains) {
      chains = rawMatch.method._chains;
    }
  }

  return {
    source,
    method: discoveryMethod,
    parameters,
    requestBody: bodyFields?.length
      ? { schemaName: bodySchemaName, fields: bodyFields }
      : null,
    contentTypes,
    chains,
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
  if (maxNum === 0) {
    // If we have no numbered fields, but it's supposed to be an object/message,
    // return an empty array if we are in a JSPB context.
    return [];
  }

  // JSPB uses 0-based indexing for field 1 (i.e. index 0 is field 1)
  const arr = new Array(maxNum).fill(null);
  for (const f of fields) {
    if (!f.number) continue;
    
    const targetIdx = f.number - 1;
    if (f.type === "message" && f.label !== "repeated") {
      arr[targetIdx] = encodeFormToJspb(f.children || []);
    } else if (f.label === "repeated" && f.type === "message" && Array.isArray(f.value)) {
      // Repeated message: each item's children must be recursively encoded
      arr[targetIdx] = f.value.map((item) => {
        if (item && item.children) return encodeFormToJspb(item.children);
        if (Array.isArray(item)) return item;
        return item;
      });
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
      // Packed encoding for repeated scalar numeric types (proto3 default)
      const packableTypes = [
        "int32", "int64", "uint32", "uint64", "sint32", "sint64",
        "bool", "enum", "fixed32", "fixed64", "sfixed32", "sfixed64",
        "float", "double",
      ];
      if (packableTypes.includes(f.type)) {
        const innerParts = [];
        for (const v of f.value) {
          innerParts.push(encodeSinglePbFieldRaw(f.type, v));
        }
        const packed = concatBytes.apply(null, innerParts.length ? innerParts : [new Uint8Array(0)]);
        parts.push(pbEncodeLenField(f.number, packed));
      } else {
        // Non-packable types (string, bytes, message): individual tag+value pairs
        for (const v of f.value) {
          parts.push(encodeSinglePbField(f.number, f.type, v, null));
        }
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
      // Arithmetic ZigZag to avoid 32-bit truncation from bitwise ops
      const n = Number(value) || 0;
      const zigzag = n >= 0 ? n * 2 : (-n) * 2 - 1;
      return pbEncodeVarintField(num, zigzag);
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
    case "double": {
      const buf = new Uint8Array(8);
      new DataView(buf.buffer).setFloat64(0, Number(value) || 0, true);
      return concatBytes(pbTag(num, PB_64BIT), buf);
    }
    case "fixed64":
    case "sfixed64": {
      // 64-bit integer encoding (not float64)
      const buf = new Uint8Array(8);
      const n = Number(value) || 0;
      const dv = new DataView(buf.buffer);
      dv.setUint32(0, n >>> 0, true);
      dv.setUint32(4, Math.floor(n / 0x100000000) >>> 0, true);
      return concatBytes(pbTag(num, PB_64BIT), buf);
    }
    default:
      return pbEncodeLenField(num, String(value));
  }
}

/**
 * Encode a single protobuf scalar value WITHOUT the field tag.
 * Used for packed repeated encoding where values are concatenated inside
 * a single length-delimited field.
 */
function encodeSinglePbFieldRaw(type, value) {
  switch (type) {
    case "bool":
      return pbWriteVarint(value ? 1 : 0);
    case "enum":
    case "int32":
    case "int64":
    case "uint32":
    case "uint64":
      return pbWriteVarint(Number(value) || 0);
    case "sint32":
    case "sint64": {
      const n = Number(value) || 0;
      return pbWriteVarint(n >= 0 ? n * 2 : (-n) * 2 - 1);
    }
    case "float":
    case "fixed32":
    case "sfixed32": {
      const buf = new Uint8Array(4);
      if (type === "float")
        new DataView(buf.buffer).setFloat32(0, Number(value) || 0, true);
      else new DataView(buf.buffer).setUint32(0, Number(value) || 0, true);
      return buf;
    }
    case "double": {
      const buf = new Uint8Array(8);
      new DataView(buf.buffer).setFloat64(0, Number(value) || 0, true);
      return buf;
    }
    case "fixed64":
    case "sfixed64": {
      const buf = new Uint8Array(8);
      const n = Number(value) || 0;
      const dv = new DataView(buf.buffer);
      dv.setUint32(0, n >>> 0, true);
      dv.setUint32(4, Math.floor(n / 0x100000000) >>> 0, true);
      return buf;
    }
    default:
      return pbWriteVarint(Number(value) || 0);
  }
}

function coerceValue(value, type) {
  if (value == null) return null;
  if (type === "bool") return value === true || value === "true";
  if (type === "enum") {
    var n = Number(value);
    return isNaN(n) ? String(value) : n;
  }
  if (
    [
      "int32",
      "int64",
      "uint32",
      "uint64",
      "double",
      "float",
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

  // API key: endpoint → service keys → discovery doc key
  const tab = getTab(tabId);
  const epKey = msg.endpointKey;
  const ep = epKey ? tab.endpoints.get(epKey) : null;
  let apiKey = ep?.apiKey || null;
  let apiKeySource = ep?.apiKeySource || "header";

  if (!apiKey && service) {
    const hostname = parsedUrl.hostname;
    const svcKeys = collectKeysForService(tab, service, hostname);
    // Also check globalStore for keys from previous sessions
    if (svcKeys.length === 0) {
      for (const [key, data] of globalStore.apiKeys) {
        if (data.services?.has(service) || data.hosts?.has(hostname)) {
          svcKeys.push(key);
        }
      }
    }
    if (svcKeys.length > 0) {
      apiKey = svcKeys[0];
    }
    // Fall back to discovery doc's key
    if (!apiKey) {
      const docEntry = tab.discoveryDocs.get(service) || globalStore.discoveryDocs.get(service);
      if (docEntry?.apiKey) apiKey = docEntry.apiKey;
    }
  }

  // Only add key if not already present in headers or URL
  const hasKeyHeader = headers["X-Goog-Api-Key"] || headers["x-goog-api-key"];
  const hasKeyParam = parsedUrl.searchParams.has("key");
  if (apiKey && !hasKeyHeader && !hasKeyParam) {
    if (apiKeySource === "url") {
      parsedUrl.searchParams.set("key", apiKey);
    } else {
      headers["X-Goog-Api-Key"] = apiKey;
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
      const argsArray = encodeFormToJspb(fields);
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
      if (
        msg.contentType === "application/x-protobuf" ||
        msg.contentType === "application/grpc-web+proto" ||
        msg.contentType === "application/grpc-web-text+proto"
      ) {
        body = msg.body.rawBody;
        bodyEncoding = "base64";
      } else {
        body = msg.body.rawBody;
      }
    } else if (msg.body.mode === "form" && msg.body.formData?.fields?.length) {
      const fields = msg.body.formData.fields;
      if (
        msg.contentType === "application/grpc-web+proto" ||
        msg.contentType === "application/grpc-web-text+proto"
      ) {
        // gRPC-Web: encode protobuf, wrap in frame
        const pbBytes = encodeFormToProtobuf(fields);
        const framed = encodeGrpcWebFrame(pbBytes);
        body = uint8ToBase64(framed);
        bodyEncoding = "base64";
      } else if (msg.contentType === "application/x-protobuf") {
        const encoded = encodeFormToProtobuf(fields);
        body = uint8ToBase64(encoded);
        bodyEncoding = "base64";
      } else if (msg.contentType === "application/json+protobuf") {
        body = JSON.stringify(encodeFormToJspb(fields));
      } else if (msg.contentType?.startsWith("application/x-www-form-urlencoded")) {
        // Form-urlencoded with f.req JSPB (non-batchexecute)
        const argsArray = encodeFormToJspb(fields);
        const params = new URLSearchParams();
        params.set("f.req", JSON.stringify(argsArray));
        body = params.toString();
      } else {
        body = JSON.stringify(encodeFormToJson(fields));
      }
    }
  }

  // GraphQL: wrap query/variables in standard envelope
  if (isGraphQLUrl(url) && msg.body?.mode === "graphql") {
    const gqlBody = {
      query: msg.body.query || "",
    };
    if (msg.body.variables) {
      try {
        gqlBody.variables = JSON.parse(msg.body.variables);
      } catch (_) {
        gqlBody.variables = msg.body.variables;
      }
    }
    if (msg.body.operationName) {
      gqlBody.operationName = msg.body.operationName;
    }
    body = JSON.stringify(gqlBody);
    headers["Content-Type"] = "application/json";
  }

  // Resolve initiator origin
  const initiatorOrigin =
    ep?.origin || ep?.referer || tab.authContext?.origin || null;

  // Send request via page context (session-aware)
  let resp;
  try {
    resp = await pageContextFetch(
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
  } catch (err) {
    return { error: `fetch_exception: ${err.message}`, timing: Date.now() - startTime };
  }

  const timing = Date.now() - startTime;

  if (!resp || resp.error) {
    return { error: resp?.error || "fetch_failed: no response", timing };
  }

  // Decode response
  const respCt = resp.headers?.["content-type"] || "";
  let bodyResult;

  if (isGrpcWeb(respCt)) {
    // gRPC-Web: pass raw bytes for frame-level rendering in popup
    try {
      let bytes;
      if (isGrpcWebText(respCt)) {
        bytes = base64ToUint8(
          resp.bodyEncoding === "base64" ? resp.body : btoa(resp.body),
        );
      } else {
        bytes = resp.bodyEncoding === "base64"
          ? base64ToUint8(resp.body)
          : new TextEncoder().encode(resp.body);
      }
      // Scan protobuf frames for keys
      const parsed = parseGrpcWebFrames(bytes);
      if (parsed) {
        for (const frame of parsed.frames) {
          if (frame.type !== "data") continue;
          try {
            pbDecodeTree(frame.data, 8, (val) => {
              if (typeof val === "string") {
                extractKeysFromText(tabId, val, url, "send_response_grpc");
              }
            });
          } catch (_) {}
        }
      }
      // Serialize bytes as base64 array for message passing
      bodyResult = {
        format: "grpc_web",
        bytesB64: uint8ToBase64(bytes),
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
  } else if (
    (resp.bodyEncoding === "base64" || isBinaryContentType(respCt)) &&
    (/^(image|video|audio)\//i.test(respCt) || /application\/(pdf|zip)/i.test(respCt))
  ) {
    // Non-API binary (media/document) — pass through for download
    const size = resp.bodyEncoding === "base64"
      ? Math.floor(resp.body.length * 3 / 4)
      : resp.body.length;
    bodyResult = {
      format: "binary_download",
      raw: resp.body,
      bodyEncoding: resp.bodyEncoding || "text",
      contentType: respCt,
      size,
    };
  } else if (resp.bodyEncoding === "base64" || isBinaryContentType(respCt)) {
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
    // Try JSON parse (strip Google XSSI prefix if present)
    let jsonText = resp.body || "";
    if (jsonText.trimStart().startsWith(")]}'")) {
      jsonText = jsonText.trimStart().substring(4).trimStart();
    }
    try {
      const parsed = JSON.parse(jsonText);
      if (
        Array.isArray(parsed) &&
        (respCt.includes("json+protobuf") ||
          (respCt.includes("text/plain") &&
            parsed.length > 0 &&
            parsed.some((item) => item === null || Array.isArray(item) || typeof item !== "object")) ||
          (respCt.includes("json") &&
            parsed.length > 0 &&
            parsed.some((item) => item === null || Array.isArray(item) || typeof item !== "object")))
      ) {
        // JSPB format: json+protobuf content-type, or text/plain/json with array structure
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

  // Preserve "learned" methods (deep copy to avoid aliasing)
  if (oldDoc.resources?.learned) {
    if (!newDoc.resources) newDoc.resources = {};
    newDoc.resources.learned = JSON.parse(JSON.stringify(oldDoc.resources.learned));
  }

  // Preserve "probed" methods (deep copy to avoid aliasing)
  if (oldDoc.resources?.probed) {
    if (!newDoc.resources) newDoc.resources = {};
    newDoc.resources.probed = JSON.parse(JSON.stringify(oldDoc.resources.probed));
  }

  // Preserve learned schemas + carry over custom renames into new schemas
  if (oldDoc.schemas) {
    for (const [name, schema] of Object.entries(oldDoc.schemas)) {
      if (!newDoc.schemas[name]) {
        newDoc.schemas[name] = schema;
      } else {
        // Schema exists in both — preserve customName fields from old
        const oldProps = schema.properties || {};
        const newProps = newDoc.schemas[name].properties || {};
        for (const [pKey, pVal] of Object.entries(oldProps)) {
          if (pVal.customName && newProps[pKey]) {
            newProps[pKey].name = pVal.name;
            newProps[pKey].customName = true;
          }
        }
      }
    }
  }

  // Carry over custom parameter renames from old methods
  if (oldDoc.resources) {
    function carryRenames(oldRes, newRes) {
      if (!oldRes || !newRes) return;
      for (const [rName, r] of Object.entries(oldRes)) {
        if (!newRes[rName]) continue;
        for (const [mName, oldM] of Object.entries(r.methods || {})) {
          const newM = newRes[rName]?.methods?.[mName];
          if (!newM) continue;
          // Carry parameter renames
          if (oldM.parameters) {
            for (const [pName, pVal] of Object.entries(oldM.parameters)) {
              if (pVal.customName && newM.parameters?.[pName]) {
                newM.parameters[pName].name = pVal.name;
                newM.parameters[pName].customName = true;
              }
            }
          }
          // Carry stats and chains
          if (oldM._stats && !newM._stats) newM._stats = oldM._stats;
          if (oldM._chains && !newM._chains) newM._chains = oldM._chains;
        }
      }
    }
    carryRenames(oldDoc.resources, newDoc.resources);
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

function mergedSecurityFindings(tab) {
  // Global base (keyed by sourceUrl), tab overwrites
  var merged = new Map();
  for (const [k, v] of globalStore.securityFindings) {
    merged.set(k, v);
  }
  if (tab._securityFindings) {
    for (var i = 0; i < tab._securityFindings.length; i++) {
      var f = tab._securityFindings[i];
      merged.set(f.sourceUrl || ("unknown_" + i), f);
    }
  }
  return [...merged.values()];
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

  // Discovery docs: global base, tab overwrites with full doc
  const mergedDiscovery = {};
  for (const [k, v] of globalStore.discoveryDocs) {
    if (v.status === "found") {
      mergedDiscovery[k] = {
        status: v.status,
        url: v.url,
        method: v.method,
        apiKey: v.apiKey || null,
        fetchedAt: v.fetchedAt,
        doc: v.doc || null,
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
    securityFindings: mergedSecurityFindings(tab),
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
      scheduleSessionSave(details.tabId);
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
      scheduleSessionSave(details.tabId);
      notifyPopup(details.tabId);
    }
  },
  { urls: ["<all_urls>"] },
);
