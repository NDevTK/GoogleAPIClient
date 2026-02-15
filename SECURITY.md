# Security Model

## Primary Threat

A compromised renderer process can execute code in any content script's isolated world running in that process. In a standard extension using `chrome.storage.local`, this grants read/write access to **all** stored data — not just data from the compromised site. For this extension, that would leak cross-site structural metadata: API schemas, endpoint URLs, field names, and API keys learned from every site the user has visited.

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│  Extension Process (trusted)                            │
│  ┌────────────────────┐  ┌───────────────────────────┐  │
│  │  background.js     │  │  popup.js                 │  │
│  │  (service worker)  │  │  (extension page)         │  │
│  │                    │  │                           │  │
│  │  IndexedDB ────────│──│── read via message only   │  │
│  │  chrome.storage    │  │                           │  │
│  │  .session          │  │                           │  │
│  └──────▲─────────────┘  └───────────────────────────┘  │
│         │ sendMessage                                   │
│         │ (type-gated)                                  │
└─────────┼───────────────────────────────────────────────┘
          │
┌─────────┼───────────────────────────────────────────────┐
│  Web Page Renderer (untrusted)                          │
│  ┌──────┴─────────────┐  ┌───────────────────────────┐  │
│  │  content.js        │  │  intercept.js             │  │
│  │  (isolated world)  │  │  (main world)             │  │
│  │                    │  │                           │  │
│  │  Can send:         │  │  No extension APIs.       │  │
│  │  - CONTENT_KEYS    │  │  Same-site fetch/XHR      │  │
│  │  - CONTENT_ENDPOINTS  │  only. Communicates via │  │
│  │  - RESPONSE_BODY   │  │  CustomEvent to           │  │
│  │                    │◄─│  content.js only.         │  │
│  │  Cannot:           │  │                           │  │
│  │  - Read IndexedDB  │  └───────────────────────────┘  │
│  │  - Read chrome.    │                                 │
│  │    storage.session │                                 │
│  │  - Send GET_STATE, │                                 │
│  │    GET_ALL_LOGS,   │                                 │
│  │    etc.            │                                 │
│  └────────────────────┘                                 │
└─────────────────────────────────────────────────────────┘
```

## Storage Isolation

| Store | Backend | Accessible from | Clears |
|-------|---------|----------------|--------|
| GlobalStore (schemas, endpoints, API keys, probe results) | IndexedDB (`uasr_store`) | Service worker only | Manual clear or extension uninstall |
| Request logs (URLs, headers, bodies) | `chrome.storage.session` | Service worker + extension pages (`TRUSTED_CONTEXTS` default) | Browser close |

**Why not `chrome.storage.local`?** Content scripts in the isolated world can call `chrome.storage.local.get()` if the extension has the `storage` permission. A compromised renderer that gains execution in the content script context gets direct read access to all keys — leaking cross-site metadata. IndexedDB in the service worker origin (`chrome-extension://<id>`) is not accessible from content scripts, so a compromised renderer has no direct read path.

**Why `chrome.storage.session` for request logs?** It defaults to `TRUSTED_CONTEXTS` access level, which excludes content scripts. It also auto-clears on browser close, preventing persistent leakage of URLs that may contain tokens or internal endpoints.

## Message Gating

The `chrome.runtime.onMessage` listener in `background.js` is the central security gate:

```
1. Reject if sender.id !== chrome.runtime.id          (rejects other extensions only)
2. Check sender.url starts with chrome-extension://    (the real security gate — unforgeable)
3. Extension pages → handlePopupMessage                (all types except CONTENT_TYPES)
4. Content scripts → handleContentMessage              (CONTENT_TYPES only)
```

**Why `sender.id` is not sufficient**: Because this extension injects content scripts into every page (`<all_urls>`), a compromised renderer already has our content script running in-process. It can call `chrome.runtime.sendMessage` with our extension's `sender.id`. The `sender.id` check only rejects messages from *other* extensions.

**Why `sender.url` is the real gate**: `sender.url` is set by the browser process based on the actual page context, not by the renderer. A content script's `sender.url` is always the web page's URL (e.g., `https://example.com/...`), never `chrome-extension://`. The renderer cannot forge this value.

**Content script allowlist** (`CONTENT_TYPES`):
- `CONTENT_KEYS` — API keys found in page DOM
- `CONTENT_ENDPOINTS` — Endpoint URLs found in page DOM
- `RESPONSE_BODY` — Intercepted fetch/XHR response bodies

**Blocked for content scripts**: `GET_STATE`, `GET_ALL_LOGS`, `GET_TAB_LIST`, `BUILD_REQUEST`, `EXPORT_OPENAPI`, `RESOLVE_ENDPOINT_SCHEMA`, and all other types that return stored data. A compromised renderer sending these types is silently dropped.

**Popup validation**: `popup.js` validates `sender.url` origin before processing `STATE_UPDATED` broadcasts, preventing a compromised renderer from injecting fake state updates. The `sender.id` check is a secondary filter for other extensions; `sender.url` is the unforgeable gate.

## Intercept Script (`intercept.js`)

Runs in the page's **main world** — same origin and process as the page itself. This is the least trusted context:

- No access to extension APIs (`chrome.runtime`, `chrome.storage`, etc.)
- Can only communicate with `content.js` via `CustomEvent` on `document`
- Body capture is capped at 256KB to prevent memory exhaustion
- Filters non-API content types (images, fonts, etc.) before forwarding
- Wrapped in IIFE to avoid polluting the page's global scope
- Never blocks the caller — body reads are async

A compromised page can tamper with or suppress intercept.js, but this only affects data collection from that same site. It cannot escalate to read data from other sites.

## Attack Scenarios

| Scenario | Outcome |
|----------|---------|
| Compromised renderer reads `chrome.storage.local` | **Mitigated** — GlobalStore is in IndexedDB, not `chrome.storage.local` |
| Compromised renderer reads `chrome.storage.session` | **Mitigated** — Default `TRUSTED_CONTEXTS` excludes content scripts |
| Compromised renderer sends `GET_ALL_LOGS` via `sendMessage` | **Mitigated** — Background rejects non-`CONTENT_TYPES` from content scripts |
| Compromised renderer sends `CONTENT_KEYS` with fake data | **Accepted risk** — Same as the page containing those keys. Data is scoped to that site's service. No cross-site impact. |
| Compromised renderer tampers with `intercept.js` | **Accepted risk** — Only affects same-site data collection. Cannot read other sites' data. |
| Compromised renderer forges `sender.id` | **Not a threat** — Already has our `sender.id` (content script runs in every renderer). `sender.id` only rejects other extensions. `sender.url` is the real gate. |
| Compromised renderer forges `sender.url` as extension origin | **Not possible** — Chrome sets `sender.url` in the browser process; renderer cannot spoof it |
