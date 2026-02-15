# API Security Researcher - Development Guide

## Project Overview

A Chrome Extension (MV3) for API discovery, protocol reverse-engineering (Protobuf/JSPB/JSON/gRPC-Web/GraphQL/SSE/NDJSON), and security testing across all websites.

## Core Architecture

- **Request Interception**: `webRequest` API captures request metadata, headers, and bodies. No debugger permission needed.
- **Response Capture**: `intercept.js` runs in the page's main world (`world: "MAIN"`, `document_start`), wrapping `fetch()` and `XMLHttpRequest` to capture response bodies. Data flows: `intercept.js` → `CustomEvent(__uasr_resp)` → `content.js` relay → `chrome.runtime.sendMessage(RESPONSE_BODY)` → `background.js` handler.
- **Protocol Handlers** (in `lib/discovery.js`):
  - `parseBatchExecuteRequest/Response` — Google batchexecute RPC
  - `parseAsyncChunkedResponse` — Google hex-length-prefixed async chunks
  - `parseGrpcWebFrames` / `encodeGrpcWebFrame` — gRPC-Web frame codec
  - `parseGraphQLRequest/Response` — GraphQL query/variables/operationName
  - `parseSSE`, `parseNDJSON`, `parseMultipartBatch` — streaming/batch formats
  - `convertOpenApiToDiscovery` / `convertDiscoveryToOpenApi` — OpenAPI 3.0 bidirectional conversion
  - `lib/protobuf.js`: Wire-format codec, `jspbToTree`, recursive base64 scanning
  - `lib/req2proto.js`: Universal error-based schema probing (Google-specific + generic)
- **Schema Learning**: VDD engine maps request/response schemas and URL parameters from observed traffic. `learnFromResponse()` processes captured response bodies through the format chain: async chunked → batchexecute → gRPC-Web → SSE → NDJSON → multipart → GraphQL → JSON → protobuf.
- **Autonomous Discovery**: `buildDiscoveryUrls` probes well-known paths for official API documentation on new interfaces.
- **Collaborative Mapping**: Field and parameter renaming persisted in IndexedDB (via globalStore).
- **OpenAPI Export/Import**: `EXPORT_OPENAPI` converts a service's VDD to OpenAPI 3.0.3 (with `x-field-number` extensions for protobuf round-trip). `IMPORT_OPENAPI` converts OpenAPI specs into the internal format, merging with existing learned data.
- **Session Persistence**: Request logs saved to `chrome.storage.session` with 1-second debounced writes per tab. Survives MV3 service worker restarts, clears on browser close.
- **Cross-Tab Logs**: Popup filter dropdown shows requests from active tab, all tabs, or a specific tab. Closed tab logs are retained.
- **Auto-Determined Encoding**: Content-Type (`currentContentType`) and body mode (`currentBodyMode`) are set automatically from the VDD schema or replayed request headers — no manual dropdowns.
- **UI Management**: State-aware rendering in `popup.js` with 100ms render throttling, scroll position preservation, and independent panel navigation.

## File Map

| File | Role |
|------|------|
| `manifest.json` | MV3 manifest. Permissions: `webRequest`, `storage`, `activeTab`. |
| `intercept.js` | Main-world content script. Wraps `fetch`/`XHR`, emits `__uasr_resp` CustomEvent with response body, headers, status. Filters out non-API content types. |
| `content.js` | Isolated-world content script. DOM key/endpoint scanning, `PAGE_FETCH` relay for session-aware requests, `__uasr_resp` event relay to background. |
| `background.js` | Service worker. Request interception, key extraction, schema learning, request export builder, OpenAPI export/import, session storage, message routing. |
| `popup.js` | Popup controller. Tab rendering, service filter, cross-tab log filtering, replay, export (curl/fetch/Python/OpenAPI). |
| `popup.html` | Popup markup. |
| `popup.css` | Popup styles. |
| `lib/discovery.js` | Protocol parsers (batchexecute, async chunked, gRPC-Web, GraphQL, SSE, NDJSON, multipart), OpenAPI bidirectional conversion. |
| `lib/protobuf.js` | Protobuf wire-format codec, JSPB decoder, recursive base64 key scanning. |
| `lib/req2proto.js` | Error-based schema probing engine. |

## Development Standards

- **Naming**: `camelCase` for logic, `UPPER_SNAKE_CASE` for constants. Unified `methodId` format: `interface.name.method`.
- **MV3 Compliance**: Non-blocking `webRequest` observers. No debugger API. Response bodies captured via main-world prototype wrapping.
- **Message Routing**: `chrome.runtime.onMessage` routes by sender origin — extension pages go to `handlePopupMessage`, content scripts go to `handleContentMessage`. Allowed content script types: `CONTENT_KEYS`, `CONTENT_ENDPOINTS`, `RESPONSE_BODY`.
- **UI Security**: Strict origin checks in `onMessage` handlers. All dynamic content passed through `esc()` to prevent XSS.
- **Data Persistence**: `scheduleSave()` for global store writes (IndexedDB, inaccessible to content scripts), `scheduleSessionSave(tabId)` for per-tab request log writes (`chrome.storage.session`, 1s debounce). GlobalStore uses IndexedDB instead of `chrome.storage.local` to prevent compromised renderers from reading cross-site structural metadata.
- **Intercept Script Safety**: `intercept.js` runs in main world — never blocks the caller (async body reads), caps bodies at 256KB, filters non-API content types. Uses IIFE to avoid global pollution.
- **Send Panel**: Content-Type and body mode are auto-determined (no manual dropdowns). `currentContentType` set from `schema.contentTypes[0]` or replayed request headers. `currentBodyMode` set to `form` (schema loaded), `graphql` (GraphQL URL), or `raw` (fallback). `setBodyMode()` toggles panel visibility.

## Security Model

**Threat**: A compromised renderer process can execute code in the content script's isolated world, gaining access to any `chrome.storage.local`/`.sync` APIs the extension has permission for. This leaks cross-site data — a renderer compromised on site A could read structural metadata (API schemas, endpoint URLs, field names) learned from sites B, C, D.

**Trust boundaries**:

| Context | Process | Capabilities | Trust level |
|---------|---------|-------------|-------------|
| `intercept.js` (main world) | Web page renderer | Same-site fetch/XHR only. No extension APIs. | Untrusted — same origin as page |
| `content.js` (isolated world) | Web page renderer | `chrome.runtime.sendMessage` (type-restricted), DOM access. No storage APIs used. | Low trust — restricted message whitelist |
| `background.js` (service worker) | Extension process | Full extension APIs, IndexedDB, `chrome.storage.session` | Trusted — privileged boundary |
| `popup.js` (extension page) | Extension process | `chrome.runtime.sendMessage` to background | Trusted |

**Storage isolation**:

- **GlobalStore** (schemas, endpoints, API keys, probe results): IndexedDB in the service worker origin. Content scripts cannot access IndexedDB for `chrome-extension://` origins, so a compromised renderer has no direct read path.
- **Request logs** (URLs, headers, bodies): `chrome.storage.session` with default `TRUSTED_CONTEXTS` access level. Content scripts excluded. Auto-clears on browser close — no persistent URL leakage.

**Message gating**: `chrome.runtime.onMessage` routes by `sender.url` origin (set by the browser process, unforgeable by renderers). `sender.id` only rejects other extensions — since we inject into every page, compromised renderers already have our `sender.id`. Content scripts can only send `CONTENT_KEYS`, `CONTENT_ENDPOINTS`, `RESPONSE_BODY`. All other message types (including data-returning ones like `GET_STATE`, `GET_ALL_LOGS`, `GET_TAB_LIST`) are rejected for non-extension-page senders. See `SECURITY.md` for full threat model.

## Common Tasks

- **Extend Key Patterns**: Update `KEY_PATTERNS` in `background.js`.
- **Adjust Method Heuristics**: Modify `calculateMethodMetadata` in `background.js`.
- **Add Export Format**: Add a `formatXxx()` function in `popup.js` and a button in `popup.html`. The `BUILD_REQUEST` message handler in `background.js` returns the fully-encoded `{ url, method, headers, body }`.
- **Add Intercepted Content Types**: Modify `shouldCapture()` / `isBinary()` in `intercept.js`.
- **Add Protocol Parser**: Add parser + detector in `lib/discovery.js`, add `learnFromResponse()` branch in `background.js`, add renderer in `popup.js` (wire into `renderResultBody()`), add format badge.
- **UI Changes**: Ensure new components maintain scroll position in their respective panels. The Send panel includes export buttons (curl, fetch, Python).
- **Cross-Tab Features**: Tab metadata tracked in `_tabMeta` Map. Filter logic in popup controlled by `logFilter` state variable. New message types: `GET_TAB_LIST`, `GET_ALL_LOGS`.
- **OpenAPI Export/Import**: Service-level via `EXPORT_OPENAPI`/`IMPORT_OPENAPI` messages. `convertDiscoveryToOpenApi()` / `convertOpenApiToDiscovery()` in `lib/discovery.js`. Service selector in popup filters methods and controls export scope.
