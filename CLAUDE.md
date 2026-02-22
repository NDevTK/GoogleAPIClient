# API Security Researcher - Development Guide

## Project Overview

A Chrome Extension (MV3) for API discovery, protocol reverse-engineering (Protobuf/JSPB/JSON/gRPC-Web/GraphQL/SSE/NDJSON), JavaScript security code review, and security testing across all websites.

## Core Architecture

- **Request/Response Capture**: `intercept.js` runs in the page's main world (`world: "MAIN"`, `document_start`), wrapping `fetch()`, `XMLHttpRequest`, `WebSocket`, and `EventSource` to capture both request data (headers, body) and response data (status, headers, body). Single capture point — no `webRequest` permission needed. Data flows: `intercept.js` → `CustomEvent(__uasr_resp)` → `content.js` relay → `chrome.runtime.sendMessage(RESPONSE_BODY)` → `background.js` `handleResponseBody()` which creates log entries, extracts keys, learns schemas, triggers discovery/probing.
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
| `manifest.json` | MV3 manifest. Permissions: `storage`, `offscreen`. Host permissions: `<all_urls>`. |
| `intercept.js` | Main-world content script. Wraps `fetch`/`XHR`/`WebSocket`/`EventSource`, captures request headers+body and response headers+body. Emits `__uasr_resp` CustomEvent. Single capture point for all network data. |
| `content.js` | Isolated-world content script. DOM key/endpoint scanning, `PAGE_FETCH` relay for session-aware requests, `__uasr_resp` event relay to background. |
| `background.js` | Service worker. Request interception, key extraction, schema learning, request export builder, OpenAPI export/import, session storage, message routing. |
| `popup.js` | Popup controller. Tab rendering, service filter, cross-tab log filtering, replay, export (curl/fetch/Python/OpenAPI). |
| `popup.html` | Popup markup. |
| `popup.css` | Popup styles. |
| `lib/discovery.js` | Protocol parsers (batchexecute, async chunked, gRPC-Web, GraphQL, SSE, NDJSON, multipart), OpenAPI bidirectional conversion. |
| `lib/protobuf.js` | Protobuf wire-format codec, JSPB decoder, recursive base64 key scanning. |
| `lib/req2proto.js` | Error-based schema probing engine. |
| `lib/ast.js` | AST-based JS bundle analysis. Babel parser + traverse with scope-aware inter-procedural tracing. Extracts fetch call sites, proto field maps, enums, value constraints. Security code review: DOM XSS sinks, dangerous patterns (eval, postMessage, prototype pollution, open redirect), taint source tracking. |
| `lib/sourcemap.js` | Source map recovery. Babel parser with TypeScript plugin extracts interfaces, enums, type aliases from original sources. |
| `lib/babel-bundle.js` | Bundled Babel runtime (parser, traverse, types). Built by `node build.js` via esbuild. |
| `build.js` | esbuild config for bundling Babel into an IIFE for the service worker. |

## AST Analysis Policy

All AST analysis uses Babel's scope system (`path.scope.getBinding()`) for variable resolution and data flow tracing. Never match syntax patterns directly — always resolve through scope. No regex, no string pattern matching, no name-based lookups (code is minified — names are meaningless). No scoring or heuristics.

**Scope-aware traversal rule**: All sub-tree traversals use `path.traverse(visitor)` on Babel paths — never `_babelTraverse(rawNode, visitor)` on raw AST nodes. The only `_babelTraverse` calls are the two top-level Program traversals (pre-pass and main pass). Functions that resolve callees (`_resolveCalleeToFunction`, `_resolveHandlerFunc`, etc.) return Babel paths, not raw nodes, so downstream code can call `funcPath.traverse()` for scope-aware walking. No `noScope: true` anywhere — every traversal has full scope access.

**No caps or depth limits**: AST analysis must handle arbitrarily large scripts (1MB+ minified bundles) without losing data. No script size limits, no depth limits that discard data, no `MAX_DEPTH` constants. Functions that walk expression chains (BinaryExpression `+`, ConditionalExpression, LogicalExpression `||`/`&&`, MemberExpression) must use iterative loops with explicit stacks instead of recursion. The JS call stack is finite (~10k frames); minified code regularly produces expression chains hundreds of nodes deep. Convert recursive AST walkers to iterative whenever they process chainable node types.

**Global verification via scope**: When detecting global sinks (`fetch`, `XMLHttpRequest`) or global sources (`location`, `document`, `window`), always verify the identifier is unbound: `!path.scope.getBinding("fetch")`. A local variable shadowing a global name is not a sink/source.

- **Trace to network sinks**: The browser has two network primitives — `fetch()` and `XMLHttpRequest`. All JS network calls flow through them. AST identifies these global sinks and traces backward through scope bindings to extract URLs, methods, headers, body structure, and query params.
- **Inter-procedural tracing**: When a sink argument is a function parameter, use `binding.referencePaths` to find all call sites and resolve the concrete values passed by callers. Trace through wrapper function chains using cycle detection (visited-set), not depth limits.
- **Resolve values**: Use `path.scope.getBinding()` to follow variable references through proper scope chains. Collect value constraints from switch/case, `.includes()`, equality chains scoped by `scope.uid`.
- **Type tracking**: `_typeEnv` maps `scopeUid:varName` to deterministic types (e.g., `new XMLHttpRequest()` → `"XMLHttpRequest"`, `[...]` → `"Array"`). `_getTrackedType(path, node)` resolves an identifier's type through scope. Used to disambiguate `.open()` (XHR vs other objects) and iterator methods (`.forEach()` on Array vs non-iterable). Types are scope-keyed so shadowed constructors don't inherit outer types. Only unambiguous patterns are tracked — no heuristics.
- **Taint source classification**: `_matchTaintSource(path, node)` walks MemberExpression chains structurally, verifies the root identifier is unbound via scope, normalizes `window.`/`self.` prefixes, and matches against taint patterns. Replaces string-based `_describeNode()` lookup for security decisions.
- **CFG + sanitizer path analysis**: `_buildCFG(bodyPath)` builds a basic-block control flow graph from a function body path. `_hasSanitizerOnAllPaths()` checks whether all paths from a taint source's block to a sink's block pass through a sanitizer. Sanitizers are verified scope-aware (`_isSanitizerCall` checks `!path.scope.getBinding()` for globals like `DOMPurify`, `encodeURIComponent`). If sanitized on all paths, severity is downgraded to `"info"` rather than suppressed.
- **Feed into the learning pipeline**: AST call sites are converted to synthetic requests and passed through `learnFromRequest()` — the same function that learns from real network traffic. AST learns APIs before they happen; network traffic confirms and enriches them.
- **No protocol classification**: AST does not classify calls as gRPC/REST/RPC. Protocol detection is the network monitoring code's job.
- **Security sink detection**: Detect DOM XSS sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`, `new Function`, `insertAdjacentHTML`, `setTimeout`/`setInterval` with string arg, `setAttribute("on*")`) and open redirects (`location.href`/`location.assign`/`location.replace`). All sinks only flag when the value traces to a **user-controlled source** — no vulnerability exists without attacker-controlled data reaching the sink.
- **Taint source tracking**: `_traceValueSource()` classifies value origins by tracing through scope bindings, function params, string concatenation, and method calls. Known user-controlled sources: `location.*`, `document.referrer`, `document.URL`, `document.cookie`, `window.name`, `event.data`. Propagates taint through variable assignment chains and method calls on tainted objects.
- **Dangerous pattern detection**: Detect `postMessage` listeners without `event.origin` checks, prototype pollution (`obj[userControlledKey] = value`), dynamic `RegExp` with user-controlled patterns. Prototype pollution and RegExp only flag when the key/pattern traces to a user-controlled source — dynamic keys are ubiquitous in minified code (iterators, object merges, polyfills).
- **No sensitive data scanning**: API key and token extraction is handled by `KEY_PATTERNS` in `background.js` — AST does not duplicate this.

## Development Standards

- **Naming**: `camelCase` for logic, `UPPER_SNAKE_CASE` for constants. Unified `methodId` format: `interface.name.method`.
- **MV3 Compliance**: No `webRequest` or debugger API. All network capture via main-world prototype wrapping in `intercept.js`.
- **Message Routing**: `chrome.runtime.onMessage` routes by sender origin — extension pages go to `handlePopupMessage`, content scripts go to `handleContentMessage`. Allowed content script types: `CONTENT_KEYS`, `CONTENT_ENDPOINTS`, `RESPONSE_BODY`.
- **UI Security**: Strict origin checks in `onMessage` handlers. All dynamic content passed through `esc()` to prevent XSS.
- **Data Persistence**: `scheduleSave()` for global store writes (IndexedDB, inaccessible to content scripts), `scheduleSessionSave(tabId)` for per-tab request log writes (`chrome.storage.session`, 1s debounce). GlobalStore uses IndexedDB instead of `chrome.storage.local` to prevent compromised renderers from reading cross-site structural metadata.
- **Intercept Script Safety**: `intercept.js` runs in main world — never blocks the caller (async body reads). Uses IIFE to avoid global pollution. Filters internal requests (`_uasr_send`, `_internal_probe` hashes). Static asset and noise path filtering done in `background.js` `handleResponseBody()`.
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
- **Add Intercepted Content Types**: Modify `isBinary()` in `intercept.js` for binary encoding detection. Add static asset extensions to the filter regex in `handleResponseBody()` in `background.js`.
- **Add Protocol Parser**: Add parser + detector in `lib/discovery.js`, add `learnFromResponse()` branch in `background.js`, add renderer in `popup.js` (wire into `renderResultBody()`), add format badge.
- **UI Changes**: Ensure new components maintain scroll position in their respective panels. The Send panel includes export buttons (curl, fetch, Python).
- **Cross-Tab Features**: Tab metadata tracked in `_tabMeta` Map. Filter logic in popup controlled by `logFilter` state variable. New message types: `GET_TAB_LIST`, `GET_ALL_LOGS`.
- **OpenAPI Export/Import**: Service-level via `EXPORT_OPENAPI`/`IMPORT_OPENAPI` messages. `convertDiscoveryToOpenApi()` / `convertOpenApiToDiscovery()` in `lib/discovery.js`. Service selector in popup filters methods and controls export scope.
- **Add Security Pattern**: For new DOM XSS sinks, add detection to `_processSecurityCallSink` (call-based) or `_processSecurityAssignSink` (assignment-based) in `lib/ast.js`. For new dangerous patterns, add to `_processDangerousPattern` (call-based) or `_processDangerousAssignment` (assignment-based). Use `_traceValueSource()` to classify severity. New taint sources go in `_TAINT_SOURCES`. Add tests in `test-ast.js` in the "Security:" test sections.
