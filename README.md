# API Security Researcher

A Chrome Extension (MV3) that passively reverse-engineers APIs, learns their schemas from live traffic, analyzes JavaScript bundles for vulnerabilities, and provides a complete testing workbench — all without a debugger or proxy.

## How It Works

Browse any website. The extension works in the background:

1. **Intercepts** every fetch/XHR/WebSocket/EventSource call via main-world wrappers, capturing request headers, request bodies, response headers, response bodies, and status — no `webRequest` permission, no Chrome debugger bar.
2. **Captures** cross-frame postMessage and MessageChannel messages via isolated-world listeners.
3. **Decodes** traffic through a protocol chain: async chunked, batchexecute, gRPC-Web, SSE, NDJSON, multipart, GraphQL, JSON, and Protobuf.
4. **Learns** API structure (VDD — Value-Driven Discovery) by merging schemas from every observed request and response into a unified service map.
5. **Analyzes** JavaScript bundles with a scope-aware AST engine that extracts API call sites, value constraints, proto field maps, and security vulnerabilities — before any network call is made.
6. **Probes** for official documentation (OpenAPI, Google Discovery) at well-known paths and merges it with learned data.

Open the popup to inspect, test, and export everything it found.

## Features

### API Discovery & Schema Learning

- **Passive Learning**: Every request and response teaches the extension about URL patterns, query parameters, body fields, field types, content types, and authentication.
- **AST Static Analysis**: Babel parser + traverse with inter-procedural tracing extracts fetch/XHR call sites from JavaScript bundles — discovers APIs that haven't been called yet, including URLs, methods, headers, body structure, and query params.
- **Value Constraint Extraction**: Detects valid parameter values from `switch`/`case`, `.includes()`, and equality chains in source code. These appear as dropdowns in the Send panel for both URL params and request body fields.
- **Autonomous Documentation Discovery**: Probes well-known paths (`/.well-known/openapi.json`, `/swagger.json`, `/$discovery/rest`, etc.) with version, visibility, and auth variants.
- **Proto Field Maps & Enums**: Detects protobuf field number-to-name mappings and enum definitions from JavaScript bundles.
- **Source Map Recovery**: Fetches source maps and extracts TypeScript interfaces, enums, and type aliases. Enriches VDD parameters with original type names. Runs security analysis on unminified original sources.
- **Error-Based Schema Probing**: Sends intentionally malformed requests and learns field requirements and types from error responses.
- **Smart Key Extraction**: Scans URLs, headers, response bodies, and DOM for API keys and tokens (Google, Firebase, JWT, Stripe, Bearer, Mapbox, GitHub, etc.) with recursive base64 decoding.
- **Interface Grouping**: Groups endpoints into logical services (e.g., `api.example.com/v1`) based on host and path structure.
- **Cross-Script Analysis**: Buffers and concatenates inline and external scripts per tab for combined analysis, matching the browser's shared global scope.

### Protocol Reverse-Engineering

| Protocol | Capabilities |
|----------|-------------|
| **Google batchexecute** | Decode/encode batch RPC — nested RPC IDs, double-JSON payloads |
| **Protobuf / JSPB** | Wire-format codec, JSPB tree decoder, recursive base64 scanning |
| **gRPC-Web** | Decode binary/text frames, extract protobuf payloads and trailers, encode for replay |
| **Google Async Chunked** | Hex-length-prefixed streaming with JSPB extraction |
| **GraphQL** | Parse query/variables/operationName, render data/errors/extensions |
| **SSE / NDJSON / Multipart** | Server-Sent Events, newline-delimited JSON, multipart batch |
| **WebSocket** | Intercepts send/receive on live connections, with an interactive console for sending messages through captured sockets |
| **postMessage** | Captures cross-frame messages, grouped by source origin, with reply capability via stored `event.source` references |
| **MessageChannel** | Captures transferred ports from postMessage, instruments for bidirectional message logging, with send capability via stored port references |
| **EventSource** | Captures SSE streams |

Format badges (PROTO, JSPB, BATCH, gRPC-WEB, SSE, NDJSON, GRAPHQL, MULTIPART, ASYNC, WEBSOCKET, POSTMESSAGE, MSGCHANNEL) appear on request log entries.

### JavaScript Security Code Review

AST-based analysis using Babel's scope system — no regex, no string matching, works on minified code.

- **DOM XSS Sinks**: `innerHTML`, `outerHTML`, `document.write`, `eval`, `new Function`, `insertAdjacentHTML`, `setTimeout`/`setInterval` with string arg, `setAttribute("on*")`.
- **Open Redirects**: `location.href`, `location.assign`, `location.replace` with user-controlled values.
- **Dangerous Patterns**: `postMessage` without `event.origin` checks, prototype pollution (`obj[userKey] = value`), dynamic `RegExp` with user-controlled patterns.
- **Taint Source Tracking**: Traces data flow through scope bindings, function parameters, destructuring, string concatenation, method calls, array iteration callbacks (`.forEach`, `.map`, `.filter`, `.find`, `.reduce`), and `.then()`/`.catch()` chains. User-controlled sources: `location.*`, `document.referrer`, `document.cookie`, `window.name`, `event.data`.
- **Severity Classification**: HIGH (user-controlled source reaches sink), MEDIUM (dynamic/unresolvable), LOW (literal value).
- **No false positives from minification**: All detection is scope-aware — dynamic keys from iterators, object merges, and polyfills are not flagged.

### Replay & Export

- **Message Console**: Click any WebSocket, postMessage, or MessageChannel log entry to open an interactive console — shows connection status, message history, and a composer to send messages through the live socket, `event.source` reference, or transferred port.
- **Session-Aware Replay**: Executes requests in the target page's context via `PAGE_FETCH` relay, automatically attaching cookies and session state.
- **Form Builder**: Auto-generated input fields from learned schemas — text inputs, enum dropdowns (from AST value constraints and observed traffic), nested message expansion, repeated field support.
- **Auto-Determined Encoding**: Content-Type and body mode (form/raw/GraphQL) set automatically from schema or replayed request headers.
- **Field Renaming**: Click the pencil icon to rename any field or parameter. Names persist in IndexedDB across sessions.
- **HAR Export**: Download the visible request log as a HAR 1.2 file for use with Burp Suite, ZAP, or browser DevTools.
- **Export Formats**: curl, fetch (JavaScript), Python (requests library).
- **OpenAPI Export**: Service-level export as OpenAPI 3.0.3 with learned schemas, field aliases, and `x-field-number` extensions for protobuf round-trip.
- **OpenAPI Import**: Import OpenAPI/Swagger specs to pre-populate schemas, merging with locally-learned data.

### Cross-Tab Request Log

- **Multi-Tab Filtering**: View requests from the active tab, all tabs, or a specific closed tab.
- **Session Persistence**: Logs stored in `chrome.storage.session` — survive MV3 service worker restarts, auto-clear on browser close.
- **Closed Tab Retention**: Logs from closed tabs remain accessible.
- **Search & Filter**: Text filter across URL, method, service, content type, and tab title.
- **Virtual Scroll**: Handles large request logs without DOM bloat.

## UI Panels

| Panel | Purpose |
|-------|---------|
| **Requests** | Live request log with service grouping, protocol badges, and cross-tab filtering |
| **Send** | Manual testing — service/method selector, form builder with dropdowns, headers editor, replay, message console (WebSocket/postMessage/MessageChannel), export (curl/fetch/Python/HAR/OpenAPI) |
| **Vulns** | All security findings sorted by severity with type badges, source classification, and code locations |
| **Keys** | Extracted API keys and tokens with origin, timestamps, and associated services |

## Installation

1. Clone this repository.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the extension folder.

The Babel runtime must be built first if `lib/babel-bundle.js` is not present:
```
npm install && node build.js
```

## Architecture

```
intercept.js       Main-world fetch/XHR/WebSocket/EventSource wrapper (request + response capture)
content.js         Isolated-world content script (DOM scanning, PAGE_FETCH relay, intercept relay, postMessage/MessageChannel listener)
background.js      Service worker (request interception, VDD learning, AST orchestration, export)
popup.js           Popup controller (rendering, replay, form builder, security panel)
popup.html/css     Popup markup and styles

lib/
  ast.js           AST engine — API call site extraction, proto detection, security code review
  sourcemap.js     Source map recovery — TypeScript interfaces, enums, type aliases
  discovery.js     Protocol parsers, schema resolution, bidirectional OpenAPI conversion
  protobuf.js      Wire-format codec, JSPB decoder, recursive base64 scanning
  req2proto.js     Error-based schema probing (Google-specific + generic)
  babel-bundle.js  Bundled Babel runtime (parser, traverse, types) — built by build.js
```

### Data Flow

```
Page JS ──→ intercept.js (main world) ──→ CustomEvent ──→ content.js ──→ background.js
             (request headers/body +                                          │
              response headers/body)                                          │
                                                                              │
Cross-frame postMessage / MessageChannel ──→ content.js (message listener) ──→│
                                                                              │
                                              ┌───────────────────────────────┤
                                              ▼                               ▼
                                     VDD Schema Learning              AST Bundle Analysis
                                     (learnFromRequest/Response)      (analyzeJSBundle)
                                              │                               │
                                              ▼                               ▼
                                     Discovery Docs (IndexedDB)      Security Findings
                                     Endpoints, Keys, Schemas        Fetch Sites, Constraints
                                              │                       Proto Maps, Enums
                                              └───────────┬───────────────────┘
                                                          ▼
                                                    popup.js (UI)
```

### Storage

| Store | Backend | Scope | Lifetime |
|-------|---------|-------|----------|
| **GlobalStore** | IndexedDB (service worker origin) | Cross-tab | Persistent |
| **Request Logs** | `chrome.storage.session` | Per-tab | Browser session |
| **Field Renames** | IndexedDB (via GlobalStore) | Cross-tab | Persistent |

### Security Model

| Context | Process | Trust Level |
|---------|---------|-------------|
| `intercept.js` (main world) | Renderer | Untrusted — same origin as page, no extension APIs |
| `content.js` (isolated world) | Renderer | Low trust — message whitelist: `CONTENT_KEYS`, `CONTENT_ENDPOINTS`, `RESPONSE_BODY` |
| `background.js` (service worker) | Extension | Trusted — full extension APIs, IndexedDB |
| `popup.js` (extension page) | Extension | Trusted |

GlobalStore uses IndexedDB (inaccessible to content scripts) instead of `chrome.storage.local` to prevent compromised renderers from reading cross-site structural metadata. Message routing validates `sender.url` origin (unforgeable by the browser process).

## Security & Privacy

- This tool is for **authorized security research only**.
- Cookie values are redacted; only their presence is tracked.
- No `webRequest` or debugger permission required — no visible browser UI impact.
- All dynamic content in the popup is escaped via `esc()` to prevent self-XSS.

## Testing

```
node test-ast.js    # 527 tests — AST engine
node test-lib.js    # 180 tests — protobuf, discovery, stats, chains
```

## License

MIT
