# API Security Researcher

A Chrome Extension for reverse-engineering, security testing, and JavaScript security code review across any website. It passively discovers, maps, and learns the structure, protocols, and authentication of APIs as you browse, while analyzing JavaScript bundles for security vulnerabilities.

## Key Features

### 1. Universal Discovery & Mapping

- **Autonomous Discovery**: Probes for official documentation (OpenAPI/Swagger, Google Discovery) at well-known paths (`/.well-known/openapi.json`, `/swagger.json`, `$discovery/rest`, etc.).
- **Normalization Engine**: Converts OpenAPI/Swagger into a unified internal format for replay and testing.
- **Interface Grouping**: Groups endpoints into logical interfaces (e.g., `api.example.com/v1`) based on host and path heuristics. Service filter in the Send tab narrows the method list to a single interface.
- **Smart Key Extraction**: Scans URLs, headers, and response bodies for API keys and tokens (Google, Firebase, JWT, Stripe, Bearer, Mapbox, GitHub, etc.).
- **Collaborative Mapping**: Rename fields and URL parameters directly in the UI. Names persist in `chrome.storage` and apply across all panels.

### 2. Deep Protocol Inspection

- **batchexecute Support**: Decodes Google's internal batch RPC system, recursively unpacking nested RPC IDs and double-JSON-encoded payloads.
- **Protobuf & JSPB Support**: Decodes binary Protobuf wire format and Google's JSPB (JSON+Protobuf) into readable trees.
- **gRPC-Web**: Decodes binary and text gRPC-Web frames, extracts protobuf payloads and trailers. Encodes protobuf into gRPC-Web frames for sending.
- **Google Async Chunked**: Parses hex-length-prefixed chunked responses (used by `/async/` endpoints) with JSPB payload extraction.
- **GraphQL**: Parses query/variables/operationName from requests, renders data/errors/extensions from responses. Encodes GraphQL requests for sending.
- **SSE / NDJSON / Multipart**: Server-Sent Events, newline-delimited JSON, and multipart batch responses parsed into individual records.
- **Recursive Key Scanning**: Decodes base64-encoded strings (up to 3 levels deep) within Protobuf messages to find hidden tokens.
- **Passive Response Capture**: A main-world `fetch`/`XHR` interceptor captures response bodies without the Chrome debugger bar, enabling output schema learning and key extraction from responses.

### 3. Replay & Export

- **Session-Aware Replay**: The Send panel executes requests within the target page's context, automatically attaching cookies and authentication.
- **Auto-Determined Encoding**: Content-Type and body mode (form/raw/GraphQL) are automatically set from the learned schema or replayed request — no manual selection needed.
- **One-Click Export**: Copy any configured request as **curl**, **fetch** (JavaScript), or **Python** (requests) directly from the Send tab.
- **OpenAPI Spec Export**: Export any discovered service (or all services) as an OpenAPI 3.0.3 JSON spec, including learned schemas, field aliases, and auth.
- **OpenAPI Spec Import**: Import OpenAPI/Swagger specs to pre-populate schemas. Imported data merges with locally-learned data without overwriting.
- **Unified Inspection Workflow**: Click any request in the log to inspect decoded Protobuf, JSON, headers, and historical response data directly in the Send tab.

### 4. JavaScript Security Code Review

- **AST-Based Analysis**: Babel parser + traverse with scope-aware inter-procedural tracing analyzes JavaScript bundles for security vulnerabilities — no regex or pattern matching against minified code.
- **DOM XSS Sink Detection**: Detects dangerous sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`, `new Function`, `insertAdjacentHTML`, `setTimeout`/`setInterval` with string arg, `setAttribute("on*")`).
- **Taint Source Tracking**: Traces value origins through scope bindings, function parameters, string concatenation, and method calls. Classifies sources as user-controlled (`location.*`, `document.referrer`, `document.cookie`, `window.name`, `event.data`), dynamic, or literal.
- **Dangerous Pattern Detection**: Flags `postMessage` listeners without `event.origin` checks, prototype pollution (`obj[dynamicKey] = value`), dynamic `RegExp` construction, and open redirects (`location.href`/`location.assign`/`location.replace`).
- **Severity Classification**: Findings are rated high (user-controlled source), medium (dynamic/unresolvable), or low (literal) based on taint tracking results.
- **Security Panel**: Dedicated popup tab displays all findings sorted by severity with type badges, source descriptions, and script locations.

### 5. Cross-Tab Request Log

- **Multi-Tab Viewing**: Filter the request log by active tab, all tabs, or a specific tab via the dropdown selector.
- **Format Badges**: Request log cards show protocol badges (PROTO, JSPB, BATCH, gRPC-WEB, SSE, NDJSON, GRAPHQL, MULTIPART, ASYNC).
- **Session Persistence**: Request logs are persisted to `chrome.storage.session`, surviving MV3 service worker restarts while clearing on browser close.
- **Closed Tab Retention**: Logs from closed tabs remain accessible through the All Tabs filter.

## Installation

1. Clone this repository.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the extension folder.

## Usage

1. **Browse**: Visit any website. The extension passively maps APIs, searches for documentation, and analyzes JavaScript bundles for security vulnerabilities in the background.
2. **Inspect**: Open the popup to see discovered keys, mapped interfaces, and request traffic.
3. **Review**: Check the **Security** tab for DOM XSS sinks, dangerous patterns, and open redirects found in the page's JavaScript bundles, sorted by severity.
4. **Analyze**: Click a request in the log to view decoded Protobuf, JSON, gRPC-Web, GraphQL, or batchexecute traffic and historical responses in the Send tab.
5. **Map**: Click the **pencil** icon next to any field to give it a descriptive name.
6. **Test**: Load any method into the Send tab to replay it, or export as curl/fetch/Python for use in external tools.
7. **Share**: Export a service as an OpenAPI spec, or import a spec from another researcher.

## Architecture

```
intercept.js   Main-world fetch/XHR interceptor (response body capture)
content.js     Isolated-world content script (DOM key scanning, fetch relay, intercept relay)
background.js  Service worker (request interception, schema learning, export, security findings storage)
popup.js       Popup controller (UI rendering, security findings, cross-tab filtering, replay)
popup.html     Popup markup
popup.css      Popup styles
lib/
  ast.js         AST-based JS bundle analysis (API discovery + security code review)
  sourcemap.js   Source map recovery (TypeScript interfaces, enums, type aliases)
  discovery.js   Protocol parsers, OpenAPI conversion (both directions)
  protobuf.js    Wire-format codec, JSPB decoder, recursive base64 scanning
  req2proto.js   Error-based schema probing (Google + generic)
  babel-bundle.js  Bundled Babel runtime (parser, traverse, types)
```

## Security & Privacy

- This tool is for **authorized security research only**.
- Cookie values are redacted; only their presence is tracked for research context.
- No debugger permission required. Response capture uses non-invasive prototype wrapping with no visible browser UI.

## License

MIT
