# Universal API Security Researcher

A Chrome Extension for reverse-engineering and security testing APIs across any website. It passively discovers, maps, and learns the structure, protocols, and authentication of APIs as you browse.

## Key Features

### 1. Universal Discovery & Mapping

- **Autonomous Discovery**: Probes for official documentation (OpenAPI/Swagger, Google Discovery) at well-known paths (`/.well-known/openapi.json`, `/swagger.json`, `$discovery/rest`, etc.).
- **Normalization Engine**: Converts OpenAPI/Swagger into a unified internal format for replay and testing.
- **Interface Grouping**: Groups endpoints into logical interfaces (e.g., `api.example.com/v1`) based on host and path heuristics.
- **Smart Key Extraction**: Scans URLs, headers, and response bodies for API keys and tokens (Google, Firebase, JWT, Stripe, Bearer, Mapbox, GitHub, etc.).
- **Collaborative Mapping**: Rename fields and URL parameters directly in the UI. Names persist in `chrome.storage` and apply across all panels.

### 2. Deep Protocol Inspection

- **batchexecute Support**: Decodes Google's internal batch RPC system, recursively unpacking nested RPC IDs and double-JSON-encoded payloads.
- **Protobuf & JSPB Support**: Decodes binary Protobuf wire format and Google's JSPB (JSON+Protobuf) into readable trees.
- **Recursive Key Scanning**: Decodes base64-encoded strings (up to 3 levels deep) within Protobuf messages to find hidden tokens.
- **Passive Response Capture**: A main-world `fetch`/`XHR` interceptor captures response bodies without the Chrome debugger bar, enabling output schema learning and key extraction from responses.

### 3. Replay & Export

- **Session-Aware Replay**: The Send panel executes requests within the target page's context, automatically attaching cookies and authentication.
- **One-Click Export**: Copy any configured request as **curl**, **fetch** (JavaScript), or **Python** (requests) directly from the Send tab.
- **Unified Inspection Workflow**: Click any request in the log to inspect decoded Protobuf, JSON, headers, and historical response data directly in the Send tab.

### 4. Cross-Tab Request Log

- **Multi-Tab Viewing**: Filter the request log by active tab, all tabs, or a specific tab via the dropdown selector.
- **Session Persistence**: Request logs are persisted to `chrome.storage.session`, surviving MV3 service worker restarts while clearing on browser close.
- **Closed Tab Retention**: Logs from closed tabs remain accessible through the All Tabs filter.

## Installation

1. Clone this repository.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the extension folder.

## Usage

1. **Browse**: Visit any website. The extension passively maps APIs and searches for documentation in the background.
2. **Inspect**: Open the popup to see discovered keys, mapped interfaces, and request traffic.
3. **Analyze**: Click a request in the log to view decoded Protobuf, JSON, or batchexecute traffic and historical responses in the Send tab.
4. **Map**: Click the **pencil** icon next to any field to give it a descriptive name.
5. **Test**: Load any method into the Send tab to replay it, or export as curl/fetch/Python for use in external tools.

## Architecture

```
intercept.js   Main-world fetch/XHR interceptor (response body capture)
content.js     Isolated-world content script (DOM key scanning, fetch relay, intercept relay)
background.js  Service worker (request interception, schema learning, export, storage)
popup.js       Popup controller (UI rendering, cross-tab filtering, replay)
popup.html     Popup markup
popup.css      Popup styles
lib/
  discovery.js   batchexecute parsing, OpenAPI/Swagger normalization
  protobuf.js    Wire-format codec, JSPB decoder, recursive base64 scanning
  req2proto.js   Error-based schema probing (Google + generic)
```

## Security & Privacy

- This tool is for **authorized security research only**.
- Cookie values are redacted; only their presence is tracked for research context.
- No debugger permission required. Response capture uses non-invasive prototype wrapping with no visible browser UI.

## License

MIT
