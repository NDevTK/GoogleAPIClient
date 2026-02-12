# Google API Security Research Extension

Chrome MV3 extension for Google internal API security research. Passively captures API keys, endpoints, and auth context from Google services, then actively probes undocumented APIs to discover request schemas, service metadata, and OAuth scope requirements.

## Features

- **Service Auto-Discovery** — identifies active Google services (`storage`, `compute`, etc.) from traffic and automatically fetches their Discovery Documents
- **API Key Extraction** — captures keys from network headers and page source; tracks which keys unlock which services
- **Smart Schema Discovery** — tries public Discovery docs first; falls back to **req2proto** probing for private/undocumented APIs
- **Virtual Discovery Docs** — dynamically generates and _merges_ OpenAPI-like schemas for probed endpoints, persisting them across sessions
- **JSPB & Protobuf Support** — full deep decoding of binary Protobuf and JSPB (`application/json+protobuf`) traffic with schema-aware field names
- **High-Fidelity Replay** — one-click "Load into Send" populates schema-aware forms with original request data and synchronizes Content-Type
- **Auth Status** — visibility of credential presence (cookies, Authorization) without storing sensitive values

## Install

1. Clone or download this repo
2. Open `chrome://extensions`
3. Enable **Developer mode**
4. Click **Load unpacked** and select this directory
5. Browse any Google service — the extension icon activates on matched domains

## Architecture

```
manifest.json          Chrome MV3 manifest (permissions, content script matches)
background.js          Service worker — webRequest interception, state management, message routing
content.js             Content script — DOM scanning, fetch relay (shares page cookie jar)
popup.html/css/js      Extension popup UI — renders captured data, triggers probes
lib/
  discovery.js         Discovery document URL builder and parser
  req2proto.js         Error-based schema probing engine (JSON + binary protobuf)
  protobuf.js          Minimal protobuf wire format codec (zero dependencies)
```

### Data Flow

1. `background.js` intercepts requests via `chrome.webRequest.onBeforeSendHeaders` — extracts API keys, endpoints, auth presence
2. `content.js` scans page DOM for hardcoded keys and endpoint URLs
3. Discovery documents are fetched through the content script (page cookie jar) with all known API keys
4. Probing runs through the content script relay so requests carry the page's credentials automatically

### Security Model

- Content scripts are **untrusted** — they can only send `CONTENT_KEYS` and `CONTENT_ENDPOINTS` messages
- Popup messages are validated by `chrome-extension://` origin
- The fetch relay validates all URLs against Google API hostname allowlist (both in background and content script)
- No cookie values, session tokens, or credentials are extracted or stored — only boolean presence flags
- All data is per-tab and cleared on tab close

## Permissions

| Permission         | Purpose                                                                                                  |
| ------------------ | -------------------------------------------------------------------------------------------------------- |
| `webRequest`       | Intercept request/response headers for key, endpoint, and scope extraction                               |
| `cookies`          | Required by `webRequest` for header access on matched hosts                                              |
| `storage`          | Reserved for future settings persistence                                                                 |
| `activeTab`        | Popup access to the active tab                                                                           |
| `scripting`        | Content script injection                                                                                 |
| `host_permissions` | `*.googleapis.com`, `*.clients6.google.com`, `*.google.com`, `*.youtube.com`, `*.sandbox.googleapis.com` |

## Usage

### 1. Passive Collection

Browse any Google service normally. The extension identifies active services (e.g., `people`, `drive`) and fetches their schema definitions automatically.

### 2. Request Log & Replay

Open the **Requests** tab to see a real-time log of API requests. Click **"Load into Send"** to replay any request. The extension automatically populates the form in the **Send** tab, matches the original Protobuf/JSPB format, and preserves headers.

### 3. Schema Probing (req2proto)

For unpublished APIs, use the **Send** tab to "Probe" an endpoint. The extension will send crafted payloads to reverse-engineer the request schema from error messages. Discovered fields, including nested messages, are saved into "Virtual Discovery Documents" that provide field names for the entire service.
