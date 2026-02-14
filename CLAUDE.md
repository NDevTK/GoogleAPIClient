# Universal API Security Researcher - Development Guide

## Project Overview

A Chrome Extension (MV3) for API discovery, protocol reverse-engineering (Protobuf/JSPB/JSON), and security testing across all websites.

## Core Architecture

- **Request Interception**: `webRequest` API captures request metadata, headers, and bodies. No debugger permission needed.
- **Response Capture**: `intercept.js` runs in the page's main world (`world: "MAIN"`, `document_start`), wrapping `fetch()` and `XMLHttpRequest` to capture response bodies. Data flows: `intercept.js` → `CustomEvent(__uasr_resp)` → `content.js` relay → `chrome.runtime.sendMessage(RESPONSE_BODY)` → `background.js` handler.
- **Protocol Handlers**:
  - `lib/discovery.js`: `batchexecute` parsing (`parseBatchExecuteRequest/Response`) and OpenAPI/Swagger-to-Discovery conversion.
  - `lib/protobuf.js`: Wire-format codec and `jspbToTree` with recursive base64 scanning for nested keys.
  - `lib/req2proto.js`: Universal error-based schema probing (Google-specific + generic).
- **Schema Learning**: VDD engine maps request/response schemas and URL parameters from observed traffic. `learnFromResponse()` processes captured response bodies for output schema generation.
- **Autonomous Discovery**: `buildDiscoveryUrls` probes well-known paths for official API documentation on new interfaces.
- **Collaborative Mapping**: Field and parameter renaming persisted in `chrome.storage.local`.
- **Session Persistence**: Request logs saved to `chrome.storage.session` with 1-second debounced writes per tab. Survives MV3 service worker restarts, clears on browser close.
- **Cross-Tab Logs**: Popup filter dropdown shows requests from active tab, all tabs, or a specific tab. Closed tab logs are retained.
- **UI Management**: State-aware rendering in `popup.js` with 100ms render throttling, scroll position preservation, and independent panel navigation.

## File Map

| File | Role |
|------|------|
| `manifest.json` | MV3 manifest. Permissions: `webRequest`, `storage`, `activeTab`. |
| `intercept.js` | Main-world content script. Wraps `fetch`/`XHR`, emits `__uasr_resp` CustomEvent with response body, headers, status. Filters out non-API content types. |
| `content.js` | Isolated-world content script. DOM key/endpoint scanning, `PAGE_FETCH` relay for session-aware requests, `__uasr_resp` event relay to background. |
| `background.js` | Service worker. Request interception, key extraction, schema learning, request export builder, session storage, message routing. |
| `popup.js` | Popup controller. Tab rendering, cross-tab log filtering, replay, export (curl/fetch/Python). |
| `popup.html` | Popup markup. |
| `popup.css` | Popup styles. |
| `lib/discovery.js` | batchexecute parser, OpenAPI/Swagger normalization. |
| `lib/protobuf.js` | Protobuf wire-format codec, JSPB decoder, recursive base64 key scanning. |
| `lib/req2proto.js` | Error-based schema probing engine. |

## Development Standards

- **Naming**: `camelCase` for logic, `UPPER_SNAKE_CASE` for constants. Unified `methodId` format: `interface.name.method`.
- **MV3 Compliance**: Non-blocking `webRequest` observers. No debugger API. Response bodies captured via main-world prototype wrapping.
- **Message Routing**: `chrome.runtime.onMessage` routes by sender origin — extension pages go to `handlePopupMessage`, content scripts go to `handleContentMessage`. Allowed content script types: `CONTENT_KEYS`, `CONTENT_ENDPOINTS`, `RESPONSE_BODY`.
- **UI Security**: Strict origin checks in `onMessage` handlers. All dynamic content passed through `esc()` to prevent XSS.
- **Data Persistence**: `scheduleSave()` for global store writes, `scheduleSessionSave(tabId)` for per-tab request log writes (1s debounce).
- **Intercept Script Safety**: `intercept.js` runs in main world — never blocks the caller (async body reads), caps bodies at 256KB, filters non-API content types. Uses IIFE to avoid global pollution.

## Common Tasks

- **Extend Key Patterns**: Update `KEY_PATTERNS` in `background.js`.
- **Adjust Method Heuristics**: Modify `calculateMethodMetadata` in `background.js`.
- **Add Export Format**: Add a `formatXxx()` function in `popup.js` and a button in `popup.html`. The `BUILD_REQUEST` message handler in `background.js` returns the fully-encoded `{ url, method, headers, body }`.
- **Add Intercepted Content Types**: Modify `shouldCapture()` / `isBinary()` in `intercept.js`.
- **UI Changes**: Ensure new components maintain scroll position in their respective panels. The Send panel includes export buttons (curl, fetch, Python).
- **Cross-Tab Features**: Tab metadata tracked in `_tabMeta` Map. Filter logic in popup controlled by `logFilter` state variable. New message types: `GET_TAB_LIST`, `GET_ALL_LOGS`.
