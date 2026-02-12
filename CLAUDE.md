# CLAUDE.md

## Project

Chrome MV3 browser extension for Google API security research. Captures API keys, endpoints, and auth context from Google services, fetches discovery documents, and probes undocumented APIs for request schemas.

## File Layout

- `manifest.json` — Chrome MV3 manifest
- `background.js` — Service worker: webRequest interception, state, message routing, discovery + probe orchestration
- `content.js` — Content script: DOM scanning for keys/endpoints, fetch relay for page-context requests
- `popup.html` / `popup.css` / `popup.js` — Extension popup UI
- `lib/discovery.js` — Discovery document URL builder and parser
- `lib/req2proto.js` — Error-based schema probing (JSON + binary protobuf)
- `lib/protobuf.js` — Minimal protobuf wire format codec

## Key Architecture Decisions

- **Content scripts are untrusted.** They can only send `CONTENT_KEYS` and `CONTENT_ENDPOINTS` messages. Popup messages are validated by `chrome-extension://` origin. Message routing is in `background.js` `chrome.runtime.onMessage`.
- **No credentials are stored.** Cookie values, session tokens, SAPISID are never extracted. Only boolean presence flags.
- **Persistence via `chrome.storage.local`.** Discovery Docs (real and virtual) are persisted across sessions. Tab-specific data (Keys, Requests logs) is ephemeral.
- **Fetches go through the content script**, not main-world injection. Content scripts share the page's cookie jar. The fetch relay validates URLs.
- **No main-world script injection.** DOM scanning works from the isolated world. The content script does `fetch()` directly with `credentials: "include"`.
- **`lib/` files are loaded via `importScripts()` in the service worker** and are plain JS (no modules, no bundler). They use global function names.

## Security Rules

- Never store cookie values or session tokens — only track presence
- Always validate URLs against Google API hostnames before any fetch relay
- Content script messages: use `sender.origin` not `msg.origin`, never trust `msg.tabId`
- Popup messages: verify `sender.url` starts with `chrome-extension://<id>/`
- Validate API key format (`AIzaSy` + 33 chars) before storing keys from content scripts
- Validate endpoint URLs with `isGoogleApiHost()` before storing from content scripts

## Coding Conventions

- No external dependencies — everything is vanilla JS
- `lib/` functions are globals (loaded via `importScripts`)
- Use `Map` and `Set` for state; serialize to plain objects/arrays for messaging
- HTML escaping via `esc()` in popup.js (textContent/innerHTML pattern)
- Base64 encoding for binary data across Chrome message boundaries
- Error responses from Google APIs follow `google.rpc.Status` structure

## Common Tasks

### Adding a new message type

1. Add handler in `handlePopupMessage()` or `handleContentMessage()` in `background.js`
2. Content script messages are restricted to the `CONTENT_TYPES` Set — add to the Set if needed
3. Popup messages must come from `chrome-extension://` origin

### Adding a new probe strategy

1. Add to `probeConfigs` array in `probeApiEndpoint()` in `lib/req2proto.js`
2. Binary payloads use `pbEncodeProbePayload()` from `lib/protobuf.js`
3. JSON payloads use `makeStringPayload()` / `makeIntPayload()`

### Adding a new discovery strategy

1. Add candidate URLs in `buildDiscoveryUrls()` in `lib/discovery.js`
2. Discovery fetches go through `pageContextFetch` → content script relay
