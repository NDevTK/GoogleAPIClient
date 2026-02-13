# Universal API Security Researcher - Development Guide

## Project Overview

A specialized Chrome Extension for API discovery, protocol reverse-engineering (Protobuf/JSPB/JSON), and security testing across all websites.

## Core Architecture

- **Passive Discovery**: `webRequest` for metadata, `debugger` (CDP) for full response bodies.
- **Protocol Handlers**:
  - `batchexecute`: Deeply unpacks Google's double-encoded batch RPCs using `parseBatchExecuteRequest`.
  - `lib/protobuf.js`: Wire-format codec with recursive base64 scanning for nested keys.
  - `lib/req2proto.js`: Universal error-based probing (Specialized Google + Generic logic).
  - **Normalization**: `convertOpenApiToDiscovery` translates OpenAPI/Swagger definitions into unified internal Discovery schemas.
- **Smart Learning**: Built-in VDD engine that automatically maps request/response schemas and URL parameters from observed traffic.
- **Autonomous Discovery**: Universal probing engine (`buildDiscoveryUrls`) that automatically searches for official documentation on encounters with new interfaces.
- **Collaborative Mapping**: Persistent field and parameter renaming stored in `chrome.storage.local`.
- **UI Management**: State-aware rendering in `popup.js` with 100ms render throttling to ensure stability while maintaining scroll position and independent panel navigation.

## Development Standards

- **Naming**: `camelCase` for logic, `UPPER_SNAKE_CASE` for constants. Unified `methodId` format: `interface.name.method`.
- **MV3 Compliance**: Non-blocking `webRequest` observers. Debugger auto-attaches on API/Script detection.
- **UI Security**: Strict origin checks in `onMessage` handlers. All dynamic content passed through `esc()` to prevent XSS.
- **Data Persistence**: Use `scheduleSave()` pattern to deduplicate and batch storage writes.

## Common Tasks

- **Extend Key Patterns**: Update `KEY_PATTERNS` in `background.js`.
- **Add Fuzzing Payload**: Update `payloads` array in `executeFuzzing` (`background.js`).
- **Adjust Method Heuristics**: Modify `calculateMethodMetadata` in `background.js`.
- **UI Changes**: Ensure new components maintain scroll position in their respective panels to avoid state loss on re-render.
