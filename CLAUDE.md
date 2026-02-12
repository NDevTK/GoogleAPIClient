# Universal API Security Researcher - Development Guide

## Project Overview
A specialized Chrome Extension for API discovery, protocol reverse-engineering (Protobuf/JSPB/JSON), and security testing across all websites.

## Core Architecture
- **Passive Discovery**: `webRequest` for requests, `debugger` (CDP) for response bodies.
- **Smart Learning**: Automatically builds a Virtual Discovery Document (VDD) by grouping endpoints into "Interfaces" and "Methods" based on path heuristics.
- **Protocol Handlers**:
  - `lib/protobuf.js`: Wire-format codec for binary/JSPB inspection.
  - `lib/discovery.js`: Manages REST discovery schemas and mapping.
  - `lib/req2proto.js`: Error-based schema probing (Specialized Google + Generic support).
- **Fuzzing Engine**: Automated field-level probing for common web vulnerabilities.
- **Context Relay**: Executes `fetch` in the page's origin to reuse active session cookies/auth.

## Development Standards
- **Naming**: `camelCase` for variables/functions, `UPPER_SNAKE_CASE` for constants/regex.
- **MV3 Compliance**: Use `service_worker`, `chrome.storage.local`, and ensure non-blocking headers where possible.
- **Error Handling**: Always use `try/catch` around `chrome.debugger` commands and `JSON.parse`.
- **Security**: Never store actual `Cookie` header values; only track presence.

## Common Tasks
- **Add Key Pattern**: Update `KEY_PATTERNS` constant in `background.js`.
- **Modify Fuzzing Payloads**: Update `executeFuzzing` function in `background.js`.
- **Update UI**: Modify `popup.html` and use `render()` in `popup.js` to refresh data.
