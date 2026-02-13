# Universal API Security Researcher

A powerful Chrome Extension for reverse-engineering and security testing APIs across any website. It acts as an autonomous discovery engine that "learns" the structure, protocols, and authentication of APIs as you browse.

## Key Features

### 1. Universal Discovery & Mapping

- **Autonomous Discovery**: Automatically probes for official documentation like **OpenAPI (Swagger)** and Google Discovery documents (`/.well-known/openapi.json`, `/swagger.json`, `$discovery/rest`, etc.).
- **Normalization Engine**: Transparently converts various documentation standards (OpenAPI/Swagger) into a unified internal format for replay and testing.
- **Interface Grouping**: Groups endpoints into logical interfaces (e.g., `api.example.com/v1`) based on path heuristics.
- **Smart Key Extraction**: Scans URLs, Headers, and Response Bodies (via Debugger) for API keys and tokens (Google, Firebase, JWT, Stripe, Bearer, etc.).
- **Collaborative Mapping**: Rename fields (`field1` -> `session_id`) and URL parameters directly in the UI. Names are persisted in `chrome.storage` and shared across all panels.

### 2. Deep Protocol Inspection

- **batchexecute Support**: Specialized decoding for Google's internal batch system. It recursively unpacks nested RPC IDs and provides structured trees for double-JSON-encoded payloads.
- **Protobuf & JSPB Support**: Decodes binary Protobuf and Google's JSPB format into readable trees.
- **Recursive Key Scanning**: Automatically decodes base64-encoded strings (up to 3 levels deep) within Protobuf messages and scripts to find hidden tokens.
- **Passive Response Capture**: Uses the Chrome `debugger` API to capture and decode response bodies, enabling the learning of output schemas and detection of data leaks.

### 3. Advanced Security Testing

- **Fuzzing Engine**: Automated field-level probing for SQLi, XSS, Overflow, and type-confusion across any discovered method.
- **Session-Aware Replay**: The "Send" panel executes requests within the target page's context, automatically attaching active cookies and authentication.
- **Integrated Workspace**: Build your API map directly while reviewing traffic in the **Requests** tab using interactive renaming and structured details.

## Installation

1. Clone this repository.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the extension folder.
5. **Important**: Reload the extension after updates or if permissions are requested.

## Usage

1. **Browse**: Browse any website. The extension passively maps APIs and searches for documentation in the background.
2. **Inspect**: Open the popup to see discovered keys and mapped interfaces.
3. **Analyze**: Use the **Requests** tab to view decoded Protobuf, JSON, or `batchexecute` traffic.
4. **Map**: Click the **✎** icon next to any field to give it a descriptive name.
5. **Test**: Load any method into the **Send** tab to replay it, or use the **Fuzz** tab for automated vulnerability probing.

## Security & Privacy

- This tool is for **authorized security research only**.
- It **redacts** actual cookie values; it only tracks their presence to provide research context.
- Passive response capture requires the standard Chrome "Debugger" permission bar to appear.

## License

MIT
