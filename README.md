# Universal API Security Researcher

A powerful Chrome Extension for reverse-engineering and security testing APIs across any website. It acts as an autonomous discovery engine that "learns" the structure, protocols, and authentication of APIs as you browse.

## Key Features

### 1. Universal Discovery & Mapping
- **Interface Grouping**: Automatically groups endpoints into logical interfaces (e.g., `api.example.com/v1`) based on path heuristics.
- **Smart Key Extraction**: Scans URLs, Headers, and Response Bodies (via Debugger) for API keys and tokens (Google, Firebase, JWT, Stripe, Bearer, etc.).
- **Virtual Discovery Document (VDD)**: Dynamically builds a discovery-compliant schema for every interface, mapping multiple methods automatically.
- **Collaborative Mapping**: Users can **rename fields** (`field1` -> `session_id`) directly in the UI. These names are persisted in `chrome.storage` and shared across all tool panels.

### 2. Deep Protocol Inspection
- **batchexecute Support**: Specialized decoding for Google's internal batch system. It unpacks nested RPC IDs and provides structured trees for double-JSON-encoded payloads.
- **Protobuf & JSPB Support**: Decodes binary Protobuf and Google's JSPB (JSON-Protobuf) format into readable trees.
- **Recursive Key Scanning**: Automatically decodes base64-encoded strings within Protobuf messages to find hidden nested tokens.
- **Passive Response Capture**: Leverages the Chrome `debugger` API to capture response bodies, enabling the learning of output schemas and hidden server-side data.

### 3. Advanced Security Testing
- **Fuzzing Engine**: Run automated probes against any discovered method. It iterates through every schema field and injects payloads for SQLi, XSS, Overflow, and type-confusion.
- **Session-Aware Replay**: The "Send" panel executes requests within the target page's context, automatically attaching active cookies and authentication.
- **Interactive Logs**: Build your API map directly while reviewing traffic in the **Requests** tab using integrated renaming buttons.

## Installation

1. Clone this repository.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the extension folder.
5. **Important**: Reload the extension after updates or if permissions are requested.

## Usage

1. **Browse**: Simply browse any website. The extension will passively map APIs in the background.
2. **Inspect**: Open the popup to see discovered keys and interfaces.
3. **Analyze**: Use the **Requests** tab to view decoded Protobuf, JSON, or `batchexecute` traffic.
4. **Map**: Click the **✎** icon next to any field to give it a descriptive name.
5. **Test**: Load any discovered method into the **Send** tab to replay it, or use the **Fuzz** tab for automated vulnerability probing.

## Security & Privacy
- This tool is for **authorized security research only**.
- It **redacts** actual cookie values; it only tracks their presence to provide research context.
- Passive response capture requires the standard Chrome "Debugger" permission bar to appear.

## License
MIT
