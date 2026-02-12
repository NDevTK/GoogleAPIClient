# Universal API Security Researcher

A powerful Chrome Extension for reverse-engineering and security testing APIs across any website. It acts as an autonomous discovery engine that "learns" the structure, protocols, and authentication of APIs as you browse.

## Key Features

### 1. Universal Discovery & Mapping
- **Interface Grouping**: Automatically groups endpoints into logical interfaces (e.g., `api.example.com/v1`) based on path heuristics.
- **Smart Key Extraction**: Scans URLs, Headers, and Response Bodies for API keys and tokens (Google, Firebase, JWT, Stripe, Bearer, etc.).
- **Virtual Discovery Document (VDD)**: Dynamically builds a discovery-compliant schema for every interface, mapping multiple methods automatically.

### 2. Deep Protocol Inspection
- **Protobuf & JSPB Support**: Decodes binary Protobuf and Google's JSPB (JSON-Protobuf) format into readable trees.
- **Passive Response Capture**: Leverages the Chrome `debugger` API to capture and decode response bodies, enabling the learning of output schemas.
- **Schema Learning**: Automatically infers request and response structures from JSON and Protobuf traffic.

### 3. Advanced Security Testing
- **Fuzzing Engine**: Run automated probes against any discovered method. It iterates through every schema field and injects payloads for SQLi, XSS, Overflow, and type-confusion.
- **Error-Based Probing**: Generalization of the `req2proto` logic to "leak" hidden fields and types from generic API validation errors.
- **Session-Aware Replay**: The "Send" panel executes requests within the target page's context, automatically attaching active cookies and authentication.

## Installation

1. Clone this repository.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the extension folder.
5. **Important**: Reload the extension if you change permissions or add new features.

## Usage

1. **Browse**: Simply browse any website. The extension will passively map APIs in the background.
2. **Inspect**: Open the popup to see discovered keys and interfaces.
3. **Analyze**: Use the **Requests** tab to view decoded Protobuf or JSON traffic.
4. **Test**: Load any discovered method into the **Send** tab to replay it, or use the **Fuzz** tab for automated vulnerability probing.

## Security & Privacy
- This tool is for **authorized security research only**.
- It does **not** store actual cookie values; it only tracks their presence to provide research context.
- Passive response capture requires the standard Chrome "Debugger" permission bar to appear.

## License
MIT
