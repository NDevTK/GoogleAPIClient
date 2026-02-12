// req2proto.js — JS port of the req2proto error-based schema probing logic.
// Sends crafted payloads to Google API endpoints and extracts field/type
// information from validation error messages.
//
// Matches the Go implementation's exact regex patterns and probing strategy:
//  1. Send application/json+protobuf with ?alt=json to force JSON error responses
//  2. Parse field names, types, and field NUMBERS from the third regex group
//  3. Detect enums via specific error strings
//  4. Detect repeated fields via "]" suffix in field names
//  5. Recursively probe nested messages via index-based payload nesting

const PROBE_BATCH_SIZE = 300;

// ─── Type Map (main.go lines 33-49) ─────────────────────────────────────────

const ERROR_TYPE_MAP = {
  TYPE_STRING: "string",
  TYPE_BOOL: "bool",
  TYPE_INT64: "int64",
  TYPE_UINT64: "uint64",
  TYPE_INT32: "int32",
  TYPE_UINT32: "uint32",
  TYPE_DOUBLE: "double",
  TYPE_FLOAT: "float",
  TYPE_BYTES: "bytes",
  TYPE_FIXED64: "fixed64",
  TYPE_FIXED32: "fixed32",
  TYPE_SINT64: "sint64",
  TYPE_SINT32: "sint32",
  TYPE_SFIXED64: "sfixed64",
  TYPE_SFIXED32: "sfixed32",
};

// ─── Regex Patterns (verbatim from main.go lines 25-28) ─────────────────────

// Three capture groups: (field path), (type), (field number / value)
const GOOGLE_FIELD_DESC_RE =
  /Invalid value at '(.+)' \((.*)\), ?(?:Base64 decoding failed for )?"?x?([^"]*)?"?/g;

// Generic patterns for other APIs
const GENERIC_ERROR_PATTERNS = [
  { re: /['"]([^'"]+)['"] is not a valid (string|number|integer|boolean|array|object)/i, fieldIdx: 1, typeIdx: 2 },
  { re: /invalid (string|number|integer|boolean) value ['"]?([^'"]+)['"]? for field ['"]?([^'"]+)['"]?/i, fieldIdx: 3, typeIdx: 1, valIdx: 2 },
  { re: /field ['"]?([^'"]+)['"]? is required/i, fieldIdx: 1, required: true },
  { re: /unknown field ['"]?([^'"]+)['"]?/i, fieldIdx: 1 }
];

const REQUIRED_FIELD_RE = /Missing required field (.+) at '([^']+)'/g;
const MESSAGE_TYPE_RE = /^type\.googleapis\.com\/(.+)$/;
const MESSAGE_NAME_RE =
  /^((?:[a-z0-9_]+\.)*[a-z0-9_]+)\.([A-Z][A-Za-z.0-9_]+)$/;

// JSPB service/method extraction (gapi-service parse.go lines 34-35)
const JSPB_METHOD_RE = /\["method",\s*"([^"]*)"\]/g;
const JSPB_SERVICE_RE = /\["service",\s*"([^"]*)"\]/g;

// Enum detection strings (main.go lines 242-244)
const ENUM_ERROR_STRINGS = [
  "Invalid value (), Unexpected list for single non-message field.",
  "Invalid value (), List is not message or group type.",
];

// ─── Payload Generation (payload.go) ─────────────────────────────────────────

function makeIntPayload(size = PROBE_BATCH_SIZE) {
  return Array.from({ length: size }, (_, i) => i + 1);
}

// Go uses "x1", "x2", ... prefix (payload.go line 26)
function makeStringPayload(size = PROBE_BATCH_SIZE) {
  return Array.from({ length: size }, (_, i) => `x${i + 1}`);
}

// Go alternates false/true (payload.go line 33)
function makeBoolPayload(size = PROBE_BATCH_SIZE) {
  return Array.from({ length: size }, (_, i) => i % 2 === 1);
}

/**
 * Generate a nested payload for probing fields inside nested messages.
 * Mirrors payload.go lines 26-34: iterates indices backwards, wrapping
 * the inner payload in arrays at each level.
 *
 * @param {number[]} indices - Array of field numbers for nesting depth
 * @param {"int"|"str"|"bool"} type - Payload type
 * @returns {any[]} Nested array payload
 */
function makeNestedPayload(indices, type) {
  let payload;
  switch (type) {
    case "int":
      payload = makeIntPayload();
      break;
    case "str":
      payload = makeStringPayload();
      break;
    case "bool":
      payload = makeBoolPayload();
      break;
    default:
      payload = makeIntPayload();
  }

  // Wrap backwards through indices (deepest first)
  for (let i = indices.length - 1; i >= 0; i--) {
    const wrapper = new Array(indices[i]);
    wrapper[indices[i] - 1] = payload; // set at the index position (1-based)
    payload = wrapper;
  }

  return payload;
}

// ─── URL Helpers ─────────────────────────────────────────────────────────────

/**
 * Ensure ?alt=json is present on the URL (main.go modifyAltParameter).
 * The Go tool sends json+protobuf content-type but forces JSON error responses.
 */
function ensureAltJson(url) {
  const u = new URL(url);
  const alt = u.searchParams.get("alt");
  if (!alt) {
    u.searchParams.set("alt", "json");
  } else if (alt !== "json") {
    u.searchParams.set("alt", "json");
  }
  return u.toString();
}

// ─── Error Parsing ───────────────────────────────────────────────────────────

/**
 * Parse field violations from a JSON error response.
 * Matches Go's two-pass approach:
 *   Pass 1: Collect required field mappings from "Missing required field" violations
 *   Pass 2: Parse field descriptions for type/number info using the 3-group regex
 *
 * IMPORTANT: Go uses violation.field (the JSON field path property) as the primary
 * field name, NOT the regex match group 1. The regex provides type + field number.
 */
function parseJsonErrors(body) {
  const fields = [];
  const metadata = { service: null, method: null };

  if (!body) return { fields, metadata };

  // Heuristic: If body is an array, it might be a JSPB rpc.Status message
  // [code (integer), message (string), details (array)]
  if (Array.isArray(body)) {
    if (body.length >= 2 && typeof body[0] === "number") {
      body = {
        error: {
          code: body[0],
          message: body[1] || "",
          details: body[2] || [],
        },
      };
    } else {
      return { fields, metadata };
    }
  }

  if (!body.error) return { fields, metadata };

  // Collect all violations into a single list
  const violations = [];

  // Pass 0a: From details (standard)
  for (const detail of body.error.details || []) {
    if (detail["@type"]?.includes("BadRequest")) {
      for (const violation of detail.fieldViolations || []) {
        if (violation.field || violation.description) {
          violations.push(violation);
        }
      }
    }
    // Extract service/method metadata from ErrorInfo
    if (detail["@type"]?.includes("ErrorInfo") && detail.metadata) {
      if (detail.metadata.service) metadata.service = detail.metadata.service;
      if (detail.metadata.method) metadata.method = detail.metadata.method;
    }
  }

  // Pass 0b: From message (fallback for some APIs)
  if (body.error.message) {
    const lines = body.error.message.split("\n");
    for (const line of lines) {
      if (
        line.includes("Invalid value at ") ||
        line.includes("Missing required field ")
      ) {
        // Only add if not already present in details (dedup by description)
        if (!violations.some((v) => v.description === line.trim())) {
          violations.push({ description: line.trim() });
        }
      }
    }
  }

  // Pass 1: Build required field map (Go main.go lines 223-236)
  const requiredFieldMap = {};
  for (const v of violations) {
    if (v.description && v.description.startsWith("Missing required field")) {
      REQUIRED_FIELD_RE.lastIndex = 0;
      const reqMatch = REQUIRED_FIELD_RE.exec(v.description);
      if (reqMatch) {
        const requiredFieldName = reqMatch[1];
        const parentPath = v.field || reqMatch[2] || "";
        if (!requiredFieldMap[parentPath]) requiredFieldMap[parentPath] = [];
        requiredFieldMap[parentPath].push(requiredFieldName);
      }
    }
  }

  // Pass 2: Parse field descriptions for type/number info
  for (const v of violations) {
    if (!v.description) continue;
    if (v.description.startsWith("Missing required field")) continue;

    GOOGLE_FIELD_DESC_RE.lastIndex = 0;
    const match = GOOGLE_FIELD_DESC_RE.exec(v.description);
    
    if (match) {
      const regexFieldPath = match[1];
      const typeStr = match[2];
      const valueOrNumber = match[3];

      // Use violation.field if available, fall back to regex field path
      const rawFieldPath = v.field || regexFieldPath;
      const pathParts = rawFieldPath.split(".");
      const fieldName = pathParts[pathParts.length - 1];
      const fieldNumber = parseInt(valueOrNumber, 10) || null;
      const isRepeated = fieldName.endsWith("]");
      const cleanName = isRepeated
        ? fieldName.replace(/\[\d*\]$/, "")
        : fieldName;

      const parentPath =
        pathParts.length > 1 ? pathParts.slice(0, -1).join(".") : "";
      const isRequired =
        (requiredFieldMap[parentPath] || []).includes(cleanName) ||
        (requiredFieldMap[rawFieldPath] || []).length > 0;

      if (ERROR_TYPE_MAP[typeStr]) {
        fields.push({
          name: cleanName,
          type: ERROR_TYPE_MAP[typeStr],
          number: fieldNumber,
          messageType: null,
          required: isRequired,
          label: isRepeated ? "repeated" : isRequired ? "required" : "optional",
        });
        continue;
      }

      const msgMatch = MESSAGE_TYPE_RE.exec(typeStr);
      if (msgMatch) {
        const fullType = msgMatch[1];
        if (fullType === "google.protobuf.Any") {
          fields.push({
            name: cleanName,
            type: "message",
            number: fieldNumber,
            messageType: "google.protobuf.Any",
            required: isRequired,
            label: isRepeated ? "repeated" : isRequired ? "required" : "optional",
            wellKnown: true,
            children: [
              { name: "type_url", type: "string", number: 1 },
              { name: "data", type: "bytes", number: 2 },
            ],
          });
          continue;
        }

        const nameMatch = MESSAGE_NAME_RE.exec(fullType);
        fields.push({
          name: cleanName,
          type: "message",
          number: fieldNumber,
          messageType: fullType,
          package: nameMatch ? nameMatch[1] : "google",
          messageName: nameMatch ? nameMatch[2] : fullType,
          required: isRequired,
          label: isRepeated ? "repeated" : isRequired ? "required" : "optional",
          requiredChildren: requiredFieldMap[rawFieldPath] || [],
        });
        continue;
      }

      // Default / Enum check
      const isEnum = ENUM_ERROR_STRINGS.some((s) => v.description.includes(s));
      fields.push({
        name: cleanName,
        type: isEnum ? "enum" : typeStr || "unknown",
        number: fieldNumber,
        messageType: isEnum ? typeStr : null,
        required: isRequired,
        label: isRepeated ? "repeated" : isRequired ? "required" : "optional",
        isEnum,
      });
    } else {
      // Try generic patterns
      for (const pattern of GENERIC_ERROR_PATTERNS) {
        pattern.re.lastIndex = 0;
        const m = pattern.re.exec(v.description);
        if (m) {
          const fieldName = m[pattern.fieldIdx];
          const typeStr = pattern.typeIdx ? m[pattern.typeIdx] : "unknown";
          const reflectedVal = pattern.valIdx ? m[pattern.valIdx] : null;
          
          fields.push({
            name: fieldName,
            type: typeStr.toLowerCase(),
            number: reflectedVal && !isNaN(reflectedVal) ? parseInt(reflectedVal) : null,
            required: pattern.required || false,
            label: pattern.required ? "required" : "optional"
          });
          break;
        }
      }
    }
  }

  return { fields, metadata };
}

/**
 * Parse a single violation string with the 3-group fieldDescRe.
 */
function parseViolationString(text, fields) {
  GOOGLE_FIELD_DESC_RE.lastIndex = 0;
  let match;

  while ((match = GOOGLE_FIELD_DESC_RE.exec(text)) !== null) {
    const fieldPath = match[1]; // e.g. "context", "browse_id", "params[0].nested"
    const typeStr = match[2]; // e.g. "TYPE_STRING", "type.googleapis.com/pkg.Msg"
    const valueOrNumber = match[3]; // e.g. "2" (the field number from the probe payload)

    const fieldNumber = parseInt(valueOrNumber, 10) || null;
    const isRepeated = fieldPath.endsWith("]");

    // Detect enum (Go main.go lines 242-303)
    if (ENUM_ERROR_STRINGS.some((s) => text.includes(s))) {
      fields.push({
        name: fieldPath,
        type: "enum",
        number: fieldNumber,
        messageType: typeStr,
        required: false,
        label: isRepeated ? "repeated" : "optional",
      });
      continue;
    }

    // Check if scalar type
    if (ERROR_TYPE_MAP[typeStr]) {
      fields.push({
        name: fieldPath,
        type: ERROR_TYPE_MAP[typeStr],
        number: fieldNumber,
        messageType: null,
        required: false,
        label: isRepeated ? "repeated" : "optional",
      });
      continue;
    }

    // Check for message type reference (type.googleapis.com/...)
    const msgMatch = MESSAGE_TYPE_RE.exec(typeStr);
    if (msgMatch) {
      const fullType = msgMatch[1];

      // Special case: google.protobuf.Any (main.go lines 434-467)
      if (fullType === "google.protobuf.Any") {
        fields.push({
          name: fieldPath,
          type: "message",
          number: fieldNumber,
          messageType: "google.protobuf.Any",
          required: false,
          label: isRepeated ? "repeated" : "optional",
          wellKnown: true,
          children: [
            { name: "type_url", type: "string", number: 1 },
            { name: "data", type: "bytes", number: 2 },
          ],
        });
        continue;
      }

      // Parse package.MessageName
      const nameMatch = MESSAGE_NAME_RE.exec(fullType);
      const pkg = nameMatch ? nameMatch[1] : "google";
      const msgName = nameMatch ? nameMatch[2] : fullType;

      fields.push({
        name: fieldPath,
        type: "message",
        number: fieldNumber,
        messageType: fullType,
        package: pkg,
        messageName: msgName,
        required: false,
        label: isRepeated ? "repeated" : "optional",
      });
      continue;
    }

    // Unknown / fallback
    fields.push({
      name: fieldPath,
      type: typeStr || "unknown",
      number: fieldNumber,
      messageType: null,
      required: false,
      label: isRepeated ? "repeated" : "optional",
    });
  }
}

/**
 * Parse JSPB response for service/method metadata.
 * Uses the gapi-service regex patterns for ["method", "..."] and ["service", "..."].
 */
function parseJspbMetadata(text) {
  const metadata = { service: null, method: null };

  JSPB_METHOD_RE.lastIndex = 0;
  const methodMatch = JSPB_METHOD_RE.exec(text);
  if (methodMatch) metadata.method = methodMatch[1];

  JSPB_SERVICE_RE.lastIndex = 0;
  const serviceMatch = JSPB_SERVICE_RE.exec(text);
  if (serviceMatch) metadata.service = serviceMatch[1];

  return metadata;
}

// ─── Binary Content-Type Detection ────────────────────────────────────────────

function isBinaryContentType(ct) {
  if (!ct) return false;
  const lower = ct.toLowerCase();
  // JSPB (json+protobuf) is NOT binary wire format
  if (lower.includes("json")) return false;
  return (
    lower.includes("protobuf") ||
    lower.includes("proto") ||
    lower.includes("grpc") ||
    lower.includes("octet-stream")
  );
}

// ─── Fetch Adapters ──────────────────────────────────────────────────────────

/**
 * Default fetch function (used when no page-context relay is available).
 * Normalizes the response to { status, headers, body }.
 * Binary protobuf responses are base64-encoded with bodyEncoding: "base64".
 */
async function defaultFetchFn(url, opts) {
  // Handle binary request body (base64 from binary probe payloads)
  if (opts.bodyEncoding === "base64") {
    const decoded = base64ToUint8(opts.body);
    opts = { ...opts, body: decoded };
    delete opts.bodyEncoding;
  }

  const resp = await fetch(url, opts);
  const headers = {};
  resp.headers.forEach((v, k) => {
    headers[k] = v;
  });
  const ct = resp.headers.get("content-type") || "";

  // Binary response: read as ArrayBuffer and base64-encode for uniform handling
  if (isBinaryContentType(ct)) {
    const buf = await resp.arrayBuffer();
    return {
      ok: resp.ok,
      status: resp.status,
      headers,
      body: uint8ToBase64(new Uint8Array(buf)),
      bodyEncoding: "base64",
    };
  }

  const body = await resp.text();
  return { ok: resp.ok, status: resp.status, headers, body };
}

// ─── Probing ─────────────────────────────────────────────────────────────────

/**
 * Send a single probe request and parse the error response.
 * Supports both JSON and binary protobuf payloads/responses.
 *
 * @param {string} url
 * @param {any} payload - JSON array or Uint8Array (binary protobuf)
 * @param {string} contentType
 * @param {object} headers - Custom headers (API key, Authorization, etc.)
 * @param {function} fetchFn - Custom fetch function
 */
async function sendProbe(url, payload, contentType, headers, fetchFn) {
  const reqHeaders = { "Content-Type": contentType, ...headers };

  // Binary protobuf payload: Uint8Array → base64 for message relay
  const isBinary = payload instanceof Uint8Array;
  const body = isBinary ? uint8ToBase64(payload) : JSON.stringify(payload);
  const bodyEncoding = isBinary ? "base64" : undefined;

  try {
    const resp = await fetchFn(url, {
      method: "POST",
      headers: reqHeaders,
      body,
      bodyEncoding,
    });

    if (resp.error) {
      return { error: resp.error, fields: [], metadata: {} };
    }

    const respCt =
      resp.headers?.["content-type"] || resp.headers?.["Content-Type"] || "";

    // Extract scopes from Www-Authenticate on 403 (gapi-service fetch.go line 12)
    let scopes = null;
    if (resp.status === 403) {
      const wwwAuth = resp.headers?.["www-authenticate"] || "";
      const scopeMatch = wwwAuth.match(/scope="([^"]*)"/);
      if (scopeMatch) scopes = scopeMatch[1].split(/\s+/);
    }

    // ── Binary protobuf response ──
    // Decode via pbDecodeRpcStatus → same JSON shape → reuse parseJsonErrors
    if (resp.bodyEncoding === "base64" || isBinaryContentType(respCt)) {
      const bytes =
        resp.bodyEncoding === "base64"
          ? base64ToUint8(resp.body)
          : new TextEncoder().encode(resp.body);

      // pbDecodeRpcStatus returns { error: { code, message, details: [...] } }
      // which matches the JSON API error format exactly
      const decoded = pbDecodeRpcStatus(bytes);
      const parsed = parseJsonErrors(decoded);

      return {
        status: resp.status,
        fields: parsed.fields,
        metadata: parsed.metadata,
        scopes,
        raw: decoded,
        binary: true,
      };
    }

    // ── JSON / JSPB response ──
    const text = resp.body;
    let jsonBody;
    try {
      jsonBody = JSON.parse(text);
    } catch (_) {
      return { raw: text, fields: [], metadata: {}, status: resp.status };
    }

    let parsed;
    if (
      respCt.includes("application/json") &&
      !respCt.includes("json+protobuf")
    ) {
      parsed = parseJsonErrors(jsonBody);
    } else {
      parsed = parseJsonErrors(jsonBody);
      const jspbMeta = parseJspbMetadata(text);
      if (jspbMeta.method)
        parsed.metadata.method = parsed.metadata.method || jspbMeta.method;
      if (jspbMeta.service)
        parsed.metadata.service = parsed.metadata.service || jspbMeta.service;
    }

    return {
      status: resp.status,
      fields: parsed.fields,
      metadata: parsed.metadata,
      scopes,
      raw: jsonBody,
    };
  } catch (err) {
    return { error: err.message, fields: [], metadata: {} };
  }
}

/**
 * Probe an API endpoint to discover its schema.
 *
 * Strategy:
 *  1. Force ?alt=json on the URL (for JSON content types)
 *  2. Send application/json+protobuf first (JSPB — what the Go tool does)
 *  3. Fall back to application/json if no results
 *  4. Fall back to application/x-protobuf with binary payloads (for non-REST gRPC endpoints)
 *  5. Run int + str probes for each content type
 *  6. For each discovered message field, recursively probe nested structure
 *
 * @param {string} url - Full endpoint URL
 * @param {object} headers - Auth headers (API key, Authorization — NOT Cookie/Origin/Referer)
 * @param {object} opts - { maxDepth: number, fetchFn: function }
 *   fetchFn: (url, {method, headers, body}) → Promise<{status, headers, body}>
 *   When provided, all HTTP requests go through this function (e.g. page-context relay).
 * @returns {object} Probe result with discovered fields
 */
async function probeApiEndpoint(url, headers = {}, opts = {}) {
  const maxDepth = opts.maxDepth ?? 2;
  const fetchFn = opts.fetchFn || defaultFetchFn;
  const probeUrl = ensureAltJson(url);
  // For binary protobuf, don't force ?alt=json (it's a JSON-only parameter)
  const rawUrl = url;

  const allFields = new Map();
  const results = [];
  let metadata = null;
  let scopes = null;
  let usedContentType = null; // Track which content type worked (for nested probing)

  // Phase 1: Root-level probing — try JSON formats first, then binary protobuf
  // The binary path is for pure gRPC/protobuf endpoints that reject JSON entirely.
  const probeConfigs = [
    // JSON+protobuf (JSPB): most common Google API format
    { ct: "application/json+protobuf", url: probeUrl, binary: false },
    // Plain JSON: some APIs only accept this
    { ct: "application/json", url: probeUrl, binary: false },
    // Binary protobuf: for non-REST gRPC endpoints
    { ct: "application/x-protobuf", url: rawUrl, binary: true },
  ];

  for (const config of probeConfigs) {
    const payloads = config.binary
      ? [
          ["str", pbEncodeProbePayload(PROBE_BATCH_SIZE, "str")],
          ["int", pbEncodeProbePayload(PROBE_BATCH_SIZE, "int")],
        ]
      : [
          ["str", makeStringPayload()],
          ["int", makeIntPayload()],
        ];

    for (const [name, payload] of payloads) {
      const result = await sendProbe(
        config.url,
        payload,
        config.ct,
        headers,
        fetchFn,
      );
      results.push({ contentType: config.ct, probe: name, ...result });

      if (result.metadata?.method) metadata = metadata || result.metadata;
      if (result.scopes) scopes = result.scopes;

      // Merge fields, deduplicate by field number (main.go lines 218-220)
      const seenNumbers = new Set(
        [...allFields.values()].map((f) => f.number).filter(Boolean),
      );
      for (const field of result.fields || []) {
        const key = field.number ? `#${field.number}` : field.name;
        if (field.number && seenNumbers.has(field.number)) continue;
        if (!allFields.has(key)) {
          allFields.set(key, field);
          if (field.number) seenNumbers.add(field.number);
        } else {
          const existing = allFields.get(key);
          if (field.type !== "unknown" && existing.type === "unknown")
            existing.type = field.type;
          if (field.messageType && !existing.messageType)
            existing.messageType = field.messageType;
          if (field.required) existing.required = true;
          if (field.label === "repeated") existing.label = "repeated";
        }
      }
    }

    // If we got results from this content type, don't try the next one
    if (allFields.size > 0) {
      usedContentType = config;
      break;
    }
  }

  // Phase 2: Recursive nested probing for message-type AND repeated fields
  // Mirrors Go's channel-based worker (main.go lines 194-501):
  //  - Message fields: probe nested structure at [parentIndex, childIndex...]
  //  - Repeated fields: re-probe with index 1 appended (Go line 339)
  //  - Enum fields: detected at nested level, modifies parent field type
  if (maxDepth > 0) {
    const nestedQueue = [];
    for (const [, field] of allFields) {
      if (field.type === "message" && field.number && !field.wellKnown) {
        nestedQueue.push({ field, indices: [field.number], parentField: null });
      }
      // Repeated fields: Go re-probes with index 1 appended (main.go lines 337-341)
      if (field.label === "repeated" && field.number) {
        nestedQueue.push({
          field,
          indices: [field.number, 1],
          parentField: null,
          isRepeatedDive: true,
        });
      }
    }

    let depth = 0;
    while (nestedQueue.length > 0 && depth < maxDepth) {
      const batch = nestedQueue.splice(0, nestedQueue.length);
      depth++;

      for (const { field: parentField, indices, isRepeatedDive } of batch) {
        // Probe nested message with index-wrapped payloads
        // Use the same content type that worked at root level
        const isBinaryEndpoint = usedContentType?.binary;
        const ct = isBinaryEndpoint
          ? "application/x-protobuf"
          : "application/json+protobuf";
        const nestedUrl = isBinaryEndpoint ? rawUrl : probeUrl;
        const nestedFields = [];

        // Go runs int first, then str for nested (main.go lines 200-211)
        for (const type of ["int", "str"]) {
          const payload = isBinaryEndpoint
            ? pbEncodeNestedPayload(indices, PROBE_BATCH_SIZE, type)
            : makeNestedPayload(indices, type);
          const result = await sendProbe(
            nestedUrl,
            payload,
            ct,
            headers,
            fetchFn,
          );
          results.push({
            contentType: ct,
            probe: `nested_${type}_d${depth}`,
            ...result,
          });

          for (const f of result.fields || []) {
            nestedFields.push(f);
          }
        }

        // Check if this nested probe revealed an enum (Go main.go lines 242-303)
        const enumField = nestedFields.find((f) => f.isEnum);
        if (enumField) {
          // The "message" was actually an enum — update parent field type
          parentField.type = "enum";
          parentField.children = null;
          continue;
        }

        // Attach nested fields to parent
        if (nestedFields.length > 0) {
          parentField.children = parentField.children || [];
          const seenNested = new Set(
            parentField.children.map((c) => c.number).filter(Boolean),
          );

          for (const nf of nestedFields) {
            if (nf.number && seenNested.has(nf.number)) continue;
            parentField.children.push(nf);
            if (nf.number) seenNested.add(nf.number);

            // Queue deeper nesting for message-type fields
            if (nf.type === "message" && nf.number && !nf.wellKnown) {
              nestedQueue.push({
                field: nf,
                indices: [...indices, nf.number],
                parentField: parentField,
              });
            }
            // Queue deeper nesting for repeated fields (Go main.go line 339)
            if (nf.label === "repeated" && nf.number) {
              nestedQueue.push({
                field: nf,
                indices: [...indices, nf.number, 1],
                parentField: parentField,
                isRepeatedDive: true,
              });
            }
          }
        }
      }
    }
  }

  return {
    url,
    timestamp: Date.now(),
    fieldCount: allFields.size,
    fields: Object.fromEntries(allFields),
    metadata,
    scopes,
    probeDetails: results.map((r) => ({
      contentType: r.contentType,
      probe: r.probe,
      status: r.status,
      fieldCount: r.fields?.length || 0,
      error: r.error,
    })),
  };
}

// ─── gapi-service: Service/Method/Scope Discovery ─────────────────────────

/**
 * Discover the gRPC service name, method name, and required OAuth scopes
 * for any endpoint by sending minimal requests with different content types.
 *
 * Mirrors the gapi-service Go tool (tools/gapi-service/):
 *  - Tries three content types: application/json, application/json+protobuf, application/x-protobuf
 *  - Parses 403 Www-Authenticate header for scope requirements
 *  - Parses error response body for service/method metadata
 *  - Uses both JSON and JSPB response parsers
 *
 * @param {string} url - Full endpoint URL
 * @param {object} headers - Auth headers (API key, Authorization)
 * @param {object} opts - { fetchFn }
 * @returns {object} { service, method, scopes, contentTypes, details }
 */

