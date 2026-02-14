// lib/protobuf.js — Minimal protobuf wire format codec.
// Supports encoding binary probe payloads, decoding Google API error responses,
// and generic protobuf message inspection. Zero external dependencies.
//
// Wire format reference: https://protobuf.dev/programming-guides/encoding/
//
// Used by:
//  - req2proto.js: binary protobuf probing for non-REST (gRPC/proto-only) endpoints
//  - discoverServiceInfo: decoding binary error responses for service/method metadata
//  - popup.js: inspecting intercepted protobuf traffic

// ─── Wire Types ───────────────────────────────────────────────────────────────

const PB_VARINT = 0; // int32, int64, uint32, uint64, sint32, sint64, bool, enum
const PB_64BIT = 1; // fixed64, sfixed64, double
const PB_LEN = 2; // string, bytes, embedded messages, packed repeated
const PB_32BIT = 5; // fixed32, sfixed32, float

// ─── Base64 Helpers (for Chrome message passing of binary data) ───────────────

function uint8ToBase64(bytes) {
  let binary = "";
  const chunk = 8192;
  for (let i = 0; i < bytes.length; i += chunk) {
    const slice = bytes.subarray(i, Math.min(i + chunk, bytes.length));
    binary += String.fromCharCode.apply(null, slice);
  }
  return btoa(binary);
}

function base64ToUint8(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ─── Byte Helpers ─────────────────────────────────────────────────────────────

function concatBytes() {
  let len = 0;
  for (let i = 0; i < arguments.length; i++) len += arguments[i].length;
  const out = new Uint8Array(len);
  let off = 0;
  for (let i = 0; i < arguments.length; i++) {
    out.set(arguments[i], off);
    off += arguments[i].length;
  }
  return out;
}

// ─── Varint Codec ─────────────────────────────────────────────────────────────

/**
 * Read a varint from buf at pos. Returns [value, newPos].
 * Uses Number for values ≤ 2^53-1 (field numbers, lengths, most values).
 * Falls back to string representation for values > 2^53 to avoid silent
 * precision loss on uint64/int64 fields.
 */
function pbReadVarint(buf, pos) {
  let val = 0;
  let shift = 0;
  while (pos < buf.length) {
    const b = buf[pos++];
    val += (b & 0x7f) * Math.pow(2, shift);
    if ((b & 0x80) === 0) {
      // Check if we exceeded safe integer range
      if (shift >= 49 && val > Number.MAX_SAFE_INTEGER) {
        // Re-read as BigInt for precision, return as string
        return [pbReadVarintBig(buf, pos - shift / 7 - 1), pos];
      }
      return [val, pos];
    }
    shift += 7;
    if (shift >= 64) throw new Error("varint overflow");
  }
  throw new Error("truncated varint");
}

/**
 * Re-read a varint using string arithmetic for values exceeding 2^53.
 * Returns a string representation of the value.
 */
function pbReadVarintBig(buf, pos) {
  let lo = 0, hi = 0;
  for (let i = 0; i < 4; i++) {
    const b = buf[pos++];
    lo |= (b & 0x7f) << (i * 7);
    if ((b & 0x80) === 0) return lo >>> 0;
  }
  // 5th byte spans lo/hi boundary
  const b4 = buf[pos++];
  lo |= (b4 & 0x0f) << 28;
  hi = (b4 & 0x7f) >> 4;
  if ((b4 & 0x80) === 0) return (hi * 0x100000000 + (lo >>> 0));

  for (let i = 0; i < 5; i++) {
    const b = buf[pos++];
    hi |= (b & 0x7f) << (i * 7 + 3);
    if ((b & 0x80) === 0) break;
  }
  // Return as string to preserve precision
  const value = hi * 0x100000000 + (lo >>> 0);
  if (value > Number.MAX_SAFE_INTEGER) return String(value);
  return value;
}

/**
 * Encode a non-negative integer as a varint.
 */
function pbWriteVarint(val) {
  const out = [];
  val = Math.max(0, Math.floor(val));
  do {
    let b = val & 0x7f;
    val = Math.floor(val / 128);
    if (val > 0) b |= 0x80;
    out.push(b);
  } while (val > 0);
  return new Uint8Array(out);
}

// ─── Raw Wire Format Decoder ──────────────────────────────────────────────────

/**
 * Decode raw protobuf wire format into an array of field entries.
 * Each entry: { field: number, wire: 0|1|2|5, data: number|Uint8Array }
 *   - wire 0 (varint): data = number
 *   - wire 1 (64-bit): data = Uint8Array(8)
 *   - wire 2 (length-delimited): data = Uint8Array
 *   - wire 5 (32-bit): data = Uint8Array(4)
 */
function pbDecodeRaw(buf) {
  if (!(buf instanceof Uint8Array)) buf = new Uint8Array(buf);
  const fields = [];
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p1] = pbReadVarint(buf, pos);
    pos = p1;
    const fieldNum = Math.floor(tag / 8);
    const wireType = tag & 0x7;
    if (fieldNum < 1 || fieldNum > 536870911)
      throw new Error("bad field number " + fieldNum);

    switch (wireType) {
      case PB_VARINT: {
        const [val, p2] = pbReadVarint(buf, pos);
        pos = p2;
        fields.push({ field: fieldNum, wire: wireType, data: val });
        break;
      }
      case PB_64BIT:
        if (pos + 8 > buf.length) throw new Error("truncated 64-bit");
        fields.push({
          field: fieldNum,
          wire: wireType,
          data: buf.slice(pos, pos + 8),
        });
        pos += 8;
        break;
      case PB_LEN: {
        const [len, p2] = pbReadVarint(buf, pos);
        pos = p2;
        if (pos + len > buf.length)
          throw new Error("truncated length-delimited");
        fields.push({
          field: fieldNum,
          wire: wireType,
          data: buf.slice(pos, pos + len),
        });
        pos += len;
        break;
      }
      case PB_32BIT:
        if (pos + 4 > buf.length) throw new Error("truncated 32-bit");
        fields.push({
          field: fieldNum,
          wire: wireType,
          data: buf.slice(pos, pos + 4),
        });
        pos += 4;
        break;
      default:
        throw new Error("unknown wire type " + wireType);
    }
  }
  return fields;
}

/**
 * Helper: get all fields with a given field number from decoded raw fields.
 */
function pbGetFields(fields, num) {
  return fields.filter((f) => f.field === num);
}

/**
 * Helper: get first field value as string (wire type 2 → UTF-8).
 */
function pbGetString(fields, num) {
  const f = fields.find((f) => f.field === num && f.wire === PB_LEN);
  return f ? new TextDecoder().decode(f.data) : null;
}

/**
 * Helper: get first field value as varint number.
 */
function pbGetVarint(fields, num) {
  const f = fields.find((f) => f.field === num && f.wire === PB_VARINT);
  return f ? f.data : null;
}

/**
 * Helper: get first field as embedded message (decode bytes as raw fields).
 */
function pbGetMessage(fields, num) {
  const f = fields.find((f) => f.field === num && f.wire === PB_LEN);
  if (!f) return null;
  try {
    return pbDecodeRaw(f.data);
  } catch (_) {
    return null;
  }
}

/**
 * Helper: get all repeated embedded messages for a field number.
 */
function pbGetRepeatedMessages(fields, num) {
  return fields
    .filter((f) => f.field === num && f.wire === PB_LEN)
    .map((f) => {
      try {
        return pbDecodeRaw(f.data);
      } catch (_) {
        return null;
      }
    })
    .filter(Boolean);
}

// ─── Encoding ─────────────────────────────────────────────────────────────────

/** Encode a tag byte sequence: (fieldNum << 3) | wireType */
function pbTag(fieldNum, wireType) {
  return pbWriteVarint(fieldNum * 8 + wireType);
}

/** Encode a varint field. */
function pbEncodeVarintField(fieldNum, value) {
  return concatBytes(pbTag(fieldNum, PB_VARINT), pbWriteVarint(value));
}

/** Encode a length-delimited field (string, bytes, or embedded message). */
function pbEncodeLenField(fieldNum, data) {
  const bytes =
    typeof data === "string" ? new TextEncoder().encode(data) : data;
  return concatBytes(
    pbTag(fieldNum, PB_LEN),
    pbWriteVarint(bytes.length),
    bytes,
  );
}

/** Encode a 32-bit fixed field. */
function pbEncodeFixed32Field(fieldNum, value) {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, value, true);
  return concatBytes(pbTag(fieldNum, PB_32BIT), buf);
}

/** Encode a 64-bit fixed field. */
function pbEncodeFixed64Field(fieldNum, lo, hi) {
  const buf = new Uint8Array(8);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, lo, true);
  dv.setUint32(4, hi || 0, true);
  return concatBytes(pbTag(fieldNum, PB_64BIT), buf);
}

// ─── Google RPC Status Decoder ────────────────────────────────────────────────
//
// Decodes binary protobuf error responses from Google APIs.
// Standard structure:
//
//   google.rpc.Status {
//     int32 code = 1;
//     string message = 2;
//     repeated google.protobuf.Any details = 3;
//   }
//   google.protobuf.Any {
//     string type_url = 1;
//     bytes value = 2;
//   }
//   google.rpc.BadRequest {
//     repeated FieldViolation field_violations = 1;
//   }
//   FieldViolation { string field = 1; string description = 2; }
//   google.rpc.ErrorInfo { string reason = 1; string domain = 2; map<string,string> metadata = 3; }
//

/**
 * Decode a google.rpc.Status binary protobuf into a JSON-like object
 * matching the JSON error format, so it can be fed directly into parseJsonErrors.
 *
 * @param {Uint8Array|ArrayBuffer} buf
 * @returns {{ error: { code, message, details: [] } }} — same shape as JSON API errors
 */
function pbDecodeRpcStatus(buf) {
  if (!(buf instanceof Uint8Array)) buf = new Uint8Array(buf);

  const result = { error: { code: 0, message: "", details: [] } };

  try {
    const status = pbDecodeRaw(buf);

    result.error.code = pbGetVarint(status, 1) || 0;
    result.error.message = pbGetString(status, 2) || "";

    // Field 3: repeated google.protobuf.Any details
    const anyMessages = pbGetRepeatedMessages(status, 3);

    for (const anyFields of anyMessages) {
      const typeUrl = pbGetString(anyFields, 1) || "";
      const valueField = anyFields.find(
        (f) => f.field === 2 && f.wire === PB_LEN,
      );
      if (!valueField) continue;

      let innerFields;
      try {
        innerFields = pbDecodeRaw(valueField.data);
      } catch (_) {
        continue;
      }

      // google.rpc.BadRequest — has field_violations
      if (typeUrl.includes("BadRequest")) {
        const detail = { "@type": typeUrl, fieldViolations: [] };

        // Field 1: repeated FieldViolation
        const violations = pbGetRepeatedMessages(innerFields, 1);
        for (const vFields of violations) {
          detail.fieldViolations.push({
            field: pbGetString(vFields, 1) || "",
            description: pbGetString(vFields, 2) || "",
          });
        }

        result.error.details.push(detail);
      }

      // google.rpc.ErrorInfo — has service/method metadata
      else if (typeUrl.includes("ErrorInfo")) {
        const detail = {
          "@type": typeUrl,
          reason: pbGetString(innerFields, 1) || "",
          domain: pbGetString(innerFields, 2) || "",
          metadata: {},
        };

        // Field 3: map<string,string> — encoded as repeated message { key(1), value(2) }
        const mapEntries = pbGetRepeatedMessages(innerFields, 3);
        for (const entry of mapEntries) {
          const key = pbGetString(entry, 1);
          const val = pbGetString(entry, 2);
          if (key) detail.metadata[key] = val || "";
        }

        result.error.details.push(detail);
      }

      // Other detail types — decode generically
      else {
        const detail = { "@type": typeUrl, _raw: innerFields };
        result.error.details.push(detail);
      }
    }
  } catch (e) {
    result.error._decodeError = e.message;
  }

  return result;
}

// ─── Probe Payload Encoding ──────────────────────────────────────────────────
//
// Binary equivalents of the JSON array payloads used by req2proto.
// For endpoints that only accept application/x-protobuf.

/**
 * Encode a binary protobuf probe payload with fields 1..size.
 *
 * @param {number} size - Number of fields (default 300)
 * @param {"int"|"str"} type - "str" → string fields, "int" → varint fields
 * @returns {Uint8Array}
 */
function pbEncodeProbePayload(size, type) {
  if (size == null) size = 300;
  const parts = [];
  for (let i = 1; i <= size; i++) {
    if (type === "int") {
      parts.push(pbEncodeVarintField(i, i));
    } else {
      parts.push(pbEncodeLenField(i, "x" + i));
    }
  }
  return concatBytes.apply(null, parts);
}

/**
 * Encode a nested binary protobuf probe payload.
 * Wraps the probe message inside embedded message fields at the given indices.
 *
 * @param {number[]} indices - Field number path for nesting
 * @param {number} size
 * @param {"int"|"str"} type
 * @returns {Uint8Array}
 */
function pbEncodeNestedPayload(indices, size, type) {
  let payload = pbEncodeProbePayload(size, type);
  for (let i = indices.length - 1; i >= 0; i--) {
    payload = pbEncodeLenField(indices[i], payload);
  }
  return payload;
}

// ─── Generic Protobuf Inspector ──────────────────────────────────────────────
//
// Decodes any binary protobuf into a human-readable tree.
// Useful for inspecting intercepted traffic with unknown schemas.

/**
 * Decode binary protobuf into a nested tree for display.
 * Length-delimited fields are heuristically decoded as either
 * embedded messages or UTF-8 strings.
 *
 * @param {Uint8Array|ArrayBuffer} buf
 * @param {number} maxDepth
 * @returns {object[]}
 */
function pbDecodeTree(buf, maxDepth, valueCallback) {
  if (maxDepth == null) maxDepth = 8;
  if (!(buf instanceof Uint8Array)) buf = new Uint8Array(buf);
  try {
    return pbDecodeRaw(buf).map(function (f) {
      return pbTreeNode(f, maxDepth, valueCallback);
    });
  } catch (e) {
    return [{ error: e.message }];
  }
}

function pbTreeNode(f, depth, valueCallback) {
  var node = { field: f.field, wire: f.wire };

  if (f.wire === PB_VARINT) {
    node.value = f.data;
    // ZigZag decode for signed interpretation (arithmetic to avoid 32-bit truncation)
    if (typeof f.data === "number") {
      node.asSigned = f.data % 2 === 0
        ? Math.floor(f.data / 2)
        : -Math.floor(f.data / 2) - 1;
    } else {
      node.asSigned = f.data; // string representation for very large values
    }
    if (valueCallback) valueCallback(node.value);
    return node;
  }

  if (f.wire === PB_32BIT) {
    var dv32 = new DataView(f.data.buffer, f.data.byteOffset, 4);
    node.asUint32 = dv32.getUint32(0, true);
    node.asInt32 = dv32.getInt32(0, true);
    node.asFloat = dv32.getFloat32(0, true);
    if (valueCallback) valueCallback(node.asUint32);
    return node;
  }

  if (f.wire === PB_64BIT) {
    var dv64 = new DataView(f.data.buffer, f.data.byteOffset, 8);
    node.asDouble = dv64.getFloat64(0, true);
    node.hex = bytesToHex(f.data);
    if (valueCallback) valueCallback(node.hex);
    return node;
  }

  if (f.wire === PB_LEN) {
    // Try as embedded message
    if (depth > 0 && f.data.length > 1) {
      try {
        var nested = pbDecodeRaw(f.data);
        if (nested.length > 0) {
          // Sanity checks to avoid misidentifying strings as messages:
          // 1. All field numbers must be reasonable (1-10000)
          // 2. Must consume all bytes (no trailing garbage)
          // 3. Reject single-field messages where the data is very short
          //    (likely a short string that happens to parse as valid protobuf)
          // 4. Field numbers should be somewhat sequential (no huge gaps)
          var valid = true;
          var maxField = 0;
          var minField = Infinity;
          for (var i = 0; i < nested.length; i++) {
            if (nested[i].field < 1 || nested[i].field > 10000) {
              valid = false;
              break;
            }
            if (nested[i].field > maxField) maxField = nested[i].field;
            if (nested[i].field < minField) minField = nested[i].field;
          }
          // Reject if the gap between min and max field is implausibly large
          // relative to the number of fields (e.g., fields [1, 9999] with only 2 entries)
          if (valid && nested.length > 0 && maxField - minField > nested.length * 100) {
            valid = false;
          }
          // For very short data (≤4 bytes), require at least 2 fields to confirm it's a message
          if (valid && f.data.length <= 4 && nested.length < 2) {
            valid = false;
          }
          if (valid) {
            node.message = nested.map(function (nf) {
              return pbTreeNode(nf, depth - 1, valueCallback);
            });
            return node;
          }
        }
      } catch (_) {}
    }
    // Try as packed repeated (proto3 default for repeated scalars)
    var packed = pbTryDecodePacked(f.data);
    if (packed !== null) {
      node.packed = packed;
      node.value = packed;
      if (valueCallback) {
        for (var pi = 0; pi < packed.length; pi++) valueCallback(packed[pi]);
      }
      return node;
    }
    // Try as UTF-8 string
    var str = tryUtf8(f.data);
    if (str !== null) {
      node.string = str;
      if (valueCallback) valueCallback(str);
    } else {
      node.hex = bytesToHex(f.data);
      if (valueCallback) valueCallback(node.hex);
    }
    node.length = f.data.length;
    return node;
  }

  return node;
}

function tryUtf8(bytes) {
  try {
    var str = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    // Accept printable ASCII + common unicode
    if (/^[\x20-\x7E\t\n\r\u00A0-\uFFFF]+$/.test(str)) return str;
  } catch (_) {}
  return null;
}

function bytesToHex(bytes) {
  var hex = "";
  for (var i = 0; i < bytes.length; i++) {
    hex += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
  }
  return hex;
}

/**
 * Try to decode a length-delimited field as packed repeated scalars (varints).
 * Returns an array of values if successful, null if not valid packed encoding.
 * Packed encoding is the default for repeated scalar fields in proto3.
 *
 * @param {Uint8Array} data - The raw bytes of the length-delimited field
 * @returns {number[]|null} Array of decoded varint values, or null
 */
function pbTryDecodePacked(data) {
  if (data.length === 0) return [];
  try {
    var values = [];
    var pos = 0;
    while (pos < data.length) {
      var result = pbReadVarint(data, pos);
      values.push(result[0]);
      pos = result[1];
    }
    // Must consume all bytes exactly — partial consumption means it's not packed
    if (pos === data.length && values.length > 1) return values;
  } catch (_) {}
  return null;
}

/**
 * Decode a JSPB (positional array) message into a tree structure.
 * @param {Array} arr - The JSPB array
 * @returns {Array<object>} Tree of nodes
 */
function jspbToTree(arr) {
  const nodes = [];
  if (!Array.isArray(arr)) {
    console.warn("[Protobuf] jspbToTree: input is not an array:", arr);
    return nodes;
  }

  arr.forEach((val, idx) => {
    if (val === null || val === undefined) return;

    const fieldNum = idx + 1;
    let node = {
      field: fieldNum,
      value: val,
      isJspb: true,
      wire: 2, // General purpose for JS values
    };

    if (Array.isArray(val)) {
      // Distinguish repeated scalars from nested messages:
      // - If array contains ONLY primitives (string/number/bool/null) → repeated scalar
      // - If array contains any sub-arrays → nested message (JSPB positional encoding)
      // - Empty array → keep as value (empty repeated or empty message)
      const hasSubArrays = val.some((item) => Array.isArray(item));
      const allPrimitives = val.length > 0 && val.every(
        (item) => item === null || item === undefined ||
          typeof item === "string" || typeof item === "number" || typeof item === "boolean"
      );

      if (allPrimitives && !hasSubArrays) {
        // Repeated scalar field — keep as array value, don't recurse
        node.wire = 2;
        node.isRepeatedScalar = true;
      } else {
        // Nested message (positional JSPB encoding)
        node.message = jspbToTree(val);
        node.wire = 2;
      }
    } else if (typeof val === "number") {
      node.wire = Number.isInteger(val) ? 0 : 5;
    } else if (typeof val === "boolean") {
      node.wire = 0;
    }

    nodes.push(node);
  });
  return nodes;
}
