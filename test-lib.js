// test-lib.js — Test suite for protobuf, discovery, stats, and chains libraries
// Run: node test-lib.js

var fs = require("fs");

// ─── Load Libraries ─────────────────────────────────────────────────────────

var protobufCode = fs.readFileSync(__dirname + "/lib/protobuf.js", "utf8");
new Function(protobufCode
  + "\nglobalThis.uint8ToBase64 = uint8ToBase64;"
  + "\nglobalThis.base64ToUint8 = base64ToUint8;"
  + "\nglobalThis.pbWriteVarint = pbWriteVarint;"
  + "\nglobalThis.pbReadVarint = pbReadVarint;"
  + "\nglobalThis.pbDecodeRaw = pbDecodeRaw;"
  + "\nglobalThis.pbGetFields = pbGetFields;"
  + "\nglobalThis.pbGetString = pbGetString;"
  + "\nglobalThis.pbGetVarint = pbGetVarint;"
  + "\nglobalThis.pbGetMessage = pbGetMessage;"
  + "\nglobalThis.pbEncodeVarintField = pbEncodeVarintField;"
  + "\nglobalThis.pbEncodeLenField = pbEncodeLenField;"
  + "\nglobalThis.pbEncodeFixed32Field = pbEncodeFixed32Field;"
  + "\nglobalThis.pbDecodeTree = pbDecodeTree;"
  + "\nglobalThis.pbTryDecodePacked = pbTryDecodePacked;"
  + "\nglobalThis.jspbToTree = jspbToTree;"
  + "\nglobalThis.concatBytes = concatBytes;"
  + "\nglobalThis.bytesToHex = bytesToHex;"
  + "\nglobalThis.pbEncodeFixed64Field = pbEncodeFixed64Field;"
  + "\nglobalThis.pbTag = pbTag;"
)();

var discoveryCode = fs.readFileSync(__dirname + "/lib/discovery.js", "utf8");
new Function(discoveryCode
  + "\nglobalThis.parseBatchExecuteRequest = parseBatchExecuteRequest;"
  + "\nglobalThis.parseBatchExecuteResponse = parseBatchExecuteResponse;"
  + "\nglobalThis.parseAsyncChunkedResponse = parseAsyncChunkedResponse;"
  + "\nglobalThis.isAsyncChunkedResponse = isAsyncChunkedResponse;"
  + "\nglobalThis.isBatchExecuteResponse = isBatchExecuteResponse;"
  + "\nglobalThis.parseGrpcWebFrames = parseGrpcWebFrames;"
  + "\nglobalThis.encodeGrpcWebFrame = encodeGrpcWebFrame;"
  + "\nglobalThis.isGrpcWeb = isGrpcWeb;"
  + "\nglobalThis.isGrpcWebText = isGrpcWebText;"
  + "\nglobalThis.parseSSE = parseSSE;"
  + "\nglobalThis.isSSE = isSSE;"
  + "\nglobalThis.parseNDJSON = parseNDJSON;"
  + "\nglobalThis.isNDJSON = isNDJSON;"
  + "\nglobalThis.parseGraphQLRequest = parseGraphQLRequest;"
  + "\nglobalThis.parseGraphQLResponse = parseGraphQLResponse;"
  + "\nglobalThis.isGraphQLUrl = isGraphQLUrl;"
  + "\nglobalThis.parseMultipartBatch = parseMultipartBatch;"
  + "\nglobalThis.isMultipartBatch = isMultipartBatch;"
  + "\nglobalThis.convertDiscoveryToOpenApi = convertDiscoveryToOpenApi;"
  + "\nglobalThis.convertOpenApiToDiscovery = convertOpenApiToDiscovery;"
  + "\nglobalThis.buildDiscoveryUrls = buildDiscoveryUrls;"
  + "\nglobalThis.findMethodById = findMethodById;"
  + "\nglobalThis.resolveDiscoverySchema = resolveDiscoverySchema;"
)();

var statsCode = fs.readFileSync(__dirname + "/lib/stats.js", "utf8");
new Function(statsCode
  + "\nglobalThis.createParamStats = createParamStats;"
  + "\nglobalThis.updateParamStats = updateParamStats;"
  + "\nglobalThis.analyzeRequired = analyzeRequired;"
  + "\nglobalThis.analyzeEnum = analyzeEnum;"
  + "\nglobalThis.analyzeDefault = analyzeDefault;"
  + "\nglobalThis.analyzeFormat = analyzeFormat;"
  + "\nglobalThis.analyzeRange = analyzeRange;"
  + "\nglobalThis.detectCorrelations = detectCorrelations;"
  + "\nglobalThis.mergeParamStats = mergeParamStats;"
)();

var chainsCode = fs.readFileSync(__dirname + "/lib/chains.js", "utf8");
new Function(chainsCode
  + "\nglobalThis.createValueIndex = createValueIndex;"
  + "\nglobalThis.indexResponseValues = indexResponseValues;"
  + "\nglobalThis.findChainLinks = findChainLinks;"
  + "\nglobalThis.flattenObjectValues = flattenObjectValues;"
  + "\nglobalThis.mergeChainLinks = mergeChainLinks;"
)();

// ─── Test Runner ────────────────────────────────────────────────────────────

var passed = 0, failed = 0, total = 0;

function test(name, fn) {
  total++;
  try {
    var ok = fn();
    if (ok) {
      passed++;
      console.log("  PASS: " + name);
    } else {
      failed++;
      console.log("  FAIL: " + name);
    }
  } catch (e) {
    failed++;
    console.log("  ERROR: " + name + " — " + e.message);
  }
}

// Helper to compare Uint8Arrays
function arraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROTOBUF TESTS
// ═══════════════════════════════════════════════════════════════════════════════

console.log("\n=== Protobuf: Varint Encode/Decode ===\n");

test("varint roundtrip — small value (1)", function() {
  var encoded = pbWriteVarint(1);
  var result = pbReadVarint(encoded, 0);
  return result[0] === 1 && result[1] === encoded.length;
});

test("varint roundtrip — zero", function() {
  var encoded = pbWriteVarint(0);
  var result = pbReadVarint(encoded, 0);
  return result[0] === 0 && result[1] === 1;
});

test("varint roundtrip — medium value (300)", function() {
  var encoded = pbWriteVarint(300);
  var result = pbReadVarint(encoded, 0);
  return result[0] === 300 && result[1] === encoded.length;
});

test("varint roundtrip — large value (123456789)", function() {
  var encoded = pbWriteVarint(123456789);
  var result = pbReadVarint(encoded, 0);
  return result[0] === 123456789;
});

test("varint roundtrip — max safe 32-bit (2^31-1)", function() {
  var val = Math.pow(2, 31) - 1;
  var encoded = pbWriteVarint(val);
  var result = pbReadVarint(encoded, 0);
  return result[0] === val;
});

test("varint encoding — 1 is single byte 0x01", function() {
  var encoded = pbWriteVarint(1);
  return encoded.length === 1 && encoded[0] === 0x01;
});

test("varint encoding — 128 requires 2 bytes", function() {
  var encoded = pbWriteVarint(128);
  return encoded.length === 2 && encoded[0] === 0x80 && encoded[1] === 0x01;
});

console.log("\n=== Protobuf: Base64 Roundtrip ===\n");

test("base64 roundtrip — simple bytes", function() {
  var original = new Uint8Array([1, 2, 3, 4, 5]);
  var b64 = uint8ToBase64(original);
  var decoded = base64ToUint8(b64);
  return arraysEqual(original, decoded);
});

test("base64 roundtrip — empty array", function() {
  var original = new Uint8Array([]);
  var b64 = uint8ToBase64(original);
  var decoded = base64ToUint8(b64);
  return arraysEqual(original, decoded);
});

test("base64 roundtrip — all byte values 0-255", function() {
  var original = new Uint8Array(256);
  for (var i = 0; i < 256; i++) original[i] = i;
  var b64 = uint8ToBase64(original);
  var decoded = base64ToUint8(b64);
  return arraysEqual(original, decoded);
});

test("base64 roundtrip — large array (10000 bytes)", function() {
  var original = new Uint8Array(10000);
  for (var i = 0; i < 10000; i++) original[i] = i & 0xff;
  var b64 = uint8ToBase64(original);
  var decoded = base64ToUint8(b64);
  return arraysEqual(original, decoded);
});

console.log("\n=== Protobuf: Raw Decode ===\n");

test("pbDecodeRaw — varint field", function() {
  var msg = pbEncodeVarintField(1, 42);
  var fields = pbDecodeRaw(msg);
  return fields.length === 1 && fields[0].field === 1 && fields[0].wire === 0 && fields[0].data === 42;
});

test("pbDecodeRaw — len-delimited string field", function() {
  var msg = pbEncodeLenField(2, "hello");
  var fields = pbDecodeRaw(msg);
  return fields.length === 1 && fields[0].field === 2 && fields[0].wire === 2 &&
    new TextDecoder().decode(fields[0].data) === "hello";
});

test("pbDecodeRaw — fixed32 field", function() {
  var msg = pbEncodeFixed32Field(3, 0x12345678);
  var fields = pbDecodeRaw(msg);
  return fields.length === 1 && fields[0].field === 3 && fields[0].wire === 5 &&
    fields[0].data.length === 4;
});

test("pbDecodeRaw — fixed64 field", function() {
  var msg = pbEncodeFixed64Field(4, 0x12345678, 0x9ABCDEF0);
  var fields = pbDecodeRaw(msg);
  return fields.length === 1 && fields[0].field === 4 && fields[0].wire === 1 &&
    fields[0].data.length === 8;
});

test("pbDecodeRaw — multiple fields", function() {
  var msg = concatBytes(
    pbEncodeVarintField(1, 10),
    pbEncodeLenField(2, "world"),
    pbEncodeFixed32Field(3, 99)
  );
  var fields = pbDecodeRaw(msg);
  return fields.length === 3 &&
    fields[0].field === 1 && fields[0].data === 10 &&
    fields[1].field === 2 && new TextDecoder().decode(fields[1].data) === "world" &&
    fields[2].field === 3;
});

console.log("\n=== Protobuf: Field Accessors ===\n");

test("pbGetFields — returns matching fields", function() {
  var msg = concatBytes(
    pbEncodeVarintField(1, 10),
    pbEncodeLenField(2, "a"),
    pbEncodeVarintField(1, 20)
  );
  var fields = pbDecodeRaw(msg);
  var f1s = pbGetFields(fields, 1);
  return f1s.length === 2 && f1s[0].data === 10 && f1s[1].data === 20;
});

test("pbGetString — extracts string from field", function() {
  var msg = concatBytes(
    pbEncodeVarintField(1, 5),
    pbEncodeLenField(2, "test_string")
  );
  var fields = pbDecodeRaw(msg);
  return pbGetString(fields, 2) === "test_string";
});

test("pbGetString — returns null for missing field", function() {
  var msg = pbEncodeVarintField(1, 5);
  var fields = pbDecodeRaw(msg);
  return pbGetString(fields, 99) === null;
});

test("pbGetVarint — extracts varint value", function() {
  var msg = concatBytes(
    pbEncodeVarintField(1, 42),
    pbEncodeLenField(2, "ignored")
  );
  var fields = pbDecodeRaw(msg);
  return pbGetVarint(fields, 1) === 42;
});

test("pbGetVarint — returns null for missing field", function() {
  var msg = pbEncodeLenField(2, "only_string");
  var fields = pbDecodeRaw(msg);
  return pbGetVarint(fields, 1) === null;
});

test("pbGetMessage — decodes embedded message", function() {
  var inner = concatBytes(
    pbEncodeVarintField(1, 100),
    pbEncodeLenField(2, "nested")
  );
  var msg = pbEncodeLenField(3, inner);
  var fields = pbDecodeRaw(msg);
  var nested = pbGetMessage(fields, 3);
  return nested !== null && nested.length === 2 &&
    nested[0].data === 100 && pbGetString(nested, 2) === "nested";
});

console.log("\n=== Protobuf: Tree Decode ===\n");

test("pbDecodeTree — simple message with varint and string", function() {
  // Use a string with multi-byte UTF-8 chars to prevent packed varint misdetection
  var msg = concatBytes(
    pbEncodeVarintField(1, 7),
    pbEncodeLenField(2, "caf\u00E9")
  );
  var tree = pbDecodeTree(msg);
  return tree.length === 2 &&
    tree[0].field === 1 && tree[0].value === 7 &&
    tree[1].field === 2 && tree[1].string === "caf\u00E9";
});

test("pbDecodeTree — nested message decoded as tree", function() {
  // The outer len-delimited field containing a valid protobuf message
  // should be decoded as a nested message (not packed or string)
  var inner = concatBytes(
    pbEncodeVarintField(1, 5),
    pbEncodeVarintField(2, 10)
  );
  var msg = pbEncodeLenField(1, inner);
  var tree = pbDecodeTree(msg);
  return tree.length === 1 && tree[0].field === 1 &&
    Array.isArray(tree[0].message) &&
    tree[0].message.length === 2 &&
    tree[0].message[0].value === 5 &&
    tree[0].message[1].value === 10;
});

test("pbDecodeTree — fixed32 has asUint32 and asFloat", function() {
  var msg = pbEncodeFixed32Field(1, 42);
  var tree = pbDecodeTree(msg);
  return tree.length === 1 && tree[0].field === 1 &&
    tree[0].asUint32 === 42 && typeof tree[0].asFloat === "number";
});

test("pbDecodeTree — fixed64 has asDouble and hex", function() {
  var msg = pbEncodeFixed64Field(1, 0, 0);
  var tree = pbDecodeTree(msg);
  return tree.length === 1 && tree[0].field === 1 &&
    typeof tree[0].asDouble === "number" && typeof tree[0].hex === "string";
});

console.log("\n=== Protobuf: JSPB Decode ===\n");

test("jspbToTree — skips null/undefined entries", function() {
  var tree = jspbToTree([null, "hello", undefined, 42]);
  return tree.length === 2 &&
    tree[0].field === 2 && tree[0].value === "hello" &&
    tree[1].field === 4 && tree[1].value === 42;
});

test("jspbToTree — strings are wire=2, integers are wire=0", function() {
  var tree = jspbToTree(["abc", 7]);
  return tree.length === 2 &&
    tree[0].wire === 2 && tree[0].value === "abc" &&
    tree[1].wire === 0 && tree[1].value === 7;
});

test("jspbToTree — nested arrays produce message children", function() {
  // Array must contain sub-arrays to be treated as nested message (not repeated scalar)
  var tree = jspbToTree([["inner_str", [1, 2]]]);
  return tree.length === 1 && tree[0].field === 1 &&
    Array.isArray(tree[0].message) && tree[0].message.length === 2 &&
    tree[0].message[0].value === "inner_str";
});

test("jspbToTree — boolean values are wire=0", function() {
  var tree = jspbToTree([true, false]);
  return tree.length === 2 &&
    tree[0].wire === 0 && tree[0].value === true &&
    tree[1].wire === 0 && tree[1].value === false;
});

test("jspbToTree — plain objects expand as named fields", function() {
  var tree = jspbToTree([{key: "val"}]);
  return tree.length === 1 && tree[0].field === 1 &&
    Array.isArray(tree[0].message) && tree[0].message.length === 1 &&
    tree[0].message[0].field === "key" && tree[0].message[0].string === "val";
});

test("jspbToTree — repeated scalars stay as array value", function() {
  var tree = jspbToTree([["a", "b", "c"]]);
  return tree.length === 1 && tree[0].field === 1 &&
    tree[0].isRepeatedScalar === true &&
    Array.isArray(tree[0].value) && tree[0].value.length === 3;
});

test("jspbToTree — non-array input returns empty nodes", function() {
  var tree = jspbToTree("not_an_array");
  return Array.isArray(tree) && tree.length === 0;
});

test("jspbToTree — floating point is wire=5", function() {
  var tree = jspbToTree([3.14]);
  return tree.length === 1 && tree[0].wire === 5;
});

console.log("\n=== Protobuf: Packed Decode ===\n");

test("pbTryDecodePacked — valid packed varints", function() {
  var data = concatBytes(pbWriteVarint(10), pbWriteVarint(20), pbWriteVarint(30));
  var result = pbTryDecodePacked(data);
  return result !== null && result.length === 3 &&
    result[0] === 10 && result[1] === 20 && result[2] === 30;
});

test("pbTryDecodePacked — single varint returns null (needs 2+)", function() {
  var data = pbWriteVarint(42);
  var result = pbTryDecodePacked(data);
  return result === null;
});

test("pbTryDecodePacked — empty data returns empty array", function() {
  var result = pbTryDecodePacked(new Uint8Array(0));
  return result !== null && result.length === 0;
});

test("pbTryDecodePacked — invalid bytes (truncated varint) returns null", function() {
  var data = new Uint8Array([0x80]); // continuation bit set but no more bytes... actually pbReadVarint throws
  var result = pbTryDecodePacked(data);
  return result === null;
});

console.log("\n=== Protobuf: Byte Helpers ===\n");

test("concatBytes — concatenate two arrays", function() {
  var a = new Uint8Array([1, 2, 3]);
  var b = new Uint8Array([4, 5]);
  var result = concatBytes(a, b);
  return result.length === 5 && arraysEqual(result, new Uint8Array([1, 2, 3, 4, 5]));
});

test("concatBytes — concatenate three arrays", function() {
  var a = new Uint8Array([1]);
  var b = new Uint8Array([2]);
  var c = new Uint8Array([3]);
  var result = concatBytes(a, b, c);
  return result.length === 3 && arraysEqual(result, new Uint8Array([1, 2, 3]));
});

test("concatBytes — empty arrays", function() {
  var a = new Uint8Array([]);
  var b = new Uint8Array([1, 2]);
  var result = concatBytes(a, b);
  return result.length === 2 && arraysEqual(result, new Uint8Array([1, 2]));
});

test("bytesToHex — standard encoding", function() {
  return bytesToHex(new Uint8Array([0, 1, 15, 16, 255])) === "00010f10ff";
});

test("bytesToHex — empty array", function() {
  return bytesToHex(new Uint8Array([])) === "";
});

console.log("\n=== Protobuf: gRPC-Web Frame Encode/Decode ===\n");

test("gRPC-Web frame roundtrip", function() {
  var payload = concatBytes(
    pbEncodeVarintField(1, 42),
    pbEncodeLenField(2, "grpc_test")
  );
  var frame = encodeGrpcWebFrame(payload);
  var parsed = parseGrpcWebFrames(frame);
  return parsed !== null && parsed.frames.length === 1 &&
    parsed.frames[0].type === "data" &&
    arraysEqual(parsed.frames[0].data, payload);
});

test("gRPC-Web frame — flag byte is 0x00 (uncompressed)", function() {
  var payload = new Uint8Array([1, 2, 3]);
  var frame = encodeGrpcWebFrame(payload);
  return frame[0] === 0x00;
});

test("gRPC-Web frame — length is big-endian 4 bytes", function() {
  var payload = new Uint8Array(256);
  var frame = encodeGrpcWebFrame(payload);
  var len = (frame[1] << 24) | (frame[2] << 16) | (frame[3] << 8) | frame[4];
  return len === 256;
});

test("gRPC-Web frame — trailer frame (flag 0x80)", function() {
  var trailerText = "grpc-status: 0\r\ngrpc-message: OK\r\n";
  var trailerBytes = new TextEncoder().encode(trailerText);
  var frame = new Uint8Array(5 + trailerBytes.length);
  frame[0] = 0x80; // trailer flag
  frame[1] = (trailerBytes.length >> 24) & 0xff;
  frame[2] = (trailerBytes.length >> 16) & 0xff;
  frame[3] = (trailerBytes.length >> 8) & 0xff;
  frame[4] = trailerBytes.length & 0xff;
  frame.set(trailerBytes, 5);
  var parsed = parseGrpcWebFrames(frame);
  return parsed !== null && parsed.frames.length === 1 &&
    parsed.frames[0].type === "trailers" &&
    parsed.trailers["grpc-status"] === "0";
});

console.log("\n=== Protobuf: Tag Encoding ===\n");

test("pbTag — field 1 varint = 0x08", function() {
  var tag = pbTag(1, 0);
  return tag.length === 1 && tag[0] === 0x08;
});

test("pbTag — field 1 len-delimited = 0x0A", function() {
  var tag = pbTag(1, 2);
  return tag.length === 1 && tag[0] === 0x0A;
});

test("pbTag — field 2 varint = 0x10", function() {
  var tag = pbTag(2, 0);
  return tag.length === 1 && tag[0] === 0x10;
});

// ═══════════════════════════════════════════════════════════════════════════════
// DISCOVERY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

console.log("\n=== Discovery: BatchExecute Request ===\n");

test("parseBatchExecuteRequest — valid f.req", function() {
  var body = "f.req=" + encodeURIComponent(JSON.stringify([
    [["rpc1", JSON.stringify([1, "test"]), null, "generic"]]
  ]));
  var result = parseBatchExecuteRequest(body);
  return result !== null && result.length === 1 &&
    result[0].rpcId === "rpc1" &&
    Array.isArray(result[0].data) && result[0].data[0] === 1;
});

test("parseBatchExecuteRequest — multiple RPCs", function() {
  var body = "f.req=" + encodeURIComponent(JSON.stringify([
    [
      ["GetUser", JSON.stringify({id: 123}), null, "generic"],
      ["ListItems", JSON.stringify([]), null, "generic"]
    ]
  ]));
  var result = parseBatchExecuteRequest(body);
  return result !== null && result.length === 2 &&
    result[0].rpcId === "GetUser" && result[1].rpcId === "ListItems";
});

test("parseBatchExecuteRequest — returns null for missing f.req", function() {
  var result = parseBatchExecuteRequest("other_param=value");
  return result === null;
});

test("parseBatchExecuteRequest — returns null for invalid JSON", function() {
  var result = parseBatchExecuteRequest("f.req=not_valid_json");
  return result === null;
});

console.log("\n=== Discovery: BatchExecute Response ===\n");

test("parseBatchExecuteResponse — XSSI prefix + wrb.fr entries", function() {
  var entry = JSON.stringify([["wrb.fr", "rpc1", JSON.stringify([1, 2, 3]), null]]);
  var body = ")]}'\n" + entry.length + "\n" + entry;
  var result = parseBatchExecuteResponse(body);
  return result !== null && result.length === 1 &&
    result[0].rpcId === "rpc1" &&
    Array.isArray(result[0].data) && result[0].data[0] === 1;
});

test("parseBatchExecuteResponse — error entry with code", function() {
  var entry = JSON.stringify([["wrb.fr", "rpc2", null, 5, null, null, JSON.stringify({msg: "fail"})]]);
  var body = ")]}'\n" + entry.length + "\n" + entry;
  var result = parseBatchExecuteResponse(body);
  return result !== null && result.length === 1 &&
    result[0].rpcId === "rpc2" &&
    result[0].error !== undefined && result[0].error.code === 5;
});

test("parseBatchExecuteResponse — returns empty array for no wrb.fr", function() {
  var body = ")]}'\n5\n[1,2]";
  var result = parseBatchExecuteResponse(body);
  return result !== null && result.length === 0;
});

console.log("\n=== Discovery: Async Chunked Response ===\n");

test("parseAsyncChunkedResponse — hex-length-prefixed JSPB chunk", function() {
  var payload = JSON.stringify([1, "test", null]);
  var hex = payload.length.toString(16);
  var body = ")]}'\n" + hex + ";" + payload;
  var result = parseAsyncChunkedResponse(body);
  return result !== null && result.length === 1 &&
    result[0].type === "jspb" && Array.isArray(result[0].data) &&
    result[0].data[1] === "test";
});

test("parseAsyncChunkedResponse — multiple chunks", function() {
  var p1 = JSON.stringify([1]);
  var p2 = JSON.stringify([2]);
  var body = ")]}'\n" + p1.length.toString(16) + ";" + p1 + "\n" +
    p2.length.toString(16) + ";" + p2;
  var result = parseAsyncChunkedResponse(body);
  return result !== null && result.length === 2;
});

test("parseAsyncChunkedResponse — HTML chunk classified as html", function() {
  var payload = "<div>some html</div>";
  var hex = payload.length.toString(16);
  var body = ")]}'\n" + hex + ";" + payload;
  var result = parseAsyncChunkedResponse(body);
  return result !== null && result.length === 1 && result[0].type === "html";
});

test("isAsyncChunkedResponse — true for valid format", function() {
  return isAsyncChunkedResponse(")]}'\n1a;[1,2,3]") === true;
});

test("isAsyncChunkedResponse — false for plain JSON", function() {
  return isAsyncChunkedResponse('{"key": "value"}') === false;
});

test("isAsyncChunkedResponse — false for null", function() {
  return isAsyncChunkedResponse(null) === false;
});

console.log("\n=== Discovery: BatchExecute Detection ===\n");

test("isBatchExecuteResponse — true for valid format", function() {
  var entry = JSON.stringify([["wrb.fr", "rpc1", null, null]]);
  var body = ")]}'\n" + entry.length + "\n" + entry;
  return isBatchExecuteResponse(body) === true;
});

test("isBatchExecuteResponse — false for plain JSON", function() {
  return isBatchExecuteResponse('{"data": [1,2,3]}') === false;
});

test("isBatchExecuteResponse — false for null/empty", function() {
  return isBatchExecuteResponse(null) === false && isBatchExecuteResponse("") === false;
});

console.log("\n=== Discovery: SSE Parser ===\n");

test("parseSSE — single event with data", function() {
  var text = "data: hello world\n\n";
  var result = parseSSE(text);
  return result !== null && result.length === 1 &&
    result[0].event === "message" && result[0].data === "hello world";
});

test("parseSSE — multiple events", function() {
  var text = "data: first\n\ndata: second\n\n";
  var result = parseSSE(text);
  return result !== null && result.length === 2 &&
    result[0].data === "first" && result[1].data === "second";
});

test("parseSSE — event with type and id", function() {
  var text = "event: update\nid: 42\ndata: {\"key\":\"val\"}\n\n";
  var result = parseSSE(text);
  return result !== null && result.length === 1 &&
    result[0].event === "update" && result[0].id === "42" &&
    typeof result[0].data === "object" && result[0].data.key === "val";
});

test("parseSSE — comments are skipped", function() {
  var text = ": this is a comment\ndata: real_data\n\n";
  var result = parseSSE(text);
  return result !== null && result.length === 1 &&
    result[0].data === "real_data";
});

test("parseSSE — multi-line data", function() {
  var text = "data: line1\ndata: line2\n\n";
  var result = parseSSE(text);
  return result !== null && result.length === 1 &&
    result[0].raw === "line1\nline2";
});

test("parseSSE — returns null for empty input", function() {
  return parseSSE("") === null;
});

console.log("\n=== Discovery: NDJSON Parser ===\n");

test("parseNDJSON — valid NDJSON with 2 lines", function() {
  var text = '{"a":1}\n{"b":2}\n';
  var result = parseNDJSON(text);
  return result !== null && result.length === 2 &&
    result[0].a === 1 && result[1].b === 2;
});

test("parseNDJSON — returns null for single line", function() {
  var result = parseNDJSON('{"a":1}\n');
  return result === null;
});

test("parseNDJSON — returns null for non-JSON lines", function() {
  var result = parseNDJSON("not json\nalso not json\n");
  return result === null;
});

test("parseNDJSON — handles trailing newlines", function() {
  var text = '{"x":1}\n{"y":2}\n\n\n';
  var result = parseNDJSON(text);
  return result !== null && result.length === 2;
});

console.log("\n=== Discovery: GraphQL ===\n");

test("parseGraphQLRequest — valid query with variables", function() {
  var body = JSON.stringify({
    query: "query GetUser($id: ID!) { user(id: $id) { name } }",
    variables: { id: "123" },
    operationName: "GetUser"
  });
  var result = parseGraphQLRequest(body);
  return result !== null && result.query.includes("GetUser") &&
    result.variables.id === "123" && result.operationName === "GetUser";
});

test("parseGraphQLRequest — returns null for non-GraphQL JSON", function() {
  var result = parseGraphQLRequest(JSON.stringify({ data: "hello" }));
  return result === null;
});

test("parseGraphQLRequest — returns null for invalid JSON", function() {
  var result = parseGraphQLRequest("not json");
  return result === null;
});

test("parseGraphQLResponse — valid response with data", function() {
  var body = JSON.stringify({ data: { user: { name: "Alice" } } });
  var result = parseGraphQLResponse(body);
  return result !== null && result.data.user.name === "Alice" &&
    result.errors === null && result.extensions === null;
});

test("parseGraphQLResponse — response with errors", function() {
  var body = JSON.stringify({
    data: null,
    errors: [{ message: "Not found" }]
  });
  var result = parseGraphQLResponse(body);
  return result !== null && result.data === null &&
    result.errors.length === 1 && result.errors[0].message === "Not found";
});

test("parseGraphQLResponse — response with extensions", function() {
  var body = JSON.stringify({
    data: {},
    extensions: { tracing: { duration: 100 } }
  });
  var result = parseGraphQLResponse(body);
  return result !== null && result.extensions.tracing.duration === 100;
});

test("parseGraphQLResponse — returns null for non-GraphQL", function() {
  var result = parseGraphQLResponse(JSON.stringify({ items: [] }));
  return result === null;
});

console.log("\n=== Discovery: Content Type Detection ===\n");

test("isGrpcWeb — true for application/grpc-web", function() {
  return isGrpcWeb("application/grpc-web") === true;
});

test("isGrpcWeb — true for application/grpc-web+proto", function() {
  return isGrpcWeb("application/grpc-web+proto") === true;
});

test("isGrpcWeb — false for application/json", function() {
  return isGrpcWeb("application/json") === false;
});

test("isGrpcWeb — false for null", function() {
  return isGrpcWeb(null) === false;
});

test("isGrpcWebText — true for grpc-web-text", function() {
  return isGrpcWebText("application/grpc-web-text") === true;
});

test("isGrpcWebText — false for grpc-web (binary)", function() {
  return isGrpcWebText("application/grpc-web") === false;
});

test("isSSE — true for text/event-stream", function() {
  return isSSE("text/event-stream") === true;
});

test("isSSE — false for text/plain", function() {
  return isSSE("text/plain") === false;
});

test("isNDJSON — true for application/x-ndjson", function() {
  return isNDJSON("application/x-ndjson") === true;
});

test("isNDJSON — true for application/jsonl", function() {
  return isNDJSON("application/jsonl") === true;
});

test("isNDJSON — false for application/json", function() {
  return isNDJSON("application/json") === false;
});

test("isGraphQLUrl — true for /graphql path", function() {
  return isGraphQLUrl("https://api.example.com/graphql") === true;
});

test("isGraphQLUrl — true for /api/graphql", function() {
  return isGraphQLUrl("https://example.com/api/graphql") === true;
});

test("isGraphQLUrl — false for /api/rest", function() {
  return isGraphQLUrl("https://example.com/api/rest") === false;
});

test("isMultipartBatch — true for multipart/mixed with boundary", function() {
  return isMultipartBatch("multipart/mixed; boundary=batch123") === true;
});

test("isMultipartBatch — false for multipart/mixed without boundary", function() {
  return isMultipartBatch("multipart/mixed") === false;
});

test("isMultipartBatch — false for application/json", function() {
  return isMultipartBatch("application/json") === false;
});

console.log("\n=== Discovery: buildDiscoveryUrls ===\n");

test("buildDiscoveryUrls — returns array with generic paths", function() {
  var urls = buildDiscoveryUrls("api.example.com", null);
  return Array.isArray(urls) && urls.length > 0 &&
    urls.some(function(u) { return u.url.includes("openapi.json"); }) &&
    urls.some(function(u) { return u.url.includes("swagger.json"); });
});

test("buildDiscoveryUrls — includes Google-specific patterns for googleapis.com", function() {
  var urls = buildDiscoveryUrls("people.googleapis.com", null);
  return urls.some(function(u) { return u.url.includes("$discovery/rest"); });
});

test("buildDiscoveryUrls — includes API key variants when key provided", function() {
  var urls = buildDiscoveryUrls("people.googleapis.com", "AIzaTest123");
  return urls.some(function(u) { return u.url.includes("key=AIzaTest123"); }) &&
    urls.some(function(u) { return u.headers["X-Goog-Api-Key"] === "AIzaTest123"; });
});

test("buildDiscoveryUrls — includes POST override", function() {
  var urls = buildDiscoveryUrls("people.googleapis.com", null);
  return urls.some(function(u) {
    return u.method === "POST" && u.headers["X-Http-Method-Override"] === "GET";
  });
});

test("buildDiscoveryUrls — clients6.google.com generates googleapis.com variant", function() {
  var urls = buildDiscoveryUrls("people-pa.clients6.google.com", null);
  return urls.some(function(u) {
    return u.url.includes("people-pa.googleapis.com");
  });
});

console.log("\n=== Discovery: OpenAPI Conversion ===\n");

// Build a minimal discovery doc for testing
var minimalDiscoveryDoc = {
  kind: "discovery#restDescription",
  name: "testapi",
  version: "v1",
  title: "Test API",
  description: "A test API",
  rootUrl: "https://test.googleapis.com/",
  servicePath: "",
  baseUrl: "https://test.googleapis.com/",
  resources: {
    users: {
      methods: {
        get: {
          id: "testapi.users.get",
          path: "v1/users/{userId}",
          httpMethod: "GET",
          description: "Get a user",
          parameters: {
            userId: { type: "string", location: "path", required: true, description: "User ID" }
          },
          response: { $ref: "User" }
        },
        create: {
          id: "testapi.users.create",
          path: "v1/users",
          httpMethod: "POST",
          description: "Create a user",
          request: { $ref: "User" },
          response: { $ref: "User" }
        }
      }
    }
  },
  schemas: {
    User: {
      id: "User",
      type: "object",
      properties: {
        name: { type: "string", description: "User name" },
        age: { type: "integer", format: "int32", description: "User age" },
        email: { type: "string", description: "Email address" }
      }
    }
  }
};

test("convertDiscoveryToOpenApi — produces valid OpenAPI 3.0.3 structure", function() {
  var spec = convertDiscoveryToOpenApi(minimalDiscoveryDoc, "test.googleapis.com");
  return spec.openapi === "3.0.3" &&
    spec.info.title === "Test API" &&
    spec.info.version === "v1" &&
    spec.servers.length === 1 &&
    spec.servers[0].url === "https://test.googleapis.com/";
});

test("convertDiscoveryToOpenApi — converts schemas", function() {
  var spec = convertDiscoveryToOpenApi(minimalDiscoveryDoc, "test.googleapis.com");
  return spec.components.schemas.User !== undefined &&
    spec.components.schemas.User.type === "object" &&
    spec.components.schemas.User.properties.name !== undefined &&
    spec.components.schemas.User.properties.name.type === "string";
});

test("convertDiscoveryToOpenApi — converts methods to paths", function() {
  var spec = convertDiscoveryToOpenApi(minimalDiscoveryDoc, "test.googleapis.com");
  return spec.paths["/v1/users/{userId}"] !== undefined &&
    spec.paths["/v1/users/{userId}"].get !== undefined &&
    spec.paths["/v1/users/{userId}"].get.operationId === "testapi.users.get";
});

test("convertDiscoveryToOpenApi — includes parameters", function() {
  var spec = convertDiscoveryToOpenApi(minimalDiscoveryDoc, "test.googleapis.com");
  var getOp = spec.paths["/v1/users/{userId}"].get;
  return getOp.parameters.length === 1 &&
    getOp.parameters[0].name === "userId" &&
    getOp.parameters[0].in === "path" &&
    getOp.parameters[0].required === true;
});

test("convertDiscoveryToOpenApi — includes request body ref", function() {
  var spec = convertDiscoveryToOpenApi(minimalDiscoveryDoc, "test.googleapis.com");
  var postOp = spec.paths["/v1/users"].post;
  return postOp.requestBody !== undefined &&
    postOp.requestBody.content["application/json"].schema.$ref === "#/components/schemas/User";
});

test("convertDiscoveryToOpenApi — includes response ref", function() {
  var spec = convertDiscoveryToOpenApi(minimalDiscoveryDoc, "test.googleapis.com");
  var getOp = spec.paths["/v1/users/{userId}"].get;
  return getOp.responses["200"].content["application/json"].schema.$ref === "#/components/schemas/User";
});

console.log("\n=== Discovery: OpenAPI → Discovery Conversion ===\n");

test("convertOpenApiToDiscovery — converts OpenAPI spec to discovery format", function() {
  var openapi = {
    openapi: "3.0.3",
    info: { title: "Pet API", version: "v1", description: "Pets" },
    servers: [{ url: "https://api.pets.com/v1" }],
    paths: {
      "/pets": {
        get: {
          operationId: "listPets",
          tags: ["pets"],
          parameters: [
            { name: "limit", in: "query", required: false, schema: { type: "integer" }, description: "Max items" }
          ],
          responses: {
            "200": {
              content: { "application/json": { schema: { $ref: "#/components/schemas/PetList" } } }
            }
          }
        }
      }
    },
    components: {
      schemas: {
        PetList: {
          type: "object",
          properties: {
            items: { type: "array", items: { $ref: "#/components/schemas/Pet" } }
          }
        },
        Pet: {
          type: "object",
          properties: {
            name: { type: "string" },
            breed: { type: "string" }
          }
        }
      }
    }
  };
  var doc = convertOpenApiToDiscovery(openapi, "https://api.pets.com/v1/openapi.json");
  return doc.kind === "discovery#restDescription" &&
    doc.resources.pets !== undefined &&
    doc.resources.pets.methods.listPets !== undefined &&
    doc.schemas.PetList !== undefined &&
    doc.schemas.Pet !== undefined;
});

test("convertOpenApiToDiscovery — resolves server URL", function() {
  var openapi = {
    openapi: "3.0.3",
    info: { title: "API", version: "v1" },
    servers: [{ url: "https://custom.host.com/base" }],
    paths: {}
  };
  var doc = convertOpenApiToDiscovery(openapi, "https://source.com/spec.json");
  return doc.rootUrl === "https://custom.host.com/base/";
});

test("convertOpenApiToDiscovery — Swagger 2.0 host/basePath", function() {
  var swagger = {
    swagger: "2.0",
    info: { title: "Legacy API", version: "v1" },
    host: "legacy.api.com",
    basePath: "/v1",
    schemes: ["https"],
    paths: {}
  };
  var doc = convertOpenApiToDiscovery(swagger, "https://legacy.api.com/swagger.json");
  return doc.rootUrl === "https://legacy.api.com/v1/";
});

console.log("\n=== Discovery: OpenAPI Roundtrip ===\n");

test("OpenAPI roundtrip — discovery -> openapi -> discovery preserves method", function() {
  var openapi = convertDiscoveryToOpenApi(minimalDiscoveryDoc, "test.googleapis.com");
  var roundtripped = convertOpenApiToDiscovery(openapi, "https://test.googleapis.com/openapi.json");
  // Should have a resource with a method that has the same operation ID
  var foundGet = false;
  for (var rName in roundtripped.resources) {
    var methods = roundtripped.resources[rName].methods;
    for (var mName in methods) {
      if (methods[mName].id === "testapi.users.get") foundGet = true;
    }
  }
  return foundGet;
});

console.log("\n=== Discovery: findMethodById ===\n");

test("findMethodById — finds existing method", function() {
  var result = findMethodById(minimalDiscoveryDoc, "testapi.users.get");
  return result !== null && result.method.id === "testapi.users.get" &&
    result.method.httpMethod === "GET";
});

test("findMethodById — returns null for non-existent method", function() {
  var result = findMethodById(minimalDiscoveryDoc, "nonexistent.method");
  return result === null;
});

test("findMethodById — returns null for null doc", function() {
  var result = findMethodById(null, "some.method");
  return result === null;
});

console.log("\n=== Discovery: resolveDiscoverySchema ===\n");

test("resolveDiscoverySchema — resolves simple schema", function() {
  var fields = resolveDiscoverySchema(minimalDiscoveryDoc, "User");
  return fields.length === 3 &&
    fields.some(function(f) { return f.name === "name" && f.type === "string"; }) &&
    fields.some(function(f) { return f.name === "age" && f.type === "int32"; }) &&
    fields.some(function(f) { return f.name === "email" && f.type === "string"; });
});

test("resolveDiscoverySchema — returns empty array for unknown schema", function() {
  var fields = resolveDiscoverySchema(minimalDiscoveryDoc, "NonExistent");
  return Array.isArray(fields) && fields.length === 0;
});

test("resolveDiscoverySchema — handles $ref to other schemas", function() {
  var docWithRef = {
    schemas: {
      Container: {
        id: "Container",
        type: "object",
        properties: {
          item: { type: "object", $ref: "Item", description: "The item" }
        }
      },
      Item: {
        id: "Item",
        type: "object",
        properties: {
          value: { type: "string", description: "Item value" }
        }
      }
    }
  };
  var fields = resolveDiscoverySchema(docWithRef, "Container");
  return fields.length === 1 && fields[0].name === "item" &&
    fields[0].type === "message" && fields[0].children.length === 1 &&
    fields[0].children[0].name === "value";
});

test("resolveDiscoverySchema — handles circular references", function() {
  var docCircular = {
    schemas: {
      Node: {
        id: "Node",
        type: "object",
        properties: {
          name: { type: "string" },
          child: { type: "object", $ref: "Node" }
        }
      }
    }
  };
  var fields = resolveDiscoverySchema(docCircular, "Node", 3);
  return fields.length === 2 &&
    fields[1].name === "child" && fields[1].type === "message";
});

// ═══════════════════════════════════════════════════════════════════════════════
// STATS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

console.log("\n=== Stats: createParamStats ===\n");

test("createParamStats — returns correct initial structure", function() {
  var stats = createParamStats();
  return stats.observedCount === 0 &&
    typeof stats.values === "object" && Object.keys(stats.values).length === 0 &&
    stats.numericRange === null &&
    stats.formatHints["date-time"] === 0 &&
    stats.formatHints.uri === 0 &&
    stats.formatHints.email === 0 &&
    stats.formatHints.uuid === 0 &&
    stats.formatHints.integer === 0;
});

console.log("\n=== Stats: updateParamStats ===\n");

test("updateParamStats — increments observed count", function() {
  var stats = createParamStats();
  updateParamStats(stats, "hello");
  updateParamStats(stats, "world");
  return stats.observedCount === 2;
});

test("updateParamStats — tracks value frequencies", function() {
  var stats = createParamStats();
  updateParamStats(stats, "a");
  updateParamStats(stats, "b");
  updateParamStats(stats, "a");
  return stats.values["a"] === 2 && stats.values["b"] === 1;
});

test("updateParamStats — tracks numeric range", function() {
  var stats = createParamStats();
  updateParamStats(stats, 10);
  updateParamStats(stats, 5);
  updateParamStats(stats, 20);
  return stats.numericRange.min === 5 && stats.numericRange.max === 20;
});

test("updateParamStats — detects date-time format", function() {
  var stats = createParamStats();
  updateParamStats(stats, "2024-01-15T10:30:00Z");
  return stats.formatHints["date-time"] === 1;
});

test("updateParamStats — detects URI format", function() {
  var stats = createParamStats();
  updateParamStats(stats, "https://example.com/path");
  return stats.formatHints.uri === 1;
});

test("updateParamStats — detects email format", function() {
  var stats = createParamStats();
  updateParamStats(stats, "user@example.com");
  return stats.formatHints.email === 1;
});

test("updateParamStats — detects UUID format", function() {
  var stats = createParamStats();
  updateParamStats(stats, "550e8400-e29b-41d4-a716-446655440000");
  return stats.formatHints.uuid === 1;
});

test("updateParamStats — detects integer format", function() {
  var stats = createParamStats();
  updateParamStats(stats, "42");
  return stats.formatHints.integer === 1;
});

console.log("\n=== Stats: analyzeRequired ===\n");

test("analyzeRequired — required when confidence >= 1.0 with enough observations", function() {
  var stats = createParamStats();
  for (var i = 0; i < 5; i++) updateParamStats(stats, "val");
  var result = analyzeRequired(stats, 5);
  return result.required === true && result.confidence === 1.0;
});

test("analyzeRequired — not required when below threshold", function() {
  var stats = createParamStats();
  for (var i = 0; i < 3; i++) updateParamStats(stats, "val");
  var result = analyzeRequired(stats, 5);
  return result.required === false && result.confidence === 0.6;
});

test("analyzeRequired — not required with too few observations", function() {
  var stats = createParamStats();
  updateParamStats(stats, "val");
  var result = analyzeRequired(stats, 1);
  return result.required === false; // requestCount < STATS_MIN_OBS_FOR_REQUIRED (3)
});

console.log("\n=== Stats: analyzeEnum ===\n");

test("analyzeEnum — detects enum with >=5 observations and few unique values", function() {
  var stats = createParamStats();
  var vals = ["red", "green", "blue"];
  for (var i = 0; i < 6; i++) updateParamStats(stats, vals[i % 3]);
  var result = analyzeEnum(stats);
  return result.isEnum === true && result.values.length === 3 &&
    result.values.indexOf("red") >= 0;
});

test("analyzeEnum — not enum with <5 observations", function() {
  var stats = createParamStats();
  updateParamStats(stats, "a");
  updateParamStats(stats, "b");
  var result = analyzeEnum(stats);
  return result.isEnum === false;
});

test("analyzeEnum — not enum with only 1 unique value", function() {
  var stats = createParamStats();
  for (var i = 0; i < 10; i++) updateParamStats(stats, "same");
  var result = analyzeEnum(stats);
  return result.isEnum === false; // uniqueValues.length < 2
});

console.log("\n=== Stats: analyzeDefault ===\n");

test("analyzeDefault — detects dominant value above 80% threshold", function() {
  var stats = createParamStats();
  for (var i = 0; i < 9; i++) updateParamStats(stats, "default_val");
  updateParamStats(stats, "other");
  var result = analyzeDefault(stats);
  return result.hasDefault === true && result.value === "default_val" &&
    result.confidence === 0.9;
});

test("analyzeDefault — no default when values are evenly distributed", function() {
  var stats = createParamStats();
  for (var i = 0; i < 5; i++) {
    updateParamStats(stats, "val" + i);
  }
  var result = analyzeDefault(stats);
  return result.hasDefault === false;
});

test("analyzeDefault — no default with too few observations", function() {
  var stats = createParamStats();
  updateParamStats(stats, "val");
  var result = analyzeDefault(stats);
  return result.hasDefault === false;
});

console.log("\n=== Stats: analyzeFormat ===\n");

test("analyzeFormat — detects date-time format", function() {
  var stats = createParamStats();
  var dates = [
    "2024-01-01T00:00:00Z", "2024-02-15T12:30:00Z", "2024-03-20T08:00:00Z",
    "2024-04-10T15:45:00Z", "2024-05-25T20:00:00Z"
  ];
  for (var i = 0; i < dates.length; i++) updateParamStats(stats, dates[i]);
  var result = analyzeFormat(stats);
  return result === "date-time";
});

test("analyzeFormat — detects URI format", function() {
  var stats = createParamStats();
  var uris = [
    "https://a.com/1", "https://b.com/2", "https://c.com/3",
    "https://d.com/4", "https://e.com/5"
  ];
  for (var i = 0; i < uris.length; i++) updateParamStats(stats, uris[i]);
  var result = analyzeFormat(stats);
  return result === "uri";
});

test("analyzeFormat — detects email format", function() {
  var stats = createParamStats();
  var emails = ["a@b.com", "c@d.org", "e@f.net", "g@h.io", "i@j.co"];
  for (var i = 0; i < emails.length; i++) updateParamStats(stats, emails[i]);
  var result = analyzeFormat(stats);
  return result === "email";
});

test("analyzeFormat — detects uuid format", function() {
  var stats = createParamStats();
  var uuids = [
    "550e8400-e29b-41d4-a716-446655440000",
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
  ];
  for (var i = 0; i < uuids.length; i++) updateParamStats(stats, uuids[i]);
  var result = analyzeFormat(stats);
  return result === "uuid";
});

test("analyzeFormat — detects integer format", function() {
  var stats = createParamStats();
  for (var i = 0; i < 5; i++) updateParamStats(stats, String(i * 10));
  var result = analyzeFormat(stats);
  return result === "integer";
});

test("analyzeFormat — returns null with too few observations", function() {
  var stats = createParamStats();
  updateParamStats(stats, "2024-01-01T00:00:00Z");
  var result = analyzeFormat(stats);
  return result === null;
});

console.log("\n=== Stats: analyzeRange ===\n");

test("analyzeRange — returns numeric range", function() {
  var stats = createParamStats();
  updateParamStats(stats, 5);
  updateParamStats(stats, 100);
  updateParamStats(stats, 50);
  var result = analyzeRange(stats);
  return result !== null && result.min === 5 && result.max === 100;
});

test("analyzeRange — returns null for same min/max", function() {
  var stats = createParamStats();
  updateParamStats(stats, 42);
  updateParamStats(stats, 42);
  var result = analyzeRange(stats);
  return result === null;
});

test("analyzeRange — returns null for no numeric values", function() {
  var stats = createParamStats();
  updateParamStats(stats, "not_a_number");
  var result = analyzeRange(stats);
  return result === null;
});

console.log("\n=== Stats: mergeParamStats ===\n");

test("mergeParamStats — merges counts correctly", function() {
  var a = createParamStats();
  var b = createParamStats();
  for (var i = 0; i < 3; i++) updateParamStats(a, "x");
  for (var j = 0; j < 2; j++) updateParamStats(b, "y");
  var merged = mergeParamStats(a, b);
  return merged.observedCount === 5 && merged.values["x"] === 3 && merged.values["y"] === 2;
});

test("mergeParamStats — merges numeric ranges", function() {
  var a = createParamStats();
  var b = createParamStats();
  updateParamStats(a, 10);
  updateParamStats(a, 50);
  updateParamStats(b, 5);
  updateParamStats(b, 100);
  var merged = mergeParamStats(a, b);
  return merged.numericRange.min === 5 && merged.numericRange.max === 100;
});

test("mergeParamStats — merges format hints", function() {
  var a = createParamStats();
  var b = createParamStats();
  updateParamStats(a, "https://a.com");
  updateParamStats(b, "https://b.com");
  var merged = mergeParamStats(a, b);
  return merged.formatHints.uri === 2;
});

test("mergeParamStats — handles null input", function() {
  var stats = createParamStats();
  updateParamStats(stats, "val");
  return mergeParamStats(null, stats) === stats &&
    mergeParamStats(stats, null) === stats;
});

console.log("\n=== Stats: detectCorrelations ===\n");

test("detectCorrelations — detects correlated params", function() {
  var methodStats = {
    requestCount: 10,
    params: {
      userId: createParamStats(),
      userName: createParamStats()
    }
  };
  for (var i = 0; i < 10; i++) {
    updateParamStats(methodStats.params.userId, "user" + i);
    updateParamStats(methodStats.params.userName, "name" + i);
  }
  var result = detectCorrelations(methodStats);
  return result.length === 1 &&
    result[0].paramA === "userId" && result[0].paramB === "userName" &&
    result[0].confidence === 1.0;
});

test("detectCorrelations — returns empty for insufficient data", function() {
  var methodStats = {
    requestCount: 2,
    params: {
      a: createParamStats(),
      b: createParamStats()
    }
  };
  updateParamStats(methodStats.params.a, "v1");
  updateParamStats(methodStats.params.b, "v2");
  var result = detectCorrelations(methodStats);
  return result.length === 0;
});

test("detectCorrelations — returns empty for single param", function() {
  var methodStats = {
    requestCount: 10,
    params: { only: createParamStats() }
  };
  for (var i = 0; i < 10; i++) updateParamStats(methodStats.params.only, "v" + i);
  var result = detectCorrelations(methodStats);
  return result.length === 0;
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHAINS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

console.log("\n=== Chains: createValueIndex ===\n");

test("createValueIndex — returns correct structure", function() {
  var idx = createValueIndex();
  return idx.strings instanceof Map && idx.numbers instanceof Map &&
    idx.strings.size === 0 && idx.numbers.size === 0;
});

console.log("\n=== Chains: indexResponseValues ===\n");

test("indexResponseValues — indexes string values", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { id: "abc-1234", name: "test-user" }, "method.get");
  return idx.strings.has("abc-1234") && idx.strings.has("test-user") &&
    idx.strings.get("abc-1234")[0].methodId === "method.get" &&
    idx.strings.get("abc-1234")[0].fieldPath === "id";
});

test("indexResponseValues — indexes number values", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { count: 42, score: 99.5 }, "method.list");
  return idx.numbers.has(42) && idx.numbers.has(99.5);
});

test("indexResponseValues — indexes nested objects", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { user: { profile: { email: "user@test.com" } } }, "method.get");
  return idx.strings.has("user@test.com") &&
    idx.strings.get("user@test.com")[0].fieldPath === "user.profile.email";
});

test("indexResponseValues — indexes array elements", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { items: ["first-item", "second-item"] }, "method.list");
  return idx.strings.has("first-item") && idx.strings.has("second-item") &&
    idx.strings.get("first-item")[0].fieldPath === "items[0]";
});

test("indexResponseValues — respects min length (4 chars)", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { short: "ab", long: "abcdef" }, "method.get");
  return !idx.strings.has("ab") && idx.strings.has("abcdef");
});

test("indexResponseValues — ignores common values (true, false, null)", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { a: "true", b: "false", c: "null" }, "method.get");
  return !idx.strings.has("true") && !idx.strings.has("false") && !idx.strings.has("null");
});

test("indexResponseValues — ignores 0, 1, -1 numbers", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { a: 0, b: 1, c: -1, d: 42 }, "method.get");
  return !idx.numbers.has(0) && !idx.numbers.has(1) && !idx.numbers.has(-1) &&
    idx.numbers.has(42);
});

test("indexResponseValues — avoids duplicate entries for same method+field", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { id: "same-value" }, "method.get");
  indexResponseValues(idx, { id: "same-value" }, "method.get");
  return idx.strings.get("same-value").length === 1;
});

console.log("\n=== Chains: findChainLinks ===\n");

test("findChainLinks — finds link when param matches indexed response value", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { userId: "user-12345" }, "users.list");
  var links = findChainLinks(idx, { id: "user-12345" }, {}, "users.get");
  return links.length === 1 &&
    links[0].paramName === "id" &&
    links[0].sourceMethodId === "users.list" &&
    links[0].sourceFieldPath === "userId" &&
    links[0].paramLocation === "query";
});

test("findChainLinks — excludes self-links (same method)", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { token: "abc-token-123" }, "api.call");
  var links = findChainLinks(idx, { token: "abc-token-123" }, {}, "api.call");
  return links.length === 0;
});

test("findChainLinks — finds links from body values too", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { sessionId: "sess-99999" }, "auth.login");
  var links = findChainLinks(idx, {}, { session: "sess-99999" }, "data.fetch");
  return links.length === 1 && links[0].paramLocation === "body" &&
    links[0].paramName === "session";
});

test("findChainLinks — no links for unmatched values", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { id: "known-value" }, "source.method");
  var links = findChainLinks(idx, { id: "unknown-value" }, {}, "target.method");
  return links.length === 0;
});

test("findChainLinks — ignores short param values (< 4 chars)", function() {
  var idx = createValueIndex();
  indexResponseValues(idx, { x: "ab" }, "source.method");
  var links = findChainLinks(idx, { x: "ab" }, {}, "target.method");
  return links.length === 0;
});

console.log("\n=== Chains: flattenObjectValues ===\n");

test("flattenObjectValues — flattens simple object", function() {
  var result = flattenObjectValues({ a: 1, b: "hello" });
  return result.a === 1 && result.b === "hello";
});

test("flattenObjectValues — flattens nested objects with dot paths", function() {
  var result = flattenObjectValues({ user: { name: "Alice", age: 30 } });
  return result["user.name"] === "Alice" && result["user.age"] === 30;
});

test("flattenObjectValues — handles arrays with bracket paths", function() {
  var result = flattenObjectValues({ items: ["first", "second"] });
  return result["items[0]"] === "first" && result["items[1]"] === "second";
});

test("flattenObjectValues — handles deeply nested structures", function() {
  var result = flattenObjectValues({ a: { b: { c: "deep" } } });
  return result["a.b.c"] === "deep";
});

test("flattenObjectValues — handles null values", function() {
  var result = flattenObjectValues(null);
  return Object.keys(result).length === 0;
});

test("flattenObjectValues — handles primitive at root (with prefix)", function() {
  var result = flattenObjectValues("hello", "root");
  return result["root"] === "hello";
});

console.log("\n=== Chains: mergeChainLinks ===\n");

test("mergeChainLinks — adds new links to incoming", function() {
  var newLinks = [{
    paramName: "userId",
    paramLocation: "query",
    sourceMethodId: "users.list",
    sourceFieldPath: "id",
    lastSeen: 1000
  }];
  var result = mergeChainLinks(null, newLinks);
  return result.incoming.length === 1 &&
    result.incoming[0].paramName === "userId" &&
    result.incoming[0].observedCount === 1;
});

test("mergeChainLinks — increments count for duplicate links", function() {
  var existing = {
    incoming: [{
      paramName: "userId",
      paramLocation: "query",
      sourceMethodId: "users.list",
      sourceFieldPath: "id",
      observedCount: 1,
      lastSeen: 1000
    }],
    outgoing: []
  };
  var newLinks = [{
    paramName: "userId",
    paramLocation: "query",
    sourceMethodId: "users.list",
    sourceFieldPath: "id",
    lastSeen: 2000
  }];
  var result = mergeChainLinks(existing, newLinks);
  return result.incoming.length === 1 &&
    result.incoming[0].observedCount === 2 &&
    result.incoming[0].lastSeen === 2000;
});

test("mergeChainLinks — adds distinct links separately", function() {
  var existing = {
    incoming: [{
      paramName: "userId",
      paramLocation: "query",
      sourceMethodId: "users.list",
      sourceFieldPath: "id",
      observedCount: 1,
      lastSeen: 1000
    }],
    outgoing: []
  };
  var newLinks = [{
    paramName: "groupId",
    paramLocation: "query",
    sourceMethodId: "groups.list",
    sourceFieldPath: "groupId",
    lastSeen: 2000
  }];
  var result = mergeChainLinks(existing, newLinks);
  return result.incoming.length === 2;
});

test("mergeChainLinks — initializes empty structure from null", function() {
  var result = mergeChainLinks(null, []);
  return Array.isArray(result.incoming) && Array.isArray(result.outgoing) &&
    result.incoming.length === 0 && result.outgoing.length === 0;
});

// ─── Summary ────────────────────────────────────────────────────────────────

console.log("\n" + passed + "/" + total + " passed, " + failed + " failed\n");
process.exit(failed > 0 ? 1 : 0);
