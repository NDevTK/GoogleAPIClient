// test-jquery-trace.js — Test AST tracing through real jQuery source
// Run: node test-jquery-trace.js

var fs = require("fs");

// Load Babel bundle
var babelCode = fs.readFileSync(__dirname + "/lib/babel-bundle.js", "utf8");
new Function(babelCode.replace(/^var BabelBundle/, "globalThis.BabelBundle"))();

// Load ast.js
var astCode = fs.readFileSync(__dirname + "/lib/ast.js", "utf8");
new Function(astCode + "\nglobalThis.analyzeJSBundle = analyzeJSBundle;\nglobalThis.extractSourceMapUrl = extractSourceMapUrl;")();

// Load real jQuery source
var jqueryCode = fs.readFileSync(__dirname + "/jquery-3.7.1.js", "utf8");

// Append $.ajax() calls after jQuery source — simulate a page that uses jQuery
var testCode = jqueryCode + `
;
jQuery.ajax({url: "/api/test-endpoint", method: "POST", data: {name: "test"}});
jQuery.get("/api/users");
jQuery.post("/api/submit", {key: "value"});
$.ajax({url: "/api/dollar-call", type: "DELETE"});
`;

console.log("Analyzing jQuery (%d chars) + test calls...", testCode.length);
console.time("analysis");
var result = analyzeJSBundle(testCode, "test://jquery+calls", true);
console.timeEnd("analysis");

console.log("\n=== Results ===");
console.log("fetchCallSites: %d", result.fetchCallSites.length);
console.log("protoEnums: %d", result.protoEnums.length);
console.log("protoFieldMaps: %d", result.protoFieldMaps.length);
console.log("valueConstraints: %d", result.valueConstraints.length);

if (result.fetchCallSites.length > 0) {
  console.log("\n=== Discovered Call Sites ===");
  for (var i = 0; i < result.fetchCallSites.length; i++) {
    var s = result.fetchCallSites[i];
    console.log("  %s %s %s", s.method, s.url, s.params ? JSON.stringify(s.params) : "");
  }
}

// Check if any of our test calls were traced
var tests = [
  { url: "/api/test-endpoint", method: "POST", desc: "jQuery.ajax() POST" },
  { url: "/api/users", method: "GET", desc: "jQuery.get()" },
  { url: "/api/submit", method: "POST", desc: "jQuery.post()" },
  { url: "/api/dollar-call", method: "DELETE", desc: "$.ajax() DELETE" },
];

console.log("\n=== Test Results ===");
var passed = 0;
for (var ti = 0; ti < tests.length; ti++) {
  var t = tests[ti];
  var found = result.fetchCallSites.some(function(s) {
    return s.url === t.url;
  });
  var foundWithMethod = result.fetchCallSites.some(function(s) {
    return s.url === t.url && s.method === t.method;
  });
  if (foundWithMethod) {
    console.log("  PASS: %s — found %s %s", t.desc, t.method, t.url);
    passed++;
  } else if (found) {
    var match = result.fetchCallSites.find(function(s) { return s.url === t.url; });
    console.log("  PARTIAL: %s — found URL but method=%s (expected %s)", t.desc, match.method, t.method);
    passed++;
  } else {
    console.log("  FAIL: %s — not found", t.desc);
  }
}
console.log("\n%d/%d traced through jQuery", passed, tests.length);
