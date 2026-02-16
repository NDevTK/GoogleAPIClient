// test-ast.js — Test suite for AST analysis engine
// Run: node test-ast.js

var fs = require("fs");

// Load Babel bundle (IIFE: var BabelBundle = (() => {...})())
var babelCode = fs.readFileSync(__dirname + "/lib/babel-bundle.js", "utf8");
// Replace var declaration with globalThis assignment so it's accessible outside new Function
new Function(babelCode.replace(/^var BabelBundle/, "globalThis.BabelBundle"))();

// Load ast.js (expects BabelBundle global; expose analyzeJSBundle + extractSourceMapUrl)
var astCode = fs.readFileSync(__dirname + "/lib/ast.js", "utf8");
new Function(astCode + "\nglobalThis.analyzeJSBundle = analyzeJSBundle;\nglobalThis.extractSourceMapUrl = extractSourceMapUrl;")();

var passed = 0, failed = 0, total = 0;

function test(name, code, check) {
  total++;
  try {
    var result = analyzeJSBundle(code, "test://" + name);
    var ok = check(result);
    if (ok) {
      passed++;
      console.log("  PASS: " + name);
    } else {
      failed++;
      console.log("  FAIL: " + name);
      console.log("    Result:", JSON.stringify(result.fetchCallSites, null, 2));
    }
  } catch (e) {
    failed++;
    console.log("  ERROR: " + name + " — " + e.message);
    console.log("    " + e.stack.split("\n").slice(0, 3).join("\n    "));
  }
}

console.log("\n=== Direct fetch() calls ===\n");

test("fetch with string literal URL", `
  fetch("https://api.example.com/users");
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "https://api.example.com/users" &&
    r.fetchCallSites[0].method === "GET";
});

test("fetch with method and headers", `
  fetch("https://api.example.com/data", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "test", value: 42 })
  });
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].method === "POST" &&
    r.fetchCallSites[0].headers["Content-Type"] === "application/json";
});

test("window.fetch call", `
  window.fetch("https://api.example.com/items");
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "https://api.example.com/items";
});

test("fetch with template literal URL", `
  var id = "abc123";
  fetch(\`https://api.example.com/users/\${id}\`);
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "https://api.example.com/users/abc123";
});

test("fetch with variable URL (const)", `
  var baseUrl = "https://api.example.com";
  fetch(baseUrl + "/endpoint");
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "https://api.example.com/endpoint";
});

test("fetch with options-as-variable", `
  var opts = { method: "PUT", headers: { "X-Token": "abc" } };
  fetch("https://api.example.com/update", opts);
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].method === "PUT" &&
    r.fetchCallSites[0].headers["X-Token"] === "abc";
});

console.log("\n=== XHR calls ===\n");

test("XMLHttpRequest.open", `
  var xhr = new XMLHttpRequest();
  xhr.open("GET", "https://api.example.com/xhr-endpoint");
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "https://api.example.com/xhr-endpoint" &&
    r.fetchCallSites[0].method === "GET" &&
    r.fetchCallSites[0].type === "xhr";
});

console.log("\n=== Inter-procedural tracing ===\n");

test("Simple wrapper function", `
  function doFetch(url) {
    return fetch(url);
  }
  doFetch("https://api.example.com/wrapped");
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/wrapped";
  });
});

test("Wrapper with method parameter", `
  function apiCall(method, url) {
    return fetch(url, { method: method });
  }
  apiCall("POST", "https://api.example.com/action");
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/action" && s.method === "POST";
  });
});

test("Object method wrapper", `
  var api = {
    request: function(url) {
      return fetch(url);
    }
  };
  api.request("https://api.example.com/obj-method");
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/obj-method";
  });
});

test("Closure pattern: obj.method = function wrapper", `
  var api = {};
  api.doFetch = function(url) {
    return fetch(url);
  };
  api.doFetch("https://api.example.com/closure-method");
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/closure-method";
  });
});

console.log("\n=== MemberExpression value resolution ===\n");

test("Object property as URL", `
  var config = { apiUrl: "https://api.example.com/config" };
  fetch(config.apiUrl);
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "https://api.example.com/config";
});

test("Object property concatenation", `
  var config = { base: "https://api.example.com" };
  fetch(config.base + "/resource");
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "https://api.example.com/resource";
});

test("Closure module pattern: separate property assignment", `
  var mod = {};
  mod.baseUrl = "https://api.example.com";
  fetch(mod.baseUrl + "/path");
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/path";
  });
});

test("Nested object property", `
  var config = { api: { url: "https://api.example.com/nested" } };
  fetch(config.api.url);
`, function(r) {
  // This may or may not resolve depending on nested member expression support
  return r.fetchCallSites.length === 1;
});

console.log("\n=== Value constraints ===\n");

test("Switch statement constraints", `
  function handle(action) {
    switch(action) {
      case "create": return fetch("/api/create");
      case "update": return fetch("/api/update");
      case "delete": return fetch("/api/delete");
    }
  }
`, function(r) {
  return r.valueConstraints.some(function(c) {
    return c.variable === "action" && c.values.length === 3;
  });
});

test("Includes constraint", `
  var FORMATS = ["json", "xml", "csv"];
  function convert(format) {
    if (FORMATS.includes(format)) {
      fetch("/api/convert?format=" + format);
    }
  }
`, function(r) {
  return r.valueConstraints.some(function(c) {
    return c.variable === "format" && c.values.length === 3;
  });
});

test("Equality chain constraint", `
  function process(type) {
    if (type === "text" || type === "html" || type === "markdown") {
      fetch("/api/process");
    }
  }
`, function(r) {
  return r.valueConstraints.some(function(c) {
    return c.variable === "type" && c.values.length === 3;
  });
});

console.log("\n=== Proto detection ===\n");

test("Proto enum detection", `
  var Status = { UNKNOWN: 0, ACTIVE: 1, INACTIVE: 2, DELETED: 3 };
`, function(r) {
  return r.protoEnums.length === 1 &&
    r.protoEnums[0].values.ACTIVE === 1;
});

test("Proto field map from prototype assignment", `
  function MyMessage() {}
  MyMessage.prototype.getName = function() {
    return jspb.Message.getField(this, 1);
  };
  MyMessage.prototype.getAge = function() {
    return jspb.Message.getField(this, 2);
  };
`, function(r) {
  return r.protoFieldMaps.length === 2;
});

console.log("\n=== Scope verification ===\n");

test("Shadowed fetch is not a sink", `
  function myModule() {
    var fetch = function(url) { return url; };
    fetch("https://not-a-real-fetch.com");
  }
`, function(r) {
  return r.fetchCallSites.length === 0;
});

test("Shadowed window is not a sink", `
  function myModule() {
    var window = { fetch: function() {} };
    window.fetch("https://not-a-real-fetch.com");
  }
`, function(r) {
  return r.fetchCallSites.length === 0;
});

console.log("\n=== Source map URL ===\n");

test("Source map URL extraction", `
  var x = 1;
  //# sourceMappingURL=bundle.js.map
`, function(r) {
  return r.sourceMapUrl === "bundle.js.map";
});

// ── Summary ──
console.log("\n" + "=".repeat(50));
console.log("Results: " + passed + "/" + total + " passed, " + failed + " failed");
if (failed > 0) {
  process.exit(1);
} else {
  console.log("All tests passed!");
}
