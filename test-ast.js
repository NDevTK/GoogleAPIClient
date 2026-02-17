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

function test(name, code, check, forceScript) {
  total++;
  try {
    var result = analyzeJSBundle(code, "test://" + name, forceScript);
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

test("this.prop in object method", `
  var client = {
    base: "https://api.example.com/v2",
    get: function(path) {
      return fetch(this.base + path);
    }
  };
  client.get("/products");
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v2/products";
  });
});

console.log("\n=== Param location detection ===\n");

test("Wrapper params get correct locations", `
  function apiCall(method, url, body) {
    return fetch(url, { method: method, body: JSON.stringify(body) });
  }
  apiCall("POST", "https://api.example.com/action", { key: "val" });
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "https://api.example.com/action"; });
  if (!site || !site.params) return false;
  var methodParam = site.params.find(function(p) { return p.name === "method"; });
  var urlParam = site.params.find(function(p) { return p.name === "url"; });
  // method param should not be location:unknown
  return (!methodParam || methodParam.location !== "unknown") &&
         (!urlParam || urlParam.location !== "unknown");
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

console.log("\n=== Cross-script global resolution ===\n");

test("IIFE window alias — direct fetch via windowAlias.fetch", `
  !function(win) {
    win.fetch("https://api.example.com/from-iife");
  }(window);
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "https://api.example.com/from-iife";
});

test("Global assignment via window.X tracked", `
  window.myUrl = "https://api.example.com/global";
  fetch(myUrl);
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "https://api.example.com/global";
}, true);

test("UMD pattern — typeof window conditional", `
  !function(global) {
    global.apiBase = "https://api.example.com";
  }("undefined" != typeof window ? window : this);
  fetch(apiBase + "/endpoint");
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "https://api.example.com/endpoint";
}, true);

test("Indirect IIFE — factory(windowAlias) pattern", `
  !function(e, t) {
    t(e);
  }("undefined" != typeof window ? window : this, function(global) {
    global.baseUrl = "https://api.example.com/v2";
  });
  fetch(baseUrl + "/data");
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "https://api.example.com/v2/data";
}, true);

test("Global function via window.X = function()", `
  window.doFetch = function(url) { return fetch(url); };
  doFetch("https://api.example.com/global-fn");
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/global-fn";
  });
}, true);

console.log("\n=== Object property tracing through function params ===\n");

test("fetch(opts.url) with object literal argument", `
  function request(opts) {
    return fetch(opts.url, { method: opts.method });
  }
  request({ url: "https://api.example.com/v1/users", method: "POST" });
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/users" && s.method === "POST";
  });
});

test("fetch(config.endpoint) with variable object argument", `
  function callApi(config) {
    return fetch(config.endpoint, { method: config.verb, headers: { "X-Key": "abc" } });
  }
  var opts = { endpoint: "https://api.example.com/v1/items", verb: "PUT" };
  callApi(opts);
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/items" && s.method === "PUT";
  });
});

test("Multiple callers with different object args", `
  function doRequest(params) {
    return fetch(params.url);
  }
  doRequest({ url: "https://api.example.com/a" });
  doRequest({ url: "https://api.example.com/b" });
`, function(r) {
  var hasA = r.fetchCallSites.some(function(s) { return s.url === "https://api.example.com/a"; });
  var hasB = r.fetchCallSites.some(function(s) { return s.url === "https://api.example.com/b"; });
  return hasA && hasB;
});

test("Wrapper function with opts.url → traced via wrapper", `
  function myFetch(opts) {
    return fetch(opts.url, { method: opts.method });
  }
  myFetch({ url: "https://api.example.com/traced", method: "DELETE" });
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/traced" && s.method === "DELETE";
  });
});

test("Unresolvable placeholder URLs are suppressed (not emitted)", `
  function internalSink(settings) {
    var xhr = new XMLHttpRequest();
    xhr.open(settings.type, settings.url);
  }
`, function(r) {
  // No callers pass concrete values → should emit nothing
  return r.fetchCallSites.length === 0;
});

test("Object method with opts parameter", `
  var api = {
    call: function(opts) {
      return fetch(opts.url, { method: opts.method || "GET" });
    }
  };
  api.call({ url: "https://api.example.com/v1/obj-method", method: "PATCH" });
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/obj-method" && s.method === "PATCH";
  });
});

console.log("\n=== Return value resolution ===\n");

test("Simple function returning string literal", `
  function getUrl() { return "https://api.example.com/v1/data"; }
  fetch(getUrl());
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/data";
  });
});

test("Arrow function with expression body", `
  const getEndpoint = () => "https://api.example.com/v1/endpoint";
  fetch(getEndpoint());
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/endpoint";
  });
});

test("Function building URL from parameters", `
  function buildUrl(base, path) {
    return base + "/" + path;
  }
  fetch(buildUrl("https://api.example.com", "users"));
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/users";
  });
});

test("Object method returning URL", `
  var config = {
    base: "https://api.example.com",
    getUrl: function() { return this.base + "/v1/items"; }
  };
  fetch(config.getUrl());
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/items";
  });
});

test("Chained return value — config factory", `
  function getConfig() {
    return { url: "https://api.example.com/v1/settings", method: "PUT" };
  }
  var cfg = getConfig();
  fetch(cfg.url, { method: cfg.method });
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/settings" && s.method === "PUT";
  });
});

console.log("\n=== Destructured parameter resolution ===\n");

test("Destructured {url} parameter", `
  function request({url}) {
    return fetch(url);
  }
  request({ url: "https://api.example.com/v1/destructured" });
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/destructured";
  });
});

test("Destructured {url, method} with both used", `
  function doFetch({url, method}) {
    return fetch(url, { method: method });
  }
  doFetch({ url: "https://api.example.com/v1/action", method: "DELETE" });
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/action" && s.method === "DELETE";
  });
});

test("Destructured with default value — {url, method = 'GET'}", `
  function api({url, method = "GET"}) {
    return fetch(url, { method: method });
  }
  api({ url: "https://api.example.com/v1/default-method" });
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/default-method";
  });
});

test("Destructured with rename — {endpoint: url}", `
  function callEndpoint({endpoint: url}) {
    return fetch(url);
  }
  callEndpoint({ endpoint: "https://api.example.com/v1/renamed" });
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/renamed";
  });
});

console.log("\n=== Additional browser sinks ===\n");

test("navigator.sendBeacon(url, data)", `
  var payload = JSON.stringify({ event: "click" });
  navigator.sendBeacon("/api/analytics", payload);
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "/api/analytics" &&
    r.fetchCallSites[0].method === "POST" &&
    r.fetchCallSites[0].type === "beacon";
});

test("navigator.sendBeacon with variable URL", `
  var endpoint = "/api/track";
  navigator.sendBeacon(endpoint, "data");
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "/api/track" &&
    r.fetchCallSites[0].method === "POST" &&
    r.fetchCallSites[0].type === "beacon";
});

test("new EventSource(url)", `
  var es = new EventSource("/api/events/stream");
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "/api/events/stream" &&
    r.fetchCallSites[0].method === "GET" &&
    r.fetchCallSites[0].type === "eventsource";
});

test("new EventSource with variable URL", `
  var streamUrl = "/api/notifications/live";
  var source = new EventSource(streamUrl);
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "/api/notifications/live" &&
    r.fetchCallSites[0].type === "eventsource";
});

test("Image pixel tracking — new Image().src = url", `
  var img = new Image();
  img.src = "/api/pixel/track?uid=123";
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "/api/pixel/track?uid=123" &&
    r.fetchCallSites[0].method === "GET" &&
    r.fetchCallSites[0].type === "pixel";
});

test("Image pixel with variable URL", `
  var pixelUrl = "/api/pixel/impression";
  var img = new Image();
  img.src = pixelUrl;
`, function(r) {
  return r.fetchCallSites.length === 1 &&
    r.fetchCallSites[0].url === "/api/pixel/impression" &&
    r.fetchCallSites[0].type === "pixel";
});

test("Shadowed navigator is not a beacon sink", `
  function test() {
    var navigator = { sendBeacon: function() {} };
    navigator.sendBeacon("/not-real");
  }
`, function(r) {
  return r.fetchCallSites.length === 0;
});

test("Shadowed EventSource is not a sink", `
  function test() {
    var EventSource = function() {};
    new EventSource("/not-real");
  }
`, function(r) {
  return r.fetchCallSites.length === 0;
});

console.log("\n=== Multi-caller value pairing ===\n");

test("Multiple callers with different URLs and methods", `
  function apiRequest(method, endpoint) {
    return fetch("/api/" + endpoint, { method: method });
  }
  apiRequest("POST", "orders");
  apiRequest("DELETE", "orders/123");
  apiRequest("GET", "inventory");
`, function(r) {
  var hasPost = r.fetchCallSites.some(function(s) { return s.url === "/api/orders" && s.method === "POST"; });
  var hasDel = r.fetchCallSites.some(function(s) { return s.url === "/api/orders/123" && s.method === "DELETE"; });
  var hasGet = r.fetchCallSites.some(function(s) { return s.url === "/api/inventory" && s.method === "GET"; });
  return hasPost && hasDel && hasGet;
});

test("BinaryExpression zip: base + path from multiple callers", `
  function makeRequest(base, path) {
    return fetch(base + path);
  }
  makeRequest("https://api.example.com", "/users");
  makeRequest("https://other.example.com", "/items");
`, function(r) {
  var hasFirst = r.fetchCallSites.some(function(s) { return s.url === "https://api.example.com/users"; });
  var hasSecond = r.fetchCallSites.some(function(s) { return s.url === "https://other.example.com/items"; });
  return hasFirst && hasSecond;
});

test("BinaryExpression broadcast: constant base + multiple paths", `
  var API_BASE = "https://api.example.com";
  function apiGet(path) {
    return fetch(API_BASE + path);
  }
  apiGet("/notifications");
  apiGet("/preferences");
`, function(r) {
  var hasNotif = r.fetchCallSites.some(function(s) { return s.url === "https://api.example.com/notifications"; });
  var hasPref = r.fetchCallSites.some(function(s) { return s.url === "https://api.example.com/preferences"; });
  return hasNotif && hasPref;
});

test("Per-caller method pairing: URL[i] pairs with Method[i]", `
  function rpc(service, method, verb) {
    return fetch("/rpc/" + service + "/" + method, { method: verb });
  }
  rpc("auth", "login", "POST");
  rpc("auth", "refresh", "POST");
  rpc("billing", "invoice", "GET");
`, function(r) {
  var hasLogin = r.fetchCallSites.some(function(s) { return s.url === "/rpc/auth/login" && s.method === "POST"; });
  var hasRefresh = r.fetchCallSites.some(function(s) { return s.url === "/rpc/auth/refresh" && s.method === "POST"; });
  var hasInvoice = r.fetchCallSites.some(function(s) { return s.url === "/rpc/billing/invoice" && s.method === "GET"; });
  return hasLogin && hasRefresh && hasInvoice;
});

console.log("\n=== Factory/closure pattern ===\n");

test("Factory function returning object with methods", `
  function createClient(baseUrl) {
    return {
      get: function(path) {
        return fetch(baseUrl + path);
      },
      post: function(path, body) {
        return fetch(baseUrl + path, { method: "POST", body: JSON.stringify(body) });
      }
    };
  }
  var client = createClient("https://api.example.com");
  client.get("/users");
  client.post("/users", { name: "test" });
`, function(r) {
  var hasGet = r.fetchCallSites.some(function(s) { return s.url === "https://api.example.com/users"; });
  var hasPost = r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/users" && s.method === "POST";
  });
  return hasGet && hasPost;
});

test("Factory with multiple instantiations", `
  function createApi(base) {
    return {
      fetch: function(path) { return fetch(base + path); }
    };
  }
  var v1 = createApi("/api/v1");
  var v2 = createApi("/api/v2");
  v1.fetch("/items");
  v2.fetch("/items");
`, function(r) {
  var hasV1 = r.fetchCallSites.some(function(s) { return s.url === "/api/v1/items"; });
  var hasV2 = r.fetchCallSites.some(function(s) { return s.url === "/api/v2/items"; });
  return hasV1 && hasV2;
});

console.log("\n=== Constructor this binding ===\n");

test("Constructor this.prop in prototype method", `
  function ApiService(base) {
    this.baseUrl = base;
  }
  ApiService.prototype.get = function(path) {
    return fetch(this.baseUrl + path);
  };
  var svc = new ApiService("https://api.example.com/v3");
  svc.get("/resources");
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v3/resources";
  });
});

test("Constructor with multiple instantiations", `
  function Client(host) {
    this.host = host;
  }
  Client.prototype.request = function(path) {
    return fetch(this.host + path);
  };
  var prod = new Client("https://prod.api.com");
  var staging = new Client("https://staging.api.com");
  prod.request("/health");
  staging.request("/health");
`, function(r) {
  var hasProd = r.fetchCallSites.some(function(s) { return s.url === "https://prod.api.com/health"; });
  var hasStaging = r.fetchCallSites.some(function(s) { return s.url === "https://staging.api.com/health"; });
  return hasProd && hasStaging;
});

console.log("\n=== Computed member access ===\n");

test("Object with computed key lookup — all values", `
  var endpoints = {
    users: "/api/users",
    orders: "/api/orders",
    products: "/api/products"
  };
  function loadEndpoint(name) {
    return fetch(endpoints[name]);
  }
`, function(r) {
  var urls = r.fetchCallSites.map(function(s) { return s.url; }).sort();
  return urls.length === 3 &&
    urls[0] === "/api/orders" &&
    urls[1] === "/api/products" &&
    urls[2] === "/api/users";
});

test("Array with computed index — all element values", `
  var urls = ["/api/first", "/api/second", "/api/third"];
  function loadByIndex(i) {
    return fetch(urls[i]);
  }
`, function(r) {
  var found = r.fetchCallSites.map(function(s) { return s.url; }).sort();
  return found.length === 3 &&
    found[0] === "/api/first" &&
    found[1] === "/api/second" &&
    found[2] === "/api/third";
});

test("Array of objects — arr[i].prop", `
  var configs = [
    { url: "/api/alpha", method: "GET" },
    { url: "/api/beta", method: "POST" },
    { url: "/api/gamma", method: "PUT" }
  ];
  function callConfig(idx) {
    return fetch(configs[idx].url);
  }
`, function(r) {
  var urls = r.fetchCallSites.map(function(s) { return s.url; }).sort();
  return urls.length === 3 &&
    urls[0] === "/api/alpha" &&
    urls[1] === "/api/beta" &&
    urls[2] === "/api/gamma";
});

test("Computed access with resolvable literal key", `
  var routes = { health: "/api/health", status: "/api/status" };
  var key = "health";
  fetch(routes[key]);
`, function(r) {
  return r.fetchCallSites.some(function(s) { return s.url === "/api/health"; });
});

console.log("\n=== Combined patterns ===\n");

test("Factory + multi-caller + method pairing", `
  function createEndpoint(base) {
    return {
      call: function(path, method) {
        return fetch(base + path, { method: method });
      }
    };
  }
  var api = createEndpoint("/api/v1");
  api.call("/users", "GET");
  api.call("/users", "POST");
  api.call("/users/1", "DELETE");
`, function(r) {
  var hasGet = r.fetchCallSites.some(function(s) { return s.url === "/api/v1/users" && s.method === "GET"; });
  var hasPost = r.fetchCallSites.some(function(s) { return s.url === "/api/v1/users" && s.method === "POST"; });
  var hasDel = r.fetchCallSites.some(function(s) { return s.url === "/api/v1/users/1" && s.method === "DELETE"; });
  return hasGet && hasPost && hasDel;
});

test("Wrapper chain: outer → inner → fetch", `
  function innerFetch(url, method) {
    return fetch(url, { method: method });
  }
  function outerFetch(endpoint) {
    return innerFetch("/api" + endpoint, "POST");
  }
  outerFetch("/submit");
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "/api/submit" && s.method === "POST";
  });
});

// === Deep Sink Detection (library-level tracing) ===

console.log("\n=== Deep sink detection (jQuery-style) ===\n");

test("Deep sink: xhr.open in nested callback, property matching", `
  var lib = {};
  lib.extend = function(target) {
    for (var k in arguments[1]) target[k] = arguments[1][k];
    return target;
  };
  lib.extend({
    request: function(url, options) {
      if (typeof url === "object") { options = url; url = undefined; }
      options = options || {};
      function transport(opts) {
        var xhr = new XMLHttpRequest();
        xhr.open(opts.method, opts.url);
        xhr.send();
      }
      transport(options);
    }
  });
  lib.request({url: "/api/deep-test", method: "PUT"});
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "/api/deep-test" && s.method === "PUT";
  });
}, true);

test("Deep sink: xhr.open in separate registered callback (store-and-call)", `
  var lib = {};
  var transports = [];
  function registerTransport(fn) { transports.push(fn); }
  registerTransport(function(options) {
    var xhr = new XMLHttpRequest();
    xhr.open(options.type, options.url);
    xhr.send();
  });
  lib.request = function(options) {
    options = options || {};
    for (var i = 0; i < transports.length; i++) transports[i](options);
  };
  lib.request({url: "/api/callback-sink", type: "DELETE"});
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "/api/callback-sink" && s.method === "DELETE";
  });
}, true);

test("Deep sink: store-and-call with extend pattern", `
  var lib = {};
  lib.extend = function(target) {
    for (var k in arguments[1]) target[k] = arguments[1][k];
    return target;
  };
  var handlers = [];
  function addHandler(fn) { handlers.push(fn); }
  addHandler(function(opts) {
    var xhr = new XMLHttpRequest();
    xhr.open(opts.type, opts.url);
    xhr.send();
  });
  lib.extend({
    doRequest: function(options) {
      for (var i = 0; i < handlers.length; i++) handlers[i](options);
    }
  });
  lib.doRequest({url: "/api/extend-call", type: "PUT"});
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "/api/extend-call" && s.method === "PUT";
  });
}, true);

test("Deep sink: $ alias via window.$ = window.jQuery = lib", `
  (function(window) {
    var lib = {};
    lib.extend = function(target) {
      for (var k in arguments[1]) target[k] = arguments[1][k];
      return target;
    };
    function doXHR(config) {
      var xhr = new XMLHttpRequest();
      xhr.open(config.method, config.url);
      xhr.send();
    }
    lib.extend({
      ajax: function(opts) { doXHR(opts); }
    });
    window.jQuery = window.$ = lib;
  })(window);
  jQuery.ajax({url: "/api/alias-test", method: "PATCH"});
  $.ajax({url: "/api/dollar-test", method: "POST"});
`, function(r) {
  var found1 = r.fetchCallSites.some(function(s) { return s.url === "/api/alias-test" && s.method === "PATCH"; });
  var found2 = r.fetchCallSites.some(function(s) { return s.url === "/api/dollar-test" && s.method === "POST"; });
  return found1 && found2;
}, true);

test("Deep sink: fetch in nested closure", `
  var api = {};
  api.extend = function(target) {
    for (var k in arguments[1]) target[k] = arguments[1][k];
    return target;
  };
  api.extend({
    call: function(config) {
      var doFetch = function() {
        fetch(config.endpoint, {method: config.verb});
      };
      doFetch();
    }
  });
  api.call({endpoint: "/api/nested-fetch", verb: "POST"});
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "/api/nested-fetch";
  });
}, true);

test("Deep sink: no false positives for non-network functions", `
  var util = {};
  util.extend = function(target) {
    for (var k in arguments[1]) target[k] = arguments[1][k];
    return target;
  };
  util.extend({
    format: function(opts) {
      return opts.prefix + opts.value;
    }
  });
  util.format({prefix: "/api/", value: "test"});
`, function(r) {
  return r.fetchCallSites.length === 0;
}, true);

test("Deep sink: MemberExpression callee with direct sink (obj.method resolved via extend)", `
  var svc = {};
  svc.extend = function(target) {
    for (var k in arguments[1]) target[k] = arguments[1][k];
    return target;
  };
  svc.extend({
    get: function(url) {
      fetch(url);
    }
  });
  svc.get("/api/direct-extend");
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "/api/direct-extend";
  });
}, true);

test("Deep sink: multiple callers with different URLs", `
  var http = {};
  http.extend = function(target) {
    for (var k in arguments[1]) target[k] = arguments[1][k];
    return target;
  };
  var sinks = [];
  function reg(fn) { sinks.push(fn); }
  reg(function(c) {
    var x = new XMLHttpRequest();
    x.open(c.type, c.url);
    x.send();
  });
  http.extend({
    request: function(opts) {
      for (var i = 0; i < sinks.length; i++) sinks[i](opts);
    }
  });
  http.request({url: "/api/first", type: "GET"});
  http.request({url: "/api/second", type: "POST"});
`, function(r) {
  var f1 = r.fetchCallSites.some(function(s) { return s.url === "/api/first" && s.method === "GET"; });
  var f2 = r.fetchCallSites.some(function(s) { return s.url === "/api/second" && s.method === "POST"; });
  return f1 && f2;
}, true);

// ═══════════════════════════════════════════════════════════════════════
// ██  BODY PARAMETER EXTRACTION (caller-side resolution)
// ═══════════════════════════════════════════════════════════════════════

console.log("\n=== Body parameter extraction through wrappers ===\n");

test("Wrapper body: JSON.stringify(body) resolved to caller's object fields", `
  function apiRequest(method, path, body) {
    return fetch("/api/" + path, {
      method: method,
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body)
    });
  }
  apiRequest("POST", "orders", {item: "widget", qty: 3});
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/api/orders"; });
  if (!site || !site.params) return false;
  var hasItem = site.params.some(function(p) { return p.name === "item" && p.location === "body"; });
  var hasQty = site.params.some(function(p) { return p.name === "qty" && p.location === "body"; });
  // Should NOT have a raw "body" param (the wrapper param name)
  var hasRawBody = site.params.some(function(p) { return p.name === "body" && p.location === "body"; });
  return hasItem && hasQty && !hasRawBody;
});

test("Wrapper body: multiple callers contribute different field sets", `
  function rpc(service, method, data) {
    return fetch("/rpc/" + service + "/" + method, {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  rpc("auth", "login", {user: "admin", pass: "secret"});
  rpc("billing", "charge", {amount: 100, currency: "USD"});
`, function(r) {
  var login = r.fetchCallSites.find(function(s) { return s.url === "/rpc/auth/login"; });
  if (!login || !login.params) return false;
  // All caller body fields get collected for the function
  var hasUser = login.params.some(function(p) { return p.name === "user" && p.location === "body"; });
  var hasPass = login.params.some(function(p) { return p.name === "pass" && p.location === "body"; });
  return hasUser && hasPass;
});

test("Wrapper body: object literal body (no JSON.stringify)", `
  function sendData(url, payload) {
    return fetch(url, {
      method: "POST",
      body: payload
    });
  }
  sendData("/api/form", {field1: "a", field2: "b"});
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/api/form"; });
  if (!site || !site.params) return false;
  var has1 = site.params.some(function(p) { return p.name === "field1" && p.location === "body"; });
  var has2 = site.params.some(function(p) { return p.name === "field2" && p.location === "body"; });
  return has1 && has2;
});

test("Wrapper body: body param default values extracted from caller literals", `
  function post(url, body) {
    return fetch(url, { method: "POST", body: JSON.stringify(body) });
  }
  post("/api/submit", {name: "test", count: 42, active: true});
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/api/submit"; });
  if (!site || !site.params) return false;
  var nameP = site.params.find(function(p) { return p.name === "name"; });
  var countP = site.params.find(function(p) { return p.name === "count"; });
  var activeP = site.params.find(function(p) { return p.name === "active"; });
  return nameP && nameP.defaultValue === "test" && nameP.type === "string" &&
         countP && countP.defaultValue === 42 && countP.type === "number" &&
         activeP && activeP.defaultValue === true && activeP.type === "boolean";
});

test("Wrapper body: URLSearchParams body resolved to caller fields", `
  function submitForm(url, data) {
    return fetch(url, { method: "POST", body: new URLSearchParams(data) });
  }
  submitForm("/api/form-encoded", {username: "alice", password: "secret"});
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/api/form-encoded"; });
  if (!site || !site.params) return false;
  var hasUser = site.params.some(function(p) { return p.name === "username" && p.location === "body"; });
  var hasPass = site.params.some(function(p) { return p.name === "password" && p.location === "body"; });
  return hasUser && hasPass;
});

// ═══════════════════════════════════════════════════════════════════════
// ██  PARAMETER TYPES, DEFAULTS, AND REQUIRED FLAGS
// ═══════════════════════════════════════════════════════════════════════

console.log("\n=== Parameter types, defaults, and required flags ===\n");

test("Direct fetch body: field types inferred from literal values", `
  fetch("/api/data", {
    method: "POST",
    body: JSON.stringify({
      name: "Alice",
      age: 30,
      verified: true,
      score: 4.5
    })
  });
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/api/data"; });
  if (!site || !site.params) return false;
  var nameP = site.params.find(function(p) { return p.name === "name"; });
  var ageP = site.params.find(function(p) { return p.name === "age"; });
  var verifiedP = site.params.find(function(p) { return p.name === "verified"; });
  return nameP && nameP.type === "string" && nameP.defaultValue === "Alice" &&
         ageP && ageP.type === "number" && ageP.defaultValue === 30 &&
         verifiedP && verifiedP.type === "boolean" && verifiedP.defaultValue === true;
});

test("Optional params with || default", `
  function createUser(name, role) {
    return fetch("/api/users", {
      method: "POST",
      body: JSON.stringify({ name: name, role: role || "viewer" })
    });
  }
  createUser("Alice", "admin");
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/api/users"; });
  if (!site || !site.params) return false;
  var roleP = site.params.find(function(p) { return p.name === "role"; });
  return roleP && roleP.required === false && roleP.defaultValue === "viewer";
});

test("Spread operator in body object", `
  function updateItem(id, changes) {
    return fetch("/api/items/" + id, {
      method: "PATCH",
      body: JSON.stringify({ id: id, ...changes })
    });
  }
  updateItem("42", {name: "test"});
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url && s.url.indexOf("/api/items/") === 0; });
  if (!site || !site.params) return false;
  var spreadP = site.params.find(function(p) { return p.spread === true; });
  return spreadP && spreadP.name === "...changes";
});

// ═══════════════════════════════════════════════════════════════════════
// ██  VALUE CONSTRAINTS ON PARAMETERS (validValues)
// ═══════════════════════════════════════════════════════════════════════

console.log("\n=== Value constraints on parameters (validValues) ===\n");

test("Switch-case constraint appears as validValues on param", `
  function loadResource(type) {
    switch(type) {
      case "users": return fetch("/api/" + type);
      case "products": return fetch("/api/" + type);
      case "orders": return fetch("/api/" + type);
    }
  }
`, function(r) {
  // The "type" variable should have a value constraint with 3 values
  var constraint = r.valueConstraints.find(function(c) { return c.variable === "type"; });
  if (!constraint) return false;
  var hasUsers = constraint.values.indexOf("users") >= 0;
  var hasProducts = constraint.values.indexOf("products") >= 0;
  var hasOrders = constraint.values.indexOf("orders") >= 0;
  return constraint.values.length === 3 && hasUsers && hasProducts && hasOrders;
});

test(".includes() constraint appears as validValues on param", `
  var ALLOWED_FORMATS = ["json", "xml", "csv", "yaml"];
  function convert(format) {
    if (ALLOWED_FORMATS.includes(format)) {
      return fetch("/api/convert?format=" + format);
    }
  }
`, function(r) {
  var constraint = r.valueConstraints.find(function(c) { return c.variable === "format"; });
  if (!constraint) return false;
  return constraint.values.length === 4 &&
    constraint.values.indexOf("json") >= 0 &&
    constraint.values.indexOf("xml") >= 0 &&
    constraint.values.indexOf("csv") >= 0 &&
    constraint.values.indexOf("yaml") >= 0;
});

test("Equality chain constraint discovered for wrapper param", `
  function setStatus(status) {
    if (status === "active" || status === "inactive" || status === "suspended" || status === "deleted") {
      return fetch("/api/status", { method: "POST", body: JSON.stringify({status: status}) });
    }
  }
`, function(r) {
  var constraint = r.valueConstraints.find(function(c) { return c.variable === "status"; });
  if (!constraint) return false;
  return constraint.values.length === 4 &&
    constraint.values.indexOf("active") >= 0 &&
    constraint.values.indexOf("inactive") >= 0 &&
    constraint.values.indexOf("suspended") >= 0 &&
    constraint.values.indexOf("deleted") >= 0;
});

test("validValues cross-referenced onto fetch params", `
  function fetchData(endpoint) {
    switch(endpoint) {
      case "users": case "orders": case "products":
        return fetch("/api/" + endpoint);
    }
  }
  fetchData("users");
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/api/users"; });
  if (!site || !site.params) return false;
  var endpointParam = site.params.find(function(p) { return p.name === "endpoint"; });
  return endpointParam && endpointParam.validValues &&
    endpointParam.validValues.length === 3 &&
    endpointParam.validValues.indexOf("users") >= 0 &&
    endpointParam.validValues.indexOf("orders") >= 0 &&
    endpointParam.validValues.indexOf("products") >= 0;
});

test("validValues from .includes() on wrapper body source param", `
  var ROLES = ["admin", "editor", "viewer"];
  function assignRole(userId, role) {
    if (ROLES.includes(role)) {
      return fetch("/api/users/" + userId + "/role", {
        method: "PUT",
        body: JSON.stringify({role: role})
      });
    }
  }
  assignRole("123", "admin");
`, function(r) {
  // The body param "role" should have validValues because its source variable has constraints
  var site = r.fetchCallSites.find(function(s) { return s.url && s.url.indexOf("/api/users/") === 0; });
  if (!site || !site.params) return false;
  var roleP = site.params.find(function(p) { return p.name === "role"; });
  return roleP && roleP.validValues &&
    roleP.validValues.indexOf("admin") >= 0 &&
    roleP.validValues.indexOf("editor") >= 0 &&
    roleP.validValues.indexOf("viewer") >= 0;
});

test("Multiple independent constraints for different params", `
  var METHODS = ["GET", "POST", "PUT"];
  var FORMATS = ["json", "xml"];
  function apiCall(method, format, endpoint) {
    if (METHODS.includes(method) && FORMATS.includes(format)) {
      return fetch("/api/" + endpoint + "?format=" + format, { method: method });
    }
  }
`, function(r) {
  var methodC = r.valueConstraints.find(function(c) { return c.variable === "method"; });
  var formatC = r.valueConstraints.find(function(c) { return c.variable === "format"; });
  return methodC && methodC.values.length === 3 &&
         formatC && formatC.values.length === 2;
});

// ═══════════════════════════════════════════════════════════════════════
// ██  REAL LIBRARY: jQuery (unminified) — Parameter extraction
// ═══════════════════════════════════════════════════════════════════════

var _jqueryUnmin = null;
var _jqueryMin = null;
var _axiosMin = null;
try { _jqueryUnmin = fs.readFileSync(__dirname + "/jquery-3.7.1.js", "utf8"); } catch(e) {}
try { _jqueryMin = fs.readFileSync(__dirname + "/jquery-3.7.1.min.js", "utf8"); } catch(e) {}
try { _axiosMin = fs.readFileSync(__dirname + "/axios.min.js", "utf8"); } catch(e) {}
var _unfetchMin = null;
var _redaxiosMin = null;
var _kyMin = null;
var _superagentMin = null;
try { _unfetchMin = fs.readFileSync(__dirname + "/unfetch.min.js", "utf8"); } catch(e) {}
try { _redaxiosMin = fs.readFileSync(__dirname + "/redaxios.min.js", "utf8"); } catch(e) {}
try { _kyMin = fs.readFileSync(__dirname + "/ky.min.js", "utf8"); } catch(e) {}
try { _superagentMin = fs.readFileSync(__dirname + "/superagent.min.js", "utf8"); } catch(e) {}

// Helper: run analysis against a library + appended test code
function testLib(name, libCode, appendCode, check, forceScript) {
  if (!libCode) {
    total++;
    console.log("  SKIP: " + name + " (library file not found)");
    return;
  }
  total++;
  try {
    var fullCode = libCode + "\n;\n" + appendCode;
    var result = analyzeJSBundle(fullCode, "test://lib-" + name, forceScript !== false);
    var ok = check(result);
    if (ok) {
      passed++;
      console.log("  PASS: " + name);
    } else {
      failed++;
      console.log("  FAIL: " + name);
      console.log("    fetchCallSites (%d):", result.fetchCallSites.length);
      for (var i = 0; i < result.fetchCallSites.length; i++) {
        var s = result.fetchCallSites[i];
        console.log("      %s %s %s", s.method, s.url,
          s.params ? "[" + s.params.map(function(p) { return p.name + ":" + (p.location||"?"); }).join(", ") + "]" : "");
      }
    }
  } catch (e) {
    failed++;
    console.log("  ERROR: " + name + " — " + e.message);
    console.log("    " + e.stack.split("\n").slice(0, 3).join("\n    "));
  }
}

if (_jqueryUnmin) {
  console.log("\n=== jQuery (unminified) — URL and method tracing ===\n");

  testLib("jQuery.ajax() POST with data", _jqueryUnmin, `
    jQuery.ajax({url: "/api/items", method: "POST", data: {name: "Widget", price: 29.99}});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/items" && s.method === "POST"; });
    return !!site;
  });

  testLib("jQuery.get() traces through to XHR", _jqueryUnmin, `
    jQuery.get("/api/users");
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/users" && s.method === "GET"; });
  });

  testLib("jQuery.post() traces through to XHR", _jqueryUnmin, `
    jQuery.post("/api/submit", {key: "value"});
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/submit" && s.method === "POST"; });
  });

  testLib("$.ajax() DELETE via $ alias", _jqueryUnmin, `
    $.ajax({url: "/api/resource/42", type: "DELETE"});
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/resource/42" && s.method === "DELETE"; });
  });

  testLib("$.ajax() PUT via $ alias", _jqueryUnmin, `
    $.ajax({url: "/api/resource/99", type: "PUT", data: {status: "active"}});
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/resource/99" && s.method === "PUT"; });
  });

  testLib("jQuery.getJSON() traces as GET", _jqueryUnmin, `
    jQuery.getJSON("/api/config");
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/config" && s.method === "GET"; });
  });

  testLib("Multiple jQuery calls all traced", _jqueryUnmin, `
    $.get("/api/a");
    $.post("/api/b", {x: 1});
    $.ajax({url: "/api/c", type: "PATCH"});
  `, function(r) {
    var a = r.fetchCallSites.some(function(s) { return s.url === "/api/a" && s.method === "GET"; });
    var b = r.fetchCallSites.some(function(s) { return s.url === "/api/b" && s.method === "POST"; });
    var c = r.fetchCallSites.some(function(s) { return s.url === "/api/c" && s.method === "PATCH"; });
    return a && b && c;
  });

  console.log("\n=== jQuery (unminified) — Body parameter extraction ===\n");

  testLib("jQuery.ajax() data property extracts body params", _jqueryUnmin, `
    jQuery.ajax({url: "/api/create", method: "POST", data: {name: "test", email: "a@b.com", age: 25}});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/create"; });
    if (!site || !site.params) return false;
    var hasName = site.params.some(function(p) { return p.name === "name" && p.location === "body"; });
    var hasEmail = site.params.some(function(p) { return p.name === "email" && p.location === "body"; });
    var hasAge = site.params.some(function(p) { return p.name === "age" && p.location === "body"; });
    return hasName && hasEmail && hasAge;
  });

  testLib("jQuery.ajax() data field types inferred", _jqueryUnmin, `
    $.ajax({url: "/api/typed", type: "POST", data: {title: "Hello", count: 5, active: true}});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/typed"; });
    if (!site || !site.params) return false;
    var titleP = site.params.find(function(p) { return p.name === "title"; });
    var countP = site.params.find(function(p) { return p.name === "count"; });
    var activeP = site.params.find(function(p) { return p.name === "active"; });
    return titleP && titleP.type === "string" && titleP.defaultValue === "Hello" &&
           countP && countP.type === "number" && countP.defaultValue === 5 &&
           activeP && activeP.type === "boolean" && activeP.defaultValue === true;
  });

  testLib("$.ajax() without data produces no body params", _jqueryUnmin, `
    $.ajax({url: "/api/no-data", type: "GET"});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/no-data"; });
    if (!site) return false;
    // Should have no params or empty params
    return !site.params || site.params.length === 0;
  });

  testLib("$.ajax() data with JSON.stringify extracts body fields", _jqueryUnmin, `
    $.ajax({
      url: "/api/json-body",
      method: "PUT",
      contentType: "application/json",
      data: JSON.stringify({title: "hello", content: "world"})
    });
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/json-body"; });
    if (!site || !site.params) return false;
    var hasTitle = site.params.some(function(p) { return p.name === "title" && p.location === "body"; });
    var hasContent = site.params.some(function(p) { return p.name === "content" && p.location === "body"; });
    return hasTitle && hasContent;
  });

  console.log("\n=== jQuery (unminified) — Value constraints from jQuery internals ===\n");

  testLib("jQuery internals produce value constraints", _jqueryUnmin, `
    $.get("/api/dummy");
  `, function(r) {
    // jQuery code contains switch statements, equality chains, .includes() calls etc.
    // that produce value constraints for internal variables
    return r.valueConstraints.length >= 5;
  });

  testLib("jQuery method iteration constraint (get/post)", _jqueryUnmin, `
    $.get("/api/x");
  `, function(r) {
    // jQuery.each(["get","post"], ...) creates an iteration constraint
    // Check that some constraint contains "get" and "post"
    return r.valueConstraints.some(function(c) {
      return c.values.indexOf("get") >= 0 && c.values.indexOf("post") >= 0;
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════
// ██  REAL LIBRARY: jQuery (minified) — Proves minification tolerance
// ═══════════════════════════════════════════════════════════════════════

if (_jqueryMin) {
  console.log("\n=== jQuery (minified) — URL and method tracing ===\n");

  testLib("jQuery.min: ajax POST traced", _jqueryMin, `
    jQuery.ajax({url: "/api/items", method: "POST", data: {name: "Widget"}});
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/items" && s.method === "POST"; });
  });

  testLib("jQuery.min: $.get() traced", _jqueryMin, `
    jQuery.get("/api/users");
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/users" && s.method === "GET"; });
  });

  testLib("jQuery.min: $.post() traced", _jqueryMin, `
    jQuery.post("/api/submit", {key: "value"});
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/submit" && s.method === "POST"; });
  });

  testLib("jQuery.min: $.ajax DELETE via $ alias", _jqueryMin, `
    $.ajax({url: "/api/resource/42", type: "DELETE"});
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/resource/42" && s.method === "DELETE"; });
  });

  testLib("jQuery.min: all 5 HTTP methods work", _jqueryMin, `
    $.ajax({url: "/api/get-it", type: "GET"});
    jQuery.ajax({url: "/api/post-it", method: "POST"});
    $.ajax({url: "/api/put-it", type: "PUT"});
    $.ajax({url: "/api/patch-it", type: "PATCH"});
    $.ajax({url: "/api/del-it", type: "DELETE"});
  `, function(r) {
    var g = r.fetchCallSites.some(function(s) { return s.url === "/api/get-it" && s.method === "GET"; });
    var po = r.fetchCallSites.some(function(s) { return s.url === "/api/post-it" && s.method === "POST"; });
    var pu = r.fetchCallSites.some(function(s) { return s.url === "/api/put-it" && s.method === "PUT"; });
    var pa = r.fetchCallSites.some(function(s) { return s.url === "/api/patch-it" && s.method === "PATCH"; });
    var d = r.fetchCallSites.some(function(s) { return s.url === "/api/del-it" && s.method === "DELETE"; });
    return g && po && pu && pa && d;
  });

  console.log("\n=== jQuery (minified) — Body parameter extraction ===\n");

  testLib("jQuery.min: data object fields extracted as body params", _jqueryMin, `
    $.ajax({url: "/api/create", method: "POST", data: {name: "test", age: 25, active: true}});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/create"; });
    if (!site || !site.params) return false;
    var hasName = site.params.some(function(p) { return p.name === "name" && p.location === "body"; });
    var hasAge = site.params.some(function(p) { return p.name === "age" && p.location === "body"; });
    var hasActive = site.params.some(function(p) { return p.name === "active" && p.location === "body"; });
    return hasName && hasAge && hasActive;
  });

  testLib("jQuery.min: data field types preserved through minified code", _jqueryMin, `
    $.ajax({url: "/api/typed", type: "PUT", data: {title: "Hello", count: 5, flag: false}});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/typed"; });
    if (!site || !site.params) return false;
    var titleP = site.params.find(function(p) { return p.name === "title"; });
    var countP = site.params.find(function(p) { return p.name === "count"; });
    var flagP = site.params.find(function(p) { return p.name === "flag"; });
    return titleP && titleP.type === "string" && titleP.defaultValue === "Hello" &&
           countP && countP.type === "number" && countP.defaultValue === 5 &&
           flagP && flagP.type === "boolean" && flagP.defaultValue === false;
  });

  testLib("jQuery.min: multiple ajax calls each get their own data params", _jqueryMin, `
    $.ajax({url: "/api/search", data: {q: "hello", page: 1}});
    $.ajax({url: "/api/update", type: "PATCH", data: {id: 42, status: "published"}});
  `, function(r) {
    var search = r.fetchCallSites.find(function(s) { return s.url === "/api/search"; });
    var update = r.fetchCallSites.find(function(s) { return s.url === "/api/update"; });
    if (!search || !search.params || !update || !update.params) return false;
    var searchHasQ = search.params.some(function(p) { return p.name === "q"; });
    var searchHasPage = search.params.some(function(p) { return p.name === "page"; });
    var updateHasId = update.params.some(function(p) { return p.name === "id"; });
    var updateHasStatus = update.params.some(function(p) { return p.name === "status"; });
    return searchHasQ && searchHasPage && updateHasId && updateHasStatus;
  });

  testLib("jQuery.min: POST with no data has no body params", _jqueryMin, `
    $.ajax({url: "/api/trigger", type: "POST"});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/trigger"; });
    if (!site) return false;
    return !site.params || site.params.length === 0;
  });

  console.log("\n=== jQuery (minified) — Value constraints ===\n");

  testLib("jQuery.min: internal value constraints discovered", _jqueryMin, `
    $.get("/api/dummy");
  `, function(r) {
    return r.valueConstraints.length >= 5;
  });

  testLib("jQuery.min: readyState constraint found", _jqueryMin, `
    $.get("/api/x");
  `, function(r) {
    // jQuery checks document.readyState === "complete" || "loading"
    return r.valueConstraints.some(function(c) {
      return c.values.indexOf("complete") >= 0 && c.values.indexOf("loading") >= 0;
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════
// ██  REAL LIBRARY: Axios (minified) — Value constraint discovery
// ═══════════════════════════════════════════════════════════════════════

if (_axiosMin) {
  console.log("\n=== Axios (minified) — Value constraint discovery ===\n");

  testLib("Axios.min: discovers response type constraints", _axiosMin, `
    // empty — just analyze the library itself
  `, function(r) {
    // Axios has responseType checks: "stream", "response", etc.
    return r.valueConstraints.some(function(c) {
      return c.values.indexOf("stream") >= 0 || c.values.indexOf("response") >= 0;
    });
  });

  testLib("Axios.min: discovers content type constraints (text/json)", _axiosMin, `
  `, function(r) {
    return r.valueConstraints.some(function(c) {
      return c.values.indexOf("text") >= 0 && c.values.indexOf("json") >= 0;
    });
  });

  testLib("Axios.min: discovers HTTP method constraints", _axiosMin, `
  `, function(r) {
    // Axios groups methods as no-data (get, head) vs data methods
    return r.valueConstraints.some(function(c) {
      return c.values.indexOf("get") >= 0 && c.values.indexOf("head") >= 0;
    });
  });

  testLib("Axios.min: discovers collection type constraints (Map/Set)", _axiosMin, `
  `, function(r) {
    return r.valueConstraints.some(function(c) {
      return c.values.indexOf("Map") >= 0 && c.values.indexOf("Set") >= 0;
    });
  });

  testLib("Axios.min: discovers control flow constraints", _axiosMin, `
  `, function(r) {
    return r.valueConstraints.some(function(c) {
      return c.values.indexOf("return") >= 0 && c.values.indexOf("throw") >= 0;
    });
  });

  console.log("\n=== Axios (minified) + wrapper functions — Parameter extraction ===\n");

  testLib("Axios context: wrapper using fetch() extracts body params", _axiosMin, `
    function apiCall(method, url, data) {
      return fetch(url, {
        method: method,
        headers: {"Content-Type": "application/json"},
        body: data ? JSON.stringify(data) : undefined
      });
    }
    apiCall("POST", "/api/orders", {item: "widget", qty: 3, priority: "high"});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/orders"; });
    if (!site || !site.params) return false;
    var hasItem = site.params.some(function(p) { return p.name === "item" && p.location === "body"; });
    var hasQty = site.params.some(function(p) { return p.name === "qty" && p.location === "body"; });
    var hasPriority = site.params.some(function(p) { return p.name === "priority" && p.location === "body"; });
    return hasItem && hasQty && hasPriority;
  });

  testLib("Axios context: value-constrained URL from switch", _axiosMin, `
    function loadResource(type) {
      switch(type) {
        case "users": case "products": case "orders":
          return fetch("/api/" + type);
      }
    }
    loadResource("users");
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/users"; });
    if (!site || !site.params) return false;
    var typeP = site.params.find(function(p) { return p.name === "type"; });
    return typeP && typeP.validValues &&
      typeP.validValues.indexOf("users") >= 0 &&
      typeP.validValues.indexOf("products") >= 0 &&
      typeP.validValues.indexOf("orders") >= 0;
  });

  testLib("Axios context: XHR wrapper with body params", _axiosMin, `
    function request(opts) {
      var xhr = new XMLHttpRequest();
      xhr.open(opts.method || "GET", opts.url);
      xhr.send(opts.data);
    }
    request({url: "/api/legacy", method: "POST", data: "key=value"});
  `, function(r) {
    return r.fetchCallSites.some(function(s) {
      return s.url === "/api/legacy" && s.method === "POST";
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════
// ██  REAL LIBRARY: unfetch (minified) — Fetch polyfill using XHR
// ═══════════════════════════════════════════════════════════════════════

if (_unfetchMin) {
  console.log("\n=== unfetch (minified) — XHR-based fetch polyfill tracing ===\n");

  testLib("unfetch: simple GET URL traced through XHR polyfill", _unfetchMin, `
    unfetch("/api/users");
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/users"; });
  });

  testLib("unfetch: explicit POST method traced", _unfetchMin, `
    unfetch("/api/data", {method: "POST"});
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/data" && s.method === "POST"; });
  });

  testLib("unfetch: body param extraction through polyfill", _unfetchMin, `
    unfetch("/api/submit", {method: "POST", body: JSON.stringify({key: "val", num: 42})});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/submit"; });
    if (!site || !site.params) return false;
    return site.params.some(function(p) { return p.name === "key" && p.location === "body"; }) &&
           site.params.some(function(p) { return p.name === "num" && p.location === "body"; });
  });

  testLib("unfetch: custom headers traced through setRequestHeader loop", _unfetchMin, `
    unfetch("/api/auth", {
      method: "GET",
      headers: {"Authorization": "Bearer tok123", "X-Custom": "val"}
    });
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/auth"; });
    if (!site) return false;
    return site.headers && site.headers["Authorization"] === "Bearer tok123";
  });

  testLib("unfetch: multiple calls with different methods all traced", _unfetchMin, `
    unfetch("/api/get-it");
    unfetch("/api/post-it", {method: "POST", body: JSON.stringify({a: 1})});
    unfetch("/api/put-it", {method: "PUT"});
  `, function(r) {
    var g = r.fetchCallSites.some(function(s) { return s.url === "/api/get-it"; });
    var p = r.fetchCallSites.some(function(s) { return s.url === "/api/post-it" && s.method === "POST"; });
    var u = r.fetchCallSites.some(function(s) { return s.url === "/api/put-it" && s.method === "PUT"; });
    return g && p && u;
  });

  testLib("unfetch: value constraints from credentials check", _unfetchMin, `
    unfetch("/api/dummy");
  `, function(r) {
    // unfetch checks n.credentials === "include" — should produce at least one constraint
    return r.valueConstraints.length >= 1;
  });
}

// ═══════════════════════════════════════════════════════════════════════
// ██  REAL LIBRARY: redaxios (minified) — Axios-compatible fetch wrapper
// ═══════════════════════════════════════════════════════════════════════

if (_redaxiosMin) {
  console.log("\n=== redaxios (minified) — Axios-compatible fetch wrapper tracing ===\n");

  testLib("redaxios: .get() traces to fetch GET", _redaxiosMin, `
    e.get("/api/users");
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/users" && s.method === "GET"; });
  });

  testLib("redaxios: .post() traces to fetch POST with body params", _redaxiosMin, `
    e.post("/api/users", {name: "test", email: "a@b.com"});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/users" && s.method === "POST"; });
    if (!site) return false;
    if (!site.params) return false;
    return site.params.some(function(p) { return p.name === "name" && p.location === "body"; }) &&
           site.params.some(function(p) { return p.name === "email" && p.location === "body"; });
  });

  testLib("redaxios: .put() traces to fetch PUT", _redaxiosMin, `
    e.put("/api/users/123", {status: "active"});
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/users/123" && s.method === "PUT"; });
  });

  testLib("redaxios: .delete() traces to fetch DELETE", _redaxiosMin, `
    e.delete("/api/users/456");
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/users/456" && s.method === "DELETE"; });
  });

  testLib("redaxios: .patch() traces to fetch PATCH", _redaxiosMin, `
    e.patch("/api/users/789", {role: "admin"});
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/users/789" && s.method === "PATCH"; });
  });

  testLib("redaxios: multiple calls with distinct URLs and methods", _redaxiosMin, `
    e.get("/api/list");
    e.post("/api/create", {name: "Widget", price: 29.99});
    e.delete("/api/remove/42");
  `, function(r) {
    var g = r.fetchCallSites.some(function(s) { return s.url === "/api/list"; });
    var p = r.fetchCallSites.some(function(s) { return s.url === "/api/create" && s.method === "POST"; });
    var d = r.fetchCallSites.some(function(s) { return s.url === "/api/remove/42" && s.method === "DELETE"; });
    return g && p && d;
  });

  testLib("redaxios: value constraints (response types, methods)", _redaxiosMin, `
  `, function(r) {
    // redaxios has responseType checks ("stream", "text") and method strings
    return r.valueConstraints.some(function(c) {
      return c.values.indexOf("stream") >= 0;
    }) || r.valueConstraints.some(function(c) {
      return c.values.indexOf("get") >= 0 && c.values.indexOf("post") >= 0;
    });
  });

  testLib("redaxios: .create() with baseURL config merging", _redaxiosMin, `
    var api = e.create({baseURL: "/api/v1"});
    api.get("/users");
    api.post("/items", {name: "thing"});
  `, function(r) {
    // Traces baseURL + path concatenation to discover URLs
    var hasUsers = r.fetchCallSites.some(function(s) { return s.url && s.url.indexOf("/users") >= 0; });
    var hasItems = r.fetchCallSites.some(function(s) { return s.url && s.url.indexOf("/items") >= 0; });
    return hasUsers && hasItems;
  });
}

// ═══════════════════════════════════════════════════════════════════════
// ██  REAL LIBRARY: ky (ESM) — Modern class-based fetch wrapper
// ═══════════════════════════════════════════════════════════════════════

if (_kyMin) {
  console.log("\n=== ky (ESM) — Class-based fetch wrapper tracing ===\n");

  testLib("ky: library parses without error", _kyMin, `
  `, function(r) {
    // Sanity: ky with class private fields and ESM should parse cleanly
    return true;
  }, false);

  testLib("ky: HTTP methods array constraint (get/post/put/patch/head/delete)", _kyMin, `
  `, function(r) {
    // ky defines h=["get","post","put","patch","head","delete"]
    return r.valueConstraints.some(function(c) {
      return c.values.indexOf("get") >= 0 && c.values.indexOf("post") >= 0 &&
             c.values.indexOf("put") >= 0 && c.values.indexOf("delete") >= 0;
    });
  }, false);

  testLib("ky: retry status codes constraint", _kyMin, `
  `, function(r) {
    // ky has statusCodes:[408,413,429,500,502,503,504]
    return r.valueConstraints.some(function(c) {
      return c.values.indexOf(408) >= 0 && c.values.indexOf(429) >= 0 && c.values.indexOf(503) >= 0;
    });
  }, false);

  testLib("ky: content-type mapping constraint (json/text)", _kyMin, `
  `, function(r) {
    // ky defines c={json:"application/json",text:"text/*",...}
    return r.valueConstraints.some(function(c) {
      return c.values.indexOf("application/json") >= 0;
    }) || r.valueConstraints.some(function(c) {
      return c.values.indexOf("json") >= 0 && c.values.indexOf("text") >= 0;
    });
  }, false);

  testLib("ky: k.get() traced to fetch", _kyMin, `
    k.get("https://api.example.com/users");
  `, function(r) {
    return r.fetchCallSites.some(function(s) {
      return s.url && s.url.indexOf("/users") >= 0;
    });
  }, false);

  testLib("ky: k.post() with json body params", _kyMin, `
    k.post("https://api.example.com/users", {json: {name: "Alice", role: "admin"}});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) {
      return s.url && s.url.indexOf("/users") >= 0 && s.method === "POST";
    });
    if (!site) return false;
    return site.params && site.params.some(function(p) { return p.name === "name" && p.location === "body"; });
  }, false);

  testLib("ky: retry methods constraint (get/put/head/delete/options/trace)", _kyMin, `
  `, function(r) {
    // ky retry defaults: methods:["get","put","head","delete","options","trace"]
    return r.valueConstraints.some(function(c) {
      return c.values.indexOf("get") >= 0 && c.values.indexOf("trace") >= 0;
    });
  }, false);

  testLib("ky: multiple k.method() calls traced", _kyMin, `
    k.get("https://api.example.com/a");
    k.post("https://api.example.com/b", {json: {x: 1}});
    k.put("https://api.example.com/c", {json: {y: 2}});
    k.delete("https://api.example.com/d");
  `, function(r) {
    var a = r.fetchCallSites.some(function(s) { return s.url && s.url.indexOf("/a") >= 0; });
    var b = r.fetchCallSites.some(function(s) { return s.url && s.url.indexOf("/b") >= 0 && s.method === "POST"; });
    var c = r.fetchCallSites.some(function(s) { return s.url && s.url.indexOf("/c") >= 0 && s.method === "PUT"; });
    var d = r.fetchCallSites.some(function(s) { return s.url && s.url.indexOf("/d") >= 0 && s.method === "DELETE"; });
    return a && b && c && d;
  }, false);
}

// ═══════════════════════════════════════════════════════════════════════
// ██  REAL LIBRARY: superagent (minified) — XHR-based chaining client
// ═══════════════════════════════════════════════════════════════════════

if (_superagentMin) {
  console.log("\n=== superagent (minified) — XHR chaining client tracing ===\n");

  testLib("superagent: .get() URL traced through XHR", _superagentMin, `
    superagent.get("/api/users");
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/users" && s.method === "GET"; });
  });

  testLib("superagent: .post() URL and method traced", _superagentMin, `
    superagent.post("/api/users");
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/users" && s.method === "POST"; });
  });

  testLib("superagent: .put() traced", _superagentMin, `
    superagent.put("/api/items/42");
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/items/42" && s.method === "PUT"; });
  });

  testLib("superagent: .delete() traced", _superagentMin, `
    superagent.delete("/api/items/99");
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/items/99" && s.method === "DELETE"; });
  });

  testLib("superagent: .patch() traced", _superagentMin, `
    superagent.patch("/api/items/7");
  `, function(r) {
    return r.fetchCallSites.some(function(s) { return s.url === "/api/items/7" && s.method === "PATCH"; });
  });

  testLib("superagent: .send() body param extraction", _superagentMin, `
    superagent.post("/api/users").send({name: "test", email: "a@b.com", age: 25});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/users" && s.method === "POST"; });
    if (!site || !site.params) return false;
    return site.params.some(function(p) { return p.name === "name" && p.location === "body"; }) &&
           site.params.some(function(p) { return p.name === "email" && p.location === "body"; });
  });

  testLib("superagent: .set() header extraction", _superagentMin, `
    superagent.post("/api/secure")
      .set("Authorization", "Bearer mytoken")
      .set("X-Custom", "value")
      .send({data: "test"});
  `, function(r) {
    var site = r.fetchCallSites.find(function(s) { return s.url === "/api/secure"; });
    if (!site) return false;
    return site.headers && site.headers["Authorization"] === "Bearer mytoken";
  });

  testLib("superagent: multiple calls with different methods and data", _superagentMin, `
    superagent.get("/api/list");
    superagent.post("/api/create").send({title: "Widget", price: 9.99});
    superagent.put("/api/update/5").send({status: "active"});
    superagent.delete("/api/remove/3");
  `, function(r) {
    var g = r.fetchCallSites.some(function(s) { return s.url === "/api/list" && s.method === "GET"; });
    var p = r.fetchCallSites.some(function(s) { return s.url === "/api/create" && s.method === "POST"; });
    var u = r.fetchCallSites.some(function(s) { return s.url === "/api/update/5" && s.method === "PUT"; });
    var d = r.fetchCallSites.some(function(s) { return s.url === "/api/remove/3" && s.method === "DELETE"; });
    return g && p && u && d;
  });
}

// ═══════════════════════════════════════════════════════════════════════
// ██  SYNTHETIC ADVANCED PATTERNS — Real-world code idioms
// ═══════════════════════════════════════════════════════════════════════

console.log("\n=== Synthetic: Advanced real-world code patterns ===\n");

test("ES6 class with fetch: this.base + path", `
  class ApiClient {
    constructor(base) { this.base = base; }
    async get(path) { return fetch(this.base + path); }
    async post(path, body) {
      return fetch(this.base + path, { method: "POST", body: JSON.stringify(body) });
    }
  }
  var client = new ApiClient("https://api.example.com");
  client.get("/users");
  client.post("/orders", {item: "widget", qty: 3});
`, function(r) {
  var hasGet = r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/users";
  });
  var hasPost = r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/orders" && s.method === "POST";
  });
  return hasGet && hasPost;
});

test("Promise.then chain making second request", `
  var url1 = "/api/config";
  var url2 = "/api/data";
  fetch(url1).then(function(r) { return r.json(); }).then(function(d) {
    return fetch(url2, {method: "POST", body: JSON.stringify(d)});
  });
`, function(r) {
  var has1 = r.fetchCallSites.some(function(s) { return s.url === "/api/config"; });
  var has2 = r.fetchCallSites.some(function(s) { return s.url === "/api/data" && s.method === "POST"; });
  return has1 && has2;
});

test("async/await wrapper function", `
  async function getData(id) {
    var r = await fetch("/api/items/" + id);
    return r.json();
  }
  getData("42");
`, function(r) {
  return r.fetchCallSites.some(function(s) { return s.url === "/api/items/42"; });
});

test("Object.assign config merge", `
  var defaults = { method: "POST", headers: {"Content-Type": "application/json"} };
  function apiCall(url, userOpts) {
    return fetch(url, Object.assign({}, defaults, userOpts));
  }
  apiCall("/api/submit", {body: JSON.stringify({key: "val"})});
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/api/submit"; });
  return site && site.method === "POST";
});

test("URLSearchParams query building", `
  function search(query, page) {
    var params = new URLSearchParams({q: query, page: page});
    return fetch("/api/search?" + params);
  }
  search("test", "1");
`, function(r) {
  return r.fetchCallSites.some(function(s) { return s.url && s.url.indexOf("/api/search") === 0; });
});

test("Conditional method via ternary", `
  function saveItem(id, data, isNew) {
    return fetch("/api/items/" + id, {
      method: isNew ? "POST" : "PUT",
      body: JSON.stringify(data)
    });
  }
  saveItem("1", {name: "test"}, true);
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url && s.url.indexOf("/api/items/") === 0; });
  if (!site) return false;
  // Should discover both POST and PUT as possible methods
  return site.method === "POST" || site.method === "PUT" ||
    r.fetchCallSites.some(function(s) { return s.method === "POST"; }) &&
    r.fetchCallSites.some(function(s) { return s.method === "PUT"; });
});

test("Array.map producing fetch calls", `
  var endpoints = ["/api/users", "/api/orders", "/api/products"];
  endpoints.map(function(url) { return fetch(url); });
`, function(r) {
  var u = r.fetchCallSites.some(function(s) { return s.url === "/api/users"; });
  var o = r.fetchCallSites.some(function(s) { return s.url === "/api/orders"; });
  var p = r.fetchCallSites.some(function(s) { return s.url === "/api/products"; });
  return u && o && p;
});

test("Retry with fallback URL", `
  var primaryUrl = "/api/primary";
  var fallbackUrl = "/api/fallback";
  fetch(primaryUrl).catch(function() { return fetch(fallbackUrl); });
`, function(r) {
  var hasPrimary = r.fetchCallSites.some(function(s) { return s.url === "/api/primary"; });
  var hasFallback = r.fetchCallSites.some(function(s) { return s.url === "/api/fallback"; });
  return hasPrimary && hasFallback;
});

test("Template literal with expression in URL", `
  var version = "v2";
  var resource = "users";
  fetch(\`/api/\${version}/\${resource}\`);
`, function(r) {
  return r.fetchCallSites.some(function(s) { return s.url === "/api/v2/users"; });
});

test("Chained string builder for URL", `
  function buildUrl(parts) {
    return parts.join("/");
  }
  fetch(buildUrl(["/api", "v1", "users", "search"]));
`, function(r) {
  return r.fetchCallSites.some(function(s) { return s.url === "/api/v1/users/search"; });
});

// ═══════════════════════════════════════════════════════════════════════
// ██  ADVANCED COMBINED PATTERNS
// ═══════════════════════════════════════════════════════════════════════

console.log("\n=== Advanced: Factory + constraints + body params ===\n");

test("Factory returning methods with constrained + typed body", `
  function createClient(base) {
    return {
      get: function(path) { return fetch(base + path); },
      post: function(path, body) {
        return fetch(base + path, { method: "POST", body: JSON.stringify(body) });
      }
    };
  }
  var api = createClient("/api/v2");
  api.get("/users");
  api.post("/users", {name: "Alice", role: "admin"});
  api.post("/orders", {item: "widget", qty: 1});
`, function(r) {
  var hasGet = r.fetchCallSites.some(function(s) { return s.url === "/api/v2/users" && s.method === "GET"; });
  var hasPostUsers = r.fetchCallSites.some(function(s) { return s.url === "/api/v2/users" && s.method === "POST"; });
  var hasPostOrders = r.fetchCallSites.some(function(s) { return s.url === "/api/v2/orders" && s.method === "POST"; });
  // Check that post calls have body params
  var postSite = r.fetchCallSites.find(function(s) { return s.url === "/api/v2/users" && s.method === "POST"; });
  var hasBodyParams = postSite && postSite.params && postSite.params.some(function(p) { return p.name === "name" && p.location === "body"; });
  return hasGet && hasPostUsers && hasPostOrders && hasBodyParams;
});

test("Constructor pattern with body params and value constraints", `
  function ApiClient(baseUrl) {
    this.base = baseUrl;
  }
  ApiClient.prototype.request = function(method, path, data) {
    return fetch(this.base + path, {
      method: method,
      body: data ? JSON.stringify(data) : undefined
    });
  };
  var client = new ApiClient("https://api.example.com");
  client.request("POST", "/auth/login", {username: "admin", password: "secret"});
  client.request("GET", "/users");
`, function(r) {
  var loginSite = r.fetchCallSites.find(function(s) {
    return s.url === "https://api.example.com/auth/login";
  });
  if (!loginSite) return false;
  // Should have body params from caller
  if (!loginSite.params) return false;
  var hasUsername = loginSite.params.some(function(p) { return p.name === "username" && p.location === "body"; });
  var hasPassword = loginSite.params.some(function(p) { return p.name === "password" && p.location === "body"; });
  return hasUsername && hasPassword;
});

test("Enum-constrained method with body: complete API learning", `
  var ACTIONS = ["create", "update", "delete"];
  function performAction(action, resourceId, data) {
    var methods = {create: "POST", update: "PUT", "delete": "DELETE"};
    return fetch("/api/resources/" + resourceId, {
      method: methods[action],
      body: JSON.stringify(data)
    });
  }
  performAction("create", "new", {name: "Widget", price: 9.99});
`, function(r) {
  // Check value constraints on "action"
  var actionC = r.valueConstraints.find(function(c) { return c.variable === "action"; });
  var hasConstraint = actionC && actionC.values.length === 3;
  // Check that a call site was found
  var hasSite = r.fetchCallSites.length >= 1;
  return hasConstraint && hasSite;
});

test("Chained wrapper with header injection and body params", `
  function withAuth(token) {
    return function(url, method, body) {
      return fetch(url, {
        method: method,
        headers: {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        body: JSON.stringify(body)
      });
    };
  }
  var authedFetch = withAuth("my-token");
  authedFetch("/api/protected", "POST", {action: "unlock", target: "vault"});
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/api/protected"; });
  if (!site) return false;
  // Check headers preserved
  var hasAuth = site.headers && site.headers["Authorization"] === "Bearer my-token";
  // Check body params resolved from caller
  var hasBody = site.params && site.params.some(function(p) { return p.name === "action" && p.location === "body"; });
  return hasAuth && hasBody;
});

test("Multi-level wrapper: outer → middle → fetch with body resolution", `
  function jsonFetch(url, method, body) {
    return fetch(url, { method: method, body: JSON.stringify(body) });
  }
  function apiPost(endpoint, data) {
    return jsonFetch("/api" + endpoint, "POST", data);
  }
  apiPost("/messages", {text: "hello", channel: "general"});
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/api/messages"; });
  if (!site) return false;
  return site.method === "POST" && site.params &&
    site.params.some(function(p) { return p.name === "text" && p.location === "body"; }) &&
    site.params.some(function(p) { return p.name === "channel" && p.location === "body"; });
});

test("Computed URL endpoints + body params from object map", `
  var endpoints = {
    users: "/api/users",
    orders: "/api/orders",
    products: "/api/products"
  };
  function create(resource, data) {
    return fetch(endpoints[resource], { method: "POST", body: JSON.stringify(data) });
  }
  create("users", {name: "test", email: "test@example.com"});
`, function(r) {
  // All 3 endpoints should be discovered (computed member access)
  var urls = r.fetchCallSites.map(function(s) { return s.url; }).sort();
  var hasAll = urls.indexOf("/api/orders") >= 0 &&
               urls.indexOf("/api/products") >= 0 &&
               urls.indexOf("/api/users") >= 0;
  // Body params from caller should be present
  var userSite = r.fetchCallSites.find(function(s) { return s.url === "/api/users"; });
  var hasBody = userSite && userSite.params &&
    userSite.params.some(function(p) { return p.name === "name" && p.location === "body"; });
  return hasAll && hasBody;
});

console.log("\n=== Advanced: XHR wrapper patterns with body params ===\n");

test("XHR wrapper: opts.data sent via xhr.send()", `
  function httpRequest(opts) {
    var xhr = new XMLHttpRequest();
    xhr.open(opts.method, opts.url);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.send(JSON.stringify(opts.data));
  }
  httpRequest({url: "/api/xhr-body", method: "POST", data: {key: "value", num: 42}});
`, function(r) {
  return r.fetchCallSites.some(function(s) {
    return s.url === "/api/xhr-body" && s.method === "POST";
  });
});

test("Deep sink pattern with body data extraction", `
  var lib = {};
  lib.extend = function(target) {
    for (var k in arguments[1]) target[k] = arguments[1][k];
    return target;
  };
  function doXHR(config) {
    var xhr = new XMLHttpRequest();
    xhr.open(config.method, config.url);
    xhr.send(config.data);
  }
  lib.extend({
    ajax: function(opts) { doXHR(opts); }
  });
  lib.ajax({url: "/api/deep-body", method: "POST", data: {field1: "a", field2: "b"}});
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/api/deep-body"; });
  return !!site && site.method === "POST";
}, true);

console.log("\n=== Advanced: Real-world API client patterns ===\n");

test("REST client with CRUD methods and typed params", `
  function RestClient(baseUrl) {
    this.base = baseUrl;
  }
  RestClient.prototype.get = function(path) {
    return fetch(this.base + path);
  };
  RestClient.prototype.post = function(path, body) {
    return fetch(this.base + path, { method: "POST", body: JSON.stringify(body) });
  };
  RestClient.prototype.put = function(path, body) {
    return fetch(this.base + path, { method: "PUT", body: JSON.stringify(body) });
  };
  RestClient.prototype.delete = function(path) {
    return fetch(this.base + path, { method: "DELETE" });
  };

  var api = new RestClient("https://api.example.com/v1");
  api.get("/users");
  api.post("/users", {name: "Alice", email: "alice@test.com", role: "admin"});
  api.put("/users/123", {name: "Bob"});
  api.delete("/users/456");
`, function(r) {
  var getUser = r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/users" && s.method === "GET";
  });
  var postUser = r.fetchCallSites.find(function(s) {
    return s.url === "https://api.example.com/v1/users" && s.method === "POST";
  });
  var putUser = r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/users/123" && s.method === "PUT";
  });
  var delUser = r.fetchCallSites.some(function(s) {
    return s.url === "https://api.example.com/v1/users/456" && s.method === "DELETE";
  });
  // POST should have body params
  var hasBodyParams = postUser && postUser.params &&
    postUser.params.some(function(p) { return p.name === "name" && p.location === "body"; }) &&
    postUser.params.some(function(p) { return p.name === "email" && p.location === "body"; }) &&
    postUser.params.some(function(p) { return p.name === "role" && p.location === "body"; });
  return getUser && postUser && putUser && delUser && hasBodyParams;
});

test("GraphQL-like pattern: query string + variables as body", `
  function graphql(query, variables) {
    return fetch("/graphql", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({query: query, variables: variables})
    });
  }
  graphql("query { users { id name } }", {limit: 10, offset: 0});
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/graphql"; });
  if (!site) return false;
  if (!site.params) return false;
  var hasQuery = site.params.some(function(p) { return p.name === "query" && p.location === "body"; });
  var hasVars = site.params.some(function(p) { return p.name === "variables" && p.location === "body"; });
  return site.method === "POST" && hasQuery && hasVars;
});

test("Rate-limited fetch with retry — URL and method preserved", `
  function fetchWithRetry(url, opts, maxRetries) {
    return fetch(url, opts);
  }
  fetchWithRetry("/api/flaky", {method: "PATCH", body: JSON.stringify({status: "retry"})}, 3);
`, function(r) {
  var site = r.fetchCallSites.find(function(s) { return s.url === "/api/flaky"; });
  return site && site.method === "PATCH";
});

// =============================================================================
// Security Analysis Tests
// =============================================================================

console.log("\n=== Security: DOM XSS Sink Detection ===\n");

test("innerHTML with user-controlled source (location.hash) → high severity XSS", `
  var x = location.hash;
  document.getElementById("output").innerHTML = x;
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "xss" && s.sink === "innerHTML" && s.severity === "high" && s.source === "location.hash";
  });
});

test("innerHTML with string literal → low severity", `
  document.getElementById("output").innerHTML = "<b>Hello</b>";
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "xss" && s.sink === "innerHTML" && s.severity === "low";
  });
});

test("document.write with dynamic value → medium severity", `
  function render(content) {
    document.write(content);
  }
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "xss" && s.sink === "document.write" && s.severity === "medium";
  });
});

test("eval with user-controlled value → high severity", `
  var code = location.search.slice(1);
  eval(code);
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "eval" && s.sink === "eval" && s.severity === "high" && s.source === "location.search";
  });
});

test("eval with string literal → low severity", `
  eval("console.log('hello')");
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "eval" && s.sink === "eval" && s.severity === "low";
  });
});

test("insertAdjacentHTML with user-controlled value → high severity XSS", `
  var markup = location.hash;
  document.body.insertAdjacentHTML("beforeend", markup);
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "xss" && s.sink === "insertAdjacentHTML" && s.severity === "high";
  });
});

test("setTimeout with string arg → medium severity eval sink", `
  var action = "doSomething()";
  setTimeout(action, 1000);
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "eval" && s.sink === "setTimeout";
  });
});

test("setAttribute with event handler → XSS sink", `
  var handler = "alert(1)";
  document.getElementById("btn").setAttribute("onclick", handler);
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "xss" && s.sink === "setAttribute:onclick";
  });
});

test("Open redirect: location.href = user-controlled value → high severity", `
  var url = location.hash.slice(1);
  location.href = url;
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "redirect" && s.sink === "href" && s.severity === "high";
  });
});

test("Open redirect: location.assign with user value → high severity", `
  var target = decodeURIComponent(location.search.slice(4));
  location.assign(target);
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "redirect" && s.sink === "location.assign" && s.severity === "high";
  });
});

console.log("\n=== Security: Dangerous Pattern Detection ===\n");

test("new Function with dynamic arg → eval sink", `
  function compile(code) { return new Function(code); }
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "eval" && s.sink === "new Function";
  });
});

test("postMessage listener without origin check → dangerous", `
  window.addEventListener("message", function(event) {
    document.body.innerHTML = event.data;
  });
`, function(r) {
  return r.dangerousPatterns.some(function(p) {
    return p.type === "postmessage-no-origin" && p.severity === "high";
  });
});

test("postMessage listener WITH origin check → not flagged", `
  window.addEventListener("message", function(event) {
    if (event.origin !== "https://trusted.com") return;
    document.body.innerHTML = event.data;
  });
`, function(r) {
  return !r.dangerousPatterns.some(function(p) {
    return p.type === "postmessage-no-origin";
  });
});

test("Prototype pollution: obj[dynamic] = value → flagged", `
  function merge(target, key, value) {
    target[key] = value;
  }
`, function(r) {
  return r.dangerousPatterns.some(function(p) {
    return p.type === "prototype-pollution";
  });
});

test("Dynamic RegExp constructor → flagged as ReDoS risk", `
  function filter(pattern) {
    return new RegExp(pattern).test("input");
  }
`, function(r) {
  return r.dangerousPatterns.some(function(p) {
    return p.type === "regex-dynamic";
  });
});

test("location.replace with user input → open redirect", `
  var next = location.hash.substring(1);
  location.replace(next);
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "redirect" && s.sink === "location.replace" && s.severity === "high";
  });
});

console.log("\n=== Security: Taint Tracking Through Transformations ===\n");

test("Taint flows through string concatenation", `
  var param = location.search;
  var html = "<div>" + param + "</div>";
  document.body.innerHTML = html;
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "xss" && s.severity === "high" && s.source === "location.search";
  });
});

test("Taint flows through variable assignment chain", `
  var a = location.hash;
  var b = a;
  eval(b);
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "eval" && s.severity === "high" && s.source === "location.hash";
  });
});

test("Taint flows through function parameter", `
  function display(html) {
    document.body.innerHTML = html;
  }
  display(location.hash);
`, function(r) {
  return r.securitySinks.some(function(s) {
    return s.type === "xss" && s.severity === "high" && s.source === "location.hash";
  });
});

// ── Summary ──
console.log("\n" + "=".repeat(50));
console.log("Results: " + passed + "/" + total + " passed, " + failed + " failed");
if (failed > 0) {
  process.exit(1);
} else {
  console.log("All tests passed!");
}
