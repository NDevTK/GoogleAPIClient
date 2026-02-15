// lib/ast.js — AST-based JS bundle analysis engine
// Parses page JavaScript using acorn to extract proto stubs, fetch call sites,
// enums, API routes, and source map URLs.

/**
 * Analyze a JS bundle source for API-relevant patterns.
 * @param {string} code - JavaScript source text
 * @param {string} sourceUrl - URL the script was loaded from
 * @returns {object} Analysis results
 */
function analyzeJSBundle(code, sourceUrl) {
  var result = {
    sourceUrl: sourceUrl,
    protoEnums: [],
    protoFieldMaps: [],
    fetchCallSites: [],
    enumConstants: [],
    apiRoutes: [],
    stringLiterals: [],
    sourceMapUrl: extractSourceMapUrl(code),
  };

  var ast = null;
  try {
    ast = acorn.parse(code, { ecmaVersion: "latest", sourceType: "module" });
  } catch (_) {
    try {
      ast = acorn.parse(code, { ecmaVersion: "latest", sourceType: "script" });
    } catch (_2) {
      return result;
    }
  }

  acorn.walk.simple(ast, {
    ObjectExpression: function(node) {
      detectEnumObject(node, result);
    },
    CallExpression: function(node) {
      detectFetchCall(node, result);
    },
    AssignmentExpression: function(node) {
      detectProtoFieldAssignment(node, result);
    },
    Literal: function(node) {
      detectApiStringLiteral(node, result);
    },
    TemplateLiteral: function(node) {
      detectApiTemplateLiteral(node, result);
    },
  });

  return result;
}

/**
 * Detect enum-like objects: all values are sequential integers 0..N,
 * or reverse maps (int keys, string values).
 */
function detectEnumObject(node, result) {
  var props = node.properties;
  if (!props || props.length < 2 || props.length > 200) return;

  // Check if all values are numeric literals
  var allNumeric = true;
  var allString = true;
  var numericValues = [];
  var stringKeys = [];
  var numericKeys = [];

  for (var i = 0; i < props.length; i++) {
    var prop = props[i];
    if (prop.computed || prop.kind !== "init") return;

    var val = prop.value;
    if (val.type === "Literal") {
      if (typeof val.value === "number" && Number.isInteger(val.value)) {
        numericValues.push(val.value);
        allString = false;
      } else if (typeof val.value === "string") {
        allNumeric = false;
      } else {
        allNumeric = false;
        allString = false;
      }
    } else if (val.type === "UnaryExpression" && val.operator === "-" &&
               val.argument.type === "Literal" && typeof val.argument.value === "number") {
      numericValues.push(-val.argument.value);
      allString = false;
    } else {
      allNumeric = false;
      allString = false;
    }

    // Collect key info
    var key = prop.key;
    if (key.type === "Literal") {
      if (typeof key.value === "number") numericKeys.push(key.value);
      else stringKeys.push(String(key.value));
    } else if (key.type === "Identifier") {
      stringKeys.push(key.name);
    }
  }

  // Proto enum pattern: string keys → sequential integer values starting at 0
  if (allNumeric && numericValues.length >= 2) {
    var sorted = numericValues.slice().sort(function(a, b) { return a - b; });
    var isSequential = sorted[0] === 0;
    for (var s = 1; s < sorted.length && isSequential; s++) {
      if (sorted[s] !== sorted[s - 1] + 1) isSequential = false;
    }
    if (isSequential && stringKeys.length === numericValues.length) {
      var values = {};
      for (var e = 0; e < props.length; e++) {
        var k = props[e].key;
        var v = props[e].value;
        var kName = k.type === "Identifier" ? k.name : String(k.value);
        var vVal = v.type === "Literal" ? v.value : (v.type === "UnaryExpression" ? -v.argument.value : 0);
        values[kName] = vVal;
      }
      result.protoEnums.push({ values: values });
      return;
    }
  }

  // Reverse map pattern: numeric keys → string values
  if (allString && numericKeys.length >= 2 && numericKeys.length === props.length) {
    var rSorted = numericKeys.slice().sort(function(a, b) { return a - b; });
    var rSeq = rSorted[0] === 0;
    for (var rs = 1; rs < rSorted.length && rSeq; rs++) {
      if (rSorted[rs] !== rSorted[rs - 1] + 1) rSeq = false;
    }
    if (rSeq) {
      var rValues = {};
      for (var re = 0; re < props.length; re++) {
        var rk = props[re].key;
        var rv = props[re].value;
        rValues[rv.value] = rk.value;
      }
      result.protoEnums.push({ values: rValues, isReverseMap: true });
    }
  }

  // General enum constants: string keys, all-caps naming convention, integer/string values
  if (props.length >= 2 && props.length <= 100) {
    var enumVals = {};
    var allCaps = true;
    for (var ec = 0; ec < props.length; ec++) {
      var ek = props[ec].key;
      var ev = props[ec].value;
      var ekName = ek.type === "Identifier" ? ek.name : (ek.type === "Literal" ? String(ek.value) : null);
      if (!ekName) return;
      if (!/^[A-Z][A-Z0-9_]*$/.test(ekName)) allCaps = false;
      if (ev.type === "Literal" && (typeof ev.value === "string" || typeof ev.value === "number")) {
        enumVals[ekName] = ev.value;
      } else {
        return;
      }
    }
    if (allCaps && Object.keys(enumVals).length >= 2) {
      result.enumConstants.push({ values: enumVals });
    }
  }
}

/**
 * Detect fetch/XHR/axios call sites and extract URL, method, headers.
 */
function detectFetchCall(node, result) {
  var callee = node.callee;
  var fnName = null;
  var httpMethod = null;

  // fetch(...) or window.fetch(...)
  if (callee.type === "Identifier" && callee.name === "fetch") {
    fnName = "fetch";
  } else if (callee.type === "MemberExpression") {
    var obj = callee.object;
    var prop = callee.property;
    var propName = prop.type === "Identifier" ? prop.name : (prop.type === "Literal" ? prop.value : null);

    if (obj.type === "Identifier") {
      if (obj.name === "window" && propName === "fetch") {
        fnName = "fetch";
      } else if (obj.name === "$" && (propName === "ajax" || propName === "get" || propName === "post" || propName === "getJSON")) {
        fnName = "$.ajax";
        if (propName === "get" || propName === "getJSON") httpMethod = "GET";
        else if (propName === "post") httpMethod = "POST";
      } else if (obj.name === "axios") {
        fnName = "axios";
        if (propName === "get") httpMethod = "GET";
        else if (propName === "post") httpMethod = "POST";
        else if (propName === "put") httpMethod = "PUT";
        else if (propName === "delete") httpMethod = "DELETE";
        else if (propName === "patch") httpMethod = "PATCH";
      }
    }
  }

  if (!fnName) {
    // XMLHttpRequest.open(method, url)
    if (callee.type === "MemberExpression" &&
        callee.property.type === "Identifier" && callee.property.name === "open" &&
        node.arguments.length >= 2) {
      var methodArg = node.arguments[0];
      var urlArg = node.arguments[1];
      if (methodArg.type === "Literal" && typeof methodArg.value === "string" &&
          /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$/i.test(methodArg.value)) {
        var xhrUrl = extractStringValue(urlArg);
        if (xhrUrl && isApiUrl(xhrUrl)) {
          result.fetchCallSites.push({
            url: xhrUrl,
            method: methodArg.value.toUpperCase(),
            headers: {},
            type: "xhr",
          });
        }
      }
    }
    return;
  }

  // Extract URL from first argument
  var args = node.arguments;
  if (!args.length) return;

  var url = extractStringValue(args[0]);
  if (!url) return;
  if (!isApiUrl(url)) return;

  var callSite = {
    url: url,
    method: httpMethod || "GET",
    headers: {},
    type: fnName,
  };

  // Extract method/headers from options object (2nd arg for fetch, 1st for $.ajax)
  var optIdx = fnName === "$.ajax" ? 0 : 1;
  if (args[optIdx] && args[optIdx].type === "ObjectExpression") {
    var opts = args[optIdx].properties;
    for (var o = 0; o < opts.length; o++) {
      var optKey = opts[o].key;
      var optVal = opts[o].value;
      var optName = optKey.type === "Identifier" ? optKey.name : (optKey.type === "Literal" ? String(optKey.value) : null);

      if (optName === "method" && optVal.type === "Literal" && typeof optVal.value === "string") {
        callSite.method = optVal.value.toUpperCase();
      }
      if (optName === "type" && optVal.type === "Literal" && typeof optVal.value === "string") {
        callSite.method = optVal.value.toUpperCase(); // jQuery uses "type"
      }
      if ((optName === "headers" || optName === "url") && optName === "url" && optVal.type === "Literal") {
        callSite.url = optVal.value;
      }
      if (optName === "headers" && optVal.type === "ObjectExpression") {
        for (var h = 0; h < optVal.properties.length; h++) {
          var hk = optVal.properties[h].key;
          var hv = optVal.properties[h].value;
          var hName = hk.type === "Identifier" ? hk.name : (hk.type === "Literal" ? String(hk.value) : null);
          if (hName && hv.type === "Literal" && typeof hv.value === "string") {
            callSite.headers[hName] = hv.value;
          }
        }
      }
    }
  }

  result.fetchCallSites.push(callSite);
}

/**
 * Detect proto field accessor assignments: patterns like
 *   proto.SomeMessage.prototype.getFieldName = function() { return jspb.Message.getField(this, 3); }
 */
function detectProtoFieldAssignment(node, result) {
  // Pattern: left is MemberExpression (prototype method), right is FunctionExpression
  if (node.right.type !== "FunctionExpression" && node.right.type !== "ArrowFunctionExpression") return;
  if (node.left.type !== "MemberExpression") return;

  var memberProp = node.left.property;
  var accessorName = memberProp.type === "Identifier" ? memberProp.name : null;
  if (!accessorName) return;

  // Check for get/set prefix pattern
  var match = /^(get|set|has|clear|add)([A-Z].*)$/.exec(accessorName);
  if (!match) return;

  var fieldName = match[2];
  // Convert PascalCase to camelCase
  fieldName = fieldName.charAt(0).toLowerCase() + fieldName.slice(1);

  // Look for numeric literal in function body (field number)
  var fieldNumber = findFieldNumberInFunction(node.right);
  if (fieldNumber == null) return;

  result.protoFieldMaps.push({
    fieldNumber: fieldNumber,
    fieldName: fieldName,
    accessorName: accessorName,
  });
}

/**
 * Find a numeric field number literal inside a proto accessor function body.
 * Looks for patterns like getField(this, 3) or getRepeatedField(this, 5)
 */
function findFieldNumberInFunction(funcNode) {
  var body = funcNode.body;
  if (!body) return null;

  var found = null;

  try {
    acorn.walk.simple(body, {
      CallExpression: function(callNode) {
        if (found != null) return;
        var callee = callNode.callee;
        if (callee.type === "MemberExpression") {
          var name = callee.property.type === "Identifier" ? callee.property.name : "";
          if (/^(getField|setField|getRepeatedField|setRepeatedWrapperField|getFieldWithDefault|getRepeatedWrapperField|getBooleanField|getFloatingPointField|getOptionalFloatingPointField|getMapField)$/i.test(name)) {
            // Field number is typically the 2nd argument
            var args = callNode.arguments;
            for (var a = 0; a < args.length; a++) {
              if (args[a].type === "Literal" && typeof args[a].value === "number" && args[a].value >= 1 && args[a].value <= 10000) {
                found = args[a].value;
                return;
              }
            }
          }
        }
      },
    });
  } catch (_) {}

  return found;
}

/**
 * Detect API-relevant string literals.
 */
function detectApiStringLiteral(node, result) {
  if (typeof node.value !== "string") return;
  var val = node.value;
  if (val.length < 3 || val.length > 500) return;

  if (isApiPath(val)) {
    result.stringLiterals.push({ value: val, type: "api_path" });
  } else if (isApiUrl(val)) {
    result.stringLiterals.push({ value: val, type: "api_url" });
  }
}

/**
 * Detect API URLs in template literals.
 */
function detectApiTemplateLiteral(node, result) {
  // Only inspect template literals with at least one quasi
  if (!node.quasis || !node.quasis.length) return;
  var firstQuasi = node.quasis[0];
  if (!firstQuasi.value || !firstQuasi.value.raw) return;
  var raw = firstQuasi.value.raw;
  if (isApiUrl(raw) || isApiPath(raw)) {
    result.stringLiterals.push({ value: raw, type: "api_url" });
  }
}

/**
 * Extract source map URL from end of code.
 */
function extractSourceMapUrl(code) {
  // Check last 500 chars for sourceMappingURL comment
  var tail = code.length > 500 ? code.slice(-500) : code;
  var match = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/.exec(tail);
  return match ? match[1] : null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractStringValue(node) {
  if (!node) return null;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0 && node.quasis.length === 1) {
    return node.quasis[0].value.cooked || node.quasis[0].value.raw;
  }
  return null;
}

function isApiUrl(str) {
  if (!str || str.length < 8) return false;
  if (/^https?:\/\//i.test(str)) {
    // Must contain an API-like path or be a known API domain
    if (/googleapis\.com/i.test(str)) return true;
    if (/\/api\//i.test(str)) return true;
    if (/\/v[0-9]+\//i.test(str)) return true;
    if (/\/graphql/i.test(str)) return true;
    if (/\/rest\//i.test(str)) return true;
    if (/\/rpc\//i.test(str)) return true;
    // Generic API URL pattern
    if (/\/(auth|users|accounts|data|query|search|upload|download)\b/i.test(str)) return true;
  }
  return false;
}

function isApiPath(str) {
  if (!str || str.length < 4) return false;
  if (str.charAt(0) !== "/") return false;
  if (/^\/api\//i.test(str)) return true;
  if (/^\/v[0-9]+\//i.test(str)) return true;
  if (/^\/_ah\//i.test(str)) return true; // App Engine admin
  if (/^\/\$discovery\//i.test(str)) return true;
  if (/^\/\$rpc\//i.test(str)) return true;
  if (/^\/graphql/i.test(str)) return true;
  return false;
}
