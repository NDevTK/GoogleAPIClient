"use strict";
// lib/ast.js — AST-based JS bundle analysis engine
// Uses Babel parser + traverse for scope-aware data flow tracing.
// Traces from call sites through wrapper functions to network sinks
// (fetch, XMLHttpRequest) to learn API parameters and valid values.
// Security code review: DOM XSS sinks, dangerous patterns (eval,
// postMessage, prototype pollution, open redirect), taint tracking.

var _babelParse = BabelBundle.parse;
var _babelTraverse = BabelBundle.traverse;
var _t = BabelBundle.t;

var _HTTP_METHODS_LC = { "get":1, "post":1, "put":1, "delete":1, "patch":1, "head":1, "options":1 };

// Per-analysis state
var _constraints = {};  // scopeUid:varName → { varName, values: Set, sources: [] }
var _stats = null;
var _globalAssignments = {};  // name → { valuePath, valueNode } — tracks window.X = value
var _windowAliases = new Set();  // parameter names known to alias window/self/globalThis
var _lastIIFEFuncPath = null;  // scope context from last _resolveIIFEReturnedProperty resolution
var _sourceCode = null;  // original source text for code context extraction
var _globalCallerCache = {};  // key → [innerPath, ...] — caches _traverseGlobalCallers results
var _typeEnv = {};  // scopeUid:varName → type string — lightweight deterministic type tracking

// ── Resolver ─────────────────────────────────────────────────────────────────
// Manages cycle detection, error collection, and caching for value resolution.
// Created fresh for each analyzeJSBundle() call.

class Resolver {
  constructor() {
    this.visited = new Set();  // unified cycle detection (replaces _resolveStack)
    this.errors = [];          // collected resolution errors (replaces silent catches)
  }

  // Cycle guard: returns true if we should proceed (not a cycle).
  // If the node is already being visited, returns false (cycle detected).
  // Otherwise, marks it as visited and returns true.
  guard(prefix, node) {
    var key = prefix + node.start + ":" + node.end;
    if (this.visited.has(key)) return false;
    this.visited.add(key);
    return true;
  }

  // Remove a node from the visited set (called in finally blocks).
  unguard(prefix, node) {
    this.visited.delete(prefix + node.start + ":" + node.end);
  }

  // Collect a resolution error instead of silently swallowing it.
  // context: short label describing what operation failed (e.g. "resolveCallReturn")
  collectError(e, context) {
    if (this.errors.length < 100) {
      var entry = { context: context || "unknown", message: e.message || String(e) };
      if (e.stack) {
        var lines = e.stack.split("\n");
        entry.stack = lines.slice(0, 6).join("\n");
      }
      this.errors.push(entry);
    }
  }
}

var _resolver = null;  // current Resolver instance (set per analysis)

// ── Shared helpers ──

// Visitor mixin: skip nested function scopes during sub-tree traversal.
// Usage: funcPath.traverse(Object.assign({ ... }, _SKIP_NESTED_FUNCS));
var _SKIP_NESTED_FUNCS = {
  FunctionDeclaration: function(p) { p.skip(); },
  FunctionExpression: function(p) { p.skip(); },
  ArrowFunctionExpression: function(p) { p.skip(); },
};

// Generate readable code from an AST node using @babel/generator.
// Falls back to null if generator is unavailable.
// Caps output at maxLines lines.
function _generateCode(node, maxLines) {
  if (!maxLines) maxLines = 15;
  try {
    if (typeof BabelBundle.generate === "function") {
      var out = BabelBundle.generate(node, { compact: false, concise: false }).code;
      var lines = out.split("\n");
      if (lines.length > maxLines) {
        lines = lines.slice(0, maxLines);
        lines.push("  \u2026");
      }
      return lines.join("\n");
    }
  } catch (e) { _resolver.collectError(e, "generateCode"); }
  return null;
}

// Check if an identifier name refers to a global window-like object (window, self, globalThis)
// that is not shadowed by a local binding, or a known window alias from IIFE detection.
function _isGlobalObject(name, scope) {
  if ((name === "window" || name === "self" || name === "globalThis") && !scope.getBinding(name)) return true;
  return _windowAliases.has(name);
}

// Check if a callee node is a call to the global fetch function.
// Handles: fetch(), window.fetch(), self.fetch(), globalThis.fetch(), alias.fetch(),
// and LogicalExpression guards: (s.fetch || fetch)(url), (fetch || s.fetch)(url).
function _isGlobalFetchCall(callee, scope) {
  if (_t.isIdentifier(callee, { name: "fetch" }) && !scope.getBinding("fetch")) return true;
  if (_t.isMemberExpression(callee) && _t.isIdentifier(callee.property, { name: "fetch" }) &&
      _t.isIdentifier(callee.object) && _isGlobalObject(callee.object.name, scope)) return true;
  if (_t.isLogicalExpression(callee)) {
    return _isGlobalFetchCall(callee.left, scope) || _isGlobalFetchCall(callee.right, scope);
  }
  return false;
}

// Check if a MemberExpression's object node traces to an XMLHttpRequest instance.
// Uses the type tracker first, then falls back to binding init resolution.
function _isXhrObject(path, objectNode) {
  if (!_t.isIdentifier(objectNode)) return false;
  var objType = _getTrackedType(path, objectNode);
  if (objType === "XMLHttpRequest") return true;
  if (objType) return false;
  var binding = path.scope.getBinding(objectNode.name);
  if (binding && _t.isVariableDeclarator(binding.path.node) && binding.path.node.init) {
    var init = binding.path.node.init;
    if (_t.isNewExpression(init) && _t.isIdentifier(init.callee, { name: "XMLHttpRequest" }) &&
        !path.scope.getBinding("XMLHttpRequest")) return true;
    if (_t.isCallExpression(init) && _t.isMemberExpression(init.callee) &&
        _t.isIdentifier(init.callee.property, { name: "xhr" })) return true;
  }
  return false;
}

// Find the parameter index for a named parameter in a function's params array.
// Handles both plain identifiers and default values (AssignmentPattern).
// Returns -1 if not found.
function _findParamIndex(params, name) {
  for (var i = 0; i < params.length; i++) {
    var p = params[i];
    if (_t.isIdentifier(p) && p.name === name) return i;
    if (_t.isAssignmentPattern(p) && _t.isIdentifier(p.left) && p.left.name === name) return i;
  }
  return -1;
}

// Build a fetch call site object with standard schema.
function _buildFetchSite(url, method, headers, type, params, opts) {
  var site = { url: url, method: method, headers: headers || {}, type: type };
  if (params && params.length > 0) site.params = params;
  if (opts) {
    if (opts.enclosingFunction) site.enclosingFunction = opts.enclosingFunction;
    if (opts.responseType) site.responseType = opts.responseType;
  }
  return site;
}

// Unwrap JSON.stringify(x) → x. Returns the unwrapped node, or the original if not JSON.stringify.
function _unwrapJsonStringify(node, path) {
  if (_t.isCallExpression(node) && _isJsonStringify(node, path) && node.arguments.length > 0) {
    return node.arguments[0];
  }
  return node;
}

// Find `this.propName = param` in a constructor body. Returns the param name, or null.
function _findThisAssignedParam(funcPath, propName) {
  var assignedParamName = null;
  try {
    funcPath.traverse(Object.assign({
      AssignmentExpression: function(aPath) {
        if (assignedParamName) { aPath.stop(); return; }
        if (aPath.node.operator !== "=") return;
        var left = aPath.node.left;
        if (_t.isMemberExpression(left) && _t.isThisExpression(left.object) && !left.computed &&
            _t.isIdentifier(left.property, { name: propName })) {
          if (_t.isIdentifier(aPath.node.right)) assignedParamName = aPath.node.right.name;
        }
      },
    }, _SKIP_NESTED_FUNCS));
  } catch (e) { _resolver.collectError(e, "findThisAssignedParam"); }
  return assignedParamName;
}

function analyzeJSBundle(code, sourceUrl, forceScript) {
  _constraints = {};
  _stats = { protoMethods: 0, protoMethodsNoField: 0, resolvedUrls: 0, interProcTraces: 0, globalAssignments: 0, windowAliases: 0 };
  _globalAssignments = {};
  _windowAliases = new Set();
  _resolver = new Resolver();
  _globalCallerCache = {};
  _typeEnv = {};
  _sourceCode = code;
  _sourceLines = null;

  var result = {
    sourceUrl: sourceUrl,
    protoEnums: [],
    protoFieldMaps: [],
    fetchCallSites: [],
    valueConstraints: [],
    securitySinks: [],       // DOM XSS, eval, open redirect sinks
    dangerousPatterns: [],   // unsafe eval, postMessage, prototype pollution
    sourceMapUrl: extractSourceMapUrl(code),
  };

  var ast = null;
  try {
    if (forceScript) {
      // Combined cross-script analysis: parse as script (shared global scope, matching browser <script> semantics)
      ast = _babelParse(code, { sourceType: "script", plugins: ["jsx"], errorRecovery: true });
    } else {
      ast = _babelParse(code, { sourceType: "module", plugins: ["jsx"], errorRecovery: true });
    }
  } catch (e1) {
    try {
      ast = _babelParse(code, { sourceType: "script", plugins: ["jsx"], errorRecovery: true });
    } catch (e2) {
      console.debug("[AST] Parse FAILED for %s (%d chars) — %s", sourceUrl, code.length, e2.message);
      return result;
    }
  }

  // Pre-pass: collect global assignments and window aliases before main analysis
  // so that sink tracing can resolve global aliases (e.g., window.jQuery = lib)
  try {
  _babelTraverse(ast, {
    CallExpression: function(path) {
      _processIIFE(path);
    },
    AssignmentExpression: function(path) {
      _trackGlobalAssignment(path);
    },
    // Track ESM exports as global-like bindings: export { k as default, ... }
    ExportNamedDeclaration: function(path) {
      var specs = path.node.specifiers;
      if (!specs) return;
      for (var ei = 0; ei < specs.length; ei++) {
        var sp = specs[ei];
        if (_t.isIdentifier(sp.local) && !_globalAssignments[sp.local.name]) {
          _globalAssignments[sp.local.name] = { valuePath: null, valueNode: null };
          _stats.globalAssignments++;
        }
      }
    },
    ExportDefaultDeclaration: function(path) {
      var decl = path.node.declaration;
      if (_t.isIdentifier(decl) && !_globalAssignments[decl.name]) {
        _globalAssignments[decl.name] = { valuePath: null, valueNode: null };
        _stats.globalAssignments++;
      }
    },
    // Populate type tracker for deterministic constructor/literal types
    VariableDeclarator: function(path) {
      _trackTypeFromDeclarator(path);
    },
  });
  } catch (_prePassErr) {
    if (_prePassErr instanceof RangeError) {
      _resolver.collectError(_prePassErr, "prePassTraversal");
      console.debug("[AST] Pre-pass overflow on %s (%d chars) — continuing with main pass", sourceUrl, code.length);
    } else { throw _prePassErr; }
  }

  try {
  _babelTraverse(ast, {
    // ── Value constraint collection ──
    SwitchStatement: function(path) {
      _collectSwitchConstraints(path);
    },
    LogicalExpression: function(path) {
      _collectEqualityConstraints(path);
    },
    BinaryExpression: function(path) {
      if (path.node.operator === "in" &&
          _t.isIdentifier(path.node.left) && _t.isIdentifier(path.node.right)) {
        var binding = path.scope.getBinding(path.node.right.name);
        if (binding && binding.path.node.init && _t.isObjectExpression(binding.path.node.init)) {
          var keys = _getObjectKeys(binding.path.node.init);
          if (keys.length >= 1) {
            _addConstraint(path, path.node.left.name, keys, "in_object");
          }
        }
      }
      // Single equality: "value" == param.prop or param.prop === "value"
      if (path.node.operator === "==" || path.node.operator === "===" ||
          path.node.operator === "!=" || path.node.operator === "!==") {
        var eqLeft = path.node.left, eqRight = path.node.right;
        var eqLit = null, eqVar = null;
        if (_t.isStringLiteral(eqLeft)) { eqLit = eqLeft.value; eqVar = eqRight; }
        else if (_t.isStringLiteral(eqRight)) { eqLit = eqRight.value; eqVar = eqLeft; }
        if (eqLit && eqVar) {
          var eqVarName = _t.isIdentifier(eqVar) ? eqVar.name :
            (_t.isMemberExpression(eqVar) ? _memberChainKey(eqVar) : null);
          if (eqVarName) _addConstraint(path, eqVarName, [eqLit], "equality");
        }
      }
    },
    MemberExpression: function(path) {
      // Computed member access: obj[key] → key constrained to obj's property names
      if (path.node.computed && _t.isIdentifier(path.node.property)) {
        var cmObj = _resolveToObject(path.get("object"), 0);
        if (cmObj) {
          var cmKeys = _getObjectKeys(cmObj);
          if (cmKeys.length >= 1) {
            _addConstraint(path, path.node.property.name, cmKeys, "computed_member");
          }
        }
      }
    },
    CallExpression: function(path) {
      _collectIncludesConstraints(path);
      _collectIterationConstraints(path);
      _processIIFE(path);
      _processNetworkSink(path, result);
      _processExportMethodCall(path, result);
      _processSecurityCallSink(path, result);
      _processDangerousPattern(path, result);
    },
    NewExpression: function(path) {
      _processNewExpressionSink(path, result);
      _processSecurityNewSink(path, result);
    },
    // ── Proto, enum, and framework-specific detection ──
    ObjectExpression: function(path) {
      _detectEnumObject(path.node, result);
      _collectObjectLiteralConstraints(path);
      _processReactDangerousHTML(path, result);
    },
    AssignmentExpression: function(path) {
      _trackGlobalAssignment(path);
      _detectProtoFieldAssignment(path, result);
      _processImageSrcSink(path, result);
      _processSecurityAssignSink(path, result);
      _processDangerousAssignment(path, result);
    },
  });
  } catch (_mainPassErr) {
    if (_mainPassErr instanceof RangeError) {
      _resolver.collectError(_mainPassErr, "mainPassTraversal");
      console.debug("[AST] Main pass overflow on %s (%d chars) — returning partial results", sourceUrl, code.length);
    } else { throw _mainPassErr; }
  }

  // ── Export constraints for background.js ──
  var byVar = {};
  var cKeys = Object.keys(_constraints);
  for (var i = 0; i < cKeys.length; i++) {
    var c = _constraints[cKeys[i]];
    if (!byVar[c.varName]) byVar[c.varName] = { values: new Set(), sources: [] };
    c.values.forEach(function(v) { byVar[c.varName].values.add(v); });
    byVar[c.varName].sources = byVar[c.varName].sources.concat(c.sources);
  }
  var varNames = Object.keys(byVar);
  for (var vi = 0; vi < varNames.length; vi++) {
    var vals = [];
    byVar[varNames[vi]].values.forEach(function(v) { vals.push(v); });
    result.valueConstraints.push({
      variable: varNames[vi],
      values: vals,
      sources: byVar[varNames[vi]].sources,
    });
  }

  // ── Deduplicate fetchCallSites by (method, url) — merge params and headers ──
  var _seenSites = {};
  var _dedupedSites = [];
  for (var si = 0; si < result.fetchCallSites.length; si++) {
    var _s = result.fetchCallSites[si];
    var _sk = _s.method + " " + _s.url;
    if (!_seenSites[_sk]) {
      _seenSites[_sk] = _dedupedSites.length;
      _dedupedSites.push(_s);
    } else {
      // Merge params and headers deterministically from both sites
      var existIdx = _seenSites[_sk];
      var existSite = _dedupedSites[existIdx];
      var newParams = _s.params || [];
      if (newParams.length > 0) {
        var existParamNames = {};
        var existParams = existSite.params || [];
        for (var ep = 0; ep < existParams.length; ep++) {
          existParamNames[existParams[ep].name] = true;
        }
        for (var np = 0; np < newParams.length; np++) {
          if (!existParamNames[newParams[np].name]) {
            existParams.push(newParams[np]);
          }
        }
        existSite.params = existParams;
      }
      if (_s.headers) {
        if (!existSite.headers) existSite.headers = {};
        for (var hk in _s.headers) {
          if (!existSite.headers[hk]) existSite.headers[hk] = _s.headers[hk];
        }
      }
    }
  }
  result.fetchCallSites = _dedupedSites;

  // Post-pass: upgrade postMessage severity to "high" if handler contains security sinks
  for (var _pmi = 0; _pmi < result.dangerousPatterns.length; _pmi++) {
    var _pmPat = result.dangerousPatterns[_pmi];
    if (!_pmPat._handlerRange) continue;
    var _pmStart = _pmPat._handlerRange[0], _pmEnd = _pmPat._handlerRange[1];
    for (var _si = 0; _si < result.securitySinks.length; _si++) {
      var _sink = result.securitySinks[_si];
      if (_sink.location.line >= _pmStart && _sink.location.line <= _pmEnd &&
          _sink.sourceType === "user-controlled") {
        _pmPat.severity = "high";
        _pmPat.description += " (flows to " + _sink.sink + ")";
        break;
      }
    }
    delete _pmPat._handlerRange;
  }

  // ── Summary ──
  var _secCount = result.securitySinks.length + result.dangerousPatterns.length;
  if (result.protoEnums.length || result.protoFieldMaps.length || result.fetchCallSites.length || varNames.length || _secCount) {
    console.debug("[AST] %s (%d chars) → %d enums, %d fieldMaps, %d fetchSites, %d constraints, %d interProc, %d globals, %d winAliases, sourceMap=%s",
      sourceUrl, code.length, result.protoEnums.length, result.protoFieldMaps.length,
      result.fetchCallSites.length, varNames.length, _stats.interProcTraces,
      _stats.globalAssignments, _stats.windowAliases,
      result.sourceMapUrl || "none");
  }
  if (_secCount > 0) {
    console.debug("[AST:security] %s — %d sinks, %d dangerous",
      sourceUrl, result.securitySinks.length, result.dangerousPatterns.length);
  }
  if (_stats.globalAssignments > 0) {
    var globalNames = Object.keys(_globalAssignments);
    console.debug("[AST:globals] %d global assignments: %s", globalNames.length, globalNames.slice(0, 20).join(", "));
  }
  if (_stats.protoMethods > 0) {
    console.debug("[AST:proto] %s — %d prototype methods, %d matched, %d unmatched",
      sourceUrl, _stats.protoMethods, _stats.protoMethods - _stats.protoMethodsNoField, _stats.protoMethodsNoField);
  }

  if (_resolver.errors.length > 0) {
    result.resolverErrors = _resolver.errors;
    for (var _ei = 0; _ei < _resolver.errors.length; _ei++) {
      var _err = _resolver.errors[_ei];
      console.debug("[AST:resolver] %s: %s", _err.context, _err.message);
      if (_err.stack) console.debug(_err.stack);
    }
  }

  _constraints = {};
  _stats = null;
  _globalAssignments = {};
  _windowAliases = new Set();
  _resolver = null;
  return result;
}

// ─── Export/Global API Client Method Calls ──────────────────────────────────
// Detects patterns like k.get(url), k.post(url, {json: {...}}) where k is an
// ESM export or global and the method name is an HTTP method.
// This handles libraries (like ky) where the fetch sink is unreachable via
// static analysis (e.g., behind private fields).
function _processExportMethodCall(path, result) {
  var node = path.node;
  var callee = node.callee;
  if (!_t.isMemberExpression(callee) || callee.computed) return;
  if (!_t.isIdentifier(callee.object) || !_t.isIdentifier(callee.property)) return;

  var objName = callee.object.name;
  var methodName = callee.property.name;
  if (!_HTTP_METHODS_LC[methodName]) return;
  if (!_globalAssignments[objName]) return;
  // Skip if there's a local binding that shadows (function param, inner var, etc.)
  // but allow module-scope bindings (ESM exports are module-scoped consts)
  var emcBinding = path.scope.getBinding(objName);
  if (emcBinding && !emcBinding.scope.path.isProgram()) return;
  if (node.arguments.length < 1) return;

  // Extract URL from first argument
  var urlVals = _resolveAllValues(path.get("arguments.0"), 1);
  for (var ui = 0; ui < urlVals.length; ui++) {
    if (typeof urlVals[ui] !== "string") continue;
    var site = {
      url: urlVals[ui],
      method: methodName.toUpperCase(),
      headers: {},
      type: "fetch",
    };

    // Extract body params from second argument options object
    // Pattern: k.post(url, {json: {name: "Alice", role: "admin"}})
    if (node.arguments.length >= 2 && _t.isObjectExpression(node.arguments[1])) {
      var optsNode = node.arguments[1];
      for (var pi = 0; pi < optsNode.properties.length; pi++) {
        var prop = optsNode.properties[pi];
        if (!_t.isObjectProperty(prop) || prop.computed) continue;
        var keyName = _t.isIdentifier(prop.key) ? prop.key.name :
          (_t.isStringLiteral(prop.key) ? prop.key.value : null);
        if (keyName === "json" && _t.isObjectExpression(prop.value)) {
          site.params = _extractObjectProperties(prop.value);
          for (var bpi = 0; bpi < site.params.length; bpi++) site.params[bpi].location = "body";
        }
      }
    }

    console.debug("[AST:fetch] %s %s via %s.%s() (export/global API client)", site.method, site.url, objName, methodName);
    result.fetchCallSites.push(site);
  }
}

// ─── Network Sink Detection & Inter-Procedural Tracing ──────────────────────

function _processNetworkSink(path, result) {
  var node = path.node;
  var callee = node.callee;

  // ── Identify fetch() / window.fetch() — verify these are actual globals via scope ──
  if (_isGlobalFetchCall(callee, path.scope)) {
    _extractFetchCall(path, result, "fetch");
    return;
  }

  // ── Identify XMLHttpRequest.open(method, url) ──
  if (_t.isMemberExpression(callee) &&
      _t.isIdentifier(callee.property, { name: "open" }) &&
      node.arguments.length >= 2) {

    // Debug: describe what we found
    var _xhrObjDesc = _t.isIdentifier(callee.object) ? callee.object.name : callee.object.type;
    var methodArg = node.arguments[0];
    var _xhrArg0Desc = _t.isStringLiteral(methodArg) ? '"' + methodArg.value + '"' :
      (_t.isMemberExpression(methodArg) && _t.isIdentifier(methodArg.object) && _t.isIdentifier(methodArg.property)
        ? methodArg.object.name + "." + methodArg.property.name : methodArg.type);
    var _xhrArg1 = node.arguments[1];
    var _xhrArg1Desc = _t.isStringLiteral(_xhrArg1) ? '"' + _xhrArg1.value + '"' :
      (_t.isMemberExpression(_xhrArg1) && _t.isIdentifier(_xhrArg1.object) && _t.isIdentifier(_xhrArg1.property)
        ? _xhrArg1.object.name + "." + _xhrArg1.property.name : _xhrArg1.type);
    console.debug("[AST:trace] .open() found: %s.open(%s, %s) at line %d",
      _xhrObjDesc, _xhrArg0Desc, _xhrArg1Desc, node.loc ? node.loc.start.line : -1);

    // Verify the object is an XMLHttpRequest (new XMLHttpRequest() or factory.xhr())
    var isXhr = false;
    if (_t.isStringLiteral(methodArg) && _HTTP_METHODS_LC[methodArg.value.toLowerCase()]) {
      isXhr = true; // String literal method ⇒ almost certainly XHR
    }
    if (!isXhr && _t.isIdentifier(callee.object)) {
      var xhrCheckBinding = path.scope.getBinding(callee.object.name);
      if (xhrCheckBinding && _t.isVariableDeclarator(xhrCheckBinding.path.node) && xhrCheckBinding.path.node.init) {
        var _initN = xhrCheckBinding.path.node.init;
        if (_t.isNewExpression(_initN) && _t.isIdentifier(_initN.callee, { name: "XMLHttpRequest" }) &&
            !path.scope.getBinding("XMLHttpRequest")) isXhr = true;
        if (_t.isCallExpression(_initN) && _t.isMemberExpression(_initN.callee) &&
            _t.isIdentifier(_initN.callee.property, { name: "xhr" })) isXhr = true;
      }
    }
    // Try resolving method to confirm — but skip if the object is provably NOT XHR
    // (e.g., bound to `new BroadcastChannel()`, `new URL()`, or other known non-XHR constructors)
    if (!isXhr && _t.isIdentifier(callee.object)) {
      var _xhrFallbackBinding = path.scope.getBinding(callee.object.name);
      var _knownNonXhr = false;
      if (_xhrFallbackBinding && _t.isVariableDeclarator(_xhrFallbackBinding.path.node) && _xhrFallbackBinding.path.node.init) {
        var _fbInit = _xhrFallbackBinding.path.node.init;
        // If init is `new SomeConstructor()` and it's NOT XMLHttpRequest, this is NOT XHR
        if (_t.isNewExpression(_fbInit) && _t.isIdentifier(_fbInit.callee) &&
            _fbInit.callee.name !== "XMLHttpRequest") {
          _knownNonXhr = true;
        }
      }
      if (!_knownNonXhr) {
        var testVals = _resolveAllValues(path.get("arguments.0"), 0);
        if (testVals.length > 0 && typeof testVals[0] === "string" && _HTTP_METHODS_LC[testVals[0].toLowerCase()]) isXhr = true;
      }
    }

    if (isXhr) {
      // Extract headers and body from .setRequestHeader() and .send()
      var xhrHeaders = {};
      var xhrBodyParams = [];
      if (_t.isIdentifier(callee.object)) {
        var xhrBinding = path.scope.getBinding(callee.object.name);
        if (xhrBinding && xhrBinding.referencePaths) {
          for (var ri = 0; ri < xhrBinding.referencePaths.length; ri++) {
            var ref = xhrBinding.referencePaths[ri];
            var refParent = ref.parentPath;
            if (!refParent || !_t.isMemberExpression(refParent.node) || refParent.node.object !== ref.node) continue;
            var memberName = _t.isIdentifier(refParent.node.property) ? refParent.node.property.name : null;
            var callPath = refParent.parentPath;
            if (!callPath || !_t.isCallExpression(callPath.node) || callPath.node.callee !== refParent.node) continue;
            if (memberName === "send" && callPath.node.arguments.length > 0)
              xhrBodyParams = _extractBodyParams(callPath.node.arguments[0], callPath);
            if (memberName === "setRequestHeader" && callPath.node.arguments.length >= 2) {
              var hdrName = _t.isStringLiteral(callPath.node.arguments[0]) ? callPath.node.arguments[0].value : null;
              var hdrVal = _t.isStringLiteral(callPath.node.arguments[1]) ? callPath.node.arguments[1].value : null;
              if (hdrName) xhrHeaders[hdrName.toLowerCase()] = hdrVal || "(dynamic)";
            }
          }
        }
      }

      // ── Correlated resolution: detect shared-base-param pattern ──
      // When both args are P.prop1 and P.prop2 from the same parameter P, trace P
      // to concrete caller arguments and extract both properties together per-caller.
      var methodBase = _t.isMemberExpression(methodArg) && !methodArg.computed && _t.isIdentifier(methodArg.object) ? methodArg.object : null;
      var urlBase = _t.isMemberExpression(_xhrArg1) && !_xhrArg1.computed && _t.isIdentifier(_xhrArg1.object) ? _xhrArg1.object : null;

      if (methodBase && urlBase && methodBase.name === urlBase.name) {
        var sharedBinding = path.scope.getBinding(methodBase.name);
        if (sharedBinding && sharedBinding.kind === "param") {
          var methodPropName = _t.isIdentifier(methodArg.property) ? methodArg.property.name : null;
          var urlPropName = _t.isIdentifier(_xhrArg1.property) ? _xhrArg1.property.name : null;
          if (methodPropName && urlPropName) {
            console.debug("[AST:trace]   correlated resolution: %s.%s + %s.%s", methodBase.name, methodPropName, urlBase.name, urlPropName);
            var callerArgs = _resolveParamToCallerArgs(sharedBinding);
            // Deduplicate caller args by AST node position — the same expression
            // reached through different trace paths produces identical results
            var _seenArgNodes = {};
            var _uniqueArgs = [];
            for (var dai = 0; dai < callerArgs.length; dai++) {
              var _akey = callerArgs[dai].node.start + ":" + callerArgs[dai].node.end;
              if (!_seenArgNodes[_akey]) { _seenArgNodes[_akey] = true; _uniqueArgs.push(callerArgs[dai]); }
            }
            callerArgs = _uniqueArgs;
            console.debug("[AST:trace]   found %d caller arg paths (%d unique)", callerArgs.length, _uniqueArgs.length);
            // For method, also check alternate property names (method vs type)
            var methodProps = [methodPropName];
            if (methodPropName === "type") methodProps.push("method");
            else if (methodPropName === "method") methodProps.push("type");
            for (var cai = 0; cai < callerArgs.length; cai++) {
              var props = _resolvePropsFromArg(callerArgs[cai], methodProps.concat([urlPropName]));
              var resolvedMethods = [];
              for (var mpi = 0; mpi < methodProps.length; mpi++) {
                resolvedMethods = resolvedMethods.concat(props[methodProps[mpi]] || []);
              }
              var resolvedUrls = props[urlPropName] || [];
              // Filter to valid HTTP methods
              resolvedMethods = resolvedMethods.filter(function(m) { return typeof m === "string" && _HTTP_METHODS_LC[m.toLowerCase()]; });
              for (var ui = 0; ui < resolvedUrls.length; ui++) {
                // When methods and URLs have the same count, pair by index — the computed-member
                // route iterates values in the same order as the iteration variable, so index
                // correspondence is maintained (e.g., "get"→jQuery.get() callers, "post"→jQuery.post() callers).
                // When methods and URLs pair 1:1, use index correspondence.
                // When there are more methods than URLs, emit a site per method for this URL.
                var methodsForUrl = [];
                if (resolvedMethods.length === resolvedUrls.length) {
                  methodsForUrl = [resolvedMethods[ui].toUpperCase()];
                } else if (resolvedMethods.length > resolvedUrls.length) {
                  for (var emi = 0; emi < resolvedMethods.length; emi++) methodsForUrl.push(resolvedMethods[emi].toUpperCase());
                } else if (resolvedMethods.length > 0) {
                  methodsForUrl = [resolvedMethods[0].toUpperCase()];
                } else {
                  methodsForUrl = ["?"];
                }
                // Extract body params from the "data" property of caller args
                var corrBodyParams = xhrBodyParams.length > 0 ? xhrBodyParams : [];
                if (corrBodyParams.length === 0) {
                  // Resolve the caller arg to an object, then extract the "data" property
                  var callerArgObj = null;
                  try { callerArgObj = _resolveToObject(callerArgs[cai], 1); } catch(e) { _resolver.collectError(e, "xhrCallerArgResolve"); }
                  if (callerArgObj) {
                    for (var cpi = 0; cpi < callerArgObj.properties.length; cpi++) {
                      var cprop = callerArgObj.properties[cpi];
                      if (!_t.isObjectProperty(cprop) || cprop.computed) continue;
                      var cpKey = _getKeyName(cprop.key);
                      if (cpKey === "data") {
                        var dataValNode = cprop.value;
                        dataValNode = _unwrapJsonStringify(dataValNode, path);
                        if (_t.isObjectExpression(dataValNode)) {
                          corrBodyParams = _extractObjectProperties(dataValNode);
                          for (var dbp = 0; dbp < corrBodyParams.length; dbp++) corrBodyParams[dbp].location = "body";
                          break;
                        }
                      }
                    }
                  }
                }
                for (var mfi = 0; mfi < methodsForUrl.length; mfi++) {
                  result.fetchCallSites.push(_buildFetchSite(resolvedUrls[ui], methodsForUrl[mfi], xhrHeaders, "xhr", corrBodyParams));
                  console.debug("[AST:fetch] xhr %s %s", methodsForUrl[mfi], resolvedUrls[ui]);
                }
              }
            }
            return; // Done — correlated resolution handled it
          }
        }
      }

      // ── Cross-parameter correlated resolution ──
      // Method and URL come from different parameters of the same function:
      // function(url, opts) { xhr.open(opts.method||"get", url) }
      // For each caller, extract both args at their respective param indices.
      var _methodParamInfo = _identifyParamSource(methodArg, path);
      var _urlParamInfo = _identifyParamSource(_xhrArg1, path);
      if (_methodParamInfo && _urlParamInfo &&
          _methodParamInfo.funcPath === _urlParamInfo.funcPath &&
          _methodParamInfo.paramIdx !== _urlParamInfo.paramIdx) {
        var xpFuncPath = _methodParamInfo.funcPath;
        var xpCallerArgs = _findFunctionCallerArgs(xpFuncPath);
        if (xpCallerArgs.length > 0) {
          console.debug("[AST:trace]   cross-param correlated: method=param[%d].%s url=param[%d] (%d callers)",
            _methodParamInfo.paramIdx, _methodParamInfo.propName || "(direct)", _urlParamInfo.paramIdx, xpCallerArgs.length);
          for (var xci = 0; xci < xpCallerArgs.length; xci++) {
            var xpArgs = xpCallerArgs[xci];
            // Resolve URL from caller
            var xpUrls = [];
            if (_urlParamInfo.paramIdx < xpArgs.length) {
              xpUrls = _resolveAllValues(xpArgs[_urlParamInfo.paramIdx], 0);
            }
            // Resolve method from caller
            var xpMethods = [];
            if (_methodParamInfo.paramIdx < xpArgs.length) {
              if (_methodParamInfo.propName) {
                // opts.method — resolve the opts arg to object, extract the property
                var xpObj = _resolveToObject(xpArgs[_methodParamInfo.paramIdx], 0);
                if (xpObj) {
                  for (var xpi = 0; xpi < xpObj.properties.length; xpi++) {
                    var xpp = xpObj.properties[xpi];
                    if (!_t.isObjectProperty(xpp) || xpp.computed) continue;
                    var xpk = _getKeyName(xpp.key);
                    if (xpk === _methodParamInfo.propName) {
                      if (_t.isStringLiteral(xpp.value)) xpMethods.push(xpp.value.value);
                    }
                  }
                }
              } else {
                xpMethods = _resolveAllValues(xpArgs[_methodParamInfo.paramIdx], 0);
              }
            }
            // Apply default from LogicalExpression: n.method || "get"
            if (xpMethods.length === 0 && _methodParamInfo.defaultValue) {
              xpMethods = [_methodParamInfo.defaultValue];
            }
            xpMethods = xpMethods.filter(function(m) { return typeof m === "string" && _HTTP_METHODS_LC[m.toLowerCase()]; });
            // Resolve body params from caller if available
            var xpBody = xhrBodyParams.length > 0 ? xhrBodyParams : [];
            if (xpBody.length === 0 && _methodParamInfo.paramIdx < xpArgs.length && _methodParamInfo.propName) {
              var xpBodyObj = _resolveToObject(xpArgs[_methodParamInfo.paramIdx], 0);
              if (xpBodyObj) {
                for (var xbi = 0; xbi < xpBodyObj.properties.length; xbi++) {
                  var xbp = xpBodyObj.properties[xbi];
                  if (!_t.isObjectProperty(xbp) || xbp.computed) continue;
                  if (_getKeyName(xbp.key) === "body") {
                    var bodyVal = xbp.value;
                    bodyVal = _unwrapJsonStringify(bodyVal, path);
                    if (_t.isObjectExpression(bodyVal)) {
                      xpBody = _extractObjectProperties(bodyVal);
                      for (var xbpi = 0; xbpi < xpBody.length; xbpi++) xpBody[xbpi].location = "body";
                    }
                    break;
                  }
                }
              }
            }
            // Extract headers from caller's opts object (e.g. opts.headers)
            var xpHeaders = Object.assign({}, xhrHeaders);
            if (_methodParamInfo.paramIdx < xpArgs.length && _methodParamInfo.propName) {
              var xpHdrObj = _resolveToObject(xpArgs[_methodParamInfo.paramIdx], 0);
              if (xpHdrObj) {
                for (var xhi = 0; xhi < xpHdrObj.properties.length; xhi++) {
                  var xhp = xpHdrObj.properties[xhi];
                  if (!_t.isObjectProperty(xhp) || xhp.computed) continue;
                  if (_getKeyName(xhp.key) === "headers" && _t.isObjectExpression(xhp.value)) {
                    xpHeaders = Object.assign(xpHeaders, _extractHeaders(xhp.value));
                    break;
                  }
                }
              }
            }
            for (var xui = 0; xui < xpUrls.length; xui++) {
              var xpMethod = xpMethods.length > 0 ? xpMethods[0].toUpperCase() : "GET";
              result.fetchCallSites.push(_buildFetchSite(xpUrls[xui], xpMethod, xpHeaders, "xhr", xpBody));
              console.debug("[AST:fetch] xhr %s %s (cross-param)", xpMethod, xpUrls[xui]);
            }
          }
          return;
        }
      }

      // ── this.prop XHR correlated resolution (prototype methods) ──
      // When both args are this.method and this.url, trace through constructor per-caller
      var _thisMethodProp = null, _thisUrlProp = null;
      if (_t.isMemberExpression(methodArg) && _t.isThisExpression(methodArg.object) &&
          _t.isIdentifier(methodArg.property)) _thisMethodProp = methodArg.property.name;
      if (_t.isMemberExpression(_xhrArg1) && _t.isThisExpression(_xhrArg1.object) &&
          _t.isIdentifier(_xhrArg1.property)) _thisUrlProp = _xhrArg1.property.name;
      if (_thisMethodProp && _thisUrlProp) {
        var _encFunc = path.getFunctionParent();
        if (_encFunc) {
          // Find Ctor.prototype.method = function(){...} pattern
          var _ctorName = null;
          var _funcParentP = _encFunc.parentPath;
          if (_funcParentP && _t.isAssignmentExpression(_funcParentP.node) && _funcParentP.node.right === _encFunc.node) {
            var _aLeft = _funcParentP.node.left;
            if (_t.isMemberExpression(_aLeft) && _t.isMemberExpression(_aLeft.object) && !_aLeft.object.computed &&
                (_t.isIdentifier(_aLeft.object.property, {name:"prototype"}) ||
                 (_t.isStringLiteral(_aLeft.object.property) && _aLeft.object.property.value === "prototype")) &&
                _t.isIdentifier(_aLeft.object.object)) {
              _ctorName = _aLeft.object.object.name;
            }
          }
          if (_ctorName) {
            var _correlatedSites = _resolveThisPropXhrCorrelated(path, _ctorName, _thisMethodProp, _thisUrlProp, xhrHeaders, xhrBodyParams);
            if (_correlatedSites.length > 0) {
              for (var _csi = 0; _csi < _correlatedSites.length; _csi++) {
                result.fetchCallSites.push(_correlatedSites[_csi]);
              }
              return;
            }
          }
        }
      }

      // ── Fallback: independent resolution (for simple cases / non-shared params) ──
      var xhrMethod = null;
      if (_t.isStringLiteral(methodArg) && _HTTP_METHODS_LC[methodArg.value.toLowerCase()]) {
        xhrMethod = methodArg.value.toUpperCase();
      }
      var xhrMethodVals = null;
      if (!xhrMethod) {
        var methodVals = _resolveAllValues(path.get("arguments.0"), 0);
        if (methodVals.length > 0 && typeof methodVals[0] === "string" && _HTTP_METHODS_LC[methodVals[0].toLowerCase()]) {
          xhrMethod = methodVals[0].toUpperCase();
          if (methodVals.length > 1) xhrMethodVals = methodVals;
        }
      }
      if (!xhrMethod) xhrMethod = "?";

      var urls = _resolveAllValues(path.get("arguments.1"), 0);
      console.debug("[AST:trace]   url resolve → [%s] (%d values)", urls.join(", "), urls.length);

      for (var i = 0; i < urls.length; i++) {
        var pairedMethod = xhrMethod;
        if (xhrMethodVals && xhrMethodVals.length === urls.length) {
          var pm = xhrMethodVals[i];
          if (typeof pm === "string" && _HTTP_METHODS_LC[pm.toLowerCase()]) pairedMethod = pm.toUpperCase();
        }
        var xhrMethodDisplay = pairedMethod === "(dynamic)" ? "?" : pairedMethod;
        result.fetchCallSites.push(_buildFetchSite(urls[i], xhrMethodDisplay, xhrHeaders, "xhr", xhrBodyParams));
        console.debug("[AST:fetch] xhr %s %s", xhrMethodDisplay, urls[i]);
      }
    }
    return;
  }

  // ── navigator.sendBeacon(url, data) ──
  if (_t.isMemberExpression(callee) && _t.isIdentifier(callee.property, { name: "sendBeacon" }) &&
      node.arguments.length >= 1 &&
      _t.isIdentifier(callee.object, { name: "navigator" }) && !path.scope.getBinding("navigator")) {
    var beaconUrls = _resolveAllValues(path.get("arguments.0"), 0);
    for (var bi = 0; bi < beaconUrls.length; bi++) {
      var bParams = node.arguments.length > 1 ? _extractBodyParams(node.arguments[1], path) : [];
      result.fetchCallSites.push(_buildFetchSite(beaconUrls[bi], "POST", {}, "beacon", bParams));
      console.debug("[AST:fetch] beacon POST %s", beaconUrls[bi]);
    }
    return;
  }

  // ── Check if this is a call to a function that contains a network sink ──
  // Inter-procedural: if callee resolves to a function definition that has fetch/XHR inside
  var funcPath = _resolveCalleeToFunction(path);
  if (funcPath) {
    // calleeBinding is used for finding OTHER callers (wrapper tracing).
    // For MemberExpression callees ($.ajax, axios.get), binding is null — we still
    // trace the current call site's arguments through both direct and deep sink paths.
    var calleeBinding = _t.isIdentifier(callee) ? path.scope.getBinding(callee.name) : null;
    _traceWrapperFunction(path, funcPath, calleeBinding, result);
  }
}

// ─── Additional Browser Sinks ────────────────────────────────────────────────

function _processNewExpressionSink(path, result) {
  var node = path.node;
  var callee = node.callee;
  // new EventSource(url)
  if (_t.isIdentifier(callee, { name: "EventSource" }) && !path.scope.getBinding("EventSource") &&
      node.arguments.length >= 1) {
    var urls = _resolveAllValues(path.get("arguments.0"), 0);
    for (var i = 0; i < urls.length; i++) {
      result.fetchCallSites.push(_buildFetchSite(urls[i], "GET", {}, "eventsource"));
      console.debug("[AST:fetch] eventsource GET %s", urls[i]);
    }
  }
}

function _processImageSrcSink(path, result) {
  var node = path.node;
  if (node.operator !== "=") return;
  var left = node.left;
  if (!_t.isMemberExpression(left) || left.computed || !_t.isIdentifier(left.property, { name: "src" })) return;
  if (!_t.isIdentifier(left.object)) return;
  var binding = path.scope.getBinding(left.object.name);
  if (!binding || !_t.isVariableDeclarator(binding.path.node) || !binding.path.node.init) return;
  var init = binding.path.node.init;
  if (!_t.isNewExpression(init) || !_t.isIdentifier(init.callee, { name: "Image" }) || path.scope.getBinding("Image")) return;
  var urls = _resolveAllValues(path.get("right"), 0);
  for (var i = 0; i < urls.length; i++) {
    result.fetchCallSites.push(_buildFetchSite(urls[i], "GET", {}, "pixel"));
    console.debug("[AST:fetch] pixel GET %s", urls[i]);
  }
}

// ─── IIFE Window Alias Detection ─────────────────────────────────────────────
// Detects (function(e){...})(window) and !function(e){...}(window) patterns,
// marking the parameter as a window alias. Also handles indirect IIFEs where
// a function parameter is called with a window alias (e.g., t(e) inside a UMD wrapper).

function _processIIFE(path) {
  var callee = path.node.callee;
  var funcExpr = null;
  var args = path.node.arguments;

  // Direct IIFE: (function(params) { ... })(args) or !function(params) { ... }(args)
  if (_t.isFunctionExpression(callee) || _t.isArrowFunctionExpression(callee)) {
    funcExpr = callee;
  }

  // Indirect IIFE: callee is a parameter that received a FunctionExpression argument
  // e.g., t(e) where t is bound to a FunctionExpression argument of an enclosing IIFE
  if (!funcExpr && _t.isIdentifier(callee)) {
    var binding = path.scope.getBinding(callee.name);
    if (binding && binding.kind === "param") {
      var enclosingFunc = binding.scope.path;
      if (_t.isFunctionExpression(enclosingFunc.node) || _t.isArrowFunctionExpression(enclosingFunc.node)) {
        var paramIdx = _findParamIndex(enclosingFunc.node.params, callee.name);
        if (paramIdx >= 0) {
          // Check if enclosing function is itself an IIFE callee
          var enclosingCall = enclosingFunc.parentPath;
          if (enclosingCall && _t.isCallExpression(enclosingCall.node) &&
              enclosingCall.node.callee === enclosingFunc.node &&
              paramIdx < enclosingCall.node.arguments.length) {
            var paramArgNode = enclosingCall.node.arguments[paramIdx];
            if (_t.isFunctionExpression(paramArgNode) || _t.isArrowFunctionExpression(paramArgNode)) {
              funcExpr = paramArgNode;
            }
          }
        }
      }
    }
  }

  if (!funcExpr || !funcExpr.params || !funcExpr.params.length || !args || !args.length) return;

  for (var i = 0; i < funcExpr.params.length && i < args.length; i++) {
    if (!_t.isIdentifier(funcExpr.params[i])) continue;
    var paramName = funcExpr.params[i].name;
    var argNode = args[i];

    // Direct window/self/globalThis reference
    if (_t.isIdentifier(argNode) && _isGlobalObject(argNode.name, path.scope)) {
      _windowAliases.add(paramName);
      _stats.windowAliases++;
      continue;
    }
    // Known window alias passed through (e.g., t(e) where e is a window alias)
    if (_t.isIdentifier(argNode) && _windowAliases.has(argNode.name)) {
      _windowAliases.add(paramName);
      _stats.windowAliases++;
      continue;
    }
    // typeof window !== "undefined" ? window : this  (UMD pattern)
    if (_t.isConditionalExpression(argNode)) {
      var hasWindow = (_t.isIdentifier(argNode.consequent, { name: "window" }) ||
                       _t.isIdentifier(argNode.alternate, { name: "window" })) &&
                      !path.scope.getBinding("window");
      var hasThis = (_t.isThisExpression(argNode.consequent) || _t.isThisExpression(argNode.alternate));
      if (hasWindow || hasThis) {
        _windowAliases.add(paramName);
        _stats.windowAliases++;
        continue;
      }
    }
    // this at global scope (common: (function(global) { ... })(this))
    if (_t.isThisExpression(argNode)) {
      _windowAliases.add(paramName);
      _stats.windowAliases++;
    }
  }
}

// ─── Global Assignment Tracking ──────────────────────────────────────────────
// Tracks window.X = value, self.X = value, windowAlias.X = value assignments.
// These create global bindings accessible from any script on the page.

// Recursively checks if a ConditionalExpression has window/self/globalThis/this in any branch
function _hasWindowBranch(node, path) {
  // Iterative: walk ConditionalExpression chains via explicit stack
  var stack = [node];
  while (stack.length > 0) {
    var n = stack.pop();
    if (_t.isIdentifier(n) && _isGlobalObject(n.name, path.scope)) return true;
    if (_t.isThisExpression(n)) return true;
    if (_t.isConditionalExpression(n)) {
      stack.push(n.consequent, n.alternate);
    }
  }
  return false;
}

function _trackGlobalAssignment(path) {
  var node = path.node;
  if (node.operator !== "=") return;
  var left = node.left;
  if (!_t.isMemberExpression(left) || left.computed) return;

  var objName = _t.isIdentifier(left.object) ? left.object.name : null;
  if (!objName) {
    // Handle (windowAlias || self).prop = value (UMD pattern)
    if (_t.isLogicalExpression(left.object)) {
      var logLeft = left.object.left;
      var logRight = left.object.right;
      if (_t.isIdentifier(logLeft) && _windowAliases.has(logLeft.name)) {
        objName = logLeft.name;
      } else if (_t.isIdentifier(logRight) && _windowAliases.has(logRight.name)) {
        objName = logRight.name;
      } else if (_t.isIdentifier(logLeft) && _isGlobalObject(logLeft.name, path.scope)) {
        objName = logLeft.name;
      } else if (_t.isIdentifier(logRight) && _isGlobalObject(logRight.name, path.scope)) {
        objName = logRight.name;
      }
    }
    // Handle ConditionalExpression: (typeof window !== "undefined" ? window : ...).prop = value (UMD)
    if (!objName && _t.isConditionalExpression(left.object)) {
      if (_hasWindowBranch(left.object, path)) objName = "window";
    }
    if (!objName) return;
  }

  var isGlobalObj = _isGlobalObject(objName, path.scope);
  if (!isGlobalObj) return;

  var propName = _t.isIdentifier(left.property) ? left.property.name : null;
  if (!propName) return;

  _globalAssignments[propName] = {
    valuePath: path.get("right"),
    valueNode: node.right,
  };
  _stats.globalAssignments++;
}

// Resolve a property on the return value of an IIFE.
// Handles: var e = function(){ n.get = function(url){...}; return n; }(); e.get(url)
// Also handles SequenceExpression returns: return (t=t||{}, n.get=fn, n)
function _resolveIIFEReturnedProperty(callExprPath, propName) {
  var callee = callExprPath.node.callee;
  var funcNode = null;
  var funcPath = null;

  // Direct IIFE: (function(){...})()
  if (_t.isFunctionExpression(callee) || _t.isArrowFunctionExpression(callee)) {
    funcNode = callee;
    funcPath = callExprPath.get("callee");
  }
  // Named function: factoryFn()
  if (!funcNode && _t.isIdentifier(callee)) {
    var binding = callExprPath.scope.getBinding(callee.name);
    if (binding) {
      if (_t.isFunctionDeclaration(binding.path.node)) {
        funcNode = binding.path.node;
        funcPath = binding.path;
      } else if (_t.isVariableDeclarator(binding.path.node) && binding.path.node.init &&
                 (_t.isFunctionExpression(binding.path.node.init) || _t.isArrowFunctionExpression(binding.path.node.init))) {
        funcNode = binding.path.node.init;
        funcPath = binding.path.get("init");
      }
    }
  }
  if (!funcNode || !funcPath) return null;

  // Find the returned identifier name
  var returnedName = null;
  try {
    funcPath.traverse(Object.assign({
      ReturnStatement: function(retPath) {
        if (returnedName) return;
        var arg = retPath.node.argument;
        if (!arg) return;
        // Direct return: return n
        if (_t.isIdentifier(arg)) {
          returnedName = arg.name;
        }
        // SequenceExpression: return (a=..., n.get=fn, n)
        if (_t.isSequenceExpression(arg)) {
          var last = arg.expressions[arg.expressions.length - 1];
          if (_t.isIdentifier(last)) returnedName = last.name;
        }
      },
    }, _SKIP_NESTED_FUNCS));
  } catch (e) { _resolver.collectError(e, "iifeReturnName"); }
  if (!returnedName) return null;

  // Find returnedName.propName = function(){} assignments inside the IIFE
  var foundFuncPath = null;
  try {
    funcPath.traverse(Object.assign({
      AssignmentExpression: function(assignPath) {
        if (foundFuncPath) return;
        var left = assignPath.node.left;
        if (!_t.isMemberExpression(left) || left.computed) return;
        if (!_t.isIdentifier(left.object) || left.object.name !== returnedName) return;
        if (!_t.isIdentifier(left.property) || left.property.name !== propName) return;
        var right = assignPath.node.right;
        if (_t.isFunctionExpression(right) || _t.isArrowFunctionExpression(right)) {
          foundFuncPath = assignPath.get("right");
        }
      },
    }, _SKIP_NESTED_FUNCS));
  } catch (e) { _resolver.collectError(e, "iifePropertyAssignment"); }
  if (foundFuncPath) _lastIIFEFuncPath = funcPath;
  return foundFuncPath;
}

// Resolve a call expression's callee to its function node
// Returns a Babel path to the resolved function node, or null.
function _resolveCalleeToFunction(callPath) {
  var callee = callPath.node.callee;

  // Common case: identifier → scope binding, member expr → object property
  var commonPath = _resolveCalleeFuncPath(callPath, 0);
  if (commonPath) return commonPath;

  // Extended identifier resolution: global assignments, factory returns
  if (_t.isIdentifier(callee)) {
    var binding = callPath.scope.getBinding(callee.name);
    if (!binding) {
      var globalDef = _globalAssignments[callee.name];
      if (globalDef && globalDef.valueNode && globalDef.valuePath) {
        if (_t.isFunctionExpression(globalDef.valueNode) || _t.isArrowFunctionExpression(globalDef.valueNode))
          return globalDef.valuePath;
        if (_t.isCallExpression(globalDef.valueNode)) {
          var retFunc = _resolveCallReturnToFunction(globalDef.valuePath, 0);
          if (retFunc && retFunc._path) return retFunc._path;
        }
      }
      return null;
    }
    if (!binding.path) return null;
    // Higher-order: var fn = factory() where factory returns a function
    if (_t.isVariableDeclarator(binding.path.node) && binding.path.node.init &&
        _t.isCallExpression(binding.path.node.init)) {
      var retFunc = _resolveCallReturnToFunction(binding.path.get("init"), 0);
      if (retFunc && retFunc._path) return retFunc._path;
    }
    return null;
  }

  // Member expression: obj.method(url) → resolve obj, find method property
  if (_t.isMemberExpression(callee) && !callee.computed) {
    var propName = _t.isIdentifier(callee.property) ? callee.property.name : null;
    if (!propName) return null;

    // Try: obj = IIFE() returning a function/object with properties assigned inside
    // Handles: var e = function(){...n.get=fn...return n}(); e.get(url)
    if (_t.isIdentifier(callee.object)) {
      var iifeObjBinding = callPath.scope.getBinding(callee.object.name);
      if (iifeObjBinding && _t.isVariableDeclarator(iifeObjBinding.path.node) &&
          iifeObjBinding.path.node.init && _t.isCallExpression(iifeObjBinding.path.node.init)) {
        var iifePropFn = _resolveIIFEReturnedProperty(iifeObjBinding.path.get("init"), propName);
        if (iifePropFn) return iifePropFn;
      }
      // Also check global assignments: window.X = IIFE()
      if (!iifeObjBinding) {
        var gDef = _globalAssignments[callee.object.name];
        if (gDef && gDef.valuePath && _t.isCallExpression(gDef.valueNode)) {
          var gPropFn = _resolveIIFEReturnedProperty(gDef.valuePath, propName);
          if (gPropFn) return gPropFn;
        }
      }
    }

    // Second try: method assigned separately (Closure pattern: a.b = function(url) { ... })
    // Use referencePaths since Babel doesn't track property mutations as constantViolations
    if (_t.isIdentifier(callee.object)) {
      var objBinding = callPath.scope.getBinding(callee.object.name);
      // Fallback: if no local binding, check _globalAssignments.
      // Handles window.jQuery = jQuery inside IIFE → user code calls jQuery.ajax() outside.
      // Unwraps chained assignments: window.jQuery = window.$ = jQuery → jQuery
      if (!objBinding) {
        var globalDef = _globalAssignments[callee.object.name];
        if (globalDef && globalDef.valueNode) {
          var gVal = globalDef.valueNode;
          while (_t.isAssignmentExpression(gVal)) gVal = gVal.right;
          if (_t.isIdentifier(gVal)) {
            objBinding = globalDef.valuePath.scope.getBinding(gVal.name);
          }
        }
      }
      if (objBinding) {
        var refs = objBinding.referencePaths;
        for (var cv = 0; cv < refs.length; cv++) {
          var refParent = refs[cv].parent;
          if (_t.isMemberExpression(refParent) && refParent.object === refs[cv].node &&
              !refParent.computed && _t.isIdentifier(refParent.property, { name: propName })) {
            var assignParentPath = refs[cv].parentPath ? refs[cv].parentPath.parentPath : null;
            var assignExpr = assignParentPath ? assignParentPath.node : null;
            if (assignExpr && _t.isAssignmentExpression(assignExpr) && assignExpr.operator === "=" &&
                assignExpr.left === refParent) {
              if (_t.isFunctionExpression(assignExpr.right) || _t.isArrowFunctionExpression(assignExpr.right)) {
                return assignParentPath.get("right");
              }
            }
          }
          // Third try: property defined via obj.extend({method: function(){}})
          if (_t.isMemberExpression(refParent) && refParent.object === refs[cv].node && !refParent.computed) {
            var extName = _t.isIdentifier(refParent.property) ? refParent.property.name : null;
            if (extName === "extend" || extName === "mixin" || extName === "assign") {
              var extCallPath = refs[cv].parentPath ? refs[cv].parentPath.parentPath : null;
              var extCallNode = extCallPath ? extCallPath.node : null;
              if (extCallNode && _t.isCallExpression(extCallNode) && extCallNode.callee === refParent) {
                for (var ea = 0; ea < extCallNode.arguments.length; ea++) {
                  var extArgObj = extCallNode.arguments[ea];
                  if (!_t.isObjectExpression(extArgObj)) continue;
                  for (var ep = 0; ep < extArgObj.properties.length; ep++) {
                    var extProp = extArgObj.properties[ep];
                    if (!_t.isObjectProperty(extProp) || extProp.computed) continue;
                    var epKey = _t.isIdentifier(extProp.key) ? extProp.key.name :
                      (_t.isStringLiteral(extProp.key) ? extProp.key.value : null);
                    if (epKey === propName) {
                      if (_t.isFunctionExpression(extProp.value) || _t.isArrowFunctionExpression(extProp.value)) {
                        return extCallPath.get("arguments." + ea + ".properties." + ep + ".value");
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  return null;
}

function _traceWrapperFunction(callPath, funcPath, funcBinding, result) {
  var funcNode = funcPath.node;
  // Check if the function body contains a direct fetch/XHR call
  var sinkInfo = _findSinkInFunction(funcPath);
  if (!sinkInfo) {
    // No direct sink — check for deep sink (nested inside closures/callbacks).
    // This handles libraries like jQuery where $.ajax() → transport.send() → xhr.open()
    // is buried several levels deep inside nested functions.
    var deepPropMap = _findDeepSinkPropertyMap(funcPath);
    if (deepPropMap) {
      _traceDeepSinkCall(callPath, funcNode, funcBinding, deepPropMap, result);
    }
    // Chained wrapper: function(e,t){return n(e,t,"get")} where n() has the sink.
    // Map caller args through the wrapper to the inner function's args, then trace.
    if (!deepPropMap) {
      _traceChainedWrapper(callPath, funcNode, result);
    }
    return;
  }

  _stats.interProcTraces++;

  // Map caller's arguments to function parameters (both resolved values and raw argument paths)
  var paramBindings = {};  // paramName → string[]
  var paramArgPaths = {};  // paramName → argPath (for object property extraction)
  var callArgs = callPath.node.arguments;
  for (var i = 0; i < funcNode.params.length && i < callArgs.length; i++) {
    var param = funcNode.params[i];
    var paramName = _t.isIdentifier(param) ? param.name :
      (_t.isAssignmentPattern(param) && _t.isIdentifier(param.left) ? param.left.name : null);
    if (paramName) {
      var argPath = callPath.get("arguments." + i);
      paramArgPaths[paramName] = argPath;
      var resolved = _resolveAllValues(argPath, 1);
      if (resolved.length > 0) {
        paramBindings[paramName] = resolved;
      }
    }
  }

  // If function was resolved from a higher-order call (var fn = factory(args)),
  // also map the factory's params (closure bindings) into paramBindings.
  if (funcBinding && _t.isVariableDeclarator(funcBinding.path.node) &&
      funcBinding.path.node.init && _t.isCallExpression(funcBinding.path.node.init)) {
    var outerCallPath = funcBinding.path.get("init");
    var outerCallArgs = funcBinding.path.node.init.arguments;
    var outerCallee = funcBinding.path.node.init.callee;
    if (_t.isIdentifier(outerCallee)) {
      var outerBinding = funcBinding.path.scope.getBinding(outerCallee.name);
      var outerFunc = null;
      if (outerBinding) {
        if (_t.isFunctionDeclaration(outerBinding.path.node)) outerFunc = outerBinding.path.node;
        else if (_t.isVariableDeclarator(outerBinding.path.node) && outerBinding.path.node.init &&
                 (_t.isFunctionExpression(outerBinding.path.node.init) || _t.isArrowFunctionExpression(outerBinding.path.node.init)))
          outerFunc = outerBinding.path.node.init;
      }
      if (outerFunc) {
        for (var oi = 0; oi < outerFunc.params.length && oi < outerCallArgs.length; oi++) {
          var outerParam = outerFunc.params[oi];
          var outerParamName = _t.isIdentifier(outerParam) ? outerParam.name : null;
          if (outerParamName && !paramBindings[outerParamName]) {
            var outerArgResolved = _resolveAllValues(outerCallPath.get("arguments." + oi), 1);
            if (outerArgResolved.length > 0) paramBindings[outerParamName] = outerArgResolved;
          }
        }
      }
    }
  }

  // Re-resolve headers using paramBindings (handles closure variables like "Bearer " + token)
  if (sinkInfo.headersNode) {
    var enhancedHeaders = {};
    for (var hi = 0; hi < sinkInfo.headersNode.properties.length; hi++) {
      var hProp = sinkInfo.headersNode.properties[hi];
      if (!_t.isObjectProperty(hProp) || hProp.computed) continue;
      var hName = _getKeyName(hProp.key);
      if (!hName) continue;
      if (_t.isStringLiteral(hProp.value)) {
        enhancedHeaders[hName] = hProp.value.value;
      } else {
        var hResolved = _resolveHeaderValue(hProp.value, paramBindings);
        if (hResolved !== null) enhancedHeaders[hName] = hResolved;
      }
    }
    sinkInfo.headers = enhancedHeaders;
  }

  // Build call sites using the sink info + resolved parameter values
  var urls = [];
  if (sinkInfo.urlParamName && paramBindings[sinkInfo.urlParamName]) {
    urls = paramBindings[sinkInfo.urlParamName];
  } else if (sinkInfo.urlLiteral) {
    urls = [sinkInfo.urlLiteral];
  } else if (sinkInfo.urlMemberExpr && paramArgPaths[sinkInfo.urlMemberExpr.obj]) {
    // URL is opts.url — extract .url property from the caller's object argument
    urls = _resolvePropertyFromArg(paramArgPaths[sinkInfo.urlMemberExpr.obj], sinkInfo.urlMemberExpr.prop, 1);
  }
  if (urls.length === 0) return;

  var method = sinkInfo.method || "GET";
  if (sinkInfo.methodParamName && paramBindings[sinkInfo.methodParamName]) {
    method = paramBindings[sinkInfo.methodParamName][0];
    if (typeof method === "string") method = method.toUpperCase();
    else method = "GET";
  } else if (sinkInfo.methodMemberExpr && paramArgPaths[sinkInfo.methodMemberExpr.obj]) {
    // Method is opts.method — extract from caller's object argument
    var methodVals = _resolvePropertyFromArg(paramArgPaths[sinkInfo.methodMemberExpr.obj], sinkInfo.methodMemberExpr.prop, 1);
    if (methodVals.length > 0 && typeof methodVals[0] === "string" && _HTTP_METHODS_LC[methodVals[0].toLowerCase()]) {
      method = methodVals[0].toUpperCase();
    }
  }

  // Get enclosing function name for the CALLER
  var callerFunc = callPath.getFunctionParent();
  var callerName = null;
  if (callerFunc && callerFunc.node.id) callerName = callerFunc.node.id.name;

  // ── Resolve caller's body params ──
  // sinkInfo.params contains params extracted from the wrapper's fetch() body,
  // which is typically empty (body is a parameter identifier, not an object literal).
  // Instead, extract body params from the caller's actual argument.
  var callerBodyParams = sinkInfo.params || [];
  if (sinkInfo.bodyParamName && paramArgPaths[sinkInfo.bodyParamName]) {
    var cbp = _extractBodyParams(paramArgPaths[sinkInfo.bodyParamName].node, callPath);
    if (cbp.length > 0) callerBodyParams = cbp;
  } else if (sinkInfo.bodyMemberExpr && paramArgPaths[sinkInfo.bodyMemberExpr.obj]) {
    // Body comes from opts.data / opts.body — resolve the object, extract the property
    var bodyObjNode = null;
    try { bodyObjNode = _resolveToObject(paramArgPaths[sinkInfo.bodyMemberExpr.obj], 1); } catch(e) { _resolver.collectError(e, "bodyMemberResolve"); }
    if (bodyObjNode) {
      for (var bpi = 0; bpi < bodyObjNode.properties.length; bpi++) {
        var bp = bodyObjNode.properties[bpi];
        if (!_t.isObjectProperty(bp) || bp.computed) continue;
        if (_getKeyName(bp.key) === sinkInfo.bodyMemberExpr.prop) {
          var bodyPropNode = bp.value;
          if (_t.isObjectExpression(bodyPropNode)) {
            callerBodyParams = _extractObjectProperties(bodyPropNode);
            for (var cbpi = 0; cbpi < callerBodyParams.length; cbpi++) callerBodyParams[cbpi].location = "body";
          }
          break;
        }
      }
    }
  }

  // ── Build function-param metadata (which params are used as path, method, etc.) ──
  var wrapperFuncParams = [];
  for (var wpi = 0; wpi < funcNode.params.length; wpi++) {
    var wp = funcNode.params[wpi];
    var wpName = _t.isIdentifier(wp) ? wp.name :
      (_t.isAssignmentPattern(wp) && _t.isIdentifier(wp.left) ? wp.left.name : null);
    if (!wpName) continue;
    // Skip params already consumed as URL, method, or body
    if (wpName === sinkInfo.urlParamName || wpName === sinkInfo.methodParamName || wpName === sinkInfo.bodyParamName) continue;
    if (sinkInfo.urlMemberExpr && wpName === sinkInfo.urlMemberExpr.obj) continue;
    if (sinkInfo.methodMemberExpr && wpName === sinkInfo.methodMemberExpr.obj) continue;
    if (sinkInfo.bodyMemberExpr && wpName === sinkInfo.bodyMemberExpr.obj) continue;
    // This is a non-consumed param — determine its location
    if (paramBindings[wpName] && paramBindings[wpName].length > 0) {
      var wpLoc = "path";  // default: assume it contributes to URL if not body/method
      var wpRequired = !(_t.isAssignmentPattern(wp));
      var wpDefault = _t.isAssignmentPattern(wp) && _t.isStringLiteral(wp.right) ? wp.right.value : undefined;
      wrapperFuncParams.push({ name: wpName, location: wpLoc, required: wpRequired, defaultValue: wpDefault });
    }
  }

  // ── Combine params: body params from caller + function-level params ──
  var allParams = [];
  for (var abp = 0; abp < callerBodyParams.length; abp++) allParams.push(callerBodyParams[abp]);
  for (var afp = 0; afp < wrapperFuncParams.length; afp++) allParams.push(wrapperFuncParams[afp]);

  // ── Cross-reference params with value constraints ──
  for (var vc = 0; vc < allParams.length; vc++) {
    if (allParams[vc].spread) continue;
    var pName = allParams[vc].name;
    var constraint = _getConstraint(callPath, pName);
    if (!constraint && allParams[vc].source && allParams[vc].source !== pName) {
      constraint = _getConstraint(callPath, allParams[vc].source);
    }
    if (constraint && constraint.values.size >= 1) {
      var validValues = [];
      constraint.values.forEach(function(v) { validValues.push(v); });
      allParams[vc].validValues = validValues;
    }
  }

  for (var u = 0; u < urls.length; u++) {
    result.fetchCallSites.push(_buildFetchSite(urls[u], method, sinkInfo.headers, "fetch", allParams, { enclosingFunction: callerName }));
    console.debug("[AST:fetch] traced %s %s via %s()", method, urls[u],
      (funcBinding ? funcBinding.identifier.name : _describeNode(callPath.node.callee)) || "?");
  }
}

// Trace a "deep sink" call — the callee's function body doesn't have a DIRECT sink,
// but nested functions inside it eventually reach xhr.open/fetch.
// Uses property name matching: if the deep sink reads opts.url and opts.type,
// search the caller's arguments for objects with matching property names.
function _traceDeepSinkCall(callPath, funcNode, funcBinding, propMap, result) {
  _stats.interProcTraces++;

  var callArgs = callPath.node.arguments;
  var urls = [];
  var method = propMap.methodLiteral || null;

  // If the deep sink has a literal URL, use it directly
  if (propMap.urlLiteral) {
    urls = [propMap.urlLiteral];
  }

  // Search call arguments for objects with matching property names
  for (var i = 0; i < callArgs.length && i < 5; i++) {
    var argPath = callPath.get("arguments." + i);

    // Look for URL property matches (e.g., .url on the deep sink → extract .url from caller's arg)
    if (urls.length === 0 && propMap.urlProps.length > 0) {
      for (var up = 0; up < propMap.urlProps.length; up++) {
        var urlVals = _resolvePropertyFromArg(argPath, propMap.urlProps[up], 1);
        if (urlVals.length > 0) {
          urls = urlVals;
          break;
        }
      }
    }

    // Look for method property matches (e.g., .type on the deep sink → extract .type from caller's arg)
    if (!method && propMap.methodProps.length > 0) {
      for (var mp = 0; mp < propMap.methodProps.length; mp++) {
        var methodVals = _resolvePropertyFromArg(argPath, propMap.methodProps[mp], 1);
        if (methodVals.length > 0 && typeof methodVals[0] === "string" &&
            _HTTP_METHODS_LC[methodVals[0].toLowerCase()]) {
          method = methodVals[0].toUpperCase();
          break;
        }
      }
    }
  }

  // Fallback: check if any argument is a direct URL string (function takes (url, options) pattern)
  if (urls.length === 0) {
    for (var si = 0; si < callArgs.length && si < 3; si++) {
      var strVals = _resolveAllValues(callPath.get("arguments." + si), 1);
      for (var sv = 0; sv < strVals.length; sv++) {
        if (typeof strVals[sv] === "string" && strVals[sv].length > 0 &&
            (strVals[sv].charAt(0) === "/" || strVals[sv].indexOf("://") > 0)) {
          urls.push(strVals[sv]);
        }
      }
      if (urls.length > 0) break;
    }
  }

  if (urls.length === 0) return;
  if (!method) method = "GET";

  // ── Extract body params from caller args ──
  // Properties not consumed as URL or method are potential body/config params.
  var consumedProps = {};
  for (var cp = 0; cp < propMap.urlProps.length; cp++) consumedProps[propMap.urlProps[cp]] = true;
  for (var cm = 0; cm < propMap.methodProps.length; cm++) consumedProps[propMap.methodProps[cm]] = true;

  var deepParams = [];
  for (var di = 0; di < callArgs.length && di < 5; di++) {
    var deepArgPath = callPath.get("arguments." + di);
    var deepArgObj = null;
    try { deepArgObj = _resolveToObject(deepArgPath, 1); } catch(e) { _resolver.collectError(e, "deepSinkArgResolve"); }
    if (!deepArgObj) continue;
    for (var dpi = 0; dpi < deepArgObj.properties.length; dpi++) {
      var dp = deepArgObj.properties[dpi];
      if (!_t.isObjectProperty(dp) || dp.computed) continue;
      var dpKey = _getKeyName(dp.key);
      if (!dpKey || consumedProps[dpKey]) continue;
      // Skip known non-body config properties
      if (dpKey === "headers" || dpKey === "contentType" || dpKey === "dataType" ||
          dpKey === "success" || dpKey === "error" || dpKey === "complete" ||
          dpKey === "beforeSend" || dpKey === "async" || dpKey === "cache" ||
          dpKey === "timeout" || dpKey === "crossDomain" || dpKey === "processData") continue;
      // "data" property: extract its sub-properties as body params
      if (dpKey === "data") {
        if (_t.isObjectExpression(dp.value)) {
          var dataParams = _extractObjectProperties(dp.value);
          for (var ddp = 0; ddp < dataParams.length; ddp++) { dataParams[ddp].location = "body"; deepParams.push(dataParams[ddp]); }
        } else if (_t.isCallExpression(dp.value) && _isJsonStringify(dp.value, callPath) &&
                   dp.value.arguments[0] && _t.isObjectExpression(dp.value.arguments[0])) {
          var jsonParams = _extractObjectProperties(dp.value.arguments[0]);
          for (var djp = 0; djp < jsonParams.length; djp++) { jsonParams[djp].location = "body"; deepParams.push(jsonParams[djp]); }
        }
        continue;
      }
    }
  }

  var callerFunc = callPath.getFunctionParent();
  var callerName = callerFunc && callerFunc.node.id ? callerFunc.node.id.name : null;
  var calleeName = funcBinding ? funcBinding.identifier.name : _describeNode(callPath.node.callee);

  for (var u = 0; u < urls.length; u++) {
    result.fetchCallSites.push(_buildFetchSite(urls[u], method, {}, propMap.type === "xhr" ? "xhr" : "fetch", deepParams, { enclosingFunction: callerName }));
    console.debug("[AST:fetch] deep-traced %s %s via %s()", method, urls[u], calleeName || "?");
  }
}

// Trace a local variable in a function body back to a function parameter.
// e.g., function n(e,n,a,o,i){ var u = "string"!=typeof e?(n=e).url:e; ... }
// _traceLocalVarToParam(funcNode, "u") → "e" (param[0])
function _traceLocalVarToParam(funcNode, varName) {
  var stmts = funcNode.body && funcNode.body.body ? funcNode.body.body : [];
  var initExpr = null;
  for (var si = 0; si < stmts.length; si++) {
    if (_t.isVariableDeclaration(stmts[si])) {
      var decls = stmts[si].declarations;
      for (var di = 0; di < decls.length; di++) {
        if (_t.isIdentifier(decls[di].id, {name: varName}) && decls[di].init) {
          initExpr = decls[di].init;
          break;
        }
      }
    }
    if (initExpr) break;
  }
  if (!initExpr) return null;
  // Build param name set
  var paramNames = {};
  for (var pi = 0; pi < funcNode.params.length; pi++) {
    var p = funcNode.params[pi];
    if (_t.isIdentifier(p)) paramNames[p.name] = true;
    else if (_t.isAssignmentPattern(p) && _t.isIdentifier(p.left)) paramNames[p.left.name] = true;
  }
  return _findParamInExpr(initExpr, paramNames);
}
function _findParamInExpr(node, paramNames) {
  // Iterative: walk expression chains via explicit stack
  var stack = [node];
  while (stack.length > 0) {
    var n = stack.pop();
    if (!n) continue;
    if (_t.isIdentifier(n) && paramNames[n.name]) return n.name;
    if (_t.isConditionalExpression(n)) {
      stack.push(n.consequent, n.alternate);
    } else if (_t.isLogicalExpression(n)) {
      stack.push(n.left, n.right);
    } else if (_t.isAssignmentExpression(n)) {
      stack.push(n.right);
    } else if (_t.isMemberExpression(n)) {
      stack.push(n.object);
    }
  }
  return null;
}

// Chained wrapper tracing: function(e,t){return n(e,t,"get")} where n() contains the actual sink.
// Maps the outer call's arguments through the wrapper's params to the inner call's arguments,
// then recursively traces the inner function as a wrapper.
function _traceChainedWrapper(callPath, funcNode, result) {
  // Find the call expression in the function body (simple return-call or single expression)
  var innerCall = null;
  var body = funcNode.body;
  if (!_t.isBlockStatement(body)) return; // arrow with expression body handled separately
  var stmts = body.body;
  for (var si = 0; si < stmts.length; si++) {
    var stmt = stmts[si];
    if (_t.isReturnStatement(stmt) && stmt.argument && _t.isCallExpression(stmt.argument)) {
      innerCall = stmt.argument;
      break;
    }
    if (_t.isExpressionStatement(stmt) && _t.isCallExpression(stmt.expression)) {
      innerCall = stmt.expression;
    }
  }
  if (!innerCall) { return; }

  // Resolve the inner callee to a function path that contains a sink
  var innerCallee = innerCall.callee;
  var innerFuncPath = null;
  if (_t.isIdentifier(innerCallee)) {
    // Check if the inner callee resolves to a function containing a network sink
    var innerBinding = callPath.scope.getBinding(innerCallee.name);
    // Try the IIFE scope (when the wrapper was resolved from _resolveIIFEReturnedProperty)
    if (!innerBinding && _lastIIFEFuncPath) {
      try {
        innerBinding = _lastIIFEFuncPath.scope.getBinding(innerCallee.name);
      } catch(e) { _resolver.collectError(e, "iifeChainedScope"); }
    }
    if (innerBinding) {
      if (_t.isFunctionDeclaration(innerBinding.path.node)) innerFuncPath = innerBinding.path;
      else if (_t.isVariableDeclarator(innerBinding.path.node) && innerBinding.path.node.init &&
               (_t.isFunctionExpression(innerBinding.path.node.init) || _t.isArrowFunctionExpression(innerBinding.path.node.init)))
        innerFuncPath = innerBinding.path.get("init");
    }
  }
  if (!innerFuncPath) { return; }
  if (!_containsNetworkSink(innerFuncPath)) return;

  var innerFuncNode = innerFuncPath.node;
  // Map outer call args through wrapper params to inner call args
  // e.g., outerCall: e.get("/api/users") → wrapper: function(e,t){return n(e,t,"get")}
  // Maps: e→"/api/users", t→undefined, then builds synthetic inner call: n("/api/users", undefined, "get")
  var paramMap = {}; // wrapper param name → caller arg index
  for (var pi = 0; pi < funcNode.params.length; pi++) {
    var p = funcNode.params[pi];
    var pn = _t.isIdentifier(p) ? p.name : (_t.isAssignmentPattern(p) && _t.isIdentifier(p.left) ? p.left.name : null);
    if (pn) paramMap[pn] = pi;
  }

  // Build resolved arg values for the inner call by substituting wrapper params
  var resolvedArgs = [];
  for (var ai = 0; ai < innerCall.arguments.length; ai++) {
    var arg = innerCall.arguments[ai];
    if (_t.isIdentifier(arg) && paramMap[arg.name] !== undefined) {
      var outerIdx = paramMap[arg.name];
      if (outerIdx < callPath.node.arguments.length) {
        resolvedArgs.push({ fromCaller: true, callerArgIdx: outerIdx });
      } else {
        resolvedArgs.push({ literal: null });
      }
    } else if (_t.isStringLiteral(arg)) {
      resolvedArgs.push({ literal: arg.value });
    } else {
      resolvedArgs.push({ literal: null });
    }
  }

  // Now trace the inner function with the mapped arguments
  var innerSinkInfo = _findSinkInFunction(innerFuncPath);
  if (!innerSinkInfo) return;

  // Phase 1a: If URL identifier doesn't match an inner function param, trace through local var assignments
  // e.g., redaxios: var u = "string"!=typeof e?(n=e).url:e → u traces back to param e
  if (innerSinkInfo.urlParamName) {
    var _isUrlParam = false;
    for (var _iup = 0; _iup < innerFuncNode.params.length; _iup++) {
      if (_t.isIdentifier(innerFuncNode.params[_iup]) && innerFuncNode.params[_iup].name === innerSinkInfo.urlParamName)
        _isUrlParam = true;
    }
    if (!_isUrlParam) {
      var _srcParam = _traceLocalVarToParam(innerFuncNode, innerSinkInfo.urlParamName);
      if (_srcParam) {
        console.debug("[AST:trace] local var %s → param %s (url)", innerSinkInfo.urlParamName, _srcParam);
        innerSinkInfo.urlParamName = _srcParam;
      }
    }
  }
  // Same for methodParamName
  if (innerSinkInfo.methodParamName) {
    var _isMethParam = false;
    for (var _imp = 0; _imp < innerFuncNode.params.length; _imp++) {
      if (_t.isIdentifier(innerFuncNode.params[_imp]) && innerFuncNode.params[_imp].name === innerSinkInfo.methodParamName)
        _isMethParam = true;
    }
    if (!_isMethParam) {
      var _srcMethParam = _traceLocalVarToParam(innerFuncNode, innerSinkInfo.methodParamName);
      if (_srcMethParam) {
        console.debug("[AST:trace] local var %s → param %s (method)", innerSinkInfo.methodParamName, _srcMethParam);
        innerSinkInfo.methodParamName = _srcMethParam;
      }
    }
  }

  _stats.interProcTraces++;
  // Map inner function params to resolved values from the chained call
  var innerParamBindings = {};
  for (var ipi = 0; ipi < innerFuncNode.params.length && ipi < resolvedArgs.length; ipi++) {
    var ip = innerFuncNode.params[ipi];
    var ipName = _t.isIdentifier(ip) ? ip.name : null;
    if (!ipName) continue;
    var ra = resolvedArgs[ipi];
    if (ra.fromCaller) {
      var callerArgPath = callPath.get("arguments." + ra.callerArgIdx);
      var callerVals = _resolveAllValues(callerArgPath, 1);
      if (callerVals.length > 0) innerParamBindings[ipName] = callerVals;
    } else if (ra.literal !== null) {
      innerParamBindings[ipName] = [ra.literal];
    }
  }

  // Extract URL, method, body from inner sink using resolved param bindings
  var url = innerSinkInfo.urlLiteral || null;
  var method = innerSinkInfo.method || null;
  if (!url && innerSinkInfo.urlParamName && innerParamBindings[innerSinkInfo.urlParamName])
    url = innerParamBindings[innerSinkInfo.urlParamName];
  if (!method && innerSinkInfo.methodParamName && innerParamBindings[innerSinkInfo.methodParamName])
    method = innerParamBindings[innerSinkInfo.methodParamName];
  // MemberExpression method (e.g., opts.method) — resolve through param bindings
  if (!method && innerSinkInfo.methodMemberExpr) {
    var mmObj = innerSinkInfo.methodMemberExpr.obj;
    var mmProp = innerSinkInfo.methodMemberExpr.prop;
    // If the member base is a param, extract the property from caller's arg
    if (paramMap[mmObj] !== undefined || innerParamBindings[mmObj]) {
      // Resolve from caller's arg object
      for (var rai = 0; rai < resolvedArgs.length; rai++) {
        if (resolvedArgs[rai].fromCaller) {
          var argP = callPath.get("arguments." + resolvedArgs[rai].callerArgIdx);
          var propVals = _resolvePropertyFromArg(argP, mmProp, 1);
          if (propVals.length > 0) { method = propVals; break; }
        }
      }
    }
  }
  // MemberExpression URL — similar
  if (!url && innerSinkInfo.urlMemberExpr) {
    var umObj = innerSinkInfo.urlMemberExpr.obj;
    var umProp = innerSinkInfo.urlMemberExpr.prop;
    if (paramMap[umObj] !== undefined || innerParamBindings[umObj]) {
      for (var rai2 = 0; rai2 < resolvedArgs.length; rai2++) {
        if (resolvedArgs[rai2].fromCaller) {
          var argP2 = callPath.get("arguments." + resolvedArgs[rai2].callerArgIdx);
          var propVals2 = _resolvePropertyFromArg(argP2, umProp, 1);
          if (propVals2.length > 0) { url = propVals2; break; }
        }
      }
    }
  }

  var urls = Array.isArray(url) ? url : (url ? [url] : []);
  var methods = Array.isArray(method) ? method : (method ? [method] : ["?"]);
  methods = methods.filter(function(m) { return typeof m === "string"; }).map(function(m) { return m.toUpperCase(); });
  if (methods.length === 0) methods = ["?"];

  // Extract body params from caller's args mapped through inner params
  var bodyParams = [];
  // Check if inner sink has body info in its headers/params tracking
  if (innerSinkInfo.bodyParamName) {
    // Body is a direct param — extract from caller's corresponding arg
    // Don't require innerParamBindings to be set (ObjectExpression args don't resolve to strings)
    for (var bai = 0; bai < resolvedArgs.length; bai++) {
      var innerPN = innerFuncNode.params[bai];
      if (_t.isIdentifier(innerPN) && innerPN.name === innerSinkInfo.bodyParamName && resolvedArgs[bai].fromCaller) {
        var bArgPath = callPath.get("arguments." + resolvedArgs[bai].callerArgIdx);
        bodyParams = _extractBodyParams(bArgPath.node, bArgPath);
        break;
      }
    }
  }

  for (var ui = 0; ui < urls.length; ui++) {
    if (typeof urls[ui] !== "string") continue;
    for (var mi = 0; mi < methods.length; mi++) {
      result.fetchCallSites.push(_buildFetchSite(urls[ui], methods[mi], innerSinkInfo.headers, "fetch", bodyParams));
      console.debug("[AST:fetch] chained %s %s", methods[mi], urls[ui]);
    }
  }
}

function _findSinkInFunction(funcPath) {
  var sinkInfo = null;
  // Walk the function body looking for fetch() or XHR.open()
  // Scope-aware: verify fetch/XMLHttpRequest aren't shadowed by local bindings
  funcPath.traverse(Object.assign({
    CallExpression: function(innerPath) {
      if (sinkInfo) { innerPath.stop(); return; }
      var c = innerPath.node.callee;

      // fetch() / window.fetch() / (s.fetch || fetch)() — only if fetch is the global
      var isFetch = _isGlobalFetchCall(c, innerPath.scope);

      if (isFetch && innerPath.node.arguments.length >= 1) {
        sinkInfo = _extractSinkInfo(innerPath);
        innerPath.stop();
        return;
      }

      // XHR.open(method, url) — verify object traces to XMLHttpRequest
      if (_t.isMemberExpression(c) && _t.isIdentifier(c.property, { name: "open" }) &&
          innerPath.node.arguments.length >= 2 && _isXhrObject(innerPath, c.object)) {
        var xhrM = innerPath.node.arguments[0];
        var xhrMethodStr = null;
        var xhrMethodParam = null;
        if (_t.isStringLiteral(xhrM) && _HTTP_METHODS_LC[xhrM.value.toLowerCase()]) {
          xhrMethodStr = xhrM.value.toUpperCase();
        } else if (_t.isIdentifier(xhrM)) {
          xhrMethodParam = xhrM.name;
        }
        // V2 fix: handle MemberExpression method arg via direct AST node traversal
        // instead of _describeNode() string conversion
        var xhrMethodMember = null;
        if (_t.isMemberExpression(xhrM) && !xhrM.computed &&
            _t.isIdentifier(xhrM.object) && _t.isIdentifier(xhrM.property)) {
          xhrMethodMember = { obj: xhrM.object.name, prop: xhrM.property.name };
          xhrMethodParam = null; // MemberExpression handled directly
        }
        if (xhrMethodStr || xhrMethodParam || xhrMethodMember) {
          var xhrUrlNode = innerPath.node.arguments[1];
          var xhrUrlMember = null;
          if (!_t.isIdentifier(xhrUrlNode) && !_t.isStringLiteral(xhrUrlNode) &&
              _t.isMemberExpression(xhrUrlNode) && !xhrUrlNode.computed) {
            var xuObj = _t.isIdentifier(xhrUrlNode.object) ? xhrUrlNode.object.name : null;
            var xuProp = _t.isIdentifier(xhrUrlNode.property) ? xhrUrlNode.property.name : null;
            if (xuObj && xuProp) xhrUrlMember = { obj: xuObj, prop: xuProp };
          }
          sinkInfo = {
            method: xhrMethodStr,
            methodParamName: xhrMethodParam,
            methodMemberExpr: xhrMethodMember,
            urlParamName: _t.isIdentifier(xhrUrlNode) ? xhrUrlNode.name : null,
            urlLiteral: _t.isStringLiteral(xhrUrlNode) ? xhrUrlNode.value : null,
            urlMemberExpr: xhrUrlMember,
            headers: {},
          };
          innerPath.stop();
        }
      }
    },
  }, _SKIP_NESTED_FUNCS));
  return sinkInfo;
}

// ─── Lightweight Type Tracker ────────────────────────────────────────────────
// Tracks deterministic types from unambiguous patterns (new expressions, array literals).
// Keyed by scopeUid:varName so shadowed variables don't inherit outer types.

var _TYPED_CONSTRUCTORS = {
  "XMLHttpRequest": "XMLHttpRequest", "WebSocket": "WebSocket", "EventSource": "EventSource",
  "URL": "URL", "URLSearchParams": "URLSearchParams", "DOMParser": "DOMParser",
  "BroadcastChannel": "BroadcastChannel", "Worker": "Worker", "SharedWorker": "SharedWorker",
  "Headers": "Headers", "Request": "Request", "Response": "Response",
  "FormData": "FormData", "Blob": "Blob", "File": "File",
  "ReadableStream": "ReadableStream", "WritableStream": "WritableStream",
  "AbortController": "AbortController", "MutationObserver": "MutationObserver",
  "IntersectionObserver": "IntersectionObserver", "ResizeObserver": "ResizeObserver",
};

function _setType(scope, name, type) {
  _typeEnv[scope.uid + ":" + name] = type;
}

function _getType(scope, name) {
  return _typeEnv[scope.uid + ":" + name] || null;
}

// Resolve the tracked type for a node. For Identifiers, looks up binding scope.
// For NewExpressions/ArrayExpressions, returns the type directly.
function _getTrackedType(path, node) {
  if (_t.isIdentifier(node)) {
    var binding = path.scope.getBinding(node.name);
    if (binding) return _getType(binding.scope, node.name) || null;
    return null;
  }
  if (_t.isNewExpression(node) && _t.isIdentifier(node.callee) && !path.scope.getBinding(node.callee.name)) {
    return _TYPED_CONSTRUCTORS[node.callee.name] || null;
  }
  if (_t.isArrayExpression(node)) return "Array";
  return null;
}

// Populate type from a VariableDeclarator: var x = new XMLHttpRequest() → type "XMLHttpRequest"
function _trackTypeFromDeclarator(path) {
  var node = path.node;
  if (!_t.isIdentifier(node.id) || !node.init) return;
  var name = node.id.name;
  var init = node.init;
  // new Constructor() → typed constructor
  if (_t.isNewExpression(init) && _t.isIdentifier(init.callee) && !path.scope.getBinding(init.callee.name)) {
    var ctorType = _TYPED_CONSTRUCTORS[init.callee.name];
    if (ctorType) { _setType(path.scope, name, ctorType); return; }
  }
  // ArrayExpression: [...]
  if (_t.isArrayExpression(init)) { _setType(path.scope, name, "Array"); return; }
  // Array.from(x), Array.of(...), Object.keys(x), Object.values(x), Object.entries(x)
  if (_t.isCallExpression(init) && _t.isMemberExpression(init.callee) && !init.callee.computed &&
      _t.isIdentifier(init.callee.object) && _t.isIdentifier(init.callee.property)) {
    var obj = init.callee.object.name;
    var meth = init.callee.property.name;
    if ((obj === "Array" && (meth === "from" || meth === "of")) ||
        (obj === "Object" && (meth === "keys" || meth === "values" || meth === "entries"))) {
      if (!path.scope.getBinding(obj)) { _setType(path.scope, name, "Array"); return; }
    }
  }
  // .split(), .slice(), .filter(), .map(), .concat() on strings/arrays → Array
  if (_t.isCallExpression(init) && _t.isMemberExpression(init.callee) && !init.callee.computed &&
      _t.isIdentifier(init.callee.property)) {
    var arrayMethods = { "split":1, "slice":1, "filter":1, "map":1, "concat":1, "flat":1, "flatMap":1, "reverse":1, "sort":1 };
    if (arrayMethods[init.callee.property.name]) {
      _setType(path.scope, name, "Array");
      return;
    }
  }
  // document.createElement(tag) → Element, document.getElementById(id) → Element
  if (_t.isCallExpression(init) && _t.isMemberExpression(init.callee) && !init.callee.computed &&
      _t.isIdentifier(init.callee.object, { name: "document" }) && _t.isIdentifier(init.callee.property) &&
      !path.scope.getBinding("document")) {
    var docMeth = init.callee.property.name;
    if (docMeth === "createElement" || docMeth === "getElementById" || docMeth === "querySelector" ||
        docMeth === "getElementsByTagName" || docMeth === "getElementsByClassName") {
      _setType(path.scope, name, "Element");
    }
  }
}

// List of Array iteration methods — property names that survive minification
var _ITERATION_METHODS = {
  "forEach":1, "map":1, "filter":1, "some":1, "every":1,
  "find":1, "findIndex":1, "flatMap":1, "reduce":1, "reduceRight":1,
};

// Types known to be non-iterable (no .forEach/.map etc.)
var _NON_ITERABLE_TYPES = {
  "XMLHttpRequest":1, "WebSocket":1, "EventSource":1, "Element":1,
  "DOMParser":1, "BroadcastChannel":1, "Worker":1, "SharedWorker":1,
  "AbortController":1, "MutationObserver":1, "Headers":1, "Request":1,
  "Response":1, "Blob":1, "File":1,
};

// Deep sink check: does a function eventually reach a network sink through any code path?
// Unlike _findSinkInFunction, this traverses into ALL nested functions and only returns true/false.
// Used to identify high-level API functions (like jQuery.ajax) as network sinks.
function _containsNetworkSink(funcPath) {
  var found = false;
  // Scope-aware traversal: verify identifiers aren't shadowed by local bindings
  funcPath.traverse({
    CallExpression: function(innerPath) {
      if (found) { innerPath.stop(); return; }
      var c = innerPath.node.callee;
      // fetch() / window.fetch() / (s.fetch || fetch)() — only if fetch is the global
      if (_isGlobalFetchCall(c, innerPath.scope)) { found = true; innerPath.stop(); return; }
      // .open() — only a network sink if object traces to XMLHttpRequest
      if (_t.isMemberExpression(c) && _t.isIdentifier(c.property, { name: "open" }) &&
          innerPath.node.arguments.length >= 2 && _isXhrObject(innerPath, c.object)) {
        found = true; innerPath.stop(); return;
      }
    },
    NewExpression: function(innerPath) {
      if (found) { innerPath.stop(); return; }
      if (_t.isIdentifier(innerPath.node.callee, { name: "XMLHttpRequest" }) &&
          !innerPath.scope.getBinding("XMLHttpRequest")) {
        found = true; innerPath.stop();
      }
    },
    // DO search into nested functions (unlike _findSinkInFunction)
  });
  return found;
}

// Find the property names used at deep network sinks (traversing into nested functions).
// Unlike _findSinkInFunction (which skips nested functions and returns a param-name-based sinkInfo),
// this searches INTO closures/callbacks and extracts the PROPERTY NAMES used at the sink.
// E.g., xhr.open(opts.type, opts.url) → { urlProps: ["url"], methodProps: ["type"] }
// These property names can then be matched against the caller's object arguments.
function _findDeepSinkPropertyMap(funcPath) {
  var propMap = null;
  // Scope-aware: verify fetch/XMLHttpRequest aren't shadowed by local bindings
  funcPath.traverse({
    CallExpression: function(innerPath) {
      if (propMap) { innerPath.stop(); return; }
      var c = innerPath.node.callee;

      // fetch(url, opts) or window.fetch(url, opts) — only if not shadowed
      // fetch() / window.fetch() / (s.fetch || fetch)() — only if fetch is the global
      if (_isGlobalFetchCall(c, innerPath.scope) && innerPath.node.arguments.length >= 1) {
        propMap = _extractSinkPropertyMap(innerPath, "fetch");
        if (propMap && propMap.urlProps.length === 0 && !propMap.urlLiteral) propMap = null;
        if (propMap) innerPath.stop();
        return;
      }

      // xhr.open(method, url) — verify object traces to XMLHttpRequest
      if (_t.isMemberExpression(c) && _t.isIdentifier(c.property, { name: "open" }) &&
          innerPath.node.arguments.length >= 2 && _isXhrObject(innerPath, c.object)) {
        propMap = _extractSinkPropertyMap(innerPath, "xhr");
        if (propMap && propMap.urlProps.length === 0 && !propMap.urlLiteral) propMap = null;
        if (propMap) innerPath.stop();
        return;
      }
    },
    // DO search into nested functions — deep sinks are inside closures/callbacks
  });
  return propMap;
}

// Extract property names from a specific network sink's arguments.
// For xhr.open(method, url): method position → methodProps, url position → urlProps.
// For fetch(url, {method: M}): url position → urlProps, method from options → methodProps.
function _extractSinkPropertyMap(sinkPath, sinkType) {
  var map = {
    type: sinkType,
    urlProps: [],
    methodProps: [],
    methodLiteral: null,
    urlLiteral: null,
  };

  if (sinkType === "xhr") {
    // xhr.open(method, url)
    var methodArg = sinkPath.node.arguments[0];
    var urlArg = sinkPath.node.arguments[1];

    if (_t.isStringLiteral(methodArg) && _HTTP_METHODS_LC[methodArg.value.toLowerCase()]) {
      map.methodLiteral = methodArg.value.toUpperCase();
    } else {
      _collectMemberProps(methodArg, map.methodProps);
    }

    if (_t.isStringLiteral(urlArg)) {
      map.urlLiteral = urlArg.value;
    } else {
      _collectMemberProps(urlArg, map.urlProps);
    }
  } else {
    // fetch(url, opts)
    var fetchUrlArg = sinkPath.node.arguments[0];

    if (_t.isStringLiteral(fetchUrlArg)) {
      map.urlLiteral = fetchUrlArg.value;
    } else {
      _collectMemberProps(fetchUrlArg, map.urlProps);
    }

    // Look for method in options object (second arg)
    if (sinkPath.node.arguments.length >= 2) {
      var optsArg = sinkPath.node.arguments[1];
      if (_t.isObjectExpression(optsArg)) {
        for (var i = 0; i < optsArg.properties.length; i++) {
          var prop = optsArg.properties[i];
          if (!_t.isObjectProperty(prop) || prop.computed) continue;
          var key = _t.isIdentifier(prop.key) ? prop.key.name : (_t.isStringLiteral(prop.key) ? prop.key.value : null);
          if (key === "method") {
            if (_t.isStringLiteral(prop.value) && _HTTP_METHODS_LC[prop.value.value.toLowerCase()]) {
              map.methodLiteral = prop.value.value.toUpperCase();
            } else {
              _collectMemberProps(prop.value, map.methodProps);
            }
          }
        }
      } else if (_t.isIdentifier(optsArg) || _t.isMemberExpression(optsArg)) {
        // Options is a variable — the method property is accessed as opts.method
        // We can't resolve without scope, but record the pattern for future tracing
        _collectMemberProps(optsArg, map.methodProps);
      }
    }
  }

  return map;
}

// Collect terminal property names from MemberExpression chains.
// E.g., options.url → ["url"], options.type → ["type"]
// Also handles BinaryExpression (string concat): options.url + path → ["url"]
function _collectMemberProps(node, out) {
  // Iterative: walk BinaryExpression(+) chains via explicit stack
  var stack = [node];
  while (stack.length > 0) {
    var n = stack.pop();
    if (_t.isMemberExpression(n) && !n.computed && _t.isIdentifier(n.property)) {
      out.push(n.property.name);
    }
    // BinaryExpression: options.url + "/path" → still extract "url"
    if (_t.isBinaryExpression(n) && n.operator === "+") {
      stack.push(n.left, n.right);
    }
  }
}

function _extractSinkInfo(fetchPath) {
  var args = fetchPath.node.arguments;
  var urlNode = args[0];
  var info = {
    urlParamName: _t.isIdentifier(urlNode) ? urlNode.name : null,
    urlLiteral: _t.isStringLiteral(urlNode) ? urlNode.value : null,
    // MemberExpression URL: fetch(opts.url) → {obj: "opts", prop: "url"}
    urlMemberExpr: null,
    method: null,
    methodParamName: null,
    // MemberExpression method: fetch(url, {method: opts.method})
    methodMemberExpr: null,
    headers: {},
    params: undefined,
  };
  // Capture MemberExpression URL argument (opts.url, config.endpoint, etc.)
  if (!info.urlParamName && !info.urlLiteral && _t.isMemberExpression(urlNode) && !urlNode.computed) {
    var urlObj = _t.isIdentifier(urlNode.object) ? urlNode.object.name : null;
    var urlProp = _t.isIdentifier(urlNode.property) ? urlNode.property.name : null;
    if (urlObj && urlProp) info.urlMemberExpr = { obj: urlObj, prop: urlProp };
  }

  // Extract from options object
  if (args[1] && _t.isObjectExpression(args[1])) {
    var opts = args[1].properties;
    for (var i = 0; i < opts.length; i++) {
      if (!_t.isObjectProperty(opts[i]) || opts[i].computed) continue;
      var key = _getKeyName(opts[i].key);
      var val = opts[i].value;

      if (key === "method") {
        if (_t.isStringLiteral(val)) info.method = val.value.toUpperCase();
        else if (_t.isIdentifier(val)) info.methodParamName = val.name;
        else if (_t.isMemberExpression(val) && !val.computed) {
          var mObj = _t.isIdentifier(val.object) ? val.object.name : null;
          var mProp = _t.isIdentifier(val.property) ? val.property.name : null;
          if (mObj && mProp) info.methodMemberExpr = { obj: mObj, prop: mProp };
        }
        // Unwrap .toUpperCase()/.toLowerCase() and LogicalExpression chains
        // e.g., (a||s.method||"get").toUpperCase() → extract param name "a"
        if (!info.method && !info.methodParamName && !info.methodMemberExpr) {
          var _mVal = val;
          if (_t.isCallExpression(_mVal) && _t.isMemberExpression(_mVal.callee) &&
              _t.isIdentifier(_mVal.callee.property) &&
              (_mVal.callee.property.name === "toUpperCase" || _mVal.callee.property.name === "toLowerCase")) {
            _mVal = _mVal.callee.object;
          }
          if (_t.isIdentifier(_mVal)) {
            info.methodParamName = _mVal.name;
          } else if (_t.isLogicalExpression(_mVal)) {
            // Walk left-first: (a || b || c) is parsed as ((a || b) || c)
            var _cur = _mVal;
            while (_cur) {
              if (_t.isIdentifier(_cur)) { info.methodParamName = _cur.name; break; }
              if (_t.isLogicalExpression(_cur)) {
                if (_t.isIdentifier(_cur.left)) { info.methodParamName = _cur.left.name; break; }
                _cur = _t.isLogicalExpression(_cur.left) ? _cur.left : _cur.right;
              } else break;
            }
          }
        }
      }
      if (key === "headers" && _t.isObjectExpression(val)) {
        info.headers = _extractHeaders(val);
        info.headersNode = val;  // Store raw node for scope-aware resolution later
      }
      if (key === "body") {
        info.params = _extractBodyParams(val);
        // Track body source so _traceWrapperFunction can resolve through caller args
        var bodyValNode = val;
        bodyValNode = _unwrapJsonStringify(val, fetchPath);
        if (_t.isIdentifier(bodyValNode)) info.bodyParamName = bodyValNode.name;
        else if (_t.isMemberExpression(bodyValNode) && !bodyValNode.computed) {
          var bObj = _t.isIdentifier(bodyValNode.object) ? bodyValNode.object.name : null;
          var bProp = _t.isIdentifier(bodyValNode.property) ? bodyValNode.property.name : null;
          if (bObj && bProp) info.bodyMemberExpr = { obj: bObj, prop: bProp };
        }
      }
    }
  }
  return info;
}

function _extractFetchCall(path, result, type) {
  var args = path.node.arguments;
  if (!args.length) return;

  // ── Resolve URL (may produce multiple values via inter-procedural tracing) ──
  var urlArgPath = path.get("arguments.0");
  var urls = _resolveAllValues(urlArgPath, 0);

  // Template literal with interpolations → keep as URL template
  if (urls.length === 0 && _t.isTemplateLiteral(args[0]) && args[0].expressions.length > 0) {
    urls = [_templateToUrl(args[0])];
  }

  // If URL couldn't be resolved to a concrete value, skip this call site.
  // Library-internal sinks (jQuery xhr.open(i.type, i.url), axios fetch(w), etc.)
  // have unresolvable URLs — emitting placeholders creates noise, not usable endpoints.

  if (urls.length === 0) return;

  // ── Extract method, headers, body from options ──
  var httpMethod = null;
  var httpMethods = null;  // array for per-caller pairing when multiple values
  var headers = {};
  var bodyParams = [];

  // Resolve options object — inline or via variable reference or function parameter
  var optsNode = args[1] || null;
  var optsPath = args[1] ? path.get("arguments.1") : null;
  if (optsNode && _t.isIdentifier(optsNode) && optsPath) {
    var optsBinding = path.scope.getBinding(optsNode.name);
    if (optsBinding && _t.isVariableDeclarator(optsBinding.path.node) && optsBinding.path.node.init) {
      optsNode = optsBinding.path.node.init;
      optsPath = optsBinding.path.get("init");
    } else if (optsBinding && optsBinding.kind === "param") {
      // Options passed as function parameter — resolve from callers
      var optsFuncPath = optsBinding.scope.path;
      var optsFuncBinding = null;
      if (optsFuncPath.node.id) optsFuncBinding = optsFuncPath.scope.parent ? optsFuncPath.scope.parent.getBinding(optsFuncPath.node.id.name) : null;
      if (!optsFuncBinding && _t.isVariableDeclarator(optsFuncPath.parent)) optsFuncBinding = optsFuncPath.scope.parent ? optsFuncPath.scope.parent.getBinding(optsFuncPath.parent.id.name) : null;
      if (optsFuncBinding && optsFuncBinding.referencePaths) {
        var optsParamIdx = -1;
        for (var opi = 0; opi < optsFuncPath.node.params.length; opi++) {
          var opn = optsFuncPath.node.params[opi];
          var opnName = _t.isIdentifier(opn) ? opn.name : (_t.isAssignmentPattern(opn) && _t.isIdentifier(opn.left) ? opn.left.name : null);
          if (opnName === optsNode.name) { optsParamIdx = opi; break; }
        }
        if (optsParamIdx >= 0) {
          var callerRefs = optsFuncBinding.referencePaths;
          for (var cri = 0; cri < callerRefs.length; cri++) {
            var cRef = callerRefs[cri];
            if (_t.isCallExpression(cRef.parent) && cRef.parent.callee === cRef.node &&
                optsParamIdx < cRef.parent.arguments.length) {
              var callerOptsArg = cRef.parent.arguments[optsParamIdx];
              if (_t.isObjectExpression(callerOptsArg)) {
                optsNode = callerOptsArg;
                optsPath = cRef.parentPath.get("arguments." + optsParamIdx);
                break;
              }
              if (_t.isIdentifier(callerOptsArg)) {
                var callerOptsB = cRef.parentPath.scope.getBinding(callerOptsArg.name);
                if (callerOptsB && _t.isVariableDeclarator(callerOptsB.path.node) && _t.isObjectExpression(callerOptsB.path.node.init)) {
                  optsNode = callerOptsB.path.node.init;
                  optsPath = callerOptsB.path.get("init");
                  break;
                }
              }
            }
          }
        }
      }
    }
  }

  // Try _resolveToObject for non-ObjectExpression opts (e.g. Object.assign, call returns)
  if (optsNode && !_t.isObjectExpression(optsNode) && optsPath) {
    var resolvedObj = _resolveToObject(optsPath, 0);
    if (resolvedObj && resolvedObj.type === "ObjectExpression") {
      optsNode = resolvedObj;
      if (resolvedObj._path) optsPath = resolvedObj._path;
    }
  }

  if (optsNode && _t.isObjectExpression(optsNode)) {
    var opts = optsNode.properties;
    for (var o = 0; o < opts.length; o++) {
      if (!_t.isObjectProperty(opts[o]) || opts[o].computed) continue;
      var optName = _getKeyName(opts[o].key);
      var optVal = opts[o].value;

      if (optName === "method") {
        var methodPath = null;
        try { methodPath = optsPath.get("properties." + o + ".value"); } catch(e) { _resolver.collectError(e, "fetchMethodPath"); }
        var methodVals = [];
        if (_t.isStringLiteral(optVal)) {
          methodVals = [optVal.value];
        } else if (methodPath && methodPath.node) {
          methodVals = _resolveAllValues(methodPath, 0);
        }
        var validMethods = [];
        for (var mi = 0; mi < methodVals.length; mi++) {
          if (typeof methodVals[mi] === "string" && _HTTP_METHODS_LC[methodVals[mi].toLowerCase()]) {
            validMethods.push(methodVals[mi].toUpperCase());
          }
        }
        if (validMethods.length > 0) {
          httpMethod = validMethods[0];
          if (validMethods.length > 1) httpMethods = validMethods;
        }
      }
      if (optName === "headers" && _t.isObjectExpression(optVal)) {
        headers = _extractHeaders(optVal);
      }
      if (optName === "body") {
        bodyParams = _extractBodyParams(optVal, path);
      }
    }
  }

  // ── Response type from enclosing function ──
  var responseType = null;
  var funcParent = path.getFunctionParent();
  if (funcParent) {
    responseType = _detectResponseParsing(funcParent);
  }

  // ── Enclosing function params — determine location from usage in the fetch call ──
  var funcInfo = funcParent ? _extractFuncParams(funcParent.node) : null;
  var funcParams = [];
  if (funcInfo && funcInfo.params.length > 0) {
    // Build a set of param names used in specific roles
    var _usedAsUrl = new Set();    // param used as URL argument or in URL concatenation
    var _usedAsMethod = new Set(); // param used as method option value
    var _usedAsBody = new Set();   // param used in body option
    var _usedAsOpts = new Set();   // param used as the options object
    var _usedAsHeader = new Set(); // param used in headers object
    // URL argument: walk entire expression tree (handles concat, ternary, template)
    _collectIdentifiers(args[0], _usedAsUrl);
    // Options argument: fetch(url, paramName)
    if (args[1] && _t.isIdentifier(args[1])) _usedAsOpts.add(args[1].name);
    // Walk options object properties
    if (optsNode && _t.isObjectExpression(optsNode)) {
      for (var mo = 0; mo < optsNode.properties.length; mo++) {
        if (!_t.isObjectProperty(optsNode.properties[mo]) || optsNode.properties[mo].computed) continue;
        var moKey = _getKeyName(optsNode.properties[mo].key);
        var moVal = optsNode.properties[mo].value;
        if (moKey === "method") _collectIdentifiers(moVal, _usedAsMethod);
        if (moKey === "body") _collectIdentifiers(moVal, _usedAsBody);
        if (moKey === "headers" && _t.isObjectExpression(moVal)) {
          for (var hp = 0; hp < moVal.properties.length; hp++) {
            if (_t.isObjectProperty(moVal.properties[hp])) {
              _collectIdentifiers(moVal.properties[hp].value, _usedAsHeader);
            }
          }
        }
      }
    }

    // Expand through local variable bindings — if a collected name is a local
    // variable (not a function param), resolve its init and collect from that.
    // This traces e.g. var url = id ? "..." + id : "..." → id contributes to URL.
    var _funcParamNames = new Set();
    for (var _fpi = 0; _fpi < funcInfo.params.length; _fpi++) {
      _funcParamNames.add(funcInfo.params[_fpi].name);
    }
    var _allSets = [_usedAsUrl, _usedAsMethod, _usedAsBody, _usedAsOpts, _usedAsHeader];
    for (var _si = 0; _si < _allSets.length; _si++) {
      var _set = _allSets[_si];
      var _toExpand = [];
      _set.forEach(function(name) { _toExpand.push(name); });
      for (var _ei = 0; _ei < _toExpand.length; _ei++) {
        var _eName = _toExpand[_ei];
        if (_funcParamNames.has(_eName)) continue;
        var _eBinding = path.scope.getBinding(_eName);
        if (_eBinding && _t.isVariableDeclarator(_eBinding.path.node) && _eBinding.path.node.init) {
          _collectIdentifiers(_eBinding.path.node.init, _set);
        }
      }
    }

    for (var fp = 0; fp < funcInfo.params.length; fp++) {
      var fParam = funcInfo.params[fp];
      var matched = false;
      for (var ep = 0; ep < bodyParams.length; ep++) {
        if (bodyParams[ep].source === fParam.name || bodyParams[ep].name === fParam.name) {
          if (!fParam.required) {
            bodyParams[ep].required = false;
            if (fParam.defaultValue !== undefined) bodyParams[ep].defaultValue = fParam.defaultValue;
          }
          matched = true;
        }
      }
      if (!matched && !fParam.rest) {
        var loc = "unknown";
        if (_usedAsUrl.has(fParam.name)) loc = "path";
        else if (_usedAsMethod.has(fParam.name)) loc = "method";
        else if (_usedAsBody.has(fParam.name)) loc = "body";
        else if (_usedAsOpts.has(fParam.name)) loc = "options";
        else if (_usedAsHeader.has(fParam.name)) loc = "header";
        // For body params that are function parameters, try to resolve the caller's
        // actual argument to extract concrete body field names (e.g., {item: "widget"})
        // instead of just recording the wrapper's parameter name.
        if (loc === "body") {
          var bodyBinding = path.scope.getBinding(fParam.name);
          if (bodyBinding && bodyBinding.kind === "param" && bodyBinding.referencePaths) {
            var callerBodyResolved = false;
            var funcPath = bodyBinding.scope.path;
            var funcBindingForBody = null;
            if (funcPath.node.id) funcBindingForBody = funcPath.scope.parent ? funcPath.scope.parent.getBinding(funcPath.node.id.name) : null;
            if (!funcBindingForBody && _t.isVariableDeclarator(funcPath.parent)) funcBindingForBody = funcPath.scope.parent ? funcPath.scope.parent.getBinding(funcPath.parent.id.name) : null;
            // Determine paramIdx for body param
            var paramIdx = -1;
            paramIdx = _findParamIndex(funcPath.node.params, fParam.name);
            // Direct function binding: callers are funcName(args)
            if (funcBindingForBody && funcBindingForBody.referencePaths && paramIdx >= 0) {
              var refs = funcBindingForBody.referencePaths;
              for (var ri = 0; ri < refs.length; ri++) {
                var ref = refs[ri];
                if (ref.parent && _t.isCallExpression(ref.parent) && ref.parent.callee === ref.node &&
                    paramIdx < ref.parent.arguments.length) {
                  var callerArgNode = ref.parent.arguments[paramIdx];
                  var callerBodyExtracted = _extractBodyParams(callerArgNode, ref.parentPath);
                  if (callerBodyExtracted.length > 0) {
                    for (var cbe = 0; cbe < callerBodyExtracted.length; cbe++) funcParams.push(callerBodyExtracted[cbe]);
                    callerBodyResolved = true;
                  }
                }
              }
            }
            // Method-call pattern: function is a property of an object or prototype
            if (!callerBodyResolved && !funcBindingForBody && paramIdx >= 0) {
              var methodName = null;
              var objBindings = []; // bindings for variables that hold the object instance
              // Case: ObjectProperty — { method: function(body){...} }
              if (_t.isObjectProperty(funcPath.parent)) {
                methodName = _getKeyName(funcPath.parent.key);
                if (methodName && funcPath.parentPath && funcPath.parentPath.parentPath) {
                  var objExprPath = funcPath.parentPath.parentPath;
                  if (_t.isObjectExpression(objExprPath.node)) {
                    // Sub-case A: var obj = { method: function(){} }
                    if (_t.isVariableDeclarator(objExprPath.parent) && _t.isIdentifier(objExprPath.parent.id)) {
                      var ovb = objExprPath.scope.getBinding(objExprPath.parent.id.name);
                      if (ovb) objBindings.push(ovb);
                    }
                    // Sub-case B: return { method: function(){} } inside factory function
                    else if (_t.isReturnStatement(objExprPath.parent)) {
                      var factoryFunc = objExprPath.getFunctionParent();
                      if (factoryFunc) {
                        var ffb = null;
                        if (factoryFunc.node.id) ffb = factoryFunc.scope.parent ? factoryFunc.scope.parent.getBinding(factoryFunc.node.id.name) : null;
                        if (!ffb && _t.isVariableDeclarator(factoryFunc.parent)) ffb = factoryFunc.scope.parent ? factoryFunc.scope.parent.getBinding(factoryFunc.parent.id.name) : null;
                        if (ffb && ffb.referencePaths) {
                          for (var fci = 0; fci < ffb.referencePaths.length; fci++) {
                            var fRef = ffb.referencePaths[fci];
                            if (_t.isCallExpression(fRef.parent) && fRef.parent.callee === fRef.node) {
                              var fcParent = fRef.parentPath ? fRef.parentPath.parent : null;
                              if (fcParent && _t.isVariableDeclarator(fcParent) && _t.isIdentifier(fcParent.id)) {
                                var instB = fRef.parentPath.scope.getBinding(fcParent.id.name);
                                if (instB) objBindings.push(instB);
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
              // Case: Prototype — Constructor.prototype.method = function(body){...}
              else if (_t.isAssignmentExpression(funcPath.parent) && funcPath.parent.operator === "=") {
                var aLeft = funcPath.parent.left;
                if (_t.isMemberExpression(aLeft) && !aLeft.computed && _t.isIdentifier(aLeft.property) &&
                    _t.isMemberExpression(aLeft.object) && !aLeft.object.computed &&
                    _t.isIdentifier(aLeft.object.property, { name: "prototype" }) && _t.isIdentifier(aLeft.object.object)) {
                  methodName = aLeft.property.name;
                  var ctorName = aLeft.object.object.name;
                  var ctorBinding = funcPath.scope.getBinding(ctorName);
                  if (ctorBinding && ctorBinding.referencePaths) {
                    for (var nci = 0; nci < ctorBinding.referencePaths.length; nci++) {
                      var nRef = ctorBinding.referencePaths[nci];
                      if (_t.isNewExpression(nRef.parent) && nRef.parent.callee === nRef.node) {
                        var newParent = nRef.parentPath ? nRef.parentPath.parent : null;
                        if (newParent && _t.isVariableDeclarator(newParent) && _t.isIdentifier(newParent.id)) {
                          var niB = nRef.parentPath.scope.getBinding(newParent.id.name);
                          if (niB) objBindings.push(niB);
                        }
                      }
                    }
                  }
                }
              }
              // Search obj bindings for .method() calls and extract body args
              if (methodName && objBindings.length > 0) {
                for (var obi = 0; obi < objBindings.length; obi++) {
                  if (!objBindings[obi].referencePaths) continue;
                  var orefs = objBindings[obi].referencePaths;
                  for (var ori = 0; ori < orefs.length; ori++) {
                    var oRef = orefs[ori];
                    if (_t.isMemberExpression(oRef.parent) && oRef.parent.object === oRef.node &&
                        !oRef.parent.computed && _t.isIdentifier(oRef.parent.property, { name: methodName })) {
                      var mcExpr = oRef.parentPath ? oRef.parentPath.parent : null;
                      if (mcExpr && _t.isCallExpression(mcExpr) && mcExpr.callee === oRef.parent &&
                          paramIdx < mcExpr.arguments.length) {
                        var mcArg = mcExpr.arguments[paramIdx];
                        var mcBody = _extractBodyParams(mcArg, oRef.parentPath.parentPath);
                        if (mcBody.length > 0) {
                          for (var mci = 0; mci < mcBody.length; mci++) funcParams.push(mcBody[mci]);
                          callerBodyResolved = true;
                        }
                      }
                    }
                  }
                }
              }
            }
            if (callerBodyResolved) continue;  // Skip adding the wrapper param name
          }
        }
        if (loc !== "unknown") {
          funcParams.push({ name: fParam.name, location: loc, required: fParam.required, defaultValue: fParam.defaultValue, source: fParam.name });
        }
      }
    }
  }

  // ── URL template params ──
  var urlTemplateParams = [];
  if (_t.isTemplateLiteral(args[0]) && args[0].expressions.length > 0) {
    urlTemplateParams = _extractTemplateParams(args[0]);
  }

  // ── Build param list ──
  var params = [];
  for (var tp = 0; tp < urlTemplateParams.length; tp++) {
    params.push({ name: urlTemplateParams[tp], location: "path", required: true });
  }
  for (var bp = 0; bp < bodyParams.length; bp++) {
    params.push(bodyParams[bp]);
  }
  for (var fpi = 0; fpi < funcParams.length; fpi++) {
    params.push(funcParams[fpi]);
  }

  // ── Cross-reference params with value constraints ──
  for (var vc = 0; vc < params.length; vc++) {
    if (params[vc].spread) continue;
    var pName = params[vc].name;
    // For function params, also try the source variable name for constraint lookup
    var constraint = _getConstraint(path, pName);
    if (!constraint && params[vc].source && params[vc].source !== pName) {
      constraint = _getConstraint(path, params[vc].source);
    }
    if (constraint && constraint.values.size >= 1) {
      var validValues = [];
      constraint.values.forEach(function(v) { validValues.push(v); });
      params[vc].validValues = validValues;
    }
  }

  // ── Create call sites (with per-caller method pairing) ──
  for (var u = 0; u < urls.length; u++) {
    var siteMethod = httpMethods && u < httpMethods.length ? httpMethods[u] : (httpMethod || "GET");
    result.fetchCallSites.push(_buildFetchSite(urls[u], siteMethod, headers, type, params, { enclosingFunction: funcInfo ? funcInfo.name : undefined, responseType: responseType }));
  }

  if (urls.length > 0) {
    var paramSummary = "";
    if (params.length > 0) {
      paramSummary = " params=[" + params.map(function(p) {
        var desc = (p.required ? "" : "?") + p.name + ":" + (p.location || "body");
        if (p.validValues) desc += "={" + p.validValues.slice(0, 5).join("|") + (p.validValues.length > 5 ? "|..." : "") + "}";
        return desc;
      }).join(", ") + "]";
    }
    var urlDisplay = urls[0].length > 80 ? urls[0].substring(0, 80) + "..." : urls[0];
    console.debug("[AST:fetch] %s %s %s%s%s",
      type, httpMethod || "GET", urlDisplay,
      urls.length > 1 ? " (+" + (urls.length - 1) + " more)" : "",
      paramSummary);
  }
}

// ─── Value Resolution ───────────────────────────────────────────────────────

function _resolveAllValues(path, depth) {
  var node = path.node;
  if (!node) return [];

  // Literals — no recursion, return directly regardless of depth
  if (_t.isStringLiteral(node)) return [node.value];
  if (_t.isNumericLiteral(node)) return [String(node.value)];

  if (!_resolver.guard("V", node)) return [];
  try {

  // Simple template literal without interpolations
  if (_t.isTemplateLiteral(node) && node.expressions.length === 0 && node.quasis.length === 1) {
    return [node.quasis[0].value.cooked || node.quasis[0].value.raw];
  }

  // Template literal with resolvable expressions
  if (_t.isTemplateLiteral(node) && node.expressions.length > 0) {
    var allResolvable = true;
    var parts = [];
    for (var ti = 0; ti < node.quasis.length; ti++) {
      parts.push(node.quasis[ti].value.cooked || node.quasis[ti].value.raw || "");
      if (ti < node.expressions.length) {
        var exprVals = _resolveAllValues(path.get("expressions." + ti), depth + 1);
        if (exprVals.length === 0) { allResolvable = false; break; }
        parts.push(exprVals[0]); // use first resolved value
      }
    }
    if (allResolvable) return [parts.join("")];
    return [_templateToUrl(node)]; // fall back to template with placeholders
  }

  // String concatenation — flatten left-recursive chain iteratively to avoid stack overflow.
  // ((a + b) + c) + d is walked as: collect [d, c, b, a] from the left spine, reverse, then zip.
  if (_t.isBinaryExpression(node, { operator: "+" })) {
    var concatParts = [];
    var cur = path;
    while (_t.isBinaryExpression(cur.node, { operator: "+" })) {
      concatParts.push(cur.get("right"));
      cur = cur.get("left");
    }
    concatParts.push(cur); // leftmost non-+ term
    concatParts.reverse();

    // Resolve each term individually (bounded by term complexity, not chain length)
    var concatResult = _resolveAllValues(concatParts[0], depth + 1);
    var anyResolved = concatResult.length > 0;
    for (var ci = 1; ci < concatParts.length; ci++) {
      var partVals = _resolveAllValues(concatParts[ci], depth + 1);
      if (partVals.length > 0) anyResolved = true;
      if (concatResult.length > 0 && partVals.length > 0) {
        var combined = [];
        var maxLen = Math.max(concatResult.length, partVals.length);
        for (var zi = 0; zi < maxLen && combined.length < 20; zi++) {
          var l = concatResult[Math.min(zi, concatResult.length - 1)];
          var r = partVals[Math.min(zi, partVals.length - 1)];
          combined.push(String(l) + String(r));
        }
        concatResult = combined;
      } else if (concatResult.length === 0 && partVals.length > 0) {
        concatResult = partVals;
      }
      // If partVals is empty, keep concatResult as-is (partial resolution)
    }
    if (anyResolved && concatResult.length > 0) return concatResult;
  }

  // Conditional expression: a ? b : (c ? d : e) — flatten alternate-recursive chain iteratively.
  if (_t.isConditionalExpression(node)) {
    var ternaryVals = [];
    var cur = path;
    while (_t.isConditionalExpression(cur.node)) {
      ternaryVals = ternaryVals.concat(_resolveAllValues(cur.get("consequent"), depth + 1));
      cur = cur.get("alternate");
    }
    ternaryVals = ternaryVals.concat(_resolveAllValues(cur, depth + 1));
    if (ternaryVals.length > 0) return ternaryVals;
  }

  // Logical OR: (a || b) || c — flatten left-recursive chain iteratively.
  if (_t.isLogicalExpression(node, { operator: "||" })) {
    var orParts = [];
    var cur = path;
    while (_t.isLogicalExpression(cur.node, { operator: "||" })) {
      orParts.push(cur.get("right"));
      cur = cur.get("left");
    }
    orParts.push(cur);
    orParts.reverse();
    var orVals = [];
    for (var oi = 0; oi < orParts.length; oi++) {
      orVals = orVals.concat(_resolveAllValues(orParts[oi], depth + 1));
    }
    if (orVals.length > 0) return orVals;
  }

  // Call expression — resolve through function return values
  // Handles: fetch(getUrl()), fetch(buildUrl("/api", id)), var x = config.get("key")
  if (_t.isCallExpression(node)) {
    var retVals = _resolveCallReturnValues(path, depth);
    if (retVals.length > 0) return retVals;
    // String method passthrough: .replace(), .trim(), .toLowerCase(), .toUpperCase(), .slice(), .substring()
    // These return a modified version of the string — resolve the object for URL analysis
    if (_t.isMemberExpression(node.callee) && !node.callee.computed) {
      var smName = _t.isIdentifier(node.callee.property) ? node.callee.property.name : null;
      if (smName === "replace" || smName === "trim" || smName === "toLowerCase" ||
          smName === "toUpperCase" || smName === "slice" || smName === "substring" || smName === "substr") {
        var smVals = _resolveAllValues(path.get("callee.object"), depth + 1);
        if (smVals.length > 0) return smVals;
      }
      // Array.join(separator): resolve array elements and join with separator
      if (smName === "join" && node.arguments.length <= 1) {
        var joinArrNode = _resolveToArray(path.get("callee.object"), 0);
        if (joinArrNode && joinArrNode.elements && joinArrNode.elements.length > 0) {
          var sep = ",";
          if (node.arguments.length === 1 && _t.isStringLiteral(node.arguments[0])) sep = node.arguments[0].value;
          var joinParts = [];
          for (var ji = 0; ji < joinArrNode.elements.length; ji++) {
            if (_t.isStringLiteral(joinArrNode.elements[ji])) joinParts.push(joinArrNode.elements[ji].value);
            else if (_t.isNumericLiteral(joinArrNode.elements[ji])) joinParts.push(String(joinArrNode.elements[ji].value));
            else joinParts = null;
            if (!joinParts) break;
          }
          if (joinParts) return [joinParts.join(sep)];
        }
      }
    }
  }

  // Variable reference — use Babel scope analysis
  if (_t.isIdentifier(node)) {
    var binding = path.scope.getBinding(node.name);
    if (!binding) {
      // Fallback: try global assignments (window.X = value from another script)
      var globalDef = _globalAssignments[node.name];
      if (globalDef && globalDef.valuePath) {
        return _resolveAllValues(globalDef.valuePath, depth + 1);
      }
      return [];
    }

    // Constant with initializer
    if (binding.constant && _t.isVariableDeclarator(binding.path.node) && binding.path.node.init) {
      var initVals = _resolveAllValues(binding.path.get("init"), depth + 1);
      if (initVals.length > 0) {
        _stats.resolvedUrls++;
        return initVals;
      }
    }

    // Function parameter — inter-procedural tracing
    if (binding.kind === "param") {
      var callerValues = _resolveParamFromCallers(binding, depth);
      if (callerValues.length > 0) {
        _stats.interProcTraces++;
        return callerValues;
      }
    }

    // Non-constant variable — check if all assignments are string literals
    if (!binding.constant && binding.constantViolations.length > 0 && binding.constantViolations.length <= 5) {
      var vals = [];
      if (_t.isVariableDeclarator(binding.path.node) && binding.path.node.init) {
        var initVal = _resolveAllValues(binding.path.get("init"), depth + 1);
        vals = vals.concat(initVal);
      }
      for (var cv = 0; cv < binding.constantViolations.length; cv++) {
        var violation = binding.constantViolations[cv];
        if (_t.isAssignmentExpression(violation.node) && violation.node.operator === "=") {
          var rhs = _resolveAllValues(violation.get("right"), depth + 1);
          vals = vals.concat(rhs);
        }
      }
      if (vals.length > 0) return vals;
    }
  }

  // Member expression — resolve obj.prop through scope
  if (_t.isMemberExpression(node) && !node.computed) {
    var propName = _t.isIdentifier(node.property) ? node.property.name : null;
    if (propName) {
      // this.prop — resolve by walking up to the enclosing ObjectExpression
      if (_t.isThisExpression(node.object)) {
        var funcPath = path.getFunctionParent();
        if (funcPath) {
          // Walk up: function → ObjectProperty.value → ObjectExpression
          var funcParentPath = funcPath.parentPath;
          if (funcParentPath && _t.isObjectProperty(funcParentPath.node) && funcParentPath.node.value === funcPath.node) {
            var objExprPath = funcParentPath.parentPath;
            if (objExprPath && _t.isObjectExpression(objExprPath.node)) {
              var objProps = objExprPath.node.properties;
              for (var ti = 0; ti < objProps.length; ti++) {
                var tp = objProps[ti];
                if (_t.isObjectProperty(tp) && !tp.computed) {
                  var tpKey = _t.isIdentifier(tp.key) ? tp.key.name :
                    (_t.isStringLiteral(tp.key) ? tp.key.value : null);
                  if (tpKey === propName) {
                    var thisVals = _resolveAllValues(objExprPath.get("properties." + ti + ".value"), depth + 1);
                    if (thisVals.length > 0) return thisVals;
                  }
                }
              }
            }
          }
          // this.prop in a prototype method: SomeClass.prototype.method = function() { this.prop }
          // Trace through constructor's this.prop = param assignment to find values from new SomeClass() calls
          if (funcParentPath && _t.isAssignmentExpression(funcParentPath.node) && funcParentPath.node.right === funcPath.node) {
            var assignLeft = funcParentPath.node.left;
            if (_t.isMemberExpression(assignLeft) && _t.isMemberExpression(assignLeft.object) &&
                (_t.isIdentifier(assignLeft.object.property, { name: "prototype" }) ||
                 (_t.isStringLiteral(assignLeft.object.property) && assignLeft.object.property.value === "prototype"))) {
              var ctorIdent = assignLeft.object.object;
              var ctorName = _t.isIdentifier(ctorIdent) ? ctorIdent.name : null;
              if (ctorName) {
                var ctorVals = _resolveConstructorProperty(path, ctorName, propName, depth);
                if (ctorVals.length > 0) return ctorVals;
              }
            }
          }
          // this.prop in an ES6 class method: class Foo { method() { this.prop } }
          // Trace through the class constructor's this.prop = param assignment
          if (_t.isClassMethod(funcPath.node) && _t.isClassBody(funcPath.parent)) {
            var classDecl = funcPath.parentPath.parentPath;
            if (classDecl && (_t.isClassDeclaration(classDecl.node) || _t.isClassExpression(classDecl.node)) && classDecl.node.id) {
              var className = classDecl.node.id.name;
              var classCtorVals = _resolveClassConstructorProperty(path, classDecl, className, propName, depth);
              if (classCtorVals.length > 0) return classCtorVals;
            }
          }
        }
      }

      // Try inline object properties first
      var objVals = _resolveToObject(path.get("object"), depth);
      if (objVals) {
        for (var oi = 0; oi < objVals.properties.length; oi++) {
          var op = objVals.properties[oi];
          if (_t.isObjectProperty(op) && !op.computed) {
            var opKey = _t.isIdentifier(op.key) ? op.key.name :
              (_t.isStringLiteral(op.key) ? op.key.value : null);
            if (opKey === propName) {
              if (_t.isStringLiteral(op.value)) return [op.value.value];
              if (_t.isNumericLiteral(op.value)) return [String(op.value.value)];
              // Recurse for nested resolution
              var nestedVals = _resolveAllValues(objVals._path.get("properties." + oi + ".value"), depth + 1);
              if (nestedVals.length > 0) return nestedVals;
            }
          }
        }
      }
      // Try property assignments: obj.prop = value
      // Babel doesn't count property mutations as constantViolations, so scan referencePaths
      if (_t.isIdentifier(node.object)) {
        var objBinding = path.scope.getBinding(node.object.name);
        if (objBinding) {
          var refs = objBinding.referencePaths;
          for (var ri = 0; ri < refs.length; ri++) {
            var refParent = refs[ri].parent;
            // Looking for: mod.propName = value
            if (_t.isMemberExpression(refParent) && refParent.object === refs[ri].node &&
                !refParent.computed && _t.isIdentifier(refParent.property, { name: propName })) {
              var assignNode = refs[ri].parentPath ? refs[ri].parentPath.parent : null;
              if (assignNode && _t.isAssignmentExpression(assignNode) && assignNode.operator === "=" &&
                  assignNode.left === refParent) {
                var rhsVals = _resolveAllValues(refs[ri].parentPath.parentPath.get("right"), depth + 1);
                if (rhsVals.length > 0) return rhsVals;
              }
            }
          }
        }
      }

      // Inter-procedural: obj is a function parameter → trace to callers, extract property
      // from their object literal arguments. Handles patterns like:
      //   function request(opts) { fetch(opts.url, {method: opts.method}); }
      //   request({url: "/api/users", method: "GET"});
      if (_t.isIdentifier(node.object)) {
        var objParamBinding = path.scope.getBinding(node.object.name);
        if (objParamBinding && objParamBinding.kind === "param") {
          console.debug("[AST:trace]   param.prop: %s.%s (depth=%d)", node.object.name, propName, depth);
          var paramPropValues = _resolveParamFromCallers(objParamBinding, depth, propName);
          console.debug("[AST:trace]   param.prop result: [%s] (%d values)", paramPropValues.join(", "), paramPropValues.length);
          if (paramPropValues.length > 0) {
            _stats.interProcTraces++;
            return paramPropValues;
          }
        }
      }

      // arr[i].prop — extract prop from all array elements
      if (_t.isMemberExpression(node.object) && node.object.computed) {
        var arrNode = _resolveToArray(path.get("object.object"), depth);
        if (arrNode) {
          var arrPropVals = [];
          for (var ai = 0; ai < arrNode.elements.length && arrPropVals.length < 20; ai++) {
            var aElem = arrNode.elements[ai];
            if (aElem && _t.isObjectExpression(aElem)) {
              for (var api = 0; api < aElem.properties.length; api++) {
                var aep = aElem.properties[api];
                if (_t.isObjectProperty(aep) && !aep.computed && _getKeyName(aep.key) === propName) {
                  arrPropVals = arrPropVals.concat(_resolveAllValues(arrNode._path.get("elements." + ai + ".properties." + api + ".value"), depth + 1));
                }
              }
            }
          }
          if (arrPropVals.length > 0) return arrPropVals;
        }
      }
    }
  }

  // Computed member access: obj[key] or arr[idx]
  if (_t.isMemberExpression(node) && node.computed) {
    // Object with resolvable or unresolvable key — try specific keys first, fallback to all values
    var compObj = _resolveToObject(path.get("object"), depth);
    if (compObj) {
      var keyVals = _resolveAllValues(path.get("property"), depth + 1);
      if (keyVals.length > 0) {
        var resolvedVals = [];
        for (var ki = 0; ki < keyVals.length && resolvedVals.length < 20; ki++) {
          for (var vi = 0; vi < compObj.properties.length; vi++) {
            var vp = compObj.properties[vi];
            if (_t.isObjectProperty(vp) && !vp.computed && _getKeyName(vp.key) === String(keyVals[ki])) {
              resolvedVals = resolvedVals.concat(_resolveAllValues(compObj._path.get("properties." + vi + ".value"), depth + 1));
            }
          }
        }
        if (resolvedVals.length > 0) {
          // For variable keys (not literal), also include remaining property values for discovery
          if (!_t.isStringLiteral(node.property) && !_t.isNumericLiteral(node.property)) {
            for (var dpi = 0; dpi < compObj.properties.length && resolvedVals.length < 20; dpi++) {
              var dp = compObj.properties[dpi];
              if (_t.isObjectProperty(dp) && !dp.computed) {
                var dpVals = _resolveAllValues(compObj._path.get("properties." + dpi + ".value"), depth + 1);
                for (var dvi = 0; dvi < dpVals.length; dvi++) {
                  if (resolvedVals.indexOf(dpVals[dvi]) < 0) resolvedVals.push(dpVals[dvi]);
                }
              }
            }
          }
          return resolvedVals;
        }
      }
      // Can't resolve key — return all property values
      var allPropVals = [];
      for (var fpi = 0; fpi < compObj.properties.length && allPropVals.length < 20; fpi++) {
        var fp = compObj.properties[fpi];
        if (_t.isObjectProperty(fp) && !fp.computed) {
          allPropVals = allPropVals.concat(_resolveAllValues(compObj._path.get("properties." + fpi + ".value"), depth + 1));
        }
      }
      if (allPropVals.length > 0) return allPropVals;
    }
    // Array with computed index — return all element values
    var compArr = _resolveToArray(path.get("object"), depth);
    if (compArr) {
      var elemVals = [];
      for (var ei = 0; ei < compArr.elements.length && elemVals.length < 20; ei++) {
        if (compArr.elements[ei]) {
          elemVals = elemVals.concat(_resolveAllValues(compArr._path.get("elements." + ei), depth + 1));
        }
      }
      if (elemVals.length > 0) return elemVals;
    }
  }

  return [];
  } catch (_rave) {
    if (_rave instanceof RangeError) { _resolver.collectError(_rave, "resolveAllValues"); return []; }
    throw _rave;
  } finally { _resolver.unguard("V", node); }
}

// Resolve a call expression's callee to its function path (with scope info).
// Covers the common cases: identifier → scope binding, member expr → object property.
// Returns the Babel path to the function node, or null.
function _resolveCalleeFuncPath(callPath, depth) {
  var callee = callPath.node.callee;
  if (_t.isIdentifier(callee)) {
    var binding = callPath.scope.getBinding(callee.name);
    if (binding) {
      if (_t.isFunctionDeclaration(binding.path.node)) return binding.path;
      if (_t.isVariableDeclarator(binding.path.node) && binding.path.node.init) {
        var init = binding.path.node.init;
        if (_t.isFunctionExpression(init) || _t.isArrowFunctionExpression(init))
          return binding.path.get("init");
      }
    }
  }
  if (_t.isMemberExpression(callee) && !callee.computed) {
    var propName = _t.isIdentifier(callee.property) ? callee.property.name : null;
    if (propName) {
      var objNode = _resolveToObject(callPath.get("callee.object"), depth || 0);
      if (objNode) {
        for (var i = 0; i < objNode.properties.length; i++) {
          var prop = objNode.properties[i];
          if (!_t.isObjectProperty(prop) || prop.computed) continue;
          var key = _t.isIdentifier(prop.key) ? prop.key.name :
            (_t.isStringLiteral(prop.key) ? prop.key.value : null);
          if (key === propName && (_t.isFunctionExpression(prop.value) || _t.isArrowFunctionExpression(prop.value)))
            return objNode._path ? objNode._path.get("properties." + i + ".value") : null;
        }
      }
    }
  }
  return null;
}

// Resolve a call expression through the callee's return statements.
// Traces into function definitions to find what they return.
// Handles: getUrl() → "https://...", buildUrl(base, path) → base + "/" + path
function _resolveCallReturnValues(callPath, depth) {
  if (!_resolver.guard("R", callPath.node)) return [];
  try {
  var funcPath = _resolveCalleeFuncPath(callPath, depth);
  if (!funcPath) return [];

  // Arrow function with expression body: () => "/api/data" or (x) => base + x
  if (_t.isArrowFunctionExpression(funcPath.node) && !_t.isBlockStatement(funcPath.node.body)) {
    return _resolveAllValues(funcPath.get("body"), depth + 1);
  }

  // Collect return values from the function body
  var values = [];
  try {
    funcPath.traverse(Object.assign({
      ReturnStatement: function(retPath) {
        if (retPath.node.argument) {
          var retVals = _resolveAllValues(retPath.get("argument"), depth + 1);
          values = values.concat(retVals);
        }
      },
    }, _SKIP_NESTED_FUNCS));
  } catch (e) { _resolver.collectError(e, "resolveCallReturn"); }
  return values;
  } catch (_rcre) {
    if (_rcre instanceof RangeError) { _resolver.collectError(_rcre, "resolveCallReturnValues"); return []; }
    throw _rcre;
  } finally { _resolver.unguard("R", callPath.node); }
}

// Resolve a call expression to its returned ObjectExpression (if any)
function _resolveCallReturnToObject(callPath, depth) {
  if (!_resolver.guard("O", callPath.node)) return null;
  try {
  var funcPath = _resolveCalleeFuncPath(callPath, depth);
  if (!funcPath) return null;

  // Arrow function with expression body: () => ({url: "/api"})
  if (_t.isArrowFunctionExpression(funcPath.node) && !_t.isBlockStatement(funcPath.node.body)) {
    var bodyPath = funcPath.get("body");
    if (_t.isObjectExpression(bodyPath.node)) {
      bodyPath.node._path = bodyPath;
      return bodyPath.node;
    }
    return _resolveToObject(bodyPath, depth + 1);
  }

  // Traverse function body for return statements that return objects
  var result = null;
  try {
    funcPath.traverse(Object.assign({
      ReturnStatement: function(retPath) {
        if (result) return;
        if (retPath.node.argument) {
          var argPath = retPath.get("argument");
          if (_t.isObjectExpression(argPath.node)) {
            argPath.node._path = argPath;
            result = argPath.node;
          } else {
            result = _resolveToObject(argPath, depth + 1);
          }
        }
      },
    }, _SKIP_NESTED_FUNCS));
  } catch (e) { _resolver.collectError(e, "resolveCallReturnToObject"); }
  return result;
  } catch (_roe) {
    if (_roe instanceof RangeError) { _resolver.collectError(_roe, "resolveCallReturnToObject"); return null; }
    throw _roe;
  } finally { _resolver.unguard("O", callPath.node); }
}

// Resolve an expression to its ObjectExpression node (if it's a variable pointing to one)
function _resolveToObject(path, depth) {
  var node = path.node;
  // Literal ObjectExpression — no recursion, return directly regardless of depth
  if (_t.isObjectExpression(node)) {
    node._path = path;
    return node;
  }
  if (!_resolver.guard("T", node)) return null;
  try {
  if (_t.isIdentifier(node)) {
    var binding = path.scope.getBinding(node.name);
    if (!binding) {
      // Fallback: try global assignments (window.X = {...})
      var globalDef = _globalAssignments[node.name];
      if (globalDef && _t.isObjectExpression(globalDef.valueNode)) {
        globalDef.valueNode._path = globalDef.valuePath;
        return globalDef.valueNode;
      }
      return null;
    }
    if (_t.isVariableDeclarator(binding.path.node) && binding.path.node.init) {
      if (_t.isObjectExpression(binding.path.node.init)) {
        binding.path.node.init._path = binding.path.get("init");
        return binding.path.node.init;
      }
      // Call expression: var cfg = getConfig() → resolve through return values
      if (_t.isCallExpression(binding.path.node.init)) {
        return _resolveCallReturnToObject(binding.path.get("init"), depth);
      }
    }
  }
  // Object.assign({}, src1, src2, ...) → merge all object arguments
  if (_t.isCallExpression(node) && _t.isMemberExpression(node.callee) &&
      _t.isIdentifier(node.callee.object, { name: "Object" }) &&
      !path.scope.getBinding("Object") &&
      _t.isIdentifier(node.callee.property, { name: "assign" }) &&
      node.arguments.length >= 2) {
    var mergedProps = [];
    for (var oai = 0; oai < node.arguments.length; oai++) {
      var oaArg = node.arguments[oai];
      var oaObj = null;
      if (_t.isObjectExpression(oaArg)) {
        oaObj = oaArg;
      } else if (_t.isIdentifier(oaArg)) {
        var oaBinding = path.scope.getBinding(oaArg.name);
        if (oaBinding && _t.isVariableDeclarator(oaBinding.path.node) && _t.isObjectExpression(oaBinding.path.node.init)) {
          oaObj = oaBinding.path.node.init;
        }
      }
      if (oaObj) {
        for (var oap = 0; oap < oaObj.properties.length; oap++) {
          // Later args override earlier ones (like Object.assign behavior)
          var oaProp = oaObj.properties[oap];
          if (!_t.isObjectProperty(oaProp) || oaProp.computed) continue;
          var oaKey = _getKeyName(oaProp.key);
          if (oaKey) {
            // Remove earlier property with same key
            mergedProps = mergedProps.filter(function(mp) {
              var mpKey = _getKeyName(mp.key);
              return mpKey !== oaKey;
            });
            mergedProps.push(oaProp);
          }
        }
      }
    }
    if (mergedProps.length > 0) {
      // Create a synthetic ObjectExpression with merged properties
      var synObj = { type: "ObjectExpression", properties: mergedProps, _path: path };
      return synObj;
    }
  }
  // Member expression: obj.prop where prop's value is an ObjectExpression
  if (_t.isMemberExpression(node) && !node.computed) {
    var propName = _t.isIdentifier(node.property) ? node.property.name : null;
    if (propName) {
      var parentObj = _resolveToObject(path.get("object"), depth + 1);
      if (parentObj) {
        for (var i = 0; i < parentObj.properties.length; i++) {
          var prop = parentObj.properties[i];
          if (!_t.isObjectProperty(prop) || prop.computed) continue;
          var key = _t.isIdentifier(prop.key) ? prop.key.name :
            (_t.isStringLiteral(prop.key) ? prop.key.value : null);
          if (key === propName && _t.isObjectExpression(prop.value)) {
            prop.value._path = parentObj._path.get("properties." + i + ".value");
            return prop.value;
          }
        }
      }
    }
  }
  return null;
  } catch (_rtoe) {
    if (_rtoe instanceof RangeError) { _resolver.collectError(_rtoe, "resolveToObject"); return null; }
    throw _rtoe;
  } finally { _resolver.unguard("T", node); }
}

// Resolve an expression to its ArrayExpression node (if it's a variable pointing to one)
function _resolveToArray(path, depth) {
  var node = path.node;
  if (_t.isArrayExpression(node)) {
    node._path = path;
    return node;
  }
  if (!_resolver.guard("A", node)) return null;
  try {
  if (_t.isIdentifier(node)) {
    var binding = path.scope.getBinding(node.name);
    if (!binding) return null;
    if (_t.isVariableDeclarator(binding.path.node) && binding.path.node.init &&
        _t.isArrayExpression(binding.path.node.init)) {
      binding.path.node.init._path = binding.path.get("init");
      return binding.path.node.init;
    }
    // Parameter: resolve from callers to find array literal argument
    if (binding.kind === "param") {
      var paramFuncPath = binding.scope.path;
      if (_t.isFunction(paramFuncPath.node)) {
        var pIdx = _findParamIndex(paramFuncPath.node.params, node.name);
        if (pIdx >= 0) {
          var fb = null;
          if (paramFuncPath.node.id) fb = (paramFuncPath.scope.parent || paramFuncPath.scope).getBinding(paramFuncPath.node.id.name);
          if (!fb && _t.isVariableDeclarator(paramFuncPath.parent)) fb = (paramFuncPath.scope.parent || paramFuncPath.scope).getBinding(paramFuncPath.parent.id.name);
          if (fb && fb.referencePaths) {
            for (var ri = 0; ri < fb.referencePaths.length; ri++) {
              var ref = fb.referencePaths[ri];
              if (_t.isCallExpression(ref.parent) && ref.parent.callee === ref.node && pIdx < ref.parent.arguments.length) {
                var argPath = ref.parentPath.get("arguments." + pIdx);
                if (_t.isArrayExpression(argPath.node)) { argPath.node._path = argPath; return argPath.node; }
                var resolved = _resolveToArray(argPath, depth + 1);
                if (resolved) return resolved;
              }
            }
          }
        }
      }
    }
  }
  return null;
  } catch (_rtae) {
    if (_rtae instanceof RangeError) { _resolver.collectError(_rtae, "resolveToArray"); return null; }
    throw _rtae;
  } finally { _resolver.unguard("A", node); }
}

function _resolveParamFromCallers(binding, depth, propName) {
  if (!_resolver.guard("P", binding.identifier)) return [];
  try {

  // Find the function that has this parameter
  var funcPath = binding.scope.path;
  if (!_t.isFunction(funcPath.node)) return [];

  // Debug: describe the enclosing function context
  var _funcId = funcPath.node.id ? funcPath.node.id.name : "(anon)";
  var _funcParentType = funcPath.parent ? funcPath.parent.type : "none";
  var _funcParentDetail = "";
  if (_t.isObjectProperty(funcPath.parent)) {
    var _fpk = funcPath.parent.key;
    _funcParentDetail = " key=" + (_t.isIdentifier(_fpk) ? _fpk.name : (_t.isStringLiteral(_fpk) ? _fpk.value : "?"));
  } else if (_t.isCallExpression(funcPath.parent)) {
    var _fpc = funcPath.parent.callee;
    if (_t.isIdentifier(_fpc)) _funcParentDetail = " callee=" + _fpc.name;
    else if (_t.isMemberExpression(_fpc) && _t.isIdentifier(_fpc.object) && _t.isIdentifier(_fpc.property))
      _funcParentDetail = " callee=" + _fpc.object.name + "." + _fpc.property.name;
  } else if (_t.isReturnStatement(funcPath.parent)) {
    _funcParentDetail = " (returned)";
  } else if (_t.isAssignmentExpression(funcPath.parent)) {
    var _fpl = funcPath.parent.left;
    if (_t.isIdentifier(_fpl)) _funcParentDetail = " assigned=" + _fpl.name;
    else if (_t.isMemberExpression(_fpl) && _t.isIdentifier(_fpl.object) && _t.isIdentifier(_fpl.property))
      _funcParentDetail = " assigned=" + _fpl.object.name + "." + _fpl.property.name;
    else if (_t.isMemberExpression(_fpl)) _funcParentDetail = " assigned=MemberExpr";
  }
  var _paramNames = funcPath.node.params.map(function(pp) { return _t.isIdentifier(pp) ? pp.name : pp.type; }).join(", ");
  console.debug("[AST:trace]   _resolveParamFromCallers: param=%s prop=%s func=%s(%s) parent=%s%s",
    binding.identifier.name, propName || "none", _funcId, _paramNames, _funcParentType, _funcParentDetail);

  // Find parameter index
  var paramIdx = _findParamIndex(funcPath.node.params, binding.identifier.name);

  // Destructured parameter: function f({url, method}) { fetch(url); }
  // The binding "url" is inside an ObjectPattern at params[i].
  // Resolve by finding the property key, then extracting it from callers' object arguments.
  if (paramIdx === -1) {
    for (var di = 0; di < funcPath.node.params.length; di++) {
      var dParam = funcPath.node.params[di];
      // Direct destructuring: function f({url, method})
      if (_t.isObjectPattern(dParam)) {
        var dKey = _findDestructuredKey(dParam, binding.identifier.name);
        if (dKey) { paramIdx = di; propName = dKey; break; }
      }
      // Destructuring with default: function f({url, method} = {})
      if (_t.isAssignmentPattern(dParam) && _t.isObjectPattern(dParam.left)) {
        var dKey2 = _findDestructuredKey(dParam.left, binding.identifier.name);
        if (dKey2) { paramIdx = di; propName = dKey2; break; }
      }
    }
  }
  if (paramIdx === -1) { console.debug("[AST:trace]     → paramIdx not found, aborting"); return []; }
  console.debug("[AST:trace]     paramIdx=%d", paramIdx);

  // Find the function's binding (how it's referenced)
  var funcBinding = _getFunctionBinding(funcPath);
  // Also check VariableDeclarator above assignment chain: const Se = me = function()
  // When callers use Se() but funcBinding is me, we need Se's binding too
  var _altFuncBinding = null;
  if (funcBinding && _t.isAssignmentExpression(funcPath.parent)) {
    var _chain = funcPath.parentPath;
    while (_chain && _t.isAssignmentExpression(_chain.node)) _chain = _chain.parentPath;
    if (_chain && _t.isVariableDeclarator(_chain.node) && _t.isIdentifier(_chain.node.id)) {
      _altFuncBinding = _chain.scope.getBinding(_chain.node.id.name);
      if (_altFuncBinding === funcBinding) _altFuncBinding = null;
    }
  }
  if (!funcBinding && _t.isObjectProperty(funcPath.parent)) {
    // { method: function(url) { ... } } — trace via obj.method(...) call sites
    var methodKey = funcPath.parent.key;
    var methodName = _t.isIdentifier(methodKey) ? methodKey.name :
      (_t.isStringLiteral(methodKey) ? methodKey.value : null);
    if (methodName) {
      console.debug("[AST:trace]     → ObjectProperty route: methodName=%s", methodName);
      return _resolveParamFromObjectMethod(funcPath, paramIdx, methodName, depth, propName);
    }
    console.debug("[AST:trace]     → ObjectProperty but no method name, aborting");
    return [];
  }
  if (!funcBinding && _t.isAssignmentExpression(funcPath.parent) &&
      _t.isMemberExpression(funcPath.parent.left) && !funcPath.parent.left.computed) {
    // obj.method = function(url) { ... } — trace via obj.method(...) call sites
    var assignProp = funcPath.parent.left.property;
    var assignMethodName = _t.isIdentifier(assignProp) ? assignProp.name : null;
    var assignObj = funcPath.parent.left.object;
    if (assignMethodName && _t.isIdentifier(assignObj)) {
      var assignObjBinding = funcPath.scope.getBinding(assignObj.name);
      if (assignObjBinding) {
        return _resolveParamFromMethodCalls(assignObjBinding, assignMethodName, paramIdx, depth, propName);
      }
      // Global assignment: window.doFetch = function(url) { ... }
      // The function is called as doFetch(...) — a bare identifier call with no binding.
      // Use _globalAssignments to confirm this is a known global, then find callers
      // by scanning the AST for bare identifier calls matching the assigned name.
      var isGlobalTarget = _isGlobalObject(assignObj.name, funcPath.scope);
      if (isGlobalTarget && _globalAssignments[assignMethodName]) {
        return _resolveParamFromGlobalCallers(funcPath, assignMethodName, paramIdx, depth, propName);
      }
    }
    // Ctor.prototype.method = function(params) { ... } — trace via instance.method(...) call sites
    if (assignMethodName && _t.isMemberExpression(assignObj) && !assignObj.computed &&
        (_t.isIdentifier(assignObj.property, { name: "prototype" }) ||
         (_t.isStringLiteral(assignObj.property) && assignObj.property.value === "prototype")) &&
        _t.isIdentifier(assignObj.object)) {
      var protoCtorName = assignObj.object.name;
      return _resolveParamFromPrototypeMethodCallers(funcPath, protoCtorName, assignMethodName, paramIdx, depth, propName);
    }
    return [];
  }
  // Computed member assignment: obj[method] = function(url) { ... }
  // Resolve method to its string values and search for obj.get/post/... call sites
  if (!funcBinding && _t.isAssignmentExpression(funcPath.parent) &&
      _t.isMemberExpression(funcPath.parent.left) && funcPath.parent.left.computed) {
    var compObj = funcPath.parent.left.object;
    var compProp = funcPath.parent.left.property;
    if (_t.isIdentifier(compObj) && _t.isIdentifier(compProp)) {
      var compObjBinding = funcPath.scope.getBinding(compObj.name);
      var compPropVals = _resolveAllValues(funcPath.parentPath.get("left.property"), 0);
      if (compObjBinding && compPropVals.length > 0) {
        var compValues = [];
        for (var cvi = 0; cvi < compPropVals.length; cvi++) {
          if (typeof compPropVals[cvi] !== "string") continue;
          console.debug("[AST:trace]     → computed-member route: %s[%s] → %s.%s()", compObj.name, compPropVals[cvi], compObj.name, compPropVals[cvi]);
          var cmVals = _resolveParamFromMethodCalls(compObjBinding, compPropVals[cvi], paramIdx, depth, propName);
          compValues = compValues.concat(cmVals);
        }
        // Also check global aliases
        for (var gn in _globalAssignments) {
          var ga = _globalAssignments[gn];
          if (!ga.valueNode) continue;
          var gaVal = ga.valueNode;
          while (_t.isAssignmentExpression(gaVal)) gaVal = gaVal.right;
          if (_t.isIdentifier(gaVal) && gaVal.name === compObjBinding.identifier.name) {
            for (var cvi2 = 0; cvi2 < compPropVals.length; cvi2++) {
              if (typeof compPropVals[cvi2] !== "string") continue;
              console.debug("[AST:trace]     → computed-member global: %s.%s()", gn, compPropVals[cvi2]);
              var cgVals = _resolveParamFromGlobalCallers(funcPath, gn, paramIdx, depth + 1, propName, compPropVals[cvi2]);
              compValues = compValues.concat(cgVals);
            }
          }
        }
        if (compValues.length > 0) return compValues;
      }
    }
    return [];
  }
  // Callback argument pattern: someFunc(function(param) { sink(param.prop) })
  // The function is an argument to a call expression. Trace into the called function
  // to find where it invokes the callback parameter with concrete arguments.
  if (!funcBinding && _t.isCallExpression(funcPath.parent)) {
    var cbCallExpr = funcPath.parentPath;
    var cbArgIdx = -1;
    for (var cbi = 0; cbi < funcPath.parent.arguments.length; cbi++) {
      if (funcPath.parent.arguments[cbi] === funcPath.node) { cbArgIdx = cbi; break; }
    }
    if (cbArgIdx >= 0) {
      console.debug("[AST:trace]     → callback-arg route: arg[%d] of call, tracing receiver", cbArgIdx);
      var cbValues = _resolveParamFromCallbackArg(cbCallExpr, cbArgIdx, paramIdx, depth, propName);
      if (cbValues.length > 0) return cbValues;
    }
  }

  // ReturnStatement: function is returned from an enclosing function (e.g., IIFE)
  // Trace up to the IIFE call, find what its result is assigned to, then find callers.
  if (!funcBinding && _t.isReturnStatement(funcPath.parent)) {
    var enclosingFunc = funcPath.findParent(function(p) { return p.isFunction() && p !== funcPath; });
    if (enclosingFunc) {
      var encParent = enclosingFunc.parentPath;
      // IIFE: (function(){...return fn...})() — enclosingFunc is the callee of a CallExpression
      if (encParent && _t.isCallExpression(encParent.node) && encParent.node.callee === enclosingFunc.node) {
        var iifeCallPath = encParent;
        var iifeParent = iifeCallPath.parentPath;
        // var x = IIFE() → find callers of x
        if (iifeParent && _t.isVariableDeclarator(iifeParent.node) && _t.isIdentifier(iifeParent.node.id)) {
          var iifeVarBinding = iifeParent.scope.getBinding(iifeParent.node.id.name);
          if (iifeVarBinding) {
            console.debug("[AST:trace]     → returned-from-IIFE route: var %s = IIFE()", iifeParent.node.id.name);
            funcBinding = iifeVarBinding;
          }
        }
        // (windowAlias).X = IIFE() → find bare callers of X via global callers
        if (!funcBinding && iifeParent && _t.isAssignmentExpression(iifeParent.node) &&
            _t.isMemberExpression(iifeParent.node.left)) {
          var iifeAssignProp = iifeParent.node.left.property;
          var iifeGlobalName = _t.isIdentifier(iifeAssignProp) ? iifeAssignProp.name : null;
          if (iifeGlobalName && _globalAssignments[iifeGlobalName]) {
            console.debug("[AST:trace]     → returned-from-IIFE route: global %s = IIFE()", iifeGlobalName);
            return _resolveParamFromGlobalCallers(funcPath, iifeGlobalName, paramIdx, depth, propName);
          }
        }
      }
      // UMD callback pattern: !function(p, factory){...factory()...}(this, function(){return innerFn})
      // The enclosing function is an ARGUMENT to an outer IIFE, not its callee.
      // Find which parameter it maps to, then check if that parameter's call result is a global.
      if (!funcBinding && encParent && _t.isCallExpression(encParent.node) &&
          encParent.node.callee !== enclosingFunc.node) {
        var outerIIFECall = encParent.node;
        var encArgIdx = -1;
        for (var eai = 0; eai < outerIIFECall.arguments.length; eai++) {
          if (outerIIFECall.arguments[eai] === enclosingFunc.node) { encArgIdx = eai; break; }
        }
        var outerIIFECallee = outerIIFECall.callee;
        // Handle !function(){}() — UnaryExpression wrapping the FunctionExpression
        if (_t.isUnaryExpression(outerIIFECallee)) outerIIFECallee = outerIIFECallee.argument;
        if (encArgIdx >= 0 && (_t.isFunctionExpression(outerIIFECallee) || _t.isArrowFunctionExpression(outerIIFECallee)) &&
            encArgIdx < outerIIFECallee.params.length) {
          var factoryParamName = _t.isIdentifier(outerIIFECallee.params[encArgIdx])
            ? outerIIFECallee.params[encArgIdx].name : null;
          if (factoryParamName) {
            // Scan global assignments for one whose value calls this factory parameter
            for (var gn in _globalAssignments) {
              var ga = _globalAssignments[gn];
              if (ga.valueNode && _t.isCallExpression(ga.valueNode) &&
                  _t.isIdentifier(ga.valueNode.callee) && ga.valueNode.callee.name === factoryParamName) {
                console.debug("[AST:trace]     → UMD-callback route: factory param=%s, global=%s", factoryParamName, gn);
                return _resolveParamFromGlobalCallers(funcPath, gn, paramIdx, depth, propName);
              }
            }
          }
        }
      }
      // Non-IIFE cases (e.g., function withAuth(){return fn}) are already handled
      // by existing _resolveCallReturnToFunction when resolving authedFetch = withAuth()
    }
  }

  // ES6 class method: class Foo { method(param) { ... } }
  // funcPath is ClassMethod, parent is ClassBody, grandparent is ClassDeclaration
  if (!funcBinding && _t.isClassMethod(funcPath.node) && _t.isClassBody(funcPath.parent)) {
    var classDecl = funcPath.parentPath.parentPath;
    if (classDecl && (_t.isClassDeclaration(classDecl.node) || _t.isClassExpression(classDecl.node))) {
      var className = classDecl.node.id ? classDecl.node.id.name : null;
      var methodName = _t.isIdentifier(funcPath.node.key) ? funcPath.node.key.name : null;
      if (className && methodName) {
        console.debug("[AST:trace]     → class-method route: %s.%s()", className, methodName);
        return _resolveParamFromPrototypeMethodCallers(funcPath, className, methodName, paramIdx, depth, propName);
      }
    }
  }

  if (!funcBinding) {
    console.debug("[AST:trace]     → no funcBinding found (parent=%s), aborting", _funcParentType + _funcParentDetail);
    return [];
  }
  console.debug("[AST:trace]     funcBinding found: %s (refs=%d)", funcBinding.identifier.name, funcBinding.referencePaths ? funcBinding.referencePaths.length : 0);

  // Collect values from all call sites
  var values = [];
  // Check primary binding and alternative binding (for const Se = me = function pattern)
  var _bindings = [funcBinding];
  if (_altFuncBinding) _bindings.push(_altFuncBinding);
  for (var bi = 0; bi < _bindings.length; bi++) {
    var refs = _bindings[bi].referencePaths;
    if (!refs) continue;
    for (var r = 0; r < refs.length; r++) {
      var refPath = refs[r];
      if (refPath.parent && _t.isCallExpression(refPath.parent) && refPath.parent.callee === refPath.node) {
        if (paramIdx < refPath.parent.arguments.length) {
          var argPath = refPath.parentPath.get("arguments." + paramIdx);
          var argVals = propName ? _resolvePropertyFromArg(argPath, propName, depth) : _resolveAllValues(argPath, depth + 1);
          values = values.concat(argVals);
        } else {
          values = values.concat(_resolveOverloadedArg(refPath.parentPath, paramIdx, depth, propName));
        }
      }
    }
  }
  return values;
  } catch (_rpce) {
    if (_rpce instanceof RangeError) { _resolver.collectError(_rpce, "resolveParamFromCallers"); return []; }
    throw _rpce;
  } finally { _resolver.unguard("P", binding.identifier); }
}

// Resolve param from obj.method(...) calls when the function is an object property value
function _resolveParamFromObjectMethod(funcPath, paramIdx, methodName, depth, propName) {
  // Walk up to the ObjectExpression, then find its variable binding
  var objExprPath = funcPath.parentPath ? funcPath.parentPath.parentPath : null;
  if (!objExprPath || !_t.isObjectExpression(objExprPath.node)) return [];

  var declPath = objExprPath.parentPath;
  if (!declPath) return [];

  var objBinding = null;
  if (_t.isVariableDeclarator(declPath.node) && _t.isIdentifier(declPath.node.id)) {
    objBinding = declPath.scope.getBinding(declPath.node.id.name);
  }

  // Handle returned objects: the object is inside a ReturnStatement of a factory function.
  // e.g., function createClient(baseUrl) { return { get: function(path) { fetch(baseUrl + path); } }; }
  // var client = createClient("https://..."); client.get("/path");
  if (!objBinding && _t.isReturnStatement(declPath.node)) {
    var factoryFunc = declPath.getFunctionParent();
    if (factoryFunc) {
      var factoryBinding = _getFunctionBinding(factoryFunc);
      if (factoryBinding) {
        return _resolveParamFromFactoryCallers(factoryBinding, methodName, paramIdx, depth, propName);
      }
    }
  }

  // Handle extend pattern: X.extend({method: function(params) { ... }})
  // Properties get copied to X, so callers use X.method(...)
  if (!objBinding && _t.isCallExpression(declPath.node)) {
    var extCallee = declPath.node.callee;
    if (_t.isMemberExpression(extCallee) && !extCallee.computed && _t.isIdentifier(extCallee.object)) {
      var extObjBinding = declPath.scope.getBinding(extCallee.object.name);
      if (extObjBinding) {
        console.debug("[AST:trace]     extend-pattern: %s.%s({%s: fn}) → searching for %s.%s() calls",
          extCallee.object.name, extCallee.property.name || extCallee.property.value || "?",
          methodName, extCallee.object.name, methodName);
        var extVals = _resolveParamFromMethodCalls(extObjBinding, methodName, paramIdx, depth + 1, propName);
        // Always also check global aliases (external callers like $.ajax() outside the IIFE)
        // e.g., window.jQuery = lib; then jQuery.ajax(...) calls should be found
        for (var gn in _globalAssignments) {
          var ga = _globalAssignments[gn];
          if (!ga.valueNode) continue;
          var gaVal = ga.valueNode;
          while (_t.isAssignmentExpression(gaVal)) gaVal = gaVal.right;
          if (_t.isIdentifier(gaVal) && gaVal.name === extObjBinding.identifier.name) {
            console.debug("[AST:trace]     extend-pattern: %s aliased to global %s, searching for %s.%s() calls",
              extCallee.object.name, gn, gn, methodName);
            var globalVals = _resolveParamFromGlobalCallers(funcPath, gn, paramIdx, depth + 1, propName, methodName);
            extVals = extVals.concat(globalVals);
          }
        }
        return extVals;
      }
      // If the extend target has no binding (e.g., lib defined as {} at module level),
      // check _globalAssignments for it
      var globalDef = _globalAssignments[extCallee.object.name];
      if (globalDef && globalDef.valuePath) {
        var gBinding = globalDef.valuePath.scope.getBinding(extCallee.object.name);
        if (!gBinding) {
          // Try resolving through the global assignment's value
          var gVal = globalDef.valueNode;
          while (_t.isAssignmentExpression(gVal)) gVal = gVal.right;
          if (_t.isIdentifier(gVal)) {
            gBinding = globalDef.valuePath.scope.getBinding(gVal.name);
          }
        }
        if (gBinding) {
          console.debug("[AST:trace]     extend-pattern (global): %s.%s({%s: fn}) → searching for %s.%s() calls",
            extCallee.object.name, extCallee.property.name || "?",
            methodName, extCallee.object.name, methodName);
          return _resolveParamFromMethodCalls(gBinding, methodName, paramIdx, depth + 1, propName);
        }
      }
    }
  }

  if (!objBinding) return [];

  return _resolveParamFromMethodCalls(objBinding, methodName, paramIdx, depth, propName);
}

// Resolve param values when the function is a callback argument:
//   registerCallback(function(param) { sink(param.prop) })
// Traces into the called function to find where it invokes the callback and with what args.
function _resolveParamFromCallbackArg(callExprPath, cbArgIdx, paramIdx, depth, propName) {
  if (!_resolver.guard("C", callExprPath.node)) return [];
  try {
  var calleeNode = callExprPath.node.callee;

  // Resolve the called function
  var targetFuncPath = _resolveCalleeFuncPath(callExprPath, depth + 1);
  var targetFuncNode = targetFuncPath ? targetFuncPath.node : null;

  if (!targetFuncNode) {
    // Try resolving callee as a call return value (e.g. addToPrefiltersOrTransports(structure) returns a function)
    if (_t.isCallExpression(calleeNode)) {
      // Not tractable without deeper analysis
    }
    // Try identifier that resolves to a call expression returning a function
    if (_t.isIdentifier(calleeNode)) {
      var callerBinding = callExprPath.scope.getBinding(calleeNode.name);
      if (callerBinding && _t.isVariableDeclarator(callerBinding.path.node) && callerBinding.path.node.init &&
          _t.isCallExpression(callerBinding.path.node.init)) {
        var retFuncNode = _resolveCallReturnToFunction(callerBinding.path.get("init"), depth + 1);
        if (retFuncNode) { targetFuncNode = retFuncNode.node || retFuncNode; targetFuncPath = retFuncNode._path || null; }
      }
    }
    // For member expressions, resolve through property value being a call return
    if (!targetFuncNode && _t.isMemberExpression(calleeNode) && !calleeNode.computed) {
      var mProp = _t.isIdentifier(calleeNode.property) ? calleeNode.property.name : null;
      if (mProp && _t.isIdentifier(calleeNode.object)) {
        var objBinding = callExprPath.scope.getBinding(calleeNode.object.name);
        if (objBinding) {
          var refs = objBinding.referencePaths;
          for (var ri = 0; ri < refs.length && !targetFuncNode; ri++) {
            var refP = refs[ri].parent;
            // Pattern 1: obj.prop = someCallExpr() or obj.prop = function()
            if (_t.isMemberExpression(refP) && refP.object === refs[ri].node && !refP.computed &&
                _t.isIdentifier(refP.property, { name: mProp })) {
              var asgn = refs[ri].parentPath ? refs[ri].parentPath.parent : null;
              if (asgn && _t.isAssignmentExpression(asgn) && asgn.left === refP) {
                if (_t.isCallExpression(asgn.right)) {
                  var retFunc = _resolveCallReturnToFunction(refs[ri].parentPath.parentPath.get("right"), depth + 1);
                  if (retFunc) { targetFuncNode = retFunc.node || retFunc; targetFuncPath = retFunc._path || null; break; }
                }
                if (_t.isFunctionExpression(asgn.right) || _t.isArrowFunctionExpression(asgn.right)) {
                  targetFuncNode = asgn.right;
                  targetFuncPath = refs[ri].parentPath.parentPath.get("right");
                  break;
                }
              }
            }
            // Pattern 2: obj.extend({prop: value}) — property defined in an extend/mixin call
            if (_t.isMemberExpression(refP) && refP.object === refs[ri].node && !refP.computed) {
              var extProp = _t.isIdentifier(refP.property) ? refP.property.name : null;
              if (extProp === "extend" || extProp === "mixin" || extProp === "assign") {
                var extCall = refs[ri].parentPath ? refs[ri].parentPath.parent : null;
                if (extCall && _t.isCallExpression(extCall) && extCall.callee === refP) {
                  // Scan arguments for object literals containing our property
                  var extCallPath = refs[ri].parentPath.parentPath;
                  for (var ai = 0; ai < extCall.arguments.length && !targetFuncNode; ai++) {
                    var extArg = extCall.arguments[ai];
                    if (!_t.isObjectExpression(extArg)) continue;
                    for (var epi = 0; epi < extArg.properties.length; epi++) {
                      var ep = extArg.properties[epi];
                      if (!_t.isObjectProperty(ep) || ep.computed) continue;
                      var epKey = _t.isIdentifier(ep.key) ? ep.key.name : (_t.isStringLiteral(ep.key) ? ep.key.value : null);
                      if (epKey !== mProp) continue;
                      // Found the property — check if value is a function or call return
                      if (_t.isFunctionExpression(ep.value) || _t.isArrowFunctionExpression(ep.value)) {
                        targetFuncNode = ep.value;
                        targetFuncPath = extCallPath.get("arguments." + ai + ".properties." + epi + ".value");
                      } else if (_t.isCallExpression(ep.value)) {
                        var extRetFunc = _resolveCallReturnToFunction(extCallPath.get("arguments." + ai + ".properties." + epi + ".value"), depth + 1);
                        if (extRetFunc) {
                          targetFuncNode = extRetFunc.node || extRetFunc;
                          targetFuncPath = extRetFunc._path || null;
                        }
                      }
                      break;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  if (!targetFuncNode) {
    // Fallback: .forEach(fn) or X.each(arr, fn) — resolve array element values
    // forEach: arr.forEach(fn) — fn(element, index, array)
    // jQuery.each: X.each(arr, fn) — fn(index, element)
    if (_t.isMemberExpression(calleeNode) && !calleeNode.computed) {
      var iterMethod = _t.isIdentifier(calleeNode.property) ? calleeNode.property.name : null;
      if (_ITERATION_METHODS[iterMethod] || iterMethod === "each") {
        // V4: skip if callee object is a known non-iterable type
        var _cbObjType = (iterMethod !== "each") ? _getTrackedType(callExprPath.get("callee.object"), calleeNode.object) : null;
        if (_cbObjType && _NON_ITERABLE_TYPES[_cbObjType]) {
          // Known non-iterable — skip
        } else {
        var arrPath = null;
        var elemParamIdx = -1; // which param of callback receives elements
        if (_ITERATION_METHODS[iterMethod]) {
          // arr.forEach/map/filter(fn) — arr is callee.object, fn gets (element, index, array)
          arrPath = callExprPath.get("callee.object");
          elemParamIdx = 0;
        } else if (iterMethod === "each" && callExprPath.node.arguments.length >= 2) {
          // X.each(arr, fn) — arr is first arg, fn gets (index, element)
          arrPath = callExprPath.get("arguments.0");
          elemParamIdx = 1;
        }
        if (arrPath && paramIdx === elemParamIdx) {
          var arrNode = _resolveToArray(arrPath, 0);
          if (arrNode && arrNode.elements && arrNode.elements.length > 0) {
            var iterValues = [];
            for (var avi = 0; avi < arrNode.elements.length; avi++) {
              if (_t.isStringLiteral(arrNode.elements[avi])) iterValues.push(arrNode.elements[avi].value);
            }
            console.debug("[AST:trace]     callback-arg: iteration values from array: [%s]", iterValues.join(", "));
            return iterValues;
          }
        }
        } // end V4 else (not non-iterable)
      }
    }
    console.debug("[AST:trace]     callback-arg: could not resolve callee function");
    return [];
  }

  // Determine which parameter of the target function receives our callback
  // Account for string argument shifting (jQuery pattern: if typeof arg0 !== "string", func = arg0)
  var targetParams = targetFuncNode.params || [];
  var cbParamIdx = cbArgIdx;
  // If there are fewer params than args, the function might shift arguments
  if (cbParamIdx >= targetParams.length) cbParamIdx = targetParams.length - 1;
  if (cbParamIdx < 0) {
    console.debug("[AST:trace]     callback-arg: no param for arg[%d]", cbArgIdx);
    return [];
  }

  var cbParamName = _t.isIdentifier(targetParams[cbParamIdx]) ? targetParams[cbParamIdx].name : null;
  if (!cbParamName) {
    console.debug("[AST:trace]     callback-arg: param[%d] not identifier", cbParamIdx);
    return [];
  }

  console.debug("[AST:trace]     callback-arg: callee param '%s' receives our callback, searching for calls", cbParamName);

  // Search inside the target function for calls to the callback parameter
  // or storage patterns (container.push(cbParam)) that indicate store-and-call-later.
  var values = [];
  if (targetFuncPath) {
    try {
      targetFuncPath.traverse({
        CallExpression: function(innerPath) {
          var ic = innerPath.node.callee;
          // Direct call: cbParam(arg0, arg1, ...)
          if (_t.isIdentifier(ic, { name: cbParamName })) {
            var innerBinding = innerPath.scope.getBinding(cbParamName);
            // Must be the same binding (same function's param)
            if (innerBinding && innerBinding.kind === "param" && innerBinding.scope.path === targetFuncPath) {
              if (paramIdx < innerPath.node.arguments.length) {
                var argPath = innerPath.get("arguments." + paramIdx);
                var argVals = propName ? _resolvePropertyFromArg(argPath, propName, depth + 1) : _resolveAllValues(argPath, depth + 1);
                console.debug("[AST:trace]     callback-arg: direct call found, arg[%d] → [%s]", paramIdx, argVals.join(", "));
                values = values.concat(argVals);
              }
            }
          }

          // .call()/.apply() invocation: cbParam.call(thisArg, arg0, arg1, ...)
          // or cbParam.apply(thisArg, [arg0, arg1, ...])
          // .call() shifts args by 1 (arg0 is at arguments[1])
          if (_t.isMemberExpression(ic) && !ic.computed &&
              _t.isIdentifier(ic.object, { name: cbParamName })) {
            var callMethod = _t.isIdentifier(ic.property) ? ic.property.name : null;
            if (callMethod === "call") {
              var icBinding = innerPath.scope.getBinding(cbParamName);
              if (icBinding && icBinding.kind === "param" && icBinding.scope.path === targetFuncPath) {
                // .call(thisArg, arg0, arg1, ...) — paramIdx+1 to skip thisArg
                var callArgIdx = paramIdx + 1;
                if (callArgIdx < innerPath.node.arguments.length) {
                  var callArgPath = innerPath.get("arguments." + callArgIdx);
                  var callArgVals = propName ? _resolvePropertyFromArg(callArgPath, propName, depth + 1) : _resolveAllValues(callArgPath, depth + 1);
                  console.debug("[AST:trace]     callback-arg: .call() found, arg[%d] → [%s]", callArgIdx, callArgVals.join(", "));
                  values = values.concat(callArgVals);
                }
              }
            }
          }

          // Store-and-call-later: container.push(cbParam), container.unshift(cbParam),
          // or container[key][cond ? "unshift" : "push"](cbParam)
          // When the callback is stored in an array rather than called directly, trace
          // the container to find where items are later retrieved and called.
          var isPushOrUnshift = false;
          if (_t.isMemberExpression(ic) && !ic.computed &&
              (_t.isIdentifier(ic.property, { name: "push" }) || _t.isIdentifier(ic.property, { name: "unshift" }))) {
            isPushOrUnshift = true;
          }
          // Computed conditional: container[cond ? "unshift" : "push"](cb)
          if (!isPushOrUnshift && _t.isMemberExpression(ic) && ic.computed && _t.isConditionalExpression(ic.property)) {
            var condCons = ic.property.consequent;
            var condAlt = ic.property.alternate;
            if ((_t.isStringLiteral(condCons) && (condCons.value === "push" || condCons.value === "unshift")) ||
                (_t.isStringLiteral(condAlt) && (condAlt.value === "push" || condAlt.value === "unshift"))) {
              isPushOrUnshift = true;
            }
          }
          if (isPushOrUnshift) {
            var pushArgs = innerPath.node.arguments;
            var storingCb = false;
            for (var pai = 0; pai < pushArgs.length; pai++) {
              if (_t.isIdentifier(pushArgs[pai], { name: cbParamName })) {
                var pushArgBinding = innerPath.scope.getBinding(cbParamName);
                if (pushArgBinding && pushArgBinding.kind === "param" && pushArgBinding.scope.path === targetFuncPath) {
                  storingCb = true;
                }
              }
              // Also check for derived variable: func = cbParam; container.push(func)
              if (!storingCb && _t.isIdentifier(pushArgs[pai])) {
                var derivedBinding = innerPath.scope.getBinding(pushArgs[pai].name);
                if (derivedBinding && derivedBinding.constantViolations) {
                  for (var dvi = 0; dvi < derivedBinding.constantViolations.length; dvi++) {
                    var dvNode = derivedBinding.constantViolations[dvi].node;
                    if (_t.isAssignmentExpression(dvNode) && _t.isIdentifier(dvNode.right, { name: cbParamName })) {
                      storingCb = true; break;
                    }
                  }
                }
              }
            }
            if (storingCb) {
              // Unwrap to find the container variable:
              // structure[key].push(cb) → structure
              // (structure[key] = structure[key] || []).push(cb) → structure (jQuery pattern)
              var containerNode = ic.object;
              if (_t.isAssignmentExpression(containerNode)) containerNode = containerNode.left;
              while (_t.isMemberExpression(containerNode) && containerNode.computed) {
                containerNode = containerNode.object;
              }
              if (_t.isIdentifier(containerNode)) {
                var containerBinding = innerPath.scope.getBinding(containerNode.name);
                if (containerBinding) {
                  console.debug("[AST:trace]     callback-arg: stored via %s.push(), tracing container", containerNode.name);
                  var storedVals = _resolveStoredCallbackArgs(containerBinding, paramIdx, depth + 1, propName);
                  values = values.concat(storedVals);
                }
              }
            }
          }
        },
        // Don't descend into nested function declarations (scope confusion)
        FunctionDeclaration: function(p) { p.skip(); },
      });
    } catch (e) { _resolver.collectError(e, "resolveParamFromCallers"); }
  }

  // Fallback: if traversal of callee body yielded nothing, try iteration patterns.
  // .forEach(fn) — fn(element, index, array); jQuery.each(arr, fn) — fn(index, element)
  if (values.length === 0 && _t.isMemberExpression(calleeNode) && !calleeNode.computed) {
    var iterMethod = _t.isIdentifier(calleeNode.property) ? calleeNode.property.name : null;
    if (iterMethod === "forEach" || iterMethod === "each") {
      // V4: skip if callee object is a known non-iterable type
      var _fb2ObjType = (iterMethod !== "each") ? _getTrackedType(callExprPath.get("callee.object"), calleeNode.object) : null;
      if (!(_fb2ObjType && _NON_ITERABLE_TYPES[_fb2ObjType])) {
        var arrPath = null;
        var elemParamIdx = -1;
        if (iterMethod === "forEach") {
          arrPath = callExprPath.get("callee.object");
          elemParamIdx = 0;
        } else if (iterMethod === "each" && callExprPath.node.arguments.length >= 2) {
          arrPath = callExprPath.get("arguments.0");
          elemParamIdx = 1;
        }
        if (arrPath && paramIdx === elemParamIdx) {
          var arrNode = _resolveToArray(arrPath, 0);
          if (arrNode && arrNode.elements) {
            for (var avi = 0; avi < arrNode.elements.length; avi++) {
              if (_t.isStringLiteral(arrNode.elements[avi])) values.push(arrNode.elements[avi].value);
            }
            if (values.length > 0) console.debug("[AST:trace]     callback-arg: iteration values from array: [%s]", values.join(", "));
          }
        }
      }
    }
  }

  return values;
  } catch (_rce) {
    if (_rce instanceof RangeError) { _resolver.collectError(_rce, "resolvePropertyFromCall"); return []; }
    throw _rce;
  } finally { _resolver.unguard("C", callExprPath.node); }
}

// Trace a container variable (array) to find where its stored items are called.
// When a callback is stored via container.push(cb), this finds patterns like:
//   - container[i](args) — direct indexed call
//   - container.forEach(function(item) { item(args); }) — forEach
//   - someLib.each(container[key], function(_, item) { item(args); }) — library each
// If the container is a parameter, resolves from callers to find the actual variable.
function _resolveStoredCallbackArgs(containerBinding, paramIdx, depth, propName) {
  if (!_resolver.guard("S", containerBinding.identifier)) return [];
  try {
  var values = [];

  // If the container is a parameter of its function, resolve from callers
  // to find the actual variable. E.g., addToStore(structure) { structure.push(cb) }
  // → callers pass the actual array variable.
  if (containerBinding.kind === "param") {
    var enclosingFunc = containerBinding.scope.path;
    var containerParamIdx = -1;
    var params = enclosingFunc.node.params;
    for (var pi = 0; pi < params.length; pi++) {
      if (_t.isIdentifier(params[pi]) && params[pi].name === containerBinding.identifier.name) {
        containerParamIdx = pi; break;
      }
    }
    if (containerParamIdx < 0) return [];

    var funcBinding = _getFunctionBinding(enclosingFunc);
    if (!funcBinding || !funcBinding.referencePaths) return [];

    var callerRefs = funcBinding.referencePaths;
    for (var ri = 0; ri < callerRefs.length; ri++) {
      if (!callerRefs[ri].parent || !_t.isCallExpression(callerRefs[ri].parent) ||
          callerRefs[ri].parent.callee !== callerRefs[ri].node) continue;
      if (containerParamIdx >= callerRefs[ri].parent.arguments.length) continue;

      var actualArg = callerRefs[ri].parent.arguments[containerParamIdx];
      if (_t.isIdentifier(actualArg)) {
        var actualBinding = callerRefs[ri].parentPath.scope.getBinding(actualArg.name);
        if (actualBinding) {
          console.debug("[AST:trace]     stored-callback: container param '%s' bound to '%s'", containerBinding.identifier.name, actualArg.name);
          var subValues = _resolveStoredCallbackArgs(actualBinding, paramIdx, depth + 1, propName);
          values = values.concat(subValues);
        }
      }
    }
    return values;
  }

  // Container is a local/module-level variable. Search its references for patterns
  // where items are extracted and called.
  var refs = containerBinding.referencePaths;
  for (var ri = 0; ri < refs.length; ri++) {
    var refPath = refs[ri];

    // Pattern 1: container[i](args) — direct computed-member call
    // AST: CallExpression { callee: MemberExpression(container, i, computed) }
    if (_t.isMemberExpression(refPath.parent) && refPath.parent.object === refPath.node &&
        refPath.parent.computed) {
      var memberCallParent = refPath.parentPath ? refPath.parentPath.parent : null;
      if (memberCallParent && _t.isCallExpression(memberCallParent) &&
          memberCallParent.callee === refPath.parent) {
        // container[i](arg0, arg1, ...) — items are called with these args
        if (paramIdx < memberCallParent.arguments.length) {
          var argPath = refPath.parentPath.parentPath.get("arguments." + paramIdx);
          var argVals = propName ? _resolvePropertyFromArg(argPath, propName, depth + 1) : _resolveAllValues(argPath, depth + 1);
          console.debug("[AST:trace]     stored-callback: found %s[i](args), arg[%d] → [%s]", containerBinding.identifier.name, paramIdx, argVals.join(", "));
          values = values.concat(argVals);
        }
      }
    }

    // Pattern 2: container passed as argument to a function that iterates and calls items.
    // E.g., someFunc(container, ...) or someFunc(container[key] || [], ...)
    // Inside that function, a parameter derived from the container is iterated.
    if (_t.isCallExpression(refPath.parent) && refPath.parent.callee !== refPath.node) {
      var iterCallPath = refPath.parentPath;
      var iterArgIdx = -1;
      for (var iai = 0; iai < iterCallPath.node.arguments.length; iai++) {
        if (iterCallPath.node.arguments[iai] === refPath.node) { iterArgIdx = iai; break; }
        // Also check container[key] || [] patterns — container is nested in MemberExpression/LogicalExpression
        if (_containsNode(iterCallPath.node.arguments[iai], refPath.node)) { iterArgIdx = iai; break; }
      }
      if (iterArgIdx >= 0) {
        // Resolve the called function and find where it calls items from the parameter
        var iterVals = _resolveItemCallsInFunction(iterCallPath, iterArgIdx, paramIdx, depth + 1, propName);
        values = values.concat(iterVals);
      }
    }
  }

  return values;
  } catch (_rse) {
    if (_rse instanceof RangeError) { _resolver.collectError(_rse, "resolveStoredCallbackArgs"); return []; }
    throw _rse;
  } finally { _resolver.unguard("S", containerBinding.identifier); }
}

// Check if a node tree contains a target node (shallow check for LogicalExpression/MemberExpression)
function _containsNode(node, target) {
  // Iterative: walk LogicalExpression/MemberExpression chains via explicit stack
  var stack = [node];
  while (stack.length > 0) {
    var n = stack.pop();
    if (n === target) return true;
    if (_t.isLogicalExpression(n)) { stack.push(n.left, n.right); }
    else if (_t.isMemberExpression(n)) { stack.push(n.object); }
  }
  return false;
}

// Given a function call where arg[iterArgIdx] contains a container, resolve the function
// and find where items from the corresponding parameter are called.
// Handles: forEach(function(item) { item(args); }), jQuery.each(container, function(_, item) { item(args); })
function _resolveItemCallsInFunction(callPath, iterArgIdx, paramIdx, depth, propName) {
  if (!_resolver.guard("I", callPath.node)) return [];
  try {

  // Check if another argument is a callback function that calls items
  var callArgs = callPath.node.arguments;
  for (var ai = 0; ai < callArgs.length; ai++) {
    if (ai === iterArgIdx) continue;
    if (!_t.isFunctionExpression(callArgs[ai]) && !_t.isArrowFunctionExpression(callArgs[ai])) continue;

    // This argument is a callback — check if any of its params are called
    var cbFuncPath = callPath.get("arguments." + ai);
    var values = [];

    try {
      cbFuncPath.traverse(Object.assign({
        CallExpression: function(innerPath) {
          var ic = innerPath.node.callee;
          if (!_t.isIdentifier(ic)) return;
          var icBinding = innerPath.scope.getBinding(ic.name);
          if (!icBinding || icBinding.kind !== "param") return;
          // Verify this param belongs to the callback function
          if (icBinding.scope.path !== cbFuncPath) return;

          // This param of the callback is called — it's an item from the container
          if (paramIdx < innerPath.node.arguments.length) {
            var argPath = innerPath.get("arguments." + paramIdx);
            var argVals = propName ? _resolvePropertyFromArg(argPath, propName, depth + 1) : _resolveAllValues(argPath, depth + 1);
            console.debug("[AST:trace]     stored-callback: found item call in iterator callback, arg[%d] → [%s]", paramIdx, argVals.join(", "));
            values = values.concat(argVals);
          }
        },
      }, _SKIP_NESTED_FUNCS));
    } catch (e) { _resolver.collectError(e, "storedCallbackArgs"); }

    if (values.length > 0) return values;
  }

  // The called function might not have an inline callback — resolve it and search inside
  // E.g., inspectPrefiltersOrTransports(transports, s, ...) — the function iterates
  // internally and calls items. This requires resolving the function and finding the pattern.
  var targetFuncPath = _resolveCalleeToFunction(callPath);
  if (targetFuncPath && iterArgIdx < targetFuncPath.node.params.length) {
    var containerParamName = _t.isIdentifier(targetFuncPath.node.params[iterArgIdx]) ? targetFuncPath.node.params[iterArgIdx].name : null;
    if (containerParamName) {
      // Search inside the resolved function for container[key][i](args) or
      // iteration patterns using the parameter
      var funcValues = _resolveItemCallsFromParam(targetFuncPath, containerParamName, paramIdx, depth, propName);
      if (funcValues.length > 0) return funcValues;
    }
  }

  return [];
  } catch (_rie) {
    if (_rie instanceof RangeError) { _resolver.collectError(_rie, "resolveItemCallsInFunction"); return []; }
    throw _rie;
  } finally { _resolver.unguard("I", callPath.node); }
}

// Search inside a resolved function for calls to items from a container parameter.
// Handles: param[key].forEach(fn), jQuery.each(param[key], fn), for loops
function _resolveItemCallsFromParam(funcPath, containerParamName, paramIdx, depth, propName) {
  // Traverse function body to find where items from containerParamName are called.
  // Handles: jQuery.each(param[key], fn), param[key].forEach(fn), param.forEach(fn),
  // for (var i; i < param.length; i++) param[i](args), for-in/for-of loops
  if (!funcPath) return [];

  var values = [];
  try {
    funcPath.traverse({
      CallExpression: function(innerPath) {
        var ic = innerPath.node.callee;

        // Pattern: someLib.each(containerParam[key], function(_, item) { item(args); })
        // or containerParam[key].forEach(function(item) { item(args); })
        // or containerParam.forEach(function(item) { item(args); })
        var iterContainer = null;
        var cbArgStartIdx = -1;

        // .forEach() / .each() on the container or container[key]
        if (_t.isMemberExpression(ic) && !ic.computed) {
          var methodName = _t.isIdentifier(ic.property) ? ic.property.name : null;
          if (methodName === "forEach" || methodName === "each") {
            // Check if object is containerParam or containerParam[key]
            var obj = ic.object;
            if (_t.isIdentifier(obj, { name: containerParamName })) {
              iterContainer = obj; cbArgStartIdx = 0;
            } else if (_t.isMemberExpression(obj) && _t.isIdentifier(obj.object, { name: containerParamName })) {
              iterContainer = obj; cbArgStartIdx = 0;
            }
            // Also: (containerParam[key] || []).forEach(fn) — unwrap LogicalExpression
            if (!iterContainer && _t.isLogicalExpression(obj)) {
              var left = obj.left;
              if (_t.isIdentifier(left, { name: containerParamName }) ||
                  (_t.isMemberExpression(left) && _t.isIdentifier(left.object, { name: containerParamName }))) {
                iterContainer = left; cbArgStartIdx = 0;
              }
            }
          }
        }

        // jQuery.each(containerParam[key], fn) or anyLib.each(containerParam[key], fn)
        if (!iterContainer && _t.isMemberExpression(ic) && !ic.computed &&
            _t.isIdentifier(ic.property, { name: "each" })) {
          var eachArgs = innerPath.node.arguments;
          for (var eai = 0; eai < eachArgs.length; eai++) {
            var eaArg = eachArgs[eai];
            if (_t.isIdentifier(eaArg, { name: containerParamName })) {
              iterContainer = eaArg; cbArgStartIdx = eai + 1; break;
            }
            if (_t.isMemberExpression(eaArg) && _t.isIdentifier(eaArg.object, { name: containerParamName })) {
              iterContainer = eaArg; cbArgStartIdx = eai + 1; break;
            }
            // (containerParam[key] || [])
            if (_t.isLogicalExpression(eaArg)) {
              var eaLeft = eaArg.left;
              if (_t.isIdentifier(eaLeft, { name: containerParamName }) ||
                  (_t.isMemberExpression(eaLeft) && _t.isIdentifier(eaLeft.object, { name: containerParamName }))) {
                iterContainer = eaLeft; cbArgStartIdx = eai + 1; break;
              }
            }
          }
        }

        if (iterContainer && cbArgStartIdx >= 0) {
          // Find the callback argument after the container
          var callArgs = innerPath.node.arguments;
          for (var cai = cbArgStartIdx; cai < callArgs.length; cai++) {
            if (!_t.isFunctionExpression(callArgs[cai]) && !_t.isArrowFunctionExpression(callArgs[cai])) continue;
            var cbPath = innerPath.get("arguments." + cai);
            try {
              cbPath.traverse(Object.assign({
                CallExpression: function(cbInner) {
                  var cbc = cbInner.node.callee;
                  if (!_t.isIdentifier(cbc)) return;
                  var cbBinding = cbInner.scope.getBinding(cbc.name);
                  if (!cbBinding || cbBinding.kind !== "param" || cbBinding.scope.path !== cbPath) return;
                  // This is a call to a callback param — it's an item from the container
                  if (paramIdx < cbInner.node.arguments.length) {
                    var argPath = cbInner.get("arguments." + paramIdx);
                    var argVals = propName ? _resolvePropertyFromArg(argPath, propName, depth + 1) : _resolveAllValues(argPath, depth + 1);
                    values = values.concat(argVals);
                  }
                },
              }, _SKIP_NESTED_FUNCS));
            } catch (e) { _resolver.collectError(e, "itemCallsCallbackTraverse"); }
          }
        }

        // Pattern: containerParam[key][i](args) — direct indexed call on sub-array
        if (_t.isMemberExpression(ic) && ic.computed) {
          var icObj = ic.object;
          // containerParam[key][i] — two levels of member access
          if (_t.isMemberExpression(icObj) && _t.isIdentifier(icObj.object, { name: containerParamName })) {
            if (paramIdx < innerPath.node.arguments.length) {
              var argPath2 = innerPath.get("arguments." + paramIdx);
              var argVals2 = propName ? _resolvePropertyFromArg(argPath2, propName, depth + 1) : _resolveAllValues(argPath2, depth + 1);
              values = values.concat(argVals2);
            }
          }
        }
      },
      // Do NOT skip nested functions — iteration patterns are often inside
      // helper functions (e.g., jQuery's inspect() inside inspectPrefiltersOrTransports)
    });
  } catch (e) { _resolver.collectError(e, "itemCallsFromParam"); }
  return values;
}

// Resolve a call expression to the function it returns (for callback-arg tracing)
function _resolveCallReturnToFunction(callPath, depth) {
  if (!_resolver.guard("F", callPath.node)) return null;
  try {
  var callee = callPath.node.callee;
  var funcPath = _resolveCalleeFuncPath(callPath, depth);
  // Param binding: callee is a function parameter (e.g., n() in IIFE)
  if (!funcPath && _t.isIdentifier(callee)) {
    var binding = callPath.scope.getBinding(callee.name);
    if (binding && binding.kind === "param") {
      var encFn = binding.path.findParent(function(p) { return p.isFunction(); });
      if (encFn) {
        var pIdx = -1;
        for (var pi = 0; pi < encFn.node.params.length; pi++) {
          if (encFn.node.params[pi] === binding.path.node) { pIdx = pi; break; }
          if (_t.isIdentifier(encFn.node.params[pi]) && encFn.node.params[pi].name === callee.name) { pIdx = pi; break; }
        }
        if (pIdx >= 0 && encFn.parentPath && _t.isCallExpression(encFn.parent) &&
            encFn.parent.callee === encFn.node && pIdx < encFn.parent.arguments.length) {
          var iifeArg = encFn.parent.arguments[pIdx];
          if (_t.isFunctionExpression(iifeArg) || _t.isArrowFunctionExpression(iifeArg)) {
            funcPath = encFn.parentPath.get("arguments." + pIdx);
          }
        }
      }
    }
  }
  if (!funcPath) return null;

  // Find return statements that return a function
  var result = null;
  try {
    funcPath.traverse(Object.assign({
      ReturnStatement: function(retPath) {
        if (result) return;
        var arg = retPath.node.argument;
        if (!arg) return;
        if (_t.isFunctionExpression(arg) || _t.isArrowFunctionExpression(arg)) {
          result = { node: arg, _path: retPath.get("argument") };
        }
      },
    }, _SKIP_NESTED_FUNCS));
  } catch (e) { _resolver.collectError(e, "resolveCallReturnToFunction"); }
  return result;
  } catch (_rfe) {
    if (_rfe instanceof RangeError) { _resolver.collectError(_rfe, "resolveCallReturnToFunction"); return null; }
    throw _rfe;
  } finally { _resolver.unguard("F", callPath.node); }
}

// Get the scope binding for a function (by name, variable declarator, or assignment)
function _getFunctionBinding(funcPath) {
  if (funcPath.node.id) {
    var binding = funcPath.scope.parent ? funcPath.scope.parent.getBinding(funcPath.node.id.name) : null;
    if (!binding) binding = funcPath.scope.getBinding(funcPath.node.id.name);
    return binding;
  }
  if (_t.isVariableDeclarator(funcPath.parent)) {
    return funcPath.scope.parent ? funcPath.scope.parent.getBinding(funcPath.parent.id.name) : null;
  }
  if (_t.isAssignmentExpression(funcPath.parent) && _t.isIdentifier(funcPath.parent.left)) {
    return funcPath.scope.getBinding(funcPath.parent.left.name);
  }
  return null;
}

// Resolve parameter values from factory pattern: var result = factory(...); result.method(arg)
function _resolveParamFromFactoryCallers(factoryBinding, methodName, paramIdx, depth, propName) {
  var values = [];
  var refs = factoryBinding.referencePaths;
  for (var r = 0; r < refs.length; r++) {
    var refPath = refs[r];
    // Factory call: var result = factory(...)
    if (refPath.parent && _t.isCallExpression(refPath.parent) && refPath.parent.callee === refPath.node) {
      var callExprPath = refPath.parentPath;
      var callParent = callExprPath.parentPath;
      if (callParent && _t.isVariableDeclarator(callParent.node) && callParent.node.init === callExprPath.node) {
        var resultName = _t.isIdentifier(callParent.node.id) ? callParent.node.id.name : null;
        if (resultName) {
          var resultBinding = callParent.scope.getBinding(resultName);
          if (resultBinding) {
            var methodVals = _resolveParamFromMethodCalls(resultBinding, methodName, paramIdx, depth, propName);
            values = values.concat(methodVals);
          }
        }
      }
    }
  }
  return values;
}

// Handle overloaded function signatures: when paramIdx >= arguments.length,
// try earlier argument positions. This handles patterns like jQuery.ajax(url, options)
// being called as jQuery.ajax(options) — options is paramIdx=1 but caller passes it at 0.
// Only applies when propName is set (looking for a property on an object argument).
function _resolveOverloadedArg(callExprPath, paramIdx, depth, propName) {
  if (!propName) return [];
  var args = callExprPath.node.arguments;
  if (paramIdx < args.length || args.length === 0) return [];
  for (var fi = args.length - 1; fi >= 0; fi--) {
    var argPath = callExprPath.get("arguments." + fi);
    var argVals = _resolvePropertyFromArg(argPath, propName, depth);
    if (argVals.length > 0) return argVals;
  }
  return [];
}

// ─── Correlated Multi-Property Resolution ───────────────────────────────────
// Traces a parameter binding through the full call chain (callback-arg, stored-callback,
// container iteration, extend-patterns, global aliases) and returns the concrete caller
// argument paths instead of resolved values. This enables the XHR/fetch handler to extract
// multiple properties (method + url) from each caller's argument in a correlated way.

function _resolveParamToCallerArgs(binding) {
  if (!_resolver.guard("Z", binding.identifier)) return [];
  try {
    return _traceParamToArgs(binding);
  } catch (_rze) {
    if (_rze instanceof RangeError) { _resolver.collectError(_rze, "resolveParamToCallerArgs"); return []; }
    throw _rze;
  } finally { _resolver.unguard("Z", binding.identifier); }
}

function _traceParamToArgs(binding) {
  var funcPath = binding.scope.path;
  if (!_t.isFunction(funcPath.node)) return [];

  var paramIdx = _findParamIndex(funcPath.node.params, binding.identifier.name);
  if (paramIdx === -1) return [];

  // Route 1: ObjectProperty — { method: function(param) {} }
  var funcBinding = _getFunctionBinding(funcPath);
  if (!funcBinding && _t.isObjectProperty(funcPath.parent)) {
    var methodKey = funcPath.parent.key;
    var methodName = _t.isIdentifier(methodKey) ? methodKey.name :
      (_t.isStringLiteral(methodKey) ? methodKey.value : null);
    if (methodName) {
      return _traceObjectMethodToArgs(funcPath, paramIdx, methodName);
    }
    return [];
  }
  // Route 1b: obj.method = function(param) {} — trace via obj.method() call sites
  if (!funcBinding && _t.isAssignmentExpression(funcPath.parent) &&
      _t.isMemberExpression(funcPath.parent.left) && !funcPath.parent.left.computed) {
    var assignProp = funcPath.parent.left.property;
    var assignMethodName = _t.isIdentifier(assignProp) ? assignProp.name : null;
    var assignObj = funcPath.parent.left.object;
    if (assignMethodName && _t.isIdentifier(assignObj)) {
      var assignObjBinding = funcPath.scope.getBinding(assignObj.name);
      if (assignObjBinding) {
        return _collectMethodCallerArgs(assignObjBinding.referencePaths, assignMethodName, paramIdx);
      }
      // Global: window.X = function() {} or known alias
      var isGlobalTarget = _isGlobalObject(assignObj.name, funcPath.scope);
      if (isGlobalTarget && _globalAssignments[assignMethodName]) {
        return _collectGlobalCallerArgs(funcPath, assignMethodName, paramIdx);
      }
    }
    return [];
  }
  // Route 1c: obj[method] = function(param) {} — computed member assignment
  // Resolve method to string values, search for obj.get/post/... call sites
  if (!funcBinding && _t.isAssignmentExpression(funcPath.parent) &&
      _t.isMemberExpression(funcPath.parent.left) && funcPath.parent.left.computed) {
    var compObj = funcPath.parent.left.object;
    var compProp = funcPath.parent.left.property;
    if (_t.isIdentifier(compObj) && _t.isIdentifier(compProp)) {
      var compObjBinding = funcPath.scope.getBinding(compObj.name);
      var compPropVals = _resolveAllValues(funcPath.parentPath.get("left.property"), 0);
      if (compObjBinding && compPropVals.length > 0) {
        var compArgs = [];
        for (var cvi = 0; cvi < compPropVals.length; cvi++) {
          if (typeof compPropVals[cvi] !== "string") continue;
          var cmArgs = _collectMethodCallerArgs(compObjBinding.referencePaths, compPropVals[cvi], paramIdx);
          compArgs = compArgs.concat(cmArgs);
        }
        // Also check global aliases
        for (var gn in _globalAssignments) {
          var ga = _globalAssignments[gn];
          if (!ga.valueNode) continue;
          var gaVal = ga.valueNode;
          while (_t.isAssignmentExpression(gaVal)) gaVal = gaVal.right;
          if (_t.isIdentifier(gaVal) && gaVal.name === compObjBinding.identifier.name) {
            for (var cvi2 = 0; cvi2 < compPropVals.length; cvi2++) {
              if (typeof compPropVals[cvi2] !== "string") continue;
              var cgArgs = _collectGlobalMethodCallerArgs(funcPath, gn, compPropVals[cvi2], paramIdx);
              compArgs = compArgs.concat(cgArgs);
            }
          }
        }
        return compArgs;
      }
    }
    return [];
  }
  // Route 2: Callback argument — someFunc(function(param) {})
  if (!funcBinding && _t.isCallExpression(funcPath.parent)) {
    var cbCallExpr = funcPath.parentPath;
    var cbArgIdx = -1;
    for (var cbi = 0; cbi < funcPath.parent.arguments.length; cbi++) {
      if (funcPath.parent.arguments[cbi] === funcPath.node) { cbArgIdx = cbi; break; }
    }
    if (cbArgIdx >= 0) {
      return _traceCallbackArgToArgs(cbCallExpr, cbArgIdx, paramIdx);
    }
  }
  // Route 3: Ctor.prototype.method = function(param) {} — trace via instance.method()
  if (!funcBinding && _t.isAssignmentExpression(funcPath.parent) &&
      _t.isMemberExpression(funcPath.parent.left) && !funcPath.parent.left.computed) {
    var ptAssignObj = funcPath.parent.left.object;
    var ptAssignProp = funcPath.parent.left.property;
    var ptMethodName = _t.isIdentifier(ptAssignProp) ? ptAssignProp.name : null;
    if (ptMethodName && _t.isMemberExpression(ptAssignObj) && !ptAssignObj.computed &&
        (_t.isIdentifier(ptAssignObj.property, { name: "prototype" }) ||
         (_t.isStringLiteral(ptAssignObj.property) && ptAssignObj.property.value === "prototype")) &&
        _t.isIdentifier(ptAssignObj.object)) {
      var ptCtorName = ptAssignObj.object.name;
      var ptProgramPath = funcPath.findParent(function(p) { return p.isProgram(); });
      if (ptProgramPath) {
        var ptArgs = [];
        try {
          ptProgramPath.traverse({
            VariableDeclarator: function(decPath) {
              var init = decPath.node.init;
              if (!init || !_t.isNewExpression(init) || !_t.isIdentifier(init.callee, { name: ptCtorName })) return;
              var instBinding = decPath.scope.getBinding(decPath.node.id.name);
              if (instBinding) {
                ptArgs = ptArgs.concat(_collectMethodCallerArgs(instBinding.referencePaths, ptMethodName, paramIdx));
              }
            },
          });
        } catch (e) { _resolver.collectError(e, "protoMethodInstances"); }
        return ptArgs;
      }
    }
  }
  // Route 4: ReturnStatement — function returned from IIFE
  if (!funcBinding && _t.isReturnStatement(funcPath.parent)) {
    var encFunc = funcPath.findParent(function(p) { return p.isFunction() && p !== funcPath; });
    if (encFunc) {
      var encParent = encFunc.parentPath;
      if (encParent && _t.isCallExpression(encParent.node) && encParent.node.callee === encFunc.node) {
        var iifeParent = encParent.parentPath;
        if (iifeParent && _t.isVariableDeclarator(iifeParent.node) && _t.isIdentifier(iifeParent.node.id)) {
          var iifeVarBinding = iifeParent.scope.getBinding(iifeParent.node.id.name);
          if (iifeVarBinding) return _collectCallerArgs(iifeVarBinding.referencePaths, paramIdx);
        }
        if (iifeParent && _t.isAssignmentExpression(iifeParent.node) && _t.isMemberExpression(iifeParent.node.left)) {
          var iifeGlobalProp = iifeParent.node.left.property;
          var iifeGlobalName = _t.isIdentifier(iifeGlobalProp) ? iifeGlobalProp.name : null;
          if (iifeGlobalName && _globalAssignments[iifeGlobalName]) {
            return _collectGlobalCallerArgs(funcPath, iifeGlobalName, paramIdx);
          }
        }
      }
    }
  }
  // Route 5: ES6 class method — class Foo { method(param) {} }
  if (!funcBinding && _t.isClassMethod(funcPath.node) && _t.isClassBody(funcPath.parent)) {
    var classDecl = funcPath.parentPath.parentPath;
    if (classDecl && (_t.isClassDeclaration(classDecl.node) || _t.isClassExpression(classDecl.node))) {
      var className = classDecl.node.id ? classDecl.node.id.name : null;
      var clMethodName = _t.isIdentifier(funcPath.node.key) ? funcPath.node.key.name : null;
      if (className && clMethodName) {
        var clProgramPath = funcPath.findParent(function(p) { return p.isProgram(); });
        if (clProgramPath) {
          var clArgs = [];
          try {
            clProgramPath.traverse({
              VariableDeclarator: function(decPath) {
                var init = decPath.node.init;
                if (!init || !_t.isNewExpression(init) || !_t.isIdentifier(init.callee, { name: className })) return;
                var instBinding = decPath.scope.getBinding(decPath.node.id.name);
                if (instBinding) {
                  clArgs = clArgs.concat(_collectMethodCallerArgs(instBinding.referencePaths, clMethodName, paramIdx));
                }
              },
            });
          } catch (e) { _resolver.collectError(e, "classMethodInstances"); }
          return clArgs;
        }
      }
    }
  }
  // Route 6: Direct function binding — collect caller arguments
  if (!funcBinding) return [];
  return _collectCallerArgs(funcBinding.referencePaths, paramIdx);
}

// Collect concrete caller argument paths from reference paths to a function
function _collectCallerArgs(refs, paramIdx) {
  var args = [];
  if (!refs) return args;
  for (var r = 0; r < refs.length; r++) {
    var refPath = refs[r];
    if (refPath.parent && _t.isCallExpression(refPath.parent) && refPath.parent.callee === refPath.node) {
      var effectiveIdx = paramIdx < refPath.parent.arguments.length ? paramIdx :
        (refPath.parent.arguments.length > 0 ? refPath.parent.arguments.length - 1 : -1);
      if (effectiveIdx >= 0) {
        _collectOrTraceArg(refPath.parentPath.get("arguments." + effectiveIdx), args);
      }
    }
  }
  return args;
}

// If arg is a param identifier, trace further to its callers; otherwise collect it directly
function _collectOrTraceArg(argPath, out) {
  if (_t.isIdentifier(argPath.node)) {
    var binding = argPath.scope.getBinding(argPath.node.name);
    if (binding && binding.kind === "param") {
      var subArgs = _traceParamToArgs(binding);
      if (subArgs.length > 0) {
        for (var i = 0; i < subArgs.length; i++) out.push(subArgs[i]);
        return;
      }
    }
    // Local variable initialized from function call: var s = merge({}, options)
    // Trace through the call's arguments that are params to their callers
    if (binding && binding.path.isVariableDeclarator && binding.path.isVariableDeclarator()) {
      var initNode = binding.path.node.init;
      if (initNode && _t.isCallExpression(initNode)) {
        var initArgs = initNode.arguments;
        for (var ai = 0; ai < initArgs.length; ai++) {
          if (_t.isIdentifier(initArgs[ai])) {
            var argBinding = binding.path.get("init").scope.getBinding(initArgs[ai].name);
            if (argBinding && argBinding.kind === "param") {
              var callSubArgs = _traceParamToArgs(argBinding);
              if (callSubArgs.length > 0) {
                for (var ci = 0; ci < callSubArgs.length; ci++) out.push(callSubArgs[ci]);
                return;
              }
            }
          }
        }
      }
    }
  }
  out.push(argPath);
}

// Trace ObjectProperty method to caller args: { method: function(param) {} }
// Walks up to the object, then through extend-patterns and global aliases
function _traceObjectMethodToArgs(funcPath, paramIdx, methodName) {
  var objExprPath = funcPath.parentPath ? funcPath.parentPath.parentPath : null;
  if (!objExprPath || !_t.isObjectExpression(objExprPath.node)) return [];
  var declPath = objExprPath.parentPath;
  if (!declPath) return [];

  var objBinding = null;
  if (_t.isVariableDeclarator(declPath.node) && _t.isIdentifier(declPath.node.id)) {
    objBinding = declPath.scope.getBinding(declPath.node.id.name);
  }

  // Extend pattern: X.extend({method: fn}) → callers use X.method(...)
  if (!objBinding && _t.isCallExpression(declPath.node)) {
    var extCallee = declPath.node.callee;
    if (_t.isMemberExpression(extCallee) && !extCallee.computed && _t.isIdentifier(extCallee.object)) {
      var args = [];
      var extObjBinding = declPath.scope.getBinding(extCallee.object.name);
      if (extObjBinding) {
        args = _collectMethodCallerArgs(extObjBinding.referencePaths, methodName, paramIdx);
        // Also check global aliases
        for (var gn in _globalAssignments) {
          var ga = _globalAssignments[gn];
          if (!ga.valueNode) continue;
          var gaVal = ga.valueNode;
          while (_t.isAssignmentExpression(gaVal)) gaVal = gaVal.right;
          if (_t.isIdentifier(gaVal) && gaVal.name === extObjBinding.identifier.name) {
            var globalArgs = _collectGlobalMethodCallerArgs(funcPath, gn, methodName, paramIdx);
            args = args.concat(globalArgs);
          }
        }
      }
      return args;
    }
  }
  if (!objBinding) return [];
  return _collectMethodCallerArgs(objBinding.referencePaths, methodName, paramIdx);
}

// Collect caller args from obj.method(...) call sites
function _collectMethodCallerArgs(refs, methodName, paramIdx) {
  var args = [];
  if (!refs) return args;
  for (var r = 0; r < refs.length; r++) {
    var refPath = refs[r];
    if (refPath.parent && _t.isMemberExpression(refPath.parent) &&
        refPath.parent.object === refPath.node && !refPath.parent.computed &&
        _t.isIdentifier(refPath.parent.property, { name: methodName })) {
      var callNode = refPath.parentPath ? refPath.parentPath.parent : null;
      if (callNode && _t.isCallExpression(callNode) && callNode.callee === refPath.parent) {
        var effectiveIdx = paramIdx < callNode.arguments.length ? paramIdx :
          (callNode.arguments.length > 0 ? callNode.arguments.length - 1 : -1);
        if (effectiveIdx >= 0) {
          _collectOrTraceArg(refPath.parentPath.parentPath.get("arguments." + effectiveIdx), args);
        }
      }
    }
  }
  return args;
}

// Unified global caller traversal: finds all calls to globalName(...) or globalName.methodName(...)
// in the program scope and invokes onMatch(callPath) for each match.
function _traverseGlobalCallers(funcPath, globalName, methodName, onMatch) {
  var cacheKey = globalName + (methodName ? "." + methodName : "");
  var cached = _globalCallerCache[cacheKey];
  if (!cached) {
    cached = [];
    var scope = funcPath.scope;
    while (scope.parent) scope = scope.parent;
    var programPath = scope.path;
    if (!programPath) { _globalCallerCache[cacheKey] = cached; return; }
    try {
      programPath.traverse({
        CallExpression: function(innerPath) {
          var c = innerPath.node.callee;
          var isMatch = methodName
            ? (_t.isMemberExpression(c) && !c.computed &&
               _t.isIdentifier(c.object, { name: globalName }) &&
               _t.isIdentifier(c.property, { name: methodName }))
            : _t.isIdentifier(c, { name: globalName });
          if (isMatch && !innerPath.scope.getBinding(globalName)) cached.push(innerPath);
        },
      });
    } catch (e) { _resolver.collectError(e, "globalCallerTraversal"); }
    _globalCallerCache[cacheKey] = cached;
  }
  for (var _gci = 0; _gci < cached.length; _gci++) onMatch(cached[_gci]);
}

function _collectGlobalMethodCallerArgs(funcPath, globalName, methodName, paramIdx) {
  var args = [];
  _traverseGlobalCallers(funcPath, globalName, methodName, function(innerPath) {
    var effectiveIdx = paramIdx < innerPath.node.arguments.length ? paramIdx :
      (innerPath.node.arguments.length > 0 ? innerPath.node.arguments.length - 1 : -1);
    if (effectiveIdx >= 0) _collectOrTraceArg(innerPath.get("arguments." + effectiveIdx), args);
  });
  return args;
}

function _collectGlobalCallerArgs(funcPath, globalName, paramIdx) {
  var args = [];
  _traverseGlobalCallers(funcPath, globalName, null, function(innerPath) {
    if (paramIdx < innerPath.node.arguments.length) {
      args.push(innerPath.get("arguments." + paramIdx));
    } else if (innerPath.node.arguments.length > 0) {
      args.push(innerPath.get("arguments." + (innerPath.node.arguments.length - 1)));
    }
  });
  return args;
}

// Trace callback argument through callee to find where callback is invoked with args
function _traceCallbackArgToArgs(callExprPath, cbArgIdx, paramIdx) {
  if (!_resolver.guard("ZC", callExprPath.node)) return [];
  try {
    var calleeNode = callExprPath.node.callee;
    // Resolve the callee function
    var targetFuncPath = _resolveCalleeFuncPath(callExprPath, 0);
    // Member expression — resolve through extend pattern
    if (!targetFuncPath && _t.isMemberExpression(calleeNode) && !calleeNode.computed) {
      var mProp = _t.isIdentifier(calleeNode.property) ? calleeNode.property.name : null;
      if (mProp && _t.isIdentifier(calleeNode.object)) {
        var objBinding = callExprPath.scope.getBinding(calleeNode.object.name);
        if (objBinding) {
          var refs = objBinding.referencePaths;
          for (var ri = 0; ri < refs.length && !targetFuncPath; ri++) {
            var refP = refs[ri].parent;
            if (_t.isMemberExpression(refP) && refP.object === refs[ri].node && !refP.computed) {
              var extProp = _t.isIdentifier(refP.property) ? refP.property.name : null;
              if (extProp === "extend" || extProp === "mixin" || extProp === "assign") {
                var extCall = refs[ri].parentPath ? refs[ri].parentPath.parent : null;
                if (extCall && _t.isCallExpression(extCall) && extCall.callee === refP) {
                  var extCallPath = refs[ri].parentPath.parentPath;
                  for (var ai = 0; ai < extCall.arguments.length && !targetFuncPath; ai++) {
                    var extArg = extCall.arguments[ai];
                    if (!_t.isObjectExpression(extArg)) continue;
                    for (var epi = 0; epi < extArg.properties.length; epi++) {
                      var ep = extArg.properties[epi];
                      if (!_t.isObjectProperty(ep) || ep.computed) continue;
                      var epKey = _t.isIdentifier(ep.key) ? ep.key.name : (_t.isStringLiteral(ep.key) ? ep.key.value : null);
                      if (epKey !== mProp) continue;
                      if (_t.isFunctionExpression(ep.value) || _t.isArrowFunctionExpression(ep.value))
                        targetFuncPath = extCallPath.get("arguments." + ai + ".properties." + epi + ".value");
                      else if (_t.isCallExpression(ep.value)) {
                        var retFunc = _resolveCallReturnToFunction(extCallPath.get("arguments." + ai + ".properties." + epi + ".value"), 0);
                        if (retFunc) targetFuncPath = retFunc._path || null;
                      }
                      break;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    if (!targetFuncPath) return [];

    var targetParams = targetFuncPath.node.params || [];
    var cbParamIdx = cbArgIdx;
    if (cbParamIdx >= targetParams.length) cbParamIdx = targetParams.length - 1;
    if (cbParamIdx < 0) return [];
    var cbParamName = _t.isIdentifier(targetParams[cbParamIdx]) ? targetParams[cbParamIdx].name : null;
    if (!cbParamName) return [];

    // Search for stored-callback pattern: container.push(cbParam) → trace container
    var args = [];
    try {
      targetFuncPath.traverse({
        CallExpression: function(innerPath) {
          // Direct call: cbParam(arg0, ...)
          var ic = innerPath.node.callee;
          if (_t.isIdentifier(ic, { name: cbParamName })) {
            var innerBinding = innerPath.scope.getBinding(cbParamName);
            if (innerBinding && innerBinding.kind === "param" && innerBinding.scope.path === targetFuncPath) {
              if (paramIdx < innerPath.node.arguments.length) {
                args.push(innerPath.get("arguments." + paramIdx));
              }
            }
          }
          // Store-and-call-later: container.push(cbParam) → trace container
          var isPushOrUnshift = false;
          if (_t.isMemberExpression(ic) && !ic.computed &&
              (_t.isIdentifier(ic.property, { name: "push" }) || _t.isIdentifier(ic.property, { name: "unshift" })))
            isPushOrUnshift = true;
          if (!isPushOrUnshift && _t.isMemberExpression(ic) && ic.computed && _t.isConditionalExpression(ic.property)) {
            var cc = ic.property.consequent, ca = ic.property.alternate;
            if ((_t.isStringLiteral(cc) && (cc.value === "push" || cc.value === "unshift")) ||
                (_t.isStringLiteral(ca) && (ca.value === "push" || ca.value === "unshift")))
              isPushOrUnshift = true;
          }
          if (isPushOrUnshift) {
            var pushArgs = innerPath.node.arguments;
            var storingCb = false;
            for (var pai = 0; pai < pushArgs.length; pai++) {
              if (_t.isIdentifier(pushArgs[pai], { name: cbParamName })) {
                var pushB = innerPath.scope.getBinding(cbParamName);
                if (pushB && pushB.kind === "param" && pushB.scope.path === targetFuncPath) storingCb = true;
              }
              // Derived variable: func = cbParam; container.push(func)
              if (!storingCb && _t.isIdentifier(pushArgs[pai])) {
                var derivedB = innerPath.scope.getBinding(pushArgs[pai].name);
                if (derivedB && derivedB.constantViolations) {
                  for (var dvi = 0; dvi < derivedB.constantViolations.length; dvi++) {
                    var dvN = derivedB.constantViolations[dvi].node;
                    if (_t.isAssignmentExpression(dvN) && _t.isIdentifier(dvN.right, { name: cbParamName })) {
                      storingCb = true; break;
                    }
                  }
                }
              }
            }
            if (storingCb) {
              var containerNode = ic.object;
              if (_t.isAssignmentExpression(containerNode)) containerNode = containerNode.left;
              while (_t.isMemberExpression(containerNode) && containerNode.computed) containerNode = containerNode.object;
              if (_t.isIdentifier(containerNode)) {
                var containerBinding = innerPath.scope.getBinding(containerNode.name);
                if (containerBinding) {
                  var storedArgs = _traceStoredCallbackToArgs(containerBinding, paramIdx);
                  args = args.concat(storedArgs);
                }
              }
            }
          }
        },
        FunctionDeclaration: function(p) { p.skip(); },
      });
    } catch (e) { _resolver.collectError(e, "traceCallbackArgToArgs"); }
    return args;
  } catch (_rzce) {
    if (_rzce instanceof RangeError) { _resolver.collectError(_rzce, "traceCallbackArgToArgs"); return []; }
    throw _rzce;
  } finally { _resolver.unguard("ZC", callExprPath.node); }
}

// Trace a stored-callback container to find where items are called and return their arg paths
function _traceStoredCallbackToArgs(containerBinding, paramIdx) {
  if (!_resolver.guard("ZS", containerBinding.identifier)) return [];
  try {
    // If container is a param, resolve from callers
    if (containerBinding.kind === "param") {
      var enclosingFunc = containerBinding.scope.path;
      var containerParamIdx = -1;
      var params = enclosingFunc.node.params;
      for (var pi = 0; pi < params.length; pi++) {
        if (_t.isIdentifier(params[pi]) && params[pi].name === containerBinding.identifier.name) {
          containerParamIdx = pi; break;
        }
      }
      if (containerParamIdx < 0) return [];
      var funcBinding = _getFunctionBinding(enclosingFunc);
      if (!funcBinding || !funcBinding.referencePaths) return [];
      var args = [];
      var callerRefs = funcBinding.referencePaths;
      for (var ri = 0; ri < callerRefs.length; ri++) {
        if (!callerRefs[ri].parent || !_t.isCallExpression(callerRefs[ri].parent) ||
            callerRefs[ri].parent.callee !== callerRefs[ri].node) continue;
        if (containerParamIdx >= callerRefs[ri].parent.arguments.length) continue;
        var actualArg = callerRefs[ri].parent.arguments[containerParamIdx];
        if (_t.isIdentifier(actualArg)) {
          var actualBinding = callerRefs[ri].parentPath.scope.getBinding(actualArg.name);
          if (actualBinding) {
            var subArgs = _traceStoredCallbackToArgs(actualBinding, paramIdx);
            args = args.concat(subArgs);
          }
        }
      }
      return args;
    }

    // Container is local — find where items are called
    var args = [];
    var refs = containerBinding.referencePaths;
    for (var ri = 0; ri < refs.length; ri++) {
      var refPath = refs[ri];
      // Pattern 1: container[i](args) — direct indexed call
      if (_t.isMemberExpression(refPath.parent) && refPath.parent.object === refPath.node && refPath.parent.computed) {
        var memberCallParent = refPath.parentPath ? refPath.parentPath.parent : null;
        if (memberCallParent && _t.isCallExpression(memberCallParent) && memberCallParent.callee === refPath.parent) {
          if (paramIdx < memberCallParent.arguments.length) {
            var directArgPath = refPath.parentPath.parentPath.get("arguments." + paramIdx);
            // If the argument is a local variable or param, trace further to callers
            if (_t.isIdentifier(directArgPath.node)) {
              var directArgBinding = directArgPath.scope.getBinding(directArgPath.node.name);
              if (directArgBinding && directArgBinding.kind === "param") {
                var subArgs = _traceParamToArgs(directArgBinding);
                args = args.concat(subArgs);
              } else {
                args.push(directArgPath);
              }
            } else {
              args.push(directArgPath);
            }
          }
        }
      }
      // Pattern 2: container passed to a function that iterates and calls items
      if (_t.isCallExpression(refPath.parent) && refPath.parent.callee !== refPath.node) {
        var iterCallPath = refPath.parentPath;
        var iterArgIdx = -1;
        for (var iai = 0; iai < iterCallPath.node.arguments.length; iai++) {
          if (iterCallPath.node.arguments[iai] === refPath.node) { iterArgIdx = iai; break; }
          if (_containsNode(iterCallPath.node.arguments[iai], refPath.node)) { iterArgIdx = iai; break; }
        }
        if (iterArgIdx >= 0) {
          var iterArgs = _traceItemCallsToArgs(iterCallPath, iterArgIdx, paramIdx);
          args = args.concat(iterArgs);
        }
      }
    }
    return args;
  } catch (_rzse) {
    if (_rzse instanceof RangeError) { _resolver.collectError(_rzse, "traceStoredCallbackToArgs"); return []; }
    throw _rzse;
  } finally { _resolver.unguard("ZS", containerBinding.identifier); }
}

// Trace iteration pattern to find where item callbacks are called with args
function _traceItemCallsToArgs(callPath, iterArgIdx, paramIdx) {
  if (!_resolver.guard("ZI", callPath.node)) return [];
  try {
    // Resolve the called function
    var funcPath = _resolveCalleeToFunction(callPath);
    if (!funcPath) return [];
    if (iterArgIdx >= funcPath.node.params.length) return [];
    var containerParamName = _t.isIdentifier(funcPath.node.params[iterArgIdx]) ? funcPath.node.params[iterArgIdx].name : null;
    if (!containerParamName) return [];

    // Find iteration patterns inside the function that call items from container
    var args = [];
    try {
      funcPath.traverse({
        CallExpression: function(innerPath) {
          var ic = innerPath.node.callee;
          // jQuery.each(container[key] || [], function(_, item) { item(args); })
          if (_t.isMemberExpression(ic) && !ic.computed && _t.isIdentifier(ic.property, { name: "each" })) {
            var eachArgs = innerPath.node.arguments;
            var containerFound = false;
            for (var eai = 0; eai < eachArgs.length && !containerFound; eai++) {
              var eaArg = eachArgs[eai];
              var isContainer = false;
              if (_t.isIdentifier(eaArg, { name: containerParamName })) isContainer = true;
              else if (_t.isMemberExpression(eaArg) && _t.isIdentifier(eaArg.object, { name: containerParamName })) isContainer = true;
              else if (_t.isLogicalExpression(eaArg)) {
                var left = eaArg.left;
                if (_t.isIdentifier(left, { name: containerParamName }) ||
                    (_t.isMemberExpression(left) && _t.isIdentifier(left.object, { name: containerParamName }))) isContainer = true;
              }
              if (!isContainer) continue;
              containerFound = true;
              // Find callback after container arg
              for (var cai = eai + 1; cai < eachArgs.length; cai++) {
                if (!_t.isFunctionExpression(eachArgs[cai]) && !_t.isArrowFunctionExpression(eachArgs[cai])) continue;
                var cbPath = innerPath.get("arguments." + cai);
                try {
                  cbPath.traverse(Object.assign({
                    CallExpression: function(cbInner) {
                      var cbc = cbInner.node.callee;
                      if (!_t.isIdentifier(cbc)) return;
                      var cbBinding = cbInner.scope.getBinding(cbc.name);
                      if (!cbBinding || cbBinding.kind !== "param" || cbBinding.scope.path !== cbPath) return;
                      if (paramIdx < cbInner.node.arguments.length) {
                        _collectOrTraceArg(cbInner.get("arguments." + paramIdx), args);
                      }
                    },
                  }, _SKIP_NESTED_FUNCS));
                } catch (e) { _resolver.collectError(e, "traceItemCallsInner"); }
              }
            }
          }
        },
      });
    } catch (e) { _resolver.collectError(e, "traceItemCallsToArgs"); }
    return args;
  } catch (_rzie) {
    if (_rzie instanceof RangeError) { _resolver.collectError(_rzie, "traceItemCallsToArgs"); return []; }
    throw _rzie;
  } finally { _resolver.unguard("ZI", callPath.node); }
}

// Resolve correlated properties from caller arguments.
// Given an argument path (from a caller), resolve multiple properties from it.
// Returns { prop1: [val1, ...], prop2: [val2, ...] }
function _resolvePropsFromArg(argPath, propNames) {
  var result = {};
  for (var i = 0; i < propNames.length; i++) {
    result[propNames[i]] = _resolvePropertyFromArg(argPath, propNames[i], 0);
  }
  // CallExpression arg: X.extend({url: url, type: method}, ...) — check ObjectExpression args
  // Handles: jQuery.ajax(jQuery.extend({url: url, type: method, ...}, ...))
  if (allEmpty(result, propNames) && _t.isCallExpression(argPath.node)) {
    var callArgs = argPath.node.arguments;
    for (var cai = 0; cai < callArgs.length; cai++) {
      var subResult = _resolvePropsFromArg(argPath.get("arguments." + cai), propNames);
      for (var pi = 0; pi < propNames.length; pi++) {
        if (result[propNames[pi]].length === 0) result[propNames[pi]] = subResult[propNames[pi]];
      }
    }
  }
  // If arg is an identifier that's a local variable initialized from a function call (merge/extend),
  // also check the call's arguments for the properties.
  // Handles: var s = jQuery.ajaxSetup({}, options); → check options for each prop
  if (allEmpty(result, propNames) && _t.isIdentifier(argPath.node)) {
    var binding = argPath.scope.getBinding(argPath.node.name);
    if (binding && binding.path.isVariableDeclarator && binding.path.isVariableDeclarator()) {
      var initNode = binding.path.node.init;
      if (initNode && _t.isCallExpression(initNode)) {
        var initPath = binding.path.get("init");
        var initArgs = initNode.arguments;
        for (var iai = 0; iai < initArgs.length; iai++) {
          var subResult = _resolvePropsFromArg(initPath.get("arguments." + iai), propNames);
          for (var pi = 0; pi < propNames.length; pi++) {
            if (result[propNames[pi]].length === 0) result[propNames[pi]] = subResult[propNames[pi]];
          }
        }
      }
    }
    // Also check property assignments: s.url = ..., s.type = ...
    if (binding && binding.referencePaths) {
      for (var pi = 0; pi < propNames.length; pi++) {
        if (result[propNames[pi]].length > 0) continue;
        var propN = propNames[pi];
        var refs = binding.referencePaths;
        for (var ri = 0; ri < refs.length; ri++) {
          var refParent = refs[ri].parent;
          if (_t.isMemberExpression(refParent) && refParent.object === refs[ri].node &&
              !refParent.computed && _t.isIdentifier(refParent.property, { name: propN })) {
            var assignNode = refs[ri].parentPath ? refs[ri].parentPath.parent : null;
            if (assignNode && _t.isAssignmentExpression(assignNode) && assignNode.operator === "=" &&
                assignNode.left === refParent) {
              var rhsVals = _resolveAllValues(refs[ri].parentPath.parentPath.get("right"), 0);
              result[propN] = result[propN].concat(rhsVals);
            }
          }
        }
      }
    }
  }
  return result;
}

function allEmpty(obj, keys) {
  for (var i = 0; i < keys.length; i++) {
    if (obj[keys[i]] && obj[keys[i]].length > 0) return false;
  }
  return true;
}

// Search an object binding's references for obj.method(...) call sites
var _methodCallVisited = null;
function _resolveParamFromMethodCalls(objBinding, methodName, paramIdx, depth, propName) {
  // Iterative cycle protection: factory chains (a.create()→b, b.create()→c) can cycle
  var isRoot = !_methodCallVisited;
  if (isRoot) _methodCallVisited = new Set();
  var bindKey = objBinding.identifier.start + ":" + objBinding.identifier.end + ":" + methodName;
  if (_methodCallVisited.has(bindKey)) return [];
  _methodCallVisited.add(bindKey);
  try {
  var values = [];
  var refs = objBinding.referencePaths;
  for (var r = 0; r < refs.length; r++) {
    var refPath = refs[r];
    // Looking for: obj.method(...) where obj is this reference
    if (refPath.parent && _t.isMemberExpression(refPath.parent) &&
        refPath.parent.object === refPath.node && !refPath.parent.computed &&
        _t.isIdentifier(refPath.parent.property, { name: methodName })) {
      var callNode = refPath.parentPath ? refPath.parentPath.parent : null;
      if (callNode && _t.isCallExpression(callNode) && callNode.callee === refPath.parent) {
        if (paramIdx < callNode.arguments.length) {
          var argPath = refPath.parentPath.parentPath.get("arguments." + paramIdx);
          var argVals = propName ? _resolvePropertyFromArg(argPath, propName, depth) : _resolveAllValues(argPath, depth + 1);
          values = values.concat(argVals);
        } else {
          values = values.concat(_resolveOverloadedArg(refPath.parentPath.parentPath, paramIdx, depth, propName));
        }
      }
    }
  }
  // Factory clone tracking: var api = obj(...) or var api = obj.create(...)
  // The returned value has the same methods, so api.method() callers should be included.
  for (var fc = 0; fc < refs.length; fc++) {
    var fcRef = refs[fc];
    var fcCallPath = null;
    // Pattern 1: obj(...) → direct call where obj is callee
    if (fcRef.parent && _t.isCallExpression(fcRef.parent) && fcRef.parent.callee === fcRef.node) {
      fcCallPath = fcRef.parentPath;
    }
    // Pattern 2: obj.create(...) or obj.extend(...) → member method call
    else if (fcRef.parent && _t.isMemberExpression(fcRef.parent) && fcRef.parent.object === fcRef.node &&
             !fcRef.parent.computed && fcRef.parentPath && fcRef.parentPath.parent &&
             _t.isCallExpression(fcRef.parentPath.parent) && fcRef.parentPath.parent.callee === fcRef.parent) {
      fcCallPath = fcRef.parentPath.parentPath;
    }
    if (!fcCallPath) continue;
    // Check if the call result is assigned to a variable: var alias = obj.create(...)
    var fcAssignee = null;
    if (fcCallPath.parent && _t.isVariableDeclarator(fcCallPath.parent) && _t.isIdentifier(fcCallPath.parent.id)) {
      fcAssignee = fcCallPath.parentPath.scope.getBinding(fcCallPath.parent.id.name);
    } else if (fcCallPath.parent && _t.isAssignmentExpression(fcCallPath.parent) &&
               fcCallPath.parent.right === fcCallPath.node && _t.isIdentifier(fcCallPath.parent.left)) {
      fcAssignee = fcCallPath.parentPath.scope.getBinding(fcCallPath.parent.left.name);
    }
    if (fcAssignee && fcAssignee !== objBinding) {
      var cloneVals = _resolveParamFromMethodCalls(fcAssignee, methodName, paramIdx, depth, propName);
      values = values.concat(cloneVals);
    }
  }
  // If no callers found locally, check if the binding is returned from an IIFE
  // that's assigned to an outer variable/global. Pattern:
  // var e = function(){ function n(){} n.get=fn; return n; }(); e.get(url)
  // n has no method callers, but e (= n returned from IIFE) does.
  if (values.length === 0) {
    var encFuncScope = objBinding.scope.path;
    if (encFuncScope && _t.isFunction(encFuncScope.node)) {
      var encParent = encFuncScope.parentPath;
      // Direct IIFE: enclosing function is the callee of a CallExpression
      if (encParent && _t.isCallExpression(encParent.node) && encParent.node.callee === encFuncScope.node) {
        var iifeCallParent = encParent.parentPath;
        // var x = IIFE() — check x.method() callers
        if (iifeCallParent && _t.isVariableDeclarator(iifeCallParent.node) && _t.isIdentifier(iifeCallParent.node.id)) {
          var outerBinding = iifeCallParent.scope.getBinding(iifeCallParent.node.id.name);
          if (outerBinding) {
            console.debug("[AST:trace]     → IIFE-return alias: %s → %s, checking %s.%s() callers",
              objBinding.identifier.name, iifeCallParent.node.id.name, iifeCallParent.node.id.name, methodName);
            values = _resolveParamFromMethodCalls(outerBinding, methodName, paramIdx, depth, propName);
          }
        }
        // (win).X = IIFE() — check global X.method() callers
        if (values.length === 0 && iifeCallParent && _t.isAssignmentExpression(iifeCallParent.node) &&
            _t.isMemberExpression(iifeCallParent.node.left)) {
          var gProp = iifeCallParent.node.left.property;
          var gName = _t.isIdentifier(gProp) ? gProp.name : null;
          if (gName && _globalAssignments[gName]) {
            console.debug("[AST:trace]     → IIFE-return global alias: %s → global %s, checking %s.%s() callers",
              objBinding.identifier.name, gName, gName, methodName);
            values = _resolveParamFromGlobalCallers(objBinding.scope.path, gName, paramIdx, depth, propName, methodName);
          }
        }
      }
      // Factory-argument pattern: !function(t){ win.X = t() }(factoryFunc)
      // factoryFunc returns the object (Se), but it's not the callee — it's an argument
      if (values.length === 0 && encParent && _t.isCallExpression(encParent.node) &&
          encParent.node.callee !== encFuncScope.node) {
        var _outerCallee = encParent.node.callee;
        if (_t.isFunctionExpression(_outerCallee) || _t.isArrowFunctionExpression(_outerCallee)) {
          var _argIdx = -1;
          for (var _fi = 0; _fi < encParent.node.arguments.length; _fi++) {
            if (encParent.node.arguments[_fi] === encFuncScope.node) { _argIdx = _fi; break; }
          }
          if (_argIdx >= 0 && _argIdx < _outerCallee.params.length && _t.isIdentifier(_outerCallee.params[_argIdx])) {
            var _factoryParam = _outerCallee.params[_argIdx].name;
            for (var _gn in _globalAssignments) {
              var _gv = _globalAssignments[_gn];
              if (_gv.valueNode && _t.isCallExpression(_gv.valueNode) &&
                  _t.isIdentifier(_gv.valueNode.callee, {name: _factoryParam})) {
                console.debug("[AST:trace]     → factory-arg global: %s → %s(), checking %s.%s() callers",
                  objBinding.identifier.name, _gn, _gn, methodName);
                values = _resolveParamFromGlobalCallers(objBinding.scope.path, _gn, paramIdx, depth, propName, methodName);
                break;
              }
            }
          }
        }
      }
    }
  }
  return values;
  } finally { if (isRoot) _methodCallVisited = null; }
}

// Resolve parameters of prototype methods: Ctor.prototype.method = function(params) { ... }
// Find new Ctor() instances, then find instance.method(args) call sites.
function _resolveParamFromPrototypeMethodCallers(funcPath, ctorName, methodName, paramIdx, depth, propName) {
  if (!_resolver.guard("M", funcPath.node)) return [];
  try {
  var ctorBinding = funcPath.scope.getBinding(ctorName);
  if (!ctorBinding || !ctorBinding.referencePaths) return [];

  var values = [];
  var refs = ctorBinding.referencePaths;
  for (var r = 0; r < refs.length; r++) {
    var ref = refs[r];
    // Find new Ctor(...) stored in a variable: var x = new Ctor(...)
    if (ref.parent && _t.isNewExpression(ref.parent) && ref.parent.callee === ref.node) {
      var newExprPath = ref.parentPath;
      var newParent = newExprPath.parentPath;
      if (newParent && _t.isVariableDeclarator(newParent.node) && newParent.node.init === newExprPath.node &&
          _t.isIdentifier(newParent.node.id)) {
        var instanceName = newParent.node.id.name;
        var instanceBinding = newParent.scope.getBinding(instanceName);
        if (instanceBinding) {
          var methodVals = _resolveParamFromMethodCalls(instanceBinding, methodName, paramIdx, depth + 1, propName);
          values = values.concat(methodVals);
        }
      }
    }
  }
  return values;
  } catch (_rme) {
    if (_rme instanceof RangeError) { _resolver.collectError(_rme, "resolveMethodCallValues"); return []; }
    throw _rme;
  } finally { _resolver.unguard("M", funcPath.node); }
}

// Correlated this.prop XHR resolution for prototype methods.
// Traces this.method and this.url through constructor → new Ctor() callers,
// keeping method/URL paired per-caller to avoid cross-contamination.
function _resolveThisPropXhrCorrelated(fromPath, ctorName, methodProp, urlProp, headers, bodyParams) {
  var sites = [];
  var ctorBinding = fromPath.scope.getBinding(ctorName);
  if (!ctorBinding && _lastIIFEFuncPath) {
    try { ctorBinding = _lastIIFEFuncPath.scope.getBinding(ctorName); } catch(e) { _resolver.collectError(e, "xhrCtorIIFEScope"); }
  }
  if (!ctorBinding) return sites;
  var ctorNode = null, ctorPath = null;
  if (_t.isFunctionDeclaration(ctorBinding.path.node)) { ctorNode = ctorBinding.path.node; ctorPath = ctorBinding.path; }
  else if (_t.isVariableDeclarator(ctorBinding.path.node) && ctorBinding.path.node.init &&
           (_t.isFunctionExpression(ctorBinding.path.node.init) || _t.isArrowFunctionExpression(ctorBinding.path.node.init))) {
    ctorNode = ctorBinding.path.node.init; ctorPath = ctorBinding.path.get("init");
  }
  if (!ctorNode || !ctorNode.params) return sites;
  // Find this.methodProp = param and this.urlProp = param assignments
  var methodParamIdx = -1, urlParamIdx = -1;
  var paramNames = {};
  for (var pi = 0; pi < ctorNode.params.length; pi++) {
    var p = ctorNode.params[pi];
    if (_t.isIdentifier(p)) paramNames[p.name] = pi;
  }
  if (ctorNode.body && ctorNode.body.body) {
    var _checkAssign = function(expr) {
      if (_t.isAssignmentExpression(expr) && expr.operator === "=") {
        var aL = expr.left, aR = expr.right;
        if (_t.isMemberExpression(aL) && _t.isThisExpression(aL.object) && _t.isIdentifier(aL.property) &&
            _t.isIdentifier(aR) && paramNames[aR.name] !== undefined) {
          if (aL.property.name === methodProp) methodParamIdx = paramNames[aR.name];
          if (aL.property.name === urlProp) urlParamIdx = paramNames[aR.name];
        }
      }
    };
    for (var si = 0; si < ctorNode.body.body.length; si++) {
      var stmt = ctorNode.body.body[si];
      if (_t.isExpressionStatement(stmt)) {
        if (_t.isAssignmentExpression(stmt.expression)) _checkAssign(stmt.expression);
        else if (_t.isSequenceExpression(stmt.expression)) {
          for (var sei = 0; sei < stmt.expression.expressions.length; sei++) _checkAssign(stmt.expression.expressions[sei]);
        }
      }
    }
  }
  if (methodParamIdx < 0 && urlParamIdx < 0) return sites;
  // Find new Ctor() callers (direct + aliased)
  var newCallers = []; // [{argPaths: [path...]}]
  if (ctorBinding.referencePaths) {
    for (var ri = 0; ri < ctorBinding.referencePaths.length; ri++) {
      var ref = ctorBinding.referencePaths[ri];
      if (ref.parent && _t.isNewExpression(ref.parent) && ref.parent.callee === ref.node) {
        var args = [];
        for (var ai = 0; ai < ref.parent.arguments.length; ai++) args.push(ref.parentPath.get("arguments." + ai));
        newCallers.push(args);
      }
      // Aliased: obj.prop = Ctor → new obj.prop(...)
      if (ref.parent && _t.isAssignmentExpression(ref.parent) && ref.parent.right === ref.node &&
          _t.isMemberExpression(ref.parent.left) && !ref.parent.left.computed) {
        var _ao = ref.parent.left.object, _ap = ref.parent.left.property;
        if (_t.isIdentifier(_ao) && _t.isIdentifier(_ap)) {
          var _ab = ref.parentPath.scope.getBinding(_ao.name);
          if (_ab && _ab.referencePaths) {
            for (var ari = 0; ari < _ab.referencePaths.length; ari++) {
              var aRef = _ab.referencePaths[ari];
              if (_t.isMemberExpression(aRef.parent) && aRef.parent.object === aRef.node &&
                  _t.isIdentifier(aRef.parent.property, {name: _ap.name}) &&
                  aRef.parentPath && _t.isNewExpression(aRef.parentPath.parent) &&
                  aRef.parentPath.parent.callee === aRef.parent) {
                var args2 = [];
                for (var ai2 = 0; ai2 < aRef.parentPath.parent.arguments.length; ai2++)
                  args2.push(aRef.parentPath.parentPath.get("arguments." + ai2));
                newCallers.push(args2);
              }
            }
          }
        }
      }
    }
  }
  // For each new Ctor() caller, resolve method and URL with per-caller correlation
  for (var ci = 0; ci < newCallers.length; ci++) {
    var cArgs = newCallers[ci];
    var mArg = methodParamIdx >= 0 && methodParamIdx < cArgs.length ? cArgs[methodParamIdx] : null;
    var uArg = urlParamIdx >= 0 && urlParamIdx < cArgs.length ? cArgs[urlParamIdx] : null;
    if (!mArg && !uArg) continue;
    // Classify each arg: literal string, param of enclosing function, or other
    var mLiteral = mArg && _t.isStringLiteral(mArg.node) ? mArg.node.value : null;
    var uLiteral = uArg && _t.isStringLiteral(uArg.node) ? uArg.node.value : null;
    var mParamBinding = mArg && _t.isIdentifier(mArg.node) ? mArg.scope.getBinding(mArg.node.name) : null;
    var uParamBinding = uArg && _t.isIdentifier(uArg.node) ? uArg.scope.getBinding(uArg.node.name) : null;
    var mIsParam = mParamBinding && mParamBinding.kind === "param";
    var uIsParam = uParamBinding && uParamBinding.kind === "param";
    // When BOTH args are params of the SAME function, do per-caller correlated resolution.
    // Skip mixed literal+param callers — they're conditional branches where the param
    // carries wrong-type values (e.g. method strings in a URL slot).
    if (mIsParam && uIsParam && mParamBinding.scope === uParamBinding.scope) {
      var _funcP = mParamBinding.scope.path;
      var _mIdx = -1, _uIdx = -1;
      for (var _pi = 0; _pi < _funcP.node.params.length; _pi++) {
        if (_t.isIdentifier(_funcP.node.params[_pi]) && _funcP.node.params[_pi].name === mArg.node.name) _mIdx = _pi;
        if (_t.isIdentifier(_funcP.node.params[_pi]) && _funcP.node.params[_pi].name === uArg.node.name) _uIdx = _pi;
      }
      if (_mIdx >= 0 && _uIdx >= 0) {
        var _fCallers = _findFunctionCallerArgs(_funcP);
        for (var _fci = 0; _fci < _fCallers.length; _fci++) {
          var _fArgs = _fCallers[_fci];
          var _fm = [], _fu = [];
          if (_mIdx < _fArgs.length) _fm = _resolveAllValues(_fArgs[_mIdx], 2);
          if (_uIdx < _fArgs.length) _fu = _resolveAllValues(_fArgs[_uIdx], 2);
          _fm = _fm.filter(function(m) { return typeof m === "string" && _HTTP_METHODS_LC[m.toLowerCase()]; });
          for (var _fui = 0; _fui < _fu.length; _fui++) {
            if (typeof _fu[_fui] !== "string") continue;
            var _fMethod = _fm.length > 0 ? _fm[0].toUpperCase() : "GET";
            sites.push({ url: _fu[_fui], method: _fMethod, headers: headers || {}, type: "xhr" });
          }
        }
      }
      continue;
    }
    // Skip mixed: one literal + one param (conditional branch — param meaning is ambiguous)
    if ((mLiteral && uIsParam) || (uLiteral && mIsParam)) continue;
    // Both args are literals — emit directly
    if (mLiteral || uLiteral) {
      var _m = mLiteral && _HTTP_METHODS_LC[mLiteral.toLowerCase()] ? mLiteral.toUpperCase() : "GET";
      if (uLiteral) sites.push({ url: uLiteral, method: _m, headers: headers || {}, type: "xhr" });
    }
  }
  // Global method caller sweep: find globalName.httpMethod(url) callers directly.
  // This handles chained .send()/.set() and works when factory uses loop variables.
  // Prefer these results over constructor-based ones (more complete: has chaining info).
  {
    var _globalSites = [];
    var _progPath = fromPath.findParent(function(p) { return p.isProgram(); });
    if (_progPath) {
      try {
        _progPath.traverse({
          CallExpression: function(_gcPath) {
            var _gc = _gcPath.node.callee;
            if (!_t.isMemberExpression(_gc) || _gc.computed) return;
            if (!_t.isIdentifier(_gc.object) || !_t.isIdentifier(_gc.property)) return;
            var _gn = _gc.object.name, _mn = _gc.property.name;
            if (!_globalAssignments[_gn] || !_HTTP_METHODS_LC[_mn]) return;
            if (_gcPath.scope.getBinding(_gn)) return;
            if (_gcPath.node.arguments.length < 1) return;
            var _gUrls = _resolveAllValues(_gcPath.get("arguments.0"), 1);
            for (var _gui = 0; _gui < _gUrls.length; _gui++) {
              if (typeof _gUrls[_gui] === "string") {
                var _gSite = { url: _gUrls[_gui], method: _mn.toUpperCase(), headers: headers || {}, type: "xhr" };
                // Extract body params from .send({...}) chains
                var _chainNode = _gcPath;
                while (_chainNode.parentPath && _t.isMemberExpression(_chainNode.parent) &&
                       _chainNode.parent.object === _chainNode.node &&
                       _chainNode.parentPath.parentPath && _t.isCallExpression(_chainNode.parentPath.parent) &&
                       _chainNode.parentPath.parent.callee === _chainNode.parent) {
                  var _chainCall = _chainNode.parentPath.parentPath;
                  var _chainProp = _chainNode.parent.property;
                  if (_t.isIdentifier(_chainProp)) {
                    if (_chainProp.name === "send" && _chainCall.node.arguments.length > 0) {
                      var _sendArg = _chainCall.node.arguments[0];
                      if (_t.isObjectExpression(_sendArg)) {
                        _gSite.params = _extractObjectProperties(_sendArg);
                        for (var _spi = 0; _spi < _gSite.params.length; _spi++) _gSite.params[_spi].location = "body";
                      }
                    } else if (_chainProp.name === "set" && _chainCall.node.arguments.length >= 2) {
                      var _hKey = _chainCall.node.arguments[0], _hVal = _chainCall.node.arguments[1];
                      if (_t.isStringLiteral(_hKey) && _t.isStringLiteral(_hVal)) {
                        if (!_gSite.headers) _gSite.headers = {};
                        _gSite.headers[_hKey.value] = _hVal.value;
                      }
                    }
                  }
                  _chainNode = _chainCall;
                }
                _globalSites.push(_gSite);
              }
            }
          }
        });
      } catch (e) { _resolver.collectError(e, "globalMethodCallerSweep"); }
    }
    if (_globalSites.length > 0) sites = _globalSites;
  }
  return sites;
}

// Resolve this.prop through constructor: find SomeClass constructor, look for this.prop = param,
// then find new SomeClass(value) call sites and extract the corresponding argument.
function _resolveConstructorProperty(fromPath, ctorName, propName, depth) {
  if (!_resolver.guard("X", fromPath.node)) return [];
  try {
  var ctorBinding = fromPath.scope.getBinding(ctorName);
  if (!ctorBinding) return [];
  var ctorPath = null;
  if (_t.isFunctionDeclaration(ctorBinding.path.node)) ctorPath = ctorBinding.path;
  else if (_t.isVariableDeclarator(ctorBinding.path.node) && ctorBinding.path.node.init) {
    var init = ctorBinding.path.node.init;
    if (_t.isFunctionExpression(init) || _t.isArrowFunctionExpression(init))
      ctorPath = ctorBinding.path.get("init");
  }
  if (!ctorPath) return [];

  var assignedParamName = _findThisAssignedParam(ctorPath, propName);
  if (!assignedParamName) return [];

  var paramIdx = _findParamIndex(ctorPath.node.params, assignedParamName);
  if (paramIdx === -1) return [];

  // Find new CtorName(args) callers (direct and aliased)
  var values = [];
  if (ctorBinding.referencePaths) {
    for (var r = 0; r < ctorBinding.referencePaths.length; r++) {
      var ref = ctorBinding.referencePaths[r];
      // Direct: new CtorName(args)
      if (ref.parent && _t.isNewExpression(ref.parent) && ref.parent.callee === ref.node &&
          paramIdx < ref.parent.arguments.length) {
        values = values.concat(_resolveAllValues(ref.parentPath.get("arguments." + paramIdx), depth + 1));
      }
      // Aliased: obj.prop = CtorName → new obj.prop(args)
      if (ref.parent && _t.isAssignmentExpression(ref.parent) && ref.parent.right === ref.node &&
          _t.isMemberExpression(ref.parent.left) && !ref.parent.left.computed) {
        var _aliasObj = ref.parent.left.object;
        var _aliasProp = ref.parent.left.property;
        if (_t.isIdentifier(_aliasObj) && _t.isIdentifier(_aliasProp)) {
          var _aliasBinding = ref.parentPath.scope.getBinding(_aliasObj.name);
          if (_aliasBinding && _aliasBinding.referencePaths) {
            for (var ari = 0; ari < _aliasBinding.referencePaths.length; ari++) {
              var aRef = _aliasBinding.referencePaths[ari];
              // Check: new aliasObj.aliasProp(args) — aRef is Identifier(aliasObj), parent is MemberExpression
              if (_t.isMemberExpression(aRef.parent) && aRef.parent.object === aRef.node &&
                  _t.isIdentifier(aRef.parent.property, {name: _aliasProp.name}) &&
                  aRef.parentPath && _t.isNewExpression(aRef.parentPath.parent) &&
                  aRef.parentPath.parent.callee === aRef.parent &&
                  paramIdx < aRef.parentPath.parent.arguments.length) {
                values = values.concat(_resolveAllValues(
                  aRef.parentPath.parentPath.get("arguments." + paramIdx), depth + 1
                ));
              }
            }
          }
        }
      }
    }
  }
  return values;
  } catch (_rxe) {
    if (_rxe instanceof RangeError) { _resolver.collectError(_rxe, "resolveXhrOpenValues"); return []; }
    throw _rxe;
  } finally { _resolver.unguard("X", fromPath.node); }
}

// Resolve this.prop in an ES6 class method by finding the constructor's this.prop = param assignment,
// then tracing the param value from new ClassName(...) call sites.
function _resolveClassConstructorProperty(fromPath, classDecl, className, propName, depth) {
  if (!_resolver.guard("CC", fromPath.node)) return [];
  try {
  // Find the constructor ClassMethod in the class body
  var classBody = classDecl.node.body;
  var ctorMethod = null;
  var ctorMethodPath = null;
  for (var ci = 0; ci < classBody.body.length; ci++) {
    var member = classBody.body[ci];
    if (_t.isClassMethod(member) && member.kind === "constructor") {
      ctorMethod = member;
      ctorMethodPath = classDecl.get("body.body." + ci);
      break;
    }
  }
  if (!ctorMethod) return [];

  var assignedParamName = _findThisAssignedParam(ctorMethodPath, propName);
  if (!assignedParamName) return [];

  var paramIdx = _findParamIndex(ctorMethod.params, assignedParamName);
  if (paramIdx === -1) return [];

  // Find new ClassName(args) callers and extract the corresponding argument
  var classBinding = fromPath.scope.getBinding(className);
  if (!classBinding) classBinding = classDecl.scope.getBinding(className);
  if (!classBinding || !classBinding.referencePaths) return [];

  var values = [];
  for (var r = 0; r < classBinding.referencePaths.length; r++) {
    var ref = classBinding.referencePaths[r];
    if (ref.parent && _t.isNewExpression(ref.parent) && ref.parent.callee === ref.node &&
        paramIdx < ref.parent.arguments.length) {
      values = values.concat(_resolveAllValues(ref.parentPath.get("arguments." + paramIdx), depth + 1));
    }
  }
  return values;
  } catch (_rcce) {
    if (_rcce instanceof RangeError) { _resolver.collectError(_rcce, "resolveCallbackChainValues"); return []; }
    throw _rcce;
  } finally { _resolver.unguard("CC", fromPath.node); }
}

// Resolve parameter values from callers of a global function (window.X = function).
// Since there's no scope binding, walk up to the program scope and find bare
// identifier calls matching the global name.
function _resolveParamFromGlobalCallers(funcPath, globalName, paramIdx, depth, propName, methodName) {
  var values = [];
  _traverseGlobalCallers(funcPath, globalName, methodName || null, function(innerPath) {
    if (paramIdx < innerPath.node.arguments.length) {
      var argPath = innerPath.get("arguments." + paramIdx);
      var argVals = propName ? _resolvePropertyFromArg(argPath, propName, depth) : _resolveAllValues(argPath, depth + 1);
      values = values.concat(argVals);
    } else {
      values = values.concat(_resolveOverloadedArg(innerPath, paramIdx, depth, propName));
    }
  });
  return values;
}


// ─── Object Property Resolution from Caller Arguments ───────────────────────
// When a function parameter is used as obj.prop (MemberExpression), resolve the
// property value by finding callers, getting their object literal arguments,
// and extracting the named property.

function _resolvePropertyFromArg(argPath, propName, depth) {
  var objNode = _resolveToObject(argPath, depth + 1);
  if (!objNode || !objNode._path) {
    if (_t.isIdentifier(argPath.node)) {
      var paramBinding = argPath.scope.getBinding(argPath.node.name);
      // Fallback 1: if arg is a param, resolve through caller arguments
      if (paramBinding && paramBinding.kind === "param") {
        return _resolveParamFromCallers(paramBinding, depth + 1, propName);
      }
      // Fallback 2: local variable — look for obj.prop = value assignments
      // Handles: var s = jQuery.ajaxSetup({}, opts); s.type = opts.method || "GET";
      if (paramBinding && paramBinding.referencePaths) {
        var assignVals = [];
        var refs = paramBinding.referencePaths;
        for (var ri = 0; ri < refs.length; ri++) {
          var refParent = refs[ri].parent;
          if (_t.isMemberExpression(refParent) && refParent.object === refs[ri].node &&
              !refParent.computed && _t.isIdentifier(refParent.property, { name: propName })) {
            var assignNode = refs[ri].parentPath ? refs[ri].parentPath.parent : null;
            if (assignNode && _t.isAssignmentExpression(assignNode) && assignNode.operator === "=" &&
                assignNode.left === refParent) {
              var rhsVals = _resolveAllValues(refs[ri].parentPath.parentPath.get("right"), depth + 1);
              assignVals = assignVals.concat(rhsVals);
            }
          }
        }
        if (assignVals.length > 0) return assignVals;
      }
      // Fallback 3: variable initialized from function call — check if property flows through args
      // Handles: var s = merge({}, options); s.url → try options.url → callers' options.url
      if (paramBinding.path.isVariableDeclarator && paramBinding.path.isVariableDeclarator()) {
        var initNode = paramBinding.path.node.init;
        if (initNode && _t.isCallExpression(initNode)) {
          var initPath = paramBinding.path.get("init");
          var initArgs = initNode.arguments;
          for (var iai = 0; iai < initArgs.length; iai++) {
            var initArgVals = _resolvePropertyFromArg(initPath.get("arguments." + iai), propName, depth + 1);
            if (initArgVals.length > 0) return initArgVals;
          }
        }
      }
    }
    return [];
  }
  for (var i = 0; i < objNode.properties.length; i++) {
    var prop = objNode.properties[i];
    if (!_t.isObjectProperty(prop) || prop.computed) continue;
    if (_getKeyName(prop.key) === propName) {
      return _resolveAllValues(objNode._path.get("properties." + i + ".value"), depth + 1);
    }
  }
  return [];
}

// ─── Data Extraction Helpers ────────────────────────────────────────────────

// Resolve a header value node to a string using parameter bindings (for closure variables)
function _resolveHeaderValue(node, bindings) {
  if (_t.isStringLiteral(node)) return node.value;
  if (_t.isIdentifier(node) && bindings[node.name] && bindings[node.name].length > 0 &&
      typeof bindings[node.name][0] === "string") return bindings[node.name][0];
  if (_t.isBinaryExpression(node) && node.operator === "+") {
    var left = _resolveHeaderValue(node.left, bindings);
    var right = _resolveHeaderValue(node.right, bindings);
    if (left !== null && right !== null) return left + right;
  }
  if (_t.isTemplateLiteral(node)) {
    var parts = [];
    for (var qi = 0; qi < node.quasis.length; qi++) {
      parts.push(node.quasis[qi].value.cooked || node.quasis[qi].value.raw);
      if (qi < node.expressions.length) {
        var exprVal = _resolveHeaderValue(node.expressions[qi], bindings);
        if (exprVal === null) return null;
        parts.push(exprVal);
      }
    }
    return parts.join("");
  }
  return null;
}

function _extractHeaders(objNode) {
  var headers = {};
  for (var i = 0; i < objNode.properties.length; i++) {
    var prop = objNode.properties[i];
    if (!_t.isObjectProperty(prop) || prop.computed) continue;
    var name = _getKeyName(prop.key);
    if (name && _t.isStringLiteral(prop.value)) {
      headers[name] = prop.value.value;
    }
  }
  return headers;
}

var _bodyParamVisited = null;
function _extractBodyParams(valNode, scopePath) {
  var isRoot = !_bodyParamVisited;
  if (isRoot) _bodyParamVisited = new Set();
  var nodeKey = (valNode.start != null && valNode.end != null) ? "B" + valNode.start + ":" + valNode.end : null;
  if (nodeKey) {
    if (_bodyParamVisited.has(nodeKey)) return [];
    _bodyParamVisited.add(nodeKey);
  }
  try { return _extractBodyParamsInner(valNode, scopePath); }
  finally { if (isRoot) _bodyParamVisited = null; }
}
function _extractBodyParamsInner(valNode, scopePath) {
  var params = [];
  // Resolve identifiers through scope (variable reference or function parameter)
  if (_t.isIdentifier(valNode) && scopePath && scopePath.scope) {
    var bpBinding = scopePath.scope.getBinding(valNode.name);
    if (bpBinding) {
      if (_t.isVariableDeclarator(bpBinding.path.node) && bpBinding.path.node.init) {
        return _extractBodyParams(bpBinding.path.node.init, bpBinding.path);
      }
      // Function parameter — resolve from callers
      if (bpBinding.kind === "param") {
        var bpFuncPath = bpBinding.scope.path;
        var bpFuncB = null;
        if (bpFuncPath.node.id) bpFuncB = bpFuncPath.scope.parent ? bpFuncPath.scope.parent.getBinding(bpFuncPath.node.id.name) : null;
        if (!bpFuncB && _t.isVariableDeclarator(bpFuncPath.parent)) bpFuncB = bpFuncPath.scope.parent ? bpFuncPath.scope.parent.getBinding(bpFuncPath.parent.id.name) : null;
        if (bpFuncB && bpFuncB.referencePaths) {
          var bpIdx = _findParamIndex(bpFuncPath.node.params, valNode.name);
          if (bpIdx >= 0) {
            for (var bri = 0; bri < bpFuncB.referencePaths.length; bri++) {
              var bRef = bpFuncB.referencePaths[bri];
              if (_t.isCallExpression(bRef.parent) && bRef.parent.callee === bRef.node &&
                  bpIdx < bRef.parent.arguments.length) {
                var bCallerArg = _extractBodyParams(bRef.parent.arguments[bpIdx], bRef.parentPath);
                if (bCallerArg.length > 0) {
                  for (var bci = 0; bci < bCallerArg.length; bci++) params.push(bCallerArg[bci]);
                }
              }
            }
            if (params.length > 0) return params;
          }
        }
      }
    }
  }
  if (_isJsonStringify(valNode, scopePath)) {
    if (valNode.arguments[0] && _t.isObjectExpression(valNode.arguments[0])) {
      params = _extractObjectProperties(valNode.arguments[0]);
      for (var i = 0; i < params.length; i++) params[i].location = "body";
    } else if (valNode.arguments[0] && _t.isIdentifier(valNode.arguments[0]) && scopePath) {
      // JSON.stringify(identifier) — resolve the identifier
      params = _extractBodyParams(valNode.arguments[0], scopePath);
    }
  } else if (_t.isNewExpression(valNode) && _t.isIdentifier(valNode.callee, { name: "URLSearchParams" }) &&
             (!scopePath || !scopePath.scope.getBinding("URLSearchParams")) &&
             valNode.arguments[0] && _t.isObjectExpression(valNode.arguments[0])) {
    params = _extractObjectProperties(valNode.arguments[0]);
    for (var j = 0; j < params.length; j++) params[j].location = "body";
  } else if (_t.isObjectExpression(valNode)) {
    params = _extractObjectProperties(valNode);
    for (var k = 0; k < params.length; k++) params[k].location = "body";
  }
  return params;
}

function _extractObjectProperties(node) {
  if (!node || !_t.isObjectExpression(node)) return [];
  var props = [];
  for (var i = 0; i < node.properties.length; i++) {
    var p = node.properties[i];
    if (_t.isSpreadElement(p)) {
      var spreadName = _t.isIdentifier(p.argument) ? p.argument.name : null;
      if (spreadName) props.push({ name: "..." + spreadName, spread: true, required: false });
      continue;
    }
    if (!_t.isObjectProperty(p) || p.computed) continue;
    var keyName = _getKeyName(p.key);
    if (!keyName) continue;

    var prop = { name: keyName, required: true };
    var val = p.value;

    if (p.shorthand && _t.isIdentifier(val)) {
      prop.source = val.name;
    } else if (_t.isIdentifier(val)) {
      prop.source = val.name;
    }

    if (_t.isLogicalExpression(val) && (val.operator === "||" || val.operator === "??")) {
      prop.required = false;
      if (_t.isStringLiteral(val.right) || _t.isNumericLiteral(val.right)) prop.defaultValue = val.right.value;
      if (_t.isIdentifier(val.left)) prop.source = val.left.name;
    }
    if (_t.isConditionalExpression(val)) {
      prop.required = false;
      var alt = val.alternate;
      if (_t.isStringLiteral(alt) || _t.isNumericLiteral(alt)) prop.defaultValue = alt.value;
    }
    if (_t.isStringLiteral(val) || _t.isNumericLiteral(val)) {
      prop.defaultValue = val.value;
      prop.type = typeof val.value;
    }
    if (_t.isBooleanLiteral(val)) {
      prop.defaultValue = val.value;
      prop.type = "boolean";
    }

    props.push(prop);
  }
  return props;
}

function _extractTemplateParams(node) {
  if (!_t.isTemplateLiteral(node)) return [];
  var params = [];
  for (var i = 0; i < node.expressions.length; i++) {
    var expr = node.expressions[i];
    if (_t.isIdentifier(expr)) params.push(expr.name);
    else if (_t.isMemberExpression(expr)) {
      var _tmplKey = _memberChainKey(expr);
      if (_tmplKey) params.push(_tmplKey);
    }
    else if (_t.isCallExpression(expr) && expr.arguments.length > 0 && _t.isIdentifier(expr.arguments[0])) {
      params.push(expr.arguments[0].name);
    }
  }
  return params;
}

function _templateToUrl(node) {
  if (!_t.isTemplateLiteral(node)) return null;
  var parts = [];
  for (var i = 0; i < node.quasis.length; i++) {
    parts.push(node.quasis[i].value.raw || node.quasis[i].value.cooked || "");
    if (i < node.expressions.length) {
      var expr = node.expressions[i];
      var name = _t.isIdentifier(expr) ? expr.name : "param" + i;
      parts.push("{" + name + "}");
    }
  }
  return parts.join("");
}

function _extractFuncParams(funcNode) {
  if (!funcNode || !funcNode.params) return null;
  var params = [];
  for (var i = 0; i < funcNode.params.length; i++) {
    var p = funcNode.params[i];
    if (_t.isIdentifier(p)) {
      params.push({ name: p.name, required: true });
    } else if (_t.isAssignmentPattern(p)) {
      var pName = _t.isIdentifier(p.left) ? p.left.name : null;
      var defVal = _t.isStringLiteral(p.right) || _t.isNumericLiteral(p.right) ? p.right.value : undefined;
      if (pName) params.push({ name: pName, required: false, defaultValue: defVal });
    } else if (_t.isObjectPattern(p)) {
      for (var j = 0; j < p.properties.length; j++) {
        var dp = p.properties[j];
        if (_t.isRestElement(dp)) {
          params.push({ name: _t.isIdentifier(dp.argument) ? dp.argument.name : "rest", required: false, rest: true });
        } else if (_t.isObjectProperty(dp)) {
          var dpName = _t.isIdentifier(dp.key) ? dp.key.name : null;
          var dpReq = true, dpDef;
          if (_t.isAssignmentPattern(dp.value)) {
            dpReq = false;
            dpDef = (_t.isStringLiteral(dp.value.right) || _t.isNumericLiteral(dp.value.right)) ? dp.value.right.value : undefined;
          }
          if (dpName) params.push({ name: dpName, required: dpReq, defaultValue: dpDef });
        }
      }
    } else if (_t.isRestElement(p)) {
      params.push({ name: _t.isIdentifier(p.argument) ? p.argument.name : "rest", required: false, rest: true });
    }
  }
  var name = funcNode.id && _t.isIdentifier(funcNode.id) ? funcNode.id.name : null;
  return { name: name, params: params };
}

function _detectResponseParsing(funcPath) {
  var found = null;
  try {
    funcPath.traverse(Object.assign({
      CallExpression: function(innerPath) {
        if (found) { innerPath.stop(); return; }
        var c = innerPath.node.callee;
        if (!_t.isMemberExpression(c)) return;
        var mName = _t.isIdentifier(c.property) ? c.property.name : null;
        if (mName === "json") found = "json";
        else if (mName === "arrayBuffer" && !found) found = "arrayBuffer";
        else if (mName === "blob" && !found) found = "blob";
      },
    }, _SKIP_NESTED_FUNCS));
  } catch (e) { _resolver.collectError(e, "detectResponseParsing"); }
  return found;
}

// ─── Value Constraint Collection ────────────────────────────────────────────

// Identify which function parameter an expression traces to.
// Returns { funcPath, paramIdx, propName, defaultValue } or null.
// Handles: identifier params, member expressions (param.prop), LogicalExpression defaults (param.prop || "default")
function _identifyParamSource(node, path) {
  // Unwrap LogicalExpression: n.method || "get" → n.method with default "get"
  var defaultValue = null;
  var inner = node;
  if (_t.isLogicalExpression(node) && node.operator === "||") {
    if (_t.isStringLiteral(node.right)) { defaultValue = node.right.value; inner = node.left; }
    else if (_t.isStringLiteral(node.left)) { defaultValue = node.left.value; inner = node.right; }
  }
  // MemberExpression: param.prop
  if (_t.isMemberExpression(inner) && !inner.computed && _t.isIdentifier(inner.object)) {
    var binding = path.scope.getBinding(inner.object.name);
    if (binding && binding.kind === "param") {
      var funcPath = binding.scope.path;
      var pIdx = _findParamIndex(funcPath.node.params, inner.object.name);
      if (pIdx >= 0) {
        var propName = _t.isIdentifier(inner.property) ? inner.property.name : null;
        return { funcPath: funcPath, paramIdx: pIdx, propName: propName, defaultValue: defaultValue };
      }
    }
  }
  // Plain identifier: param
  if (_t.isIdentifier(inner)) {
    var binding2 = path.scope.getBinding(inner.name);
    if (binding2 && binding2.kind === "param") {
      var funcPath2 = binding2.scope.path;
      var pIdx2 = -1;
      for (var j = 0; j < funcPath2.node.params.length; j++) {
        var p2 = funcPath2.node.params[j];
        if (_t.isIdentifier(p2) && p2.name === inner.name) { pIdx2 = j; break; }
      }
      if (pIdx2 >= 0) return { funcPath: funcPath2, paramIdx: pIdx2, propName: null, defaultValue: defaultValue };
    }
  }
  return null;
}

// Find all caller argument arrays for a function.
// Returns array of arrays of paths: [[arg0Path, arg1Path, ...], ...]
function _findFunctionCallerArgs(funcPath) {
  var results = [];
  var funcBinding = null;
  if (funcPath.node.id) {
    funcBinding = funcPath.scope.parent ? funcPath.scope.parent.getBinding(funcPath.node.id.name) : null;
    if (!funcBinding) funcBinding = funcPath.scope.getBinding(funcPath.node.id.name);
  }
  if (!funcBinding && _t.isVariableDeclarator(funcPath.parent))
    funcBinding = funcPath.scope.parent ? funcPath.scope.parent.getBinding(funcPath.parent.id.name) : null;
  // Handle assignment chains: const X = Y = function(){} — walk up AssignmentExpressions to VariableDeclarator
  if (!funcBinding && _t.isAssignmentExpression(funcPath.parent)) {
    var _chain = funcPath.parentPath;
    while (_chain && _t.isAssignmentExpression(_chain.node)) _chain = _chain.parentPath;
    if (_chain && _t.isVariableDeclarator(_chain.node) && _t.isIdentifier(_chain.node.id)) {
      funcBinding = _chain.scope.getBinding(_chain.node.id.name);
    }
    // Also try the direct assignment target: Y = function(){} → get binding for Y
    if (!funcBinding && _t.isIdentifier(funcPath.parent.left)) {
      funcBinding = funcPath.parentPath.scope.getBinding(funcPath.parent.left.name);
    }
    // Prototype method: Ctor.prototype.method = function(params) { ... }
    // Find callers: instance.method(args) where instance = new Ctor()
    if (!funcBinding && _t.isMemberExpression(funcPath.parent.left)) {
      var protoLeft = funcPath.parent.left;
      // Match X.prototype.Y or X.prototype["Y"]
      if (_t.isMemberExpression(protoLeft.object) && !protoLeft.object.computed &&
          _t.isIdentifier(protoLeft.object.property, { name: "prototype" }) &&
          _t.isIdentifier(protoLeft.object.object)) {
        var protoCtorName2 = protoLeft.object.object.name;
        var protoMethodName = _t.isIdentifier(protoLeft.property) ? protoLeft.property.name :
          (_t.isStringLiteral(protoLeft.property) ? protoLeft.property.value : null);
        if (protoCtorName2 && protoMethodName) {
          var protoResults = _findPrototypeMethodCallerArgs(funcPath, protoCtorName2, protoMethodName);
          if (protoResults.length > 0) return protoResults;
        }
      }
    }
  }
  if (funcBinding && funcBinding.referencePaths) {
    for (var i = 0; i < funcBinding.referencePaths.length; i++) {
      var ref = funcBinding.referencePaths[i];
      if (_t.isCallExpression(ref.parent) && ref.parent.callee === ref.node) {
        var argPaths = [];
        for (var j = 0; j < ref.parent.arguments.length; j++) argPaths.push(ref.parentPath.get("arguments." + j));
        results.push(argPaths);
      }
    }
    return results;
  }
  // Function passed as argument: makeHandler(function(data) { sink(data); })
  // If our function is an argument to a call, find the corresponding parameter in the
  // called function, then find all call sites of that parameter within the function body.
  if (!funcBinding && funcPath.parentPath && _t.isCallExpression(funcPath.parent) &&
      funcPath.parent.callee !== funcPath.node) {
    var _fpaCallNode = funcPath.parent;
    var _fpaArgIdx = -1;
    for (var _fpai = 0; _fpai < _fpaCallNode.arguments.length; _fpai++) {
      if (_fpaCallNode.arguments[_fpai] === funcPath.node) { _fpaArgIdx = _fpai; break; }
    }
    if (_fpaArgIdx >= 0) {
      // Resolve the called function
      var _fpaCallee = _fpaCallNode.callee;
      var _fpaCalleeFn = null;
      var _fpaCalleePath = null;
      if (_t.isIdentifier(_fpaCallee)) {
        var _fpaBind = funcPath.scope.getBinding(_fpaCallee.name);
        if (_fpaBind) {
          if (_t.isFunctionDeclaration(_fpaBind.path.node)) { _fpaCalleeFn = _fpaBind.path.node; _fpaCalleePath = _fpaBind.path; }
          else if (_fpaBind.path.isVariableDeclarator() && _fpaBind.path.node.init && _t.isFunction(_fpaBind.path.node.init)) {
            _fpaCalleeFn = _fpaBind.path.node.init; _fpaCalleePath = _fpaBind.path.get("init");
          }
        }
      } else if (_t.isFunctionExpression(_fpaCallee) || _t.isArrowFunctionExpression(_fpaCallee)) {
        _fpaCalleeFn = _fpaCallee; _fpaCalleePath = funcPath.parentPath.get("callee");
      }
      if (_fpaCalleeFn && _fpaCalleeFn.params && _fpaArgIdx < _fpaCalleeFn.params.length &&
          _t.isIdentifier(_fpaCalleeFn.params[_fpaArgIdx]) && _fpaCalleePath) {
        var _fpaParamName = _fpaCalleeFn.params[_fpaArgIdx].name;
        // Find all call sites of this parameter within the enclosing function body
        try {
          _fpaCalleePath.traverse({
            CallExpression: function(callP) {
              if (_t.isIdentifier(callP.node.callee, { name: _fpaParamName }) &&
                  callP.scope.getBinding(_fpaParamName) &&
                  callP.scope.getBinding(_fpaParamName).scope === _fpaCalleePath.scope) {
                var _fpaArgPaths = [];
                for (var _fpaj = 0; _fpaj < callP.node.arguments.length; _fpaj++) _fpaArgPaths.push(callP.get("arguments." + _fpaj));
                results.push(_fpaArgPaths);
              }
            }
          });
        } catch (e) { _resolver.collectError(e, "funcParamCallSites"); }
        if (results.length > 0) return results;
      }
    }
  }

  // IIFE return / UMD: function returned from enclosing function
  if (_t.isReturnStatement(funcPath.parent)) {
    var encFunc = funcPath.findParent(function(p) { return p.isFunction() && p !== funcPath; });
    if (encFunc) {
      var encParent = encFunc.parentPath;
      // UMD: encFunc is arg to outer IIFE
      if (encParent && _t.isCallExpression(encParent.node) && encParent.node.callee !== encFunc.node) {
        var outerCallee = encParent.node.callee;
        if (_t.isUnaryExpression(outerCallee)) outerCallee = outerCallee.argument;
        var argIdx = -1;
        for (var ai = 0; ai < encParent.node.arguments.length; ai++) {
          if (encParent.node.arguments[ai] === encFunc.node) { argIdx = ai; break; }
        }
        if (argIdx >= 0 && (_t.isFunctionExpression(outerCallee) || _t.isArrowFunctionExpression(outerCallee)) &&
            argIdx < outerCallee.params.length) {
          var factoryName = _t.isIdentifier(outerCallee.params[argIdx]) ? outerCallee.params[argIdx].name : null;
          if (factoryName) {
            // Find global that calls the factory: (win).X = factory()
            for (var gn in _globalAssignments) {
              var ga = _globalAssignments[gn];
              if (ga.valueNode && _t.isCallExpression(ga.valueNode) &&
                  _t.isIdentifier(ga.valueNode.callee) && ga.valueNode.callee.name === factoryName) {
                // Find all global callers: X(url, opts)
                return _collectGlobalCallerArgArrays(funcPath, gn);
              }
            }
          }
        }
      }
    }
  }
  return results;
}

// Find callers of prototype methods: instance.method(args) where instance = new Ctor()
function _findPrototypeMethodCallerArgs(funcPath, ctorName, methodName) {
  var results = [];
  // Cache: ctorName instances found via full-program traversal
  var instCacheKey = "inst:" + ctorName;
  var instanceEntries = _globalCallerCache[instCacheKey];
  if (!instanceEntries) {
    instanceEntries = [];
    var programPath = funcPath.findParent(function(p) { return p.isProgram(); });
    if (!programPath) return results;
    try {
      programPath.traverse({
        VariableDeclarator: function(decPath) {
          var init = decPath.node.init;
          if (!init || !_t.isNewExpression(init) || !_t.isIdentifier(init.callee, { name: ctorName })) return;
          var ib = decPath.scope.getBinding(decPath.node.id.name);
          if (ib) instanceEntries.push(ib);
        },
      });
    } catch(e) { _resolver.collectError(e, "protoInstanceCache"); }
    _globalCallerCache[instCacheKey] = instanceEntries;
  }
  for (var _iei = 0; _iei < instanceEntries.length; _iei++) {
    var instanceBinding = instanceEntries[_iei];
    if (!instanceBinding.referencePaths) continue;
    for (var ri = 0; ri < instanceBinding.referencePaths.length; ri++) {
      var ref = instanceBinding.referencePaths[ri];
      if (_t.isMemberExpression(ref.parent) && !ref.parent.computed &&
          ref.parent.object === ref.node &&
          _t.isIdentifier(ref.parent.property, { name: methodName }) &&
          _t.isCallExpression(ref.parentPath.parent) &&
          ref.parentPath.parent.callee === ref.parent) {
        var callNode = ref.parentPath.parent;
        var callPath2 = ref.parentPath.parentPath;
        var argPaths = [];
        for (var ai = 0; ai < callNode.arguments.length; ai++) argPaths.push(callPath2.get("arguments." + ai));
        results.push(argPaths);
      }
    }
  }
  return results;
}

// Collect caller argument arrays for global function calls
function _collectGlobalCallerArgArrays(funcPath, globalName) {
  var results = [];
  _traverseGlobalCallers(funcPath, globalName, null, function(callPath) {
    var argPaths = [];
    for (var j = 0; j < callPath.node.arguments.length; j++) argPaths.push(callPath.get("arguments." + j));
    results.push(argPaths);
  });
  return results;
}

// Structural member chain key: walks MemberExpression chain to produce a
// deterministic key like "options.type". Returns null for computed or complex expressions.
function _memberChainKey(node) {
  if (_t.isIdentifier(node)) return node.name;
  if (_t.isMemberExpression(node) && !node.computed) {
    var obj = _memberChainKey(node.object);
    if (!obj) return null;
    var prop = _t.isIdentifier(node.property) ? node.property.name :
      (_t.isStringLiteral(node.property) ? node.property.value : null);
    return prop ? obj + "." + prop : null;
  }
  return null;
}

function _addConstraint(path, varName, values, source) {
  if (!varName || !values || values.length === 0) return;
  var meaningful = values.filter(function(v) {
    if (v === true || v === false || v === null || v === undefined) return false;
    if (typeof v === "string" && v.length === 0) return false;
    return true;
  });
  if (meaningful.length === 0) return;

  var scopeUid = path.scope.uid;
  var key = scopeUid + ":" + varName;
  if (!_constraints[key]) _constraints[key] = { varName: varName, values: new Set(), sources: [] };
  for (var i = 0; i < meaningful.length; i++) _constraints[key].values.add(meaningful[i]);
  _constraints[key].sources.push(source);
}

function _getConstraint(path, varName) {
  var scope = path.scope;
  while (scope) {
    var key = scope.uid + ":" + varName;
    if (_constraints[key]) return _constraints[key];
    scope = scope.parent;
  }
  return null;
}

function _collectSwitchConstraints(path) {
  var disc = path.node.discriminant;
  var varName = _t.isIdentifier(disc) ? disc.name :
    (_t.isMemberExpression(disc) ? _memberChainKey(disc) : null);
  if (!varName) return;

  var values = [];
  var cases = path.node.cases;
  for (var i = 0; i < cases.length; i++) {
    var test = cases[i].test;
    if (!test) continue;
    if (_t.isStringLiteral(test) || _t.isNumericLiteral(test)) values.push(test.value);
  }
  if (values.length >= 1) {
    _addConstraint(path, varName, values, "switch");
  }
}

function _collectIncludesConstraints(path) {
  var node = path.node;
  if (!_t.isMemberExpression(node.callee)) return;
  if (!_t.isIdentifier(node.callee.property, { name: "includes" })) return;
  if (node.arguments.length < 1) return;

  var testedArg = node.arguments[0];
  var testedVar = _t.isIdentifier(testedArg) ? testedArg.name :
    (_t.isMemberExpression(testedArg) ? _memberChainKey(testedArg) : null);
  if (!testedVar) return;

  var obj = node.callee.object;

  // Inline array: ["json", "xml"].includes(format)
  if (_t.isArrayExpression(obj)) {
    var values = _extractLiteralArray(obj);
    if (values.length >= 1) _addConstraint(path, testedVar, values, "includes_inline");
    return;
  }

  // Named array: FORMATS.includes(type) — resolve through scope
  if (_t.isIdentifier(obj)) {
    var binding = path.scope.getBinding(obj.name);
    if (binding && binding.path.node.init && _t.isArrayExpression(binding.path.node.init)) {
      var arrValues = _extractLiteralArray(binding.path.node.init);
      if (arrValues.length >= 1) _addConstraint(path, testedVar, arrValues, "includes_ref");
    }
  }
}

function _collectEqualityConstraints(path) {
  var node = path.node;
  if (node.operator !== "||" && node.operator !== "&&") return;

  var comparisons = [];
  _flattenLogicalChain(node, comparisons);

  var byVar = {};
  for (var i = 0; i < comparisons.length; i++) {
    var c = comparisons[i];
    if (!byVar[c.varName]) byVar[c.varName] = [];
    byVar[c.varName].push(c.value);
  }

  for (var varName in byVar) {
    if (byVar[varName].length >= 1) {
      _addConstraint(path, varName, byVar[varName], "equality_chain");
    }
  }
}

// Detect iteration constraints: arr.forEach(fn), X.each(arr, fn), arr.map(fn)
// The callback parameter is constrained to the array's element values.
function _collectIterationConstraints(path) {
  var node = path.node;
  if (!_t.isMemberExpression(node.callee)) return;
  var methodName = _t.isIdentifier(node.callee.property) ? node.callee.property.name : null;
  if (!methodName) return;

  var arrNode = null, callbackNode = null;

  // Pattern: arr.forEach(fn) / arr.map(fn)
  if ((methodName === "forEach" || methodName === "map") && node.arguments.length >= 1) {
    // V4: skip if callee object is a known non-iterable type
    var _icObjType = _getTrackedType(path.get("callee.object"), node.callee.object);
    if (_icObjType && _NON_ITERABLE_TYPES[_icObjType]) return;
    var arrPath = path.get("callee.object");
    arrNode = _resolveToArray(arrPath, 0);
    callbackNode = node.arguments[0];
  }
  // Pattern: X.each(arr, fn) — jQuery.each / $.each
  else if (methodName === "each" && node.arguments.length >= 2) {
    var eachArrArg = node.arguments[0];
    if (_t.isArrayExpression(eachArrArg)) {
      arrNode = eachArrArg;
      arrNode._path = path.get("arguments.0");
    } else if (_t.isIdentifier(eachArrArg)) {
      arrNode = _resolveToArray(path.get("arguments.0"), 0);
    }
    callbackNode = node.arguments[1];
  }

  if (!arrNode || !callbackNode) return;
  if (!_t.isFunctionExpression(callbackNode) && !_t.isArrowFunctionExpression(callbackNode)) return;

  // Extract array element values
  var elemValues = [];
  for (var ei = 0; ei < arrNode.elements.length; ei++) {
    var elem = arrNode.elements[ei];
    if (_t.isStringLiteral(elem) || _t.isNumericLiteral(elem)) elemValues.push(elem.value);
  }
  if (elemValues.length < 1) return;

  // Determine which callback parameter receives the element value
  // forEach/map: fn(element, index) — param 0 is element
  // X.each: fn(index, element) — param 1 is element
  var elemParamIdx = (methodName === "each") ? 1 : 0;
  if (callbackNode.params.length <= elemParamIdx) return;
  var elemParam = callbackNode.params[elemParamIdx];
  var elemParamName = _t.isIdentifier(elemParam) ? elemParam.name : null;
  if (elemParamName) {
    _addConstraint(path, elemParamName, elemValues, "iteration");
  }
}

// Detect constraints from object literal structure:
// 1. Array properties: {statusCodes: [408,413,429,...], methods: ["get","put",...]} → emit array values
// 2. String-valued objects: {json: "application/json", text: "text/*"} → emit string values
function _collectObjectLiteralConstraints(path) {
  var node = path.node;
  if (!node.properties || node.properties.length < 1) return;

  var stringVals = [];
  for (var i = 0; i < node.properties.length; i++) {
    var prop = node.properties[i];
    if (!_t.isObjectProperty(prop) && !(_t.isProperty && _t.isProperty(prop))) continue;
    var keyName = _t.isIdentifier(prop.key) ? prop.key.name :
      (_t.isStringLiteral(prop.key) ? prop.key.value : null);
    if (!keyName) continue;
    var val = prop.value;

    // Array property: {methods: ["get","put",...], statusCodes: [408,...]}
    if (_t.isArrayExpression(val)) {
      var arrVals = _extractLiteralArray(val);
      if (arrVals.length >= 1) {
        _addConstraint(path, keyName, arrVals, "object_array_prop");
      }
    }

    // Collect string values for the object-values constraint
    if (_t.isStringLiteral(val)) stringVals.push(val.value);
  }

  // Object with 3+ string literal values: {json:"application/json", text:"text/*",...}
  if (stringVals.length >= 1) {
    // Use the variable name if available, else a generic key
    var objVarName = null;
    if (path.parent && _t.isVariableDeclarator(path.parent) && _t.isIdentifier(path.parent.id)) {
      objVarName = path.parent.id.name;
    } else if (path.parent && _t.isAssignmentExpression(path.parent) && _t.isIdentifier(path.parent.left)) {
      objVarName = path.parent.left.name;
    }
    if (objVarName) {
      _addConstraint(path, objVarName, stringVals, "object_string_values");
    }
  }
}

function _flattenLogicalChain(node, out) {
  // Iterative: walk LogicalExpression chains via explicit stack
  var stack = [node];
  while (stack.length > 0) {
    var n = stack.pop();
    if (_t.isLogicalExpression(n)) {
      stack.push(n.left, n.right);
      continue;
    }
    if (_t.isBinaryExpression(n) &&
        (n.operator === "===" || n.operator === "==" || n.operator === "!==" || n.operator === "!=")) {
      var varName = null, value = null;
      if (_t.isIdentifier(n.left) && (_t.isStringLiteral(n.right) || _t.isNumericLiteral(n.right))) {
        varName = n.left.name; value = n.right.value;
      } else if (_t.isIdentifier(n.right) && (_t.isStringLiteral(n.left) || _t.isNumericLiteral(n.left))) {
        varName = n.right.name; value = n.left.value;
      } else if (_t.isMemberExpression(n.left) && (_t.isStringLiteral(n.right) || _t.isNumericLiteral(n.right))) {
        varName = _memberChainKey(n.left); value = n.right.value;
      } else if (_t.isMemberExpression(n.right) && (_t.isStringLiteral(n.left) || _t.isNumericLiteral(n.left))) {
        varName = _memberChainKey(n.right); value = n.left.value;
      }
      if (varName !== null && value !== null) out.push({ varName: varName, value: value });
    }
  }
}

// ─── Security Analysis: Code Context Extraction ─────────────────────────────

// Extract a line range from the source code by line numbers (1-based).
// Returns trimmed lines joined by newline, each capped at 120 chars.
function _extractLines(fromLine, toLine, column) {
  if (!_sourceCode || !fromLine || !toLine) return null;
  if (!_sourceLines) {
    _sourceLines = _sourceCode.split("\n");
  }
  var start = Math.max(0, fromLine - 1);
  var end = Math.min(_sourceLines.length, toLine);
  var out = [];
  for (var i = start; i < end; i++) {
    var line = _sourceLines[i].trim();
    if (line.length > 120) {
      // For very long lines (minified code), extract around the column of interest
      // Bias toward showing more code after the sink (the relevant part)
      if (column != null && column > 20) {
        var from = Math.max(0, column - 20);
        var to = Math.min(line.length, column + 100);
        line = (from > 0 ? "\u2026" : "") + line.substring(from, to) + (to < line.length ? "\u2026" : "");
      } else {
        line = line.substring(0, 120) + "\u2026";
      }
    }
    if (line) out.push(line);
  }
  return out.length > 0 ? out.join("\n") : null;
}

// Build source-to-sink code context.
// sinkNode: the AST node of the dangerous sink (always present)
// valueSource: the taint trace result { sourceType, source, sourceLoc? }
// Returns a multi-line string showing the data flow.
function _extractCodeContext(sinkNode, valueSource) {
  if (!_sourceCode || !sinkNode || !sinkNode.loc) return null;
  var sinkLine = sinkNode.loc.start.line;
  var sinkCol = sinkNode.loc.start.column;

  // If we have a source location on a different line, show source→sink range
  if (valueSource && valueSource.sourceLoc && valueSource.sourceLoc.line !== sinkLine) {
    var srcLine = valueSource.sourceLoc.line;
    var srcCol = valueSource.sourceLoc.column;
    var fromLine = Math.min(srcLine, sinkLine);
    var toLine = Math.max(srcLine, sinkLine);
    // Cap at 10 lines — if the flow spans more, show source + sink with gap
    if (toLine - fromLine + 1 <= 10) {
      return _extractLines(fromLine, toLine, sinkCol);
    }
    // Too far apart — show source line, ellipsis, sink line
    var srcText = _extractLines(srcLine, srcLine, srcCol);
    var sinkText = _extractLines(sinkLine, sinkLine, sinkCol);
    if (srcText && sinkText) return srcText + "\n  \u2026\n" + sinkText;
    return sinkText;
  }

  // No source location or same line — show the sink line only
  return _extractLines(sinkLine, sinkLine, sinkCol);
}

var _sourceLines = null; // lazily split from _sourceCode

// ─── Security Analysis: Taint Source Tracking ───────────────────────────────

// Structural taint source patterns — matched via AST nodes, not strings.
// Each pattern: { obj: base object name, props: { propName: 1, ... } }
// Roots: these object names must be unbound globals (verified via scope).
// "window" and "self" prefixes are normalized (stripped) before matching.
var _TAINT_PATTERNS = [
  { obj: "location", props: { "hash":1, "search":1, "href":1, "pathname":1, "hostname":1, "origin":1, "protocol":1 } },
  { obj: "document", props: { "referrer":1, "URL":1, "documentURI":1, "baseURI":1, "URLUnencoded":1, "cookie":1, "domain":1, "title":1 } },
  { obj: "window", props: { "name":1, "location":1 } },
  { obj: "history", props: { "state":1 } },
  { obj: "event", props: { "data":1 } },
];

// Scope-aware taint source classification using structural AST matching.
// Replaces _describeNode() + _TAINT_SOURCES string lookup.
// Returns taint source string (e.g., "location.hash") if matched, or null.
function _matchTaintSource(path, node) {
  if (!_t.isMemberExpression(node) || node.computed) return null;

  // Collect the member chain as AST property names: [root, prop1, prop2, ...]
  var chain = [];
  var current = node;
  while (_t.isMemberExpression(current) && !current.computed && _t.isIdentifier(current.property)) {
    chain.unshift(current.property.name);
    current = current.object;
  }
  if (!_t.isIdentifier(current)) return null;
  var rootName = current.name;

  // Verify root identifier is unbound (not shadowed by local binding)
  if (path.scope.getBinding(rootName)) return null;

  // Normalize: strip "window." or "self." prefix if root is the global window/self
  var objName, propName;
  if ((rootName === "window" || rootName === "self") && chain.length >= 2) {
    objName = chain[0];
    propName = chain[1];
  } else if (chain.length >= 1) {
    objName = rootName;
    propName = chain[0];
  } else {
    return null;
  }

  // Match against patterns
  for (var pi = 0; pi < _TAINT_PATTERNS.length; pi++) {
    var pat = _TAINT_PATTERNS[pi];
    if (pat.obj === objName && pat.props[propName]) {
      return objName + "." + propName;
    }
  }
  return null;
}

// Lightweight taint tracker: classifies where a value originates.
// Returns { sourceType: "user-controlled"|"dynamic"|"literal", source: string|null, sourceLoc?: { line, column } }
// sourceLoc records where the user-controlled source was found (for source-to-sink context).
// Uses a visited-node set instead of depth limits to prevent infinite recursion while
// allowing unlimited tracing depth through variable chains, function params, and object properties.
var _taintVisited = null;
function _traceValueSource(path, _unused) {
  if (!path || !path.node) return { sourceType: "dynamic", source: null };
  var node = path.node;

  // Cycle detection via visited set keyed on AST node position
  var isRoot = !_taintVisited;
  if (isRoot) _taintVisited = new Set();
  var nodeKey = (node.start != null && node.end != null) ? node.start + ":" + node.end : null;
  if (nodeKey) {
    if (_taintVisited.has(nodeKey)) return { sourceType: "dynamic", source: null };
    _taintVisited.add(nodeKey);
  }
  try { return _traceValueSourceInner(path, node); }
  catch (_tvse) {
    if (_tvse instanceof RangeError) { _resolver.collectError(_tvse, "traceValueSource"); return { sourceType: "dynamic", source: null }; }
    throw _tvse;
  }
  finally { if (isRoot) _taintVisited = null; }
}

// Recursively walk a block statement to find all ReturnStatement nodes,
// including those inside if/else, switch/case, try/catch, for/while, etc.
// Returns the first user-controlled return source found, or null.
function _traceReturnsInBlock(blockPath) {
  if (!blockPath || !blockPath.node) return null;
  var stmts = blockPath.node.body;
  if (!stmts) return null;
  for (var _rbi = 0; _rbi < stmts.length; _rbi++) {
    var stmt = stmts[_rbi];
    var stmtPath = blockPath.get("body." + _rbi);
    if (_t.isReturnStatement(stmt) && stmt.argument) {
      var _rs = _traceValueSource(stmtPath.get("argument"));
      if (_rs.sourceType === "user-controlled") return _rs;
    } else if (_t.isIfStatement(stmt)) {
      if (stmt.consequent && _t.isBlockStatement(stmt.consequent)) {
        var _ifR = _traceReturnsInBlock(stmtPath.get("consequent"));
        if (_ifR && _ifR.sourceType === "user-controlled") return _ifR;
      }
      if (stmt.alternate) {
        if (_t.isBlockStatement(stmt.alternate)) {
          var _elR = _traceReturnsInBlock(stmtPath.get("alternate"));
          if (_elR && _elR.sourceType === "user-controlled") return _elR;
        } else if (_t.isIfStatement(stmt.alternate)) {
          // else if — recurse on the IfStatement's branches via a wrapper
          var _eiR = _traceReturnsInIfChain(stmtPath.get("alternate"));
          if (_eiR && _eiR.sourceType === "user-controlled") return _eiR;
        }
      }
    } else if (_t.isSwitchStatement(stmt)) {
      for (var _sci = 0; _sci < stmt.cases.length; _sci++) {
        var _case = stmt.cases[_sci];
        for (var _csj = 0; _csj < _case.consequent.length; _csj++) {
          var _csStmt = _case.consequent[_csj];
          if (_t.isReturnStatement(_csStmt) && _csStmt.argument) {
            var _csR = _traceValueSource(stmtPath.get("cases." + _sci + ".consequent." + _csj + ".argument"));
            if (_csR && _csR.sourceType === "user-controlled") return _csR;
          } else if (_t.isBlockStatement(_csStmt)) {
            var _csBR = _traceReturnsInBlock(stmtPath.get("cases." + _sci + ".consequent." + _csj));
            if (_csBR && _csBR.sourceType === "user-controlled") return _csBR;
          }
        }
      }
    } else if (_t.isTryStatement(stmt)) {
      if (stmt.block) {
        var _tryR = _traceReturnsInBlock(stmtPath.get("block"));
        if (_tryR && _tryR.sourceType === "user-controlled") return _tryR;
      }
      if (stmt.handler && stmt.handler.body) {
        var _catchR = _traceReturnsInBlock(stmtPath.get("handler.body"));
        if (_catchR && _catchR.sourceType === "user-controlled") return _catchR;
      }
    } else if (_t.isBlockStatement(stmt)) {
      var _blkR = _traceReturnsInBlock(stmtPath);
      if (_blkR && _blkR.sourceType === "user-controlled") return _blkR;
    } else if (stmt.body && _t.isBlockStatement(stmt.body)) {
      // for, while, do-while, etc.
      var _loopR = _traceReturnsInBlock(stmtPath.get("body"));
      if (_loopR && _loopR.sourceType === "user-controlled") return _loopR;
    }
  }
  return null;
}
function _traceReturnsInIfChain(ifPath) {
  // Iterative: walk else-if chains without recursion
  var cur = ifPath;
  while (cur && cur.node && _t.isIfStatement(cur.node)) {
    var stmt = cur.node;
    if (stmt.consequent && _t.isBlockStatement(stmt.consequent)) {
      var _r = _traceReturnsInBlock(cur.get("consequent"));
      if (_r && _r.sourceType === "user-controlled") return _r;
    }
    if (!stmt.alternate) break;
    if (_t.isBlockStatement(stmt.alternate)) {
      var _r2 = _traceReturnsInBlock(cur.get("alternate"));
      if (_r2 && _r2.sourceType === "user-controlled") return _r2;
      break;
    }
    if (_t.isIfStatement(stmt.alternate)) {
      cur = cur.get("alternate");
      continue;
    }
    break;
  }
  return null;
}

function _traceValueSourceInner(path, node) {
  var nodeLoc = node.loc ? { line: node.loc.start.line, column: node.loc.start.column } : null;

  // Literals are safe
  if (_t.isStringLiteral(node) || _t.isNumericLiteral(node) || _t.isBooleanLiteral(node) ||
      _t.isNullLiteral(node) || _t.isTemplateLiteral(node) && node.expressions.length === 0) {
    return { sourceType: "literal", source: null };
  }

  // MemberExpression: check against known user-controlled sources using structural AST matching
  if (_t.isMemberExpression(node) && !node.computed) {
    var taintMatch = _matchTaintSource(path, node);
    if (taintMatch) {
      return { sourceType: "user-controlled", source: taintMatch, sourceLoc: nodeLoc };
    }
    // Bare location object access (computed or any property) — still user-controlled
    if (_t.isIdentifier(node.object, { name: "location" }) && !path.scope.getBinding("location")) {
      return { sourceType: "user-controlled", source: "location." + (_t.isIdentifier(node.property) ? node.property.name : "*"), sourceLoc: nodeLoc };
    }
  }

  // Object property access: cfg.redirectUrl → resolve to the property value in the initializer
  if (_t.isMemberExpression(node) && !node.computed && _t.isIdentifier(node.object)) {
    var objPropName = _t.isIdentifier(node.property) ? node.property.name : null;
    if (objPropName) {
      var objBinding = path.scope.getBinding(node.object.name);
      if (objBinding && objBinding.path.isVariableDeclarator() && objBinding.path.node.init) {
        var _objInit = objBinding.path.node.init;
        // Direct ObjectExpression initializer: cfg.redirectUrl → resolve property value
        if (_t.isObjectExpression(_objInit)) {
          var objProps = _objInit.properties;
          for (var oi = 0; oi < objProps.length; oi++) {
            if (_t.isObjectProperty(objProps[oi]) &&
                ((_t.isIdentifier(objProps[oi].key) && objProps[oi].key.name === objPropName) ||
                 (_t.isStringLiteral(objProps[oi].key) && objProps[oi].key.value === objPropName))) {
              var propValSource = _traceValueSource(objBinding.path.get("init.properties." + oi + ".value"));
              if (propValSource.sourceType === "user-controlled") return propValSource;
            }
          }
        }
        // Object.assign({}, source1, source2) — resolve property from source objects.
        // var merged = Object.assign({}, config); merged.html → config.html
        if (_t.isCallExpression(_objInit) && _t.isMemberExpression(_objInit.callee) &&
            !_objInit.callee.computed && _t.isIdentifier(_objInit.callee.property, { name: "assign" }) &&
            _t.isIdentifier(_objInit.callee.object, { name: "Object" }) &&
            !path.scope.getBinding("Object") && _objInit.arguments.length >= 2) {
          // Search source args (skip target = arg 0) for the property
          for (var _oaPI = 1; _oaPI < _objInit.arguments.length; _oaPI++) {
            var _oaSrcArg = _objInit.arguments[_oaPI];
            // If source is an identifier, resolve to its init
            if (_t.isIdentifier(_oaSrcArg)) {
              var _oaSrcBind = path.scope.getBinding(_oaSrcArg.name);
              if (_oaSrcBind && _oaSrcBind.path.isVariableDeclarator() && _oaSrcBind.path.node.init &&
                  _t.isObjectExpression(_oaSrcBind.path.node.init)) {
                var _oaSrcProps = _oaSrcBind.path.node.init.properties;
                for (var _oaSPI = 0; _oaSPI < _oaSrcProps.length; _oaSPI++) {
                  if (_t.isObjectProperty(_oaSrcProps[_oaSPI]) &&
                      ((_t.isIdentifier(_oaSrcProps[_oaSPI].key) && _oaSrcProps[_oaSPI].key.name === objPropName) ||
                       (_t.isStringLiteral(_oaSrcProps[_oaSPI].key) && _oaSrcProps[_oaSPI].key.value === objPropName))) {
                    var _oaPropSrc = _traceValueSource(_oaSrcBind.path.get("init.properties." + _oaSPI + ".value"));
                    if (_oaPropSrc.sourceType === "user-controlled") return _oaPropSrc;
                  }
                }
              }
            }
            // If source arg is an inline ObjectExpression
            if (_t.isObjectExpression(_oaSrcArg)) {
              for (var _oaInlI = 0; _oaInlI < _oaSrcArg.properties.length; _oaInlI++) {
                if (_t.isObjectProperty(_oaSrcArg.properties[_oaInlI]) &&
                    ((_t.isIdentifier(_oaSrcArg.properties[_oaInlI].key) && _oaSrcArg.properties[_oaInlI].key.name === objPropName) ||
                     (_t.isStringLiteral(_oaSrcArg.properties[_oaInlI].key) && _oaSrcArg.properties[_oaInlI].key.value === objPropName))) {
                  var _oaInlSrc = _traceValueSource(objBinding.path.get("init.arguments." + _oaPI + ".properties." + _oaInlI + ".value"));
                  if (_oaInlSrc.sourceType === "user-controlled") return _oaInlSrc;
                }
              }
            }
          }
        }
      }
    }
  }

  // Non-computed MemberExpression: trace through deep property chains.
  // Handles patterns like doc.body.innerHTML where doc comes from a tainted source
  // (e.g., DOMParser().parseFromString(tainted)). Taint propagates through property access.
  if (_t.isMemberExpression(node) && !node.computed) {
    var _deepObjSource = _traceValueSource(path.get("object"));
    if (_deepObjSource.sourceType === "user-controlled") return _deepObjSource;
  }

  // Computed MemberExpression: taintedArray[i], tainted.split("=")[1], etc.
  // Taint propagates through indexed access on tainted objects.
  if (_t.isMemberExpression(node) && node.computed) {
    var compObjSource = _traceValueSource(path.get("object"));
    if (compObjSource.sourceType === "user-controlled") return compObjSource;
  }

  // Identifier: resolve via scope binding
  if (_t.isIdentifier(node)) {
    var binding = path.scope.getBinding(node.name);
    if (binding) {
      // Variable initializer
      if (binding.path.isVariableDeclarator() && binding.path.node.init) {
        return _traceValueSource(binding.path.get("init"));
      }
      // For-in/for-of loop variable: for (var key in obj) → key is user-controlled if obj is.
      // Critical for detecting prototype pollution in recursive merge functions.
      if (binding.path.isVariableDeclarator() && !binding.path.node.init) {
        var _forParent = binding.path.parentPath && binding.path.parentPath.parentPath;
        if (_forParent && (_t.isForInStatement(_forParent.node) || _t.isForOfStatement(_forParent.node)) &&
            _forParent.node.left === binding.path.parent) {
          return _traceValueSource(_forParent.get("right"));
        }
      }
      // Destructured property: const { data } = event → trace back to the parent object.
      // binding.path is the ObjectProperty or RestElement inside the pattern.
      if (_t.isObjectProperty(binding.path.node) || _t.isRestElement(binding.path.node)) {
        // Walk up to find the VariableDeclarator that holds the pattern
        var _destrParent = binding.path.parentPath;
        while (_destrParent && !_destrParent.isVariableDeclarator()) {
          _destrParent = _destrParent.parentPath;
        }
        if (_destrParent && _destrParent.node.init) {
          return _traceValueSource(_destrParent.get("init"));
        }
      }
      // Destructured array element: const [a, b] = arr → trace back to the array
      if (_t.isArrayPattern(binding.path.parent)) {
        var _arrDestrParent = binding.path.parentPath;
        while (_arrDestrParent && !_arrDestrParent.isVariableDeclarator()) {
          _arrDestrParent = _arrDestrParent.parentPath;
        }
        if (_arrDestrParent && _arrDestrParent.node.init) {
          return _traceValueSource(_arrDestrParent.get("init"));
        }
      }
      // Function parameter — check callers for user-controlled values
      if (binding.kind === "param") {
        var paramIdx = -1;
        var funcPath = binding.scope.path;
        if (funcPath && funcPath.node.params) {
          for (var pi = 0; pi < funcPath.node.params.length; pi++) {
            if (_t.isIdentifier(funcPath.node.params[pi], { name: node.name })) { paramIdx = pi; break; }
          }
          // Destructured parameter: function f({data}) {} or function f({data} = {}) {}
          // Whole-object taint propagates: if the caller's argument is user-controlled,
          // the destructured binding is user-controlled.
          if (paramIdx === -1) {
            for (var _dpi = 0; _dpi < funcPath.node.params.length; _dpi++) {
              var _dpParam = funcPath.node.params[_dpi];
              if (_t.isObjectPattern(_dpParam)) {
                if (_findDestructuredKey(_dpParam, node.name)) { paramIdx = _dpi; break; }
              }
              if (_t.isAssignmentPattern(_dpParam) && _t.isObjectPattern(_dpParam.left)) {
                if (_findDestructuredKey(_dpParam.left, node.name)) { paramIdx = _dpi; break; }
              }
            }
          }
        }
        if (paramIdx >= 0 && funcPath) {
          // Direct IIFE: (function(a) { ... })(tainted) — parent is CallExpression where callee is this function
          var _iifeParent = funcPath.parentPath;
          if (_iifeParent && _t.isCallExpression(_iifeParent.node) && _iifeParent.node.callee === funcPath.node &&
              paramIdx < _iifeParent.node.arguments.length) {
            var _iifeArgSrc = _traceValueSource(_iifeParent.get("arguments." + paramIdx));
            if (_iifeArgSrc.sourceType === "user-controlled") return _iifeArgSrc;
          }
          var callerArgs = _findFunctionCallerArgs(funcPath);
          for (var ci = 0; ci < callerArgs.length; ci++) {
            if (paramIdx < callerArgs[ci].length) {
              var argSource = _traceValueSource(callerArgs[ci][paramIdx]);
              if (argSource.sourceType === "user-controlled") return argSource;
            }
          }
          // Array iteration callback: arr.forEach(fn), arr.map(fn), etc.
          // First param receives array elements; if the array is tainted, the param is tainted.
          // Also handles .then(fn) — first param receives the resolved Promise value.
          // V4 fix: use type tracker to skip taint propagation when callee object is a known non-iterable type.
          if (paramIdx === 0) {
            var _iterParent = funcPath.parentPath;
            if (_iterParent && _iterParent.isCallExpression() &&
                _t.isMemberExpression(_iterParent.node.callee) && !_iterParent.node.callee.computed &&
                _iterParent.node.arguments.length >= 1 && _iterParent.node.arguments[0] === funcPath.node) {
              var _iterMethod = _t.isIdentifier(_iterParent.node.callee.property)
                ? _iterParent.node.callee.property.name : null;
              if (_ITERATION_METHODS[_iterMethod] || _iterMethod === "then" || _iterMethod === "catch") {
                // V4: Check if the callee object has a known non-iterable type
                var _iterObjType = _getTrackedType(_iterParent.get("callee.object"), _iterParent.node.callee.object);
                if (!(_ITERATION_METHODS[_iterMethod] && _iterObjType && _NON_ITERABLE_TYPES[_iterObjType])) {
                  var _iterObjSrc = _traceValueSource(_iterParent.get("callee.object"));
                  if (_iterObjSrc.sourceType === "user-controlled") return _iterObjSrc;
                }
              }
            }
            // Also check when function is passed by reference: var fn = function(x) {...}; arr.forEach(fn)
            var _iterBinding = _getFunctionBinding(funcPath);
            if (_iterBinding && _iterBinding.referencePaths) {
              for (var _iri = 0; _iri < _iterBinding.referencePaths.length; _iri++) {
                var _irRef = _iterBinding.referencePaths[_iri];
                var _irParent = _irRef.parentPath;
                if (_irParent && _irParent.isCallExpression() &&
                    _t.isMemberExpression(_irParent.node.callee) && !_irParent.node.callee.computed &&
                    _irParent.node.arguments.length >= 1 && _irParent.node.arguments[0] === _irRef.node) {
                  var _irMethod = _t.isIdentifier(_irParent.node.callee.property)
                    ? _irParent.node.callee.property.name : null;
                  if (_ITERATION_METHODS[_irMethod] || _irMethod === "then" || _irMethod === "catch") {
                    // V4: Check if the callee object has a known non-iterable type
                    var _irObjType = _getTrackedType(_irParent.get("callee.object"), _irParent.node.callee.object);
                    if (!(_ITERATION_METHODS[_irMethod] && _irObjType && _NON_ITERABLE_TYPES[_irObjType])) {
                      var _irObjSrc = _traceValueSource(_irParent.get("callee.object"));
                      if (_irObjSrc.sourceType === "user-controlled") return _irObjSrc;
                    }
                  }
                }
              }
            }
          }
          // reduce callback: arr.reduce(fn, init) — second param (index 1) is the accumulator on first call,
          // but first param (index 0) is the accumulator on subsequent calls, receiving previous return.
          // For taint: if array is tainted, param index 1 (currentValue) receives elements.
          if (paramIdx === 1) {
            var _redParent = funcPath.parentPath;
            if (_redParent && _redParent.isCallExpression() &&
                _t.isMemberExpression(_redParent.node.callee) && !_redParent.node.callee.computed &&
                _redParent.node.arguments.length >= 1 && _redParent.node.arguments[0] === funcPath.node) {
              var _redMethod = _t.isIdentifier(_redParent.node.callee.property)
                ? _redParent.node.callee.property.name : null;
              if (_redMethod === "reduce" || _redMethod === "reduceRight") {
                // V4: Check if the callee object has a known non-iterable type
                var _redObjType = _getTrackedType(_redParent.get("callee.object"), _redParent.node.callee.object);
                if (!(_redObjType && _NON_ITERABLE_TYPES[_redObjType])) {
                  var _redObjSrc = _traceValueSource(_redParent.get("callee.object"));
                  if (_redObjSrc.sourceType === "user-controlled") return _redObjSrc;
                }
              }
            }
          }
        }
        // Message event handler: first param is the MessageEvent object (user-controlled).
        // addEventListener("message", function(event) { ... }) or onmessage = function(e) { ... }
        if (paramIdx === 0 && funcPath) {
          var _isMsgHandler = false;
          var _mhParent = funcPath.parentPath;
          if (_mhParent) {
            // addEventListener("message", handler) or obj.addEventListener("message", handler)
            if (_mhParent.isCallExpression()) {
              var _aeNode = _mhParent.node;
              if (_aeNode.arguments.length >= 2 && _aeNode.arguments[1] === funcPath.node &&
                  _t.isStringLiteral(_aeNode.arguments[0], { value: "message" })) {
                var _aeCal = _aeNode.callee;
                if ((_t.isMemberExpression(_aeCal) && !_aeCal.computed &&
                     _t.isIdentifier(_aeCal.property, { name: "addEventListener" })) ||
                    (_t.isIdentifier(_aeCal, { name: "addEventListener" }) &&
                     !funcPath.scope.getBinding("addEventListener"))) {
                  _isMsgHandler = true;
                }
              }
            }
            // onmessage = function(e) { ... }
            if (_mhParent.isAssignmentExpression() && _mhParent.node.right === funcPath.node) {
              var _omLeft = _mhParent.node.left;
              if (_t.isMemberExpression(_omLeft) && !_omLeft.computed &&
                  _t.isIdentifier(_omLeft.property, { name: "onmessage" })) {
                _isMsgHandler = true;
              }
            }
            // Factory pattern: function returned from enclosing function whose call site
            // is in a message handler position, e.g. addEventListener("message", makeHandler(...))
            if (!_isMsgHandler && _t.isReturnStatement(_mhParent.node)) {
              var _mhEncFunc = funcPath.findParent(function(p) { return p.isFunction() && p !== funcPath; });
              if (_mhEncFunc) {
                var _mhEncBinding = null;
                if (_t.isFunctionDeclaration(_mhEncFunc.node) && _t.isIdentifier(_mhEncFunc.node.id)) {
                  _mhEncBinding = _mhEncFunc.parentPath.scope.getBinding(_mhEncFunc.node.id.name);
                } else if (_mhEncFunc.parentPath && _mhEncFunc.parentPath.isVariableDeclarator()) {
                  _mhEncBinding = _mhEncFunc.parentPath.scope.getBinding(_mhEncFunc.parentPath.node.id.name);
                }
                if (_mhEncBinding) {
                  var _mhRefs = _mhEncBinding.referencePaths || [];
                  for (var _mhri = 0; _mhri < _mhRefs.length && !_isMsgHandler; _mhri++) {
                    var _mhRefParent = _mhRefs[_mhri].parentPath;
                    if (_mhRefParent && _mhRefParent.isCallExpression() && _mhRefParent.node.callee === _mhRefs[_mhri].node) {
                      var _mhCallParent = _mhRefParent.parentPath;
                      // addEventListener("message", enclosingFunc(...))
                      if (_mhCallParent && _mhCallParent.isCallExpression()) {
                        var _mhOuterCall = _mhCallParent.node;
                        if (_mhOuterCall.arguments.length >= 2 && _mhOuterCall.arguments[1] === _mhRefParent.node &&
                            _t.isStringLiteral(_mhOuterCall.arguments[0], { value: "message" })) {
                          var _mhOuterCallee = _mhOuterCall.callee;
                          if ((_t.isMemberExpression(_mhOuterCallee) && !_mhOuterCallee.computed &&
                               _t.isIdentifier(_mhOuterCallee.property, { name: "addEventListener" })) ||
                              (_t.isIdentifier(_mhOuterCallee, { name: "addEventListener" }) &&
                               !_mhCallParent.scope.getBinding("addEventListener"))) {
                            _isMsgHandler = true;
                          }
                        }
                      }
                      // onmessage = enclosingFunc(...)
                      if (_mhCallParent && _mhCallParent.isAssignmentExpression() && _mhCallParent.node.right === _mhRefParent.node) {
                        var _mhOmLeft2 = _mhCallParent.node.left;
                        if (_t.isMemberExpression(_mhOmLeft2) && !_mhOmLeft2.computed &&
                            _t.isIdentifier(_mhOmLeft2.property, { name: "onmessage" })) {
                          _isMsgHandler = true;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          if (_isMsgHandler) {
            return { sourceType: "user-controlled", source: "event.data", sourceLoc: nodeLoc };
          }
        }
        return { sourceType: "dynamic", source: null };
      }
    }
    // Bare `location` identifier (unbound) — the location object itself is user-controlled
    if (node.name === "location") return { sourceType: "user-controlled", source: "location", sourceLoc: nodeLoc };
    // Unresolvable identifier
    return { sourceType: "dynamic", source: null };
  }

  // Template literal with expressions — check if any expression is user-controlled
  if (_t.isTemplateLiteral(node)) {
    for (var ti = 0; ti < node.expressions.length; ti++) {
      var exprSource = _traceValueSource(path.get("expressions." + ti));
      if (exprSource.sourceType === "user-controlled") return exprSource;
    }
    return node.expressions.length > 0 ? { sourceType: "dynamic", source: null } : { sourceType: "literal", source: null };
  }

  // Binary expression (string concat): check both sides
  if (_t.isBinaryExpression(node) && node.operator === "+") {
    var leftSource = _traceValueSource(path.get("left"));
    if (leftSource.sourceType === "user-controlled") return leftSource;
    var rightSource = _traceValueSource(path.get("right"));
    if (rightSource.sourceType === "user-controlled") return rightSource;
    return { sourceType: "dynamic", source: null };
  }

  // Conditional: check both branches
  if (_t.isConditionalExpression(node)) {
    var consSource = _traceValueSource(path.get("consequent"));
    if (consSource.sourceType === "user-controlled") return consSource;
    var altSource = _traceValueSource(path.get("alternate"));
    if (altSource.sourceType === "user-controlled") return altSource;
  }

  // Logical expression (||, &&, ??): taint propagates through either side.
  // Common pattern: var url = params.get("url") || "/default"
  if (_t.isLogicalExpression(node)) {
    var _logLeft = _traceValueSource(path.get("left"));
    if (_logLeft.sourceType === "user-controlled") return _logLeft;
    var _logRight = _traceValueSource(path.get("right"));
    if (_logRight.sourceType === "user-controlled") return _logRight;
  }

  // Sequence expression (comma operator): value is the last expression.
  // Common pattern: (0, eval)(tainted) — indirect eval
  if (_t.isSequenceExpression(node) && node.expressions.length > 0) {
    var _lastIdx = node.expressions.length - 1;
    return _traceValueSource(path.get("expressions." + _lastIdx));
  }

  // AwaitExpression: taint propagates through await.
  // const data = await response.json() where response is tainted
  if (_t.isAwaitExpression(node)) {
    return _traceValueSource(path.get("argument"));
  }

  // SpreadElement: taint propagates through spread.
  // [...tainted] or fn(...tainted)
  if (_t.isSpreadElement(node)) {
    return _traceValueSource(path.get("argument"));
  }

  // Call expression — check if it's a wrapper around a taint source
  if (_t.isCallExpression(node)) {
    // localStorage.getItem() / sessionStorage.getItem() — persistent DOM XSS sources.
    // Same-origin write requirement, but a recognized vulnerability class (stored DOM XSS).
    if (_t.isMemberExpression(node.callee) && !node.callee.computed &&
        _t.isIdentifier(node.callee.property, { name: "getItem" })) {
      var _storObj = node.callee.object;
      if ((_t.isIdentifier(_storObj, { name: "localStorage" }) && !path.scope.getBinding("localStorage")) ||
          (_t.isIdentifier(_storObj, { name: "sessionStorage" }) && !path.scope.getBinding("sessionStorage"))) {
        return { sourceType: "user-controlled", source: _storObj.name + ".getItem", sourceLoc: nodeLoc };
      }
    }
    // Method calls on tainted objects: tainted.slice(), tainted.substring(), tainted.trim(), etc.
    if (_t.isMemberExpression(node.callee) && !node.callee.computed) {
      var callObjSource = _traceValueSource(path.get("callee.object"));
      if (callObjSource.sourceType === "user-controlled") return callObjSource;
    }
    // Object.assign(target, ...sources) / Object.create — taint propagates from any source arg.
    // This handles var merged = Object.assign({}, taintedConfig) where the tainted data is in arg 1+.
    if (_t.isMemberExpression(node.callee) && !node.callee.computed &&
        _t.isIdentifier(node.callee.property, { name: "assign" }) &&
        _t.isIdentifier(node.callee.object, { name: "Object" }) && !path.scope.getBinding("Object") &&
        node.arguments.length >= 2) {
      for (var _oaIdx = 0; _oaIdx < node.arguments.length; _oaIdx++) {
        var _oaArgSrc = _traceValueSource(path.get("arguments." + _oaIdx));
        if (_oaArgSrc.sourceType === "user-controlled") return _oaArgSrc;
      }
    }
    // decodeURIComponent(location.hash), atob(location.search), etc.
    if (node.arguments.length > 0) {
      var argSource = _traceValueSource(path.get("arguments.0"));
      if (argSource.sourceType === "user-controlled") return argSource;
    }
    // Resolve function return value: buildApiUrl("x") → trace return statement in body
    var _calleeNode = node.callee;
    var _calleeFuncPath = null;
    if (_t.isIdentifier(_calleeNode)) {
      var _calleeBinding = path.scope.getBinding(_calleeNode.name);
      if (_calleeBinding) {
        if (_t.isFunctionDeclaration(_calleeBinding.path.node)) {
          _calleeFuncPath = _calleeBinding.path;
        } else if (_calleeBinding.path.isVariableDeclarator() && _calleeBinding.path.node.init &&
                   _t.isFunction(_calleeBinding.path.node.init)) {
          _calleeFuncPath = _calleeBinding.path.get("init");
        }
      }
    }
    if (_calleeFuncPath && _calleeFuncPath.node.body && _t.isBlockStatement(_calleeFuncPath.node.body)) {
      var _retResult = _traceReturnsInBlock(_calleeFuncPath.get("body"));
      if (_retResult && _retResult.sourceType === "user-controlled") return _retResult;
    }
  }

  // NewExpression: taint propagates through constructor arguments.
  // new URLSearchParams(tainted), new URL(tainted), new Blob([tainted]) etc.
  if (_t.isNewExpression(node) && node.arguments.length > 0) {
    for (var _ni = 0; _ni < node.arguments.length; _ni++) {
      var _nArgSrc = _traceValueSource(path.get("arguments." + _ni));
      if (_nArgSrc.sourceType === "user-controlled") return _nArgSrc;
    }
  }

  // ArrayExpression: taint propagates if any element is tainted.
  // [...tainted], [tainted, "safe"], etc.
  if (_t.isArrayExpression(node) && node.elements.length > 0) {
    for (var _ai = 0; _ai < node.elements.length; _ai++) {
      if (node.elements[_ai]) {
        var _aElSrc = _traceValueSource(path.get("elements." + _ai));
        if (_aElSrc.sourceType === "user-controlled") return _aElSrc;
      }
    }
  }

  // ObjectExpression: taint propagates if any property value is tainted.
  // {html: location.hash, safe: "ok"} → tainted because of location.hash property
  if (_t.isObjectExpression(node) && node.properties.length > 0) {
    for (var _opi = 0; _opi < node.properties.length; _opi++) {
      var _opProp = node.properties[_opi];
      if (_t.isObjectProperty(_opProp)) {
        var _opValSrc = _traceValueSource(path.get("properties." + _opi + ".value"));
        if (_opValSrc.sourceType === "user-controlled") return _opValSrc;
      }
      if (_t.isSpreadElement(_opProp)) {
        var _opSpreadSrc = _traceValueSource(path.get("properties." + _opi + ".argument"));
        if (_opSpreadSrc.sourceType === "user-controlled") return _opSpreadSrc;
      }
    }
  }

  // Assignment expression: check right side
  if (_t.isAssignmentExpression(node)) {
    return _traceValueSource(path.get("right"));
  }

  return { sourceType: "dynamic", source: null };
}

// ─── Security Analysis: Helpers ──────────────────────────────────────────────

function _nodeLoc(n) {
  return { line: n.loc ? n.loc.start.line : 0, column: n.loc ? n.loc.start.column : 0 };
}

function _pushSink(result, node, type, sink, src, path) {
  var severity = "high";
  var sanitized = false;
  if (path) {
    try {
      sanitized = _checkSanitization(path);
      if (sanitized) severity = "info";
    } catch (e) { _resolver.collectError(e, "checkSanitization"); }
  }
  result.securitySinks.push({
    type: type, sink: sink, location: _nodeLoc(node),
    sourceType: src.sourceType, source: src.source, severity: severity,
    sanitized: sanitized,
    codeContext: _extractCodeContext(node, src),
  });
}

function _pushDangerous(result, node, type, description, severity, src) {
  result.dangerousPatterns.push({
    type: type, description: description, location: _nodeLoc(node),
    severity: severity, codeContext: _extractCodeContext(node, src),
  });
}

// Check if an AST node refers to the global location object:
// location, window.location, self.location, document.location
function _isLocationObject(objNode, path) {
  if (_t.isIdentifier(objNode, { name: "location" }) && !path.scope.getBinding("location")) return true;
  if (_t.isMemberExpression(objNode) && !objNode.computed &&
      _t.isIdentifier(objNode.property, { name: "location" })) {
    var base = objNode.object;
    if ((_t.isIdentifier(base, { name: "window" }) && !path.scope.getBinding("window")) ||
        (_t.isIdentifier(base, { name: "self" }) && !path.scope.getBinding("self")) ||
        (_t.isIdentifier(base, { name: "document" }) && !path.scope.getBinding("document"))) {
      return true;
    }
  }
  return false;
}

// ─── Security Analysis: DOM XSS Sink Detection ─────────────────────────────

// Assignment-based sinks: element.innerHTML = value, element.innerHTML += value
function _processSecurityAssignSink(path, result) {
  var node = path.node;
  if (node.operator !== "=" && node.operator !== "+=") return;
  var left = node.left;

  // Bare location = taint → open redirect (Identifier, not MemberExpression)
  if (_t.isIdentifier(left, { name: "location" }) && !path.scope.getBinding("location")) {
    var _bLocSrc = _traceValueSource(path.get("right"), 0);
    if (_bLocSrc.sourceType !== "user-controlled") return;
    _pushSink(result, node, "redirect", "location", _bLocSrc, path);
    return;
  }

  if (!_t.isMemberExpression(left)) return;

  // Resolve property name — supports both el.innerHTML and el["innerHTML"]
  var propName = null;
  if (!left.computed && _t.isIdentifier(left.property)) {
    propName = left.property.name;
  } else if (left.computed && _t.isStringLiteral(left.property)) {
    propName = left.property.value;
  }
  if (!propName) return;

  var _isLoc = _isLocationObject(left.object, path);
  var sinkType = null;

  // XSS sinks: HTML/content injection properties
  if (propName === "innerHTML" || propName === "outerHTML" || propName === "srcdoc" || propName === "formAction") {
    sinkType = "xss";
  }

  // URL property sinks: href, src, action — XSS unless on location (which is redirect)
  if (!sinkType && (propName === "href" || propName === "src" || propName === "action")) {
    sinkType = _isLoc ? "redirect" : "xss";
  }

  // Open redirect sinks: location.pathname/search/hash
  if (!sinkType && _isLoc && (propName === "pathname" || propName === "search" || propName === "hash")) {
    sinkType = "redirect";
  }

  // document.location = taint / window.location = taint → open redirect
  if (!sinkType && propName === "location") {
    var _isDocWin = (_t.isIdentifier(left.object, { name: "document" }) && !path.scope.getBinding("document")) ||
                    (_t.isIdentifier(left.object, { name: "window" }) && !path.scope.getBinding("window")) ||
                    (_t.isIdentifier(left.object, { name: "self" }) && !path.scope.getBinding("self"));
    if (_isDocWin) sinkType = "redirect";
  }

  if (!sinkType) return;

  var valueSource = _traceValueSource(path.get("right"), 0);
  // Only flag when value traces to a user-controlled source — dynamic/literal
  // values produce massive noise in minified library code (frameworks do
  // innerHTML = expr constantly for legitimate DOM updates).
  if (valueSource.sourceType !== "user-controlled") return;

  _pushSink(result, node, sinkType, propName, valueSource, path);
}

// Table-driven global identifier sinks: name → { type, sink }
var _GLOBAL_CALL_SINKS = {
  "eval": { type: "eval", sink: "eval" },
  "open": { type: "redirect", sink: "window.open" },
  "fetch": { type: "request-forgery", sink: "fetch" },
  "importScripts": { type: "eval", sink: "importScripts" },
  "$": { type: "xss", sink: "jQuery" },
  "jQuery": { type: "xss", sink: "jQuery" },
};

// Call-based sinks: eval(), document.write(), setTimeout(string), insertAdjacentHTML, setAttribute("on*")
function _processSecurityCallSink(path, result) {
  var node = path.node;
  var callee = node.callee;

  // import(url) — dynamic import, eval-class sink (Babel parses as CallExpression with Import callee)
  if (callee.type === "Import" && node.arguments.length > 0) {
    var _impSrc = _traceValueSource(path.get("arguments.0"), 0);
    if (_impSrc.sourceType === "user-controlled") _pushSink(result, node, "eval", "import", _impSrc, path);
    return;
  }

  // Indirect eval: (0, eval)(value) — SequenceExpression whose last element is eval
  if (_t.isSequenceExpression(callee) && callee.expressions.length > 0 && node.arguments.length > 0) {
    var _seqLast = callee.expressions[callee.expressions.length - 1];
    if (_t.isIdentifier(_seqLast, { name: "eval" }) && !path.scope.getBinding("eval")) {
      var _indEvalSrc = _traceValueSource(path.get("arguments.0"), 0);
      if (_indEvalSrc.sourceType === "user-controlled") _pushSink(result, node, "eval", "eval", _indEvalSrc, path);
      return;
    }
  }

  // Table-driven global identifier sinks: eval, open, fetch, importScripts
  if (_t.isIdentifier(callee) && node.arguments.length > 0) {
    var _gSink = _GLOBAL_CALL_SINKS[callee.name];
    if (_gSink && !path.scope.getBinding(callee.name)) {
      var _gSrc = _traceValueSource(path.get("arguments.0"), 0);
      if (_gSrc.sourceType === "user-controlled") _pushSink(result, node, _gSink.type, _gSink.sink, _gSrc, path);
      return;
    }
  }

  // setTimeout/setInterval with string first arg (not a function)
  if (_t.isIdentifier(callee) && (callee.name === "setTimeout" || callee.name === "setInterval") &&
      !path.scope.getBinding(callee.name) && node.arguments.length > 0) {
    var firstArg = node.arguments[0];
    // Skip only if the arg is definitely a function (expression, arrow, or identifier resolving to one)
    var isFunc = _t.isFunctionExpression(firstArg) || _t.isArrowFunctionExpression(firstArg);
    if (!isFunc && _t.isIdentifier(firstArg)) {
      var timerBinding = path.scope.getBinding(firstArg.name);
      if (timerBinding && timerBinding.path.node.init && (_t.isFunctionExpression(timerBinding.path.node.init) || _t.isArrowFunctionExpression(timerBinding.path.node.init)))
        isFunc = true;
    }
    if (!isFunc) {
      var timerSource = _traceValueSource(path.get("arguments.0"), 0);
      if (timerSource.sourceType !== "user-controlled") return;
      _pushSink(result, node, "eval", callee.name, timerSource, path);
      return;
    }
  }

  if (!_t.isMemberExpression(callee) || callee.computed) return;
  var methName = _t.isIdentifier(callee.property) ? callee.property.name : null;
  if (!methName) return;

  // window.open(url) / self.open(url) — open redirect (member expression form)
  if (methName === "open" && node.arguments.length > 0) {
    var _isWin = (_t.isIdentifier(callee.object, { name: "window" }) && !path.scope.getBinding("window")) ||
                 (_t.isIdentifier(callee.object, { name: "self" }) && !path.scope.getBinding("self"));
    if (_isWin) {
      var _woSrc2 = _traceValueSource(path.get("arguments.0"), 0);
      if (_woSrc2.sourceType === "user-controlled") _pushSink(result, node, "redirect", "window.open", _woSrc2, path);
      return;
    }
  }

  // Simple method sinks: method name → { type, sink, argIdx }
  // Handles setHTMLUnsafe, parseHTMLUnsafe, insertAdjacentHTML, createContextualFragment
  if (methName === "setHTMLUnsafe" || methName === "parseHTMLUnsafe" || methName === "createContextualFragment") {
    if (node.arguments.length > 0) {
      var _htmlSrc = _traceValueSource(path.get("arguments.0"), 0);
      if (_htmlSrc.sourceType === "user-controlled") _pushSink(result, node, "xss", methName, _htmlSrc, path);
    }
    return;
  }

  // document.write(value) / document.writeln(value)
  if ((methName === "write" || methName === "writeln") && _t.isIdentifier(callee.object, { name: "document" }) &&
      !path.scope.getBinding("document") && node.arguments.length > 0) {
    var dwSource = _traceValueSource(path.get("arguments.0"), 0);
    if (dwSource.sourceType === "user-controlled") _pushSink(result, node, "xss", "document." + methName, dwSource, path);
    return;
  }

  // element.insertAdjacentHTML(position, markup)
  if (methName === "insertAdjacentHTML" && node.arguments.length >= 2) {
    var iahSource = _traceValueSource(path.get("arguments.1"), 0);
    if (iahSource.sourceType === "user-controlled") _pushSink(result, node, "xss", "insertAdjacentHTML", iahSource, path);
    return;
  }

  // element.setAttribute("onclick"/href/src/action/style, value)
  if (methName === "setAttribute" && node.arguments.length >= 2 && _t.isStringLiteral(node.arguments[0])) {
    var attrName = node.arguments[0].value.toLowerCase();
    if (attrName.startsWith("on") || attrName === "href" || attrName === "src" ||
        attrName === "action" || attrName === "style") {
      var saSource = _traceValueSource(path.get("arguments.1"), 0);
      if (saSource.sourceType === "user-controlled") _pushSink(result, node, "xss", "setAttribute:" + attrName, saSource, path);
      return;
    }
  }

  // jQuery DOM manipulation: .html(), .append(), .prepend(), .after(), .before(), .replaceWith()
  if ((methName === "html" || methName === "append" || methName === "prepend" ||
       methName === "after" || methName === "before" || methName === "replaceWith") &&
      node.arguments.length > 0) {
    var _jqSrc = _traceValueSource(path.get("arguments.0"), 0);
    if (_jqSrc.sourceType === "user-controlled") _pushSink(result, node, "xss", "." + methName, _jqSrc, path);
    return;
  }

  // Implicit ReDoS: .match(), .search() with user-controlled first arg.
  // Note: .split() does NOT create an implicit RegExp — it does literal string matching.
  if ((methName === "match" || methName === "search") &&
      node.arguments.length > 0 && !_t.isRegExpLiteral(node.arguments[0])) {
    var _reImplSrc = _traceValueSource(path.get("arguments.0"), 0);
    if (_reImplSrc.sourceType === "user-controlled") {
      _pushDangerous(result, node, "regex-implicit",
        "String." + methName + " with user-controlled pattern (implicit RegExp, potential ReDoS)", "medium", _reImplSrc);
    }
    return;
  }

  // navigator.sendBeacon(url, data) — request forgery / data exfiltration
  if (methName === "sendBeacon" && node.arguments.length > 0 &&
      _t.isIdentifier(callee.object, { name: "navigator" }) && !path.scope.getBinding("navigator")) {
    var _sbSrc = _traceValueSource(path.get("arguments.0"), 0);
    if (_sbSrc.sourceType === "user-controlled") _pushSink(result, node, "request-forgery", "navigator.sendBeacon", _sbSrc, path);
    return;
  }

  // XMLHttpRequest.open(method, url) — request forgery via user-controlled URL
  if (methName === "open" && node.arguments.length >= 2) {
    // Exclude window.open / self.open (handled above as redirect)
    var _isXhrOpen = !(_t.isIdentifier(callee.object, { name: "window" }) && !path.scope.getBinding("window")) &&
                     !(_t.isIdentifier(callee.object, { name: "self" }) && !path.scope.getBinding("self"));
    if (_isXhrOpen) {
      var _xhrUrlSrc = _traceValueSource(path.get("arguments.1"), 0);
      if (_xhrUrlSrc.sourceType === "user-controlled") _pushSink(result, node, "request-forgery", "XMLHttpRequest.open", _xhrUrlSrc, path);
    }
    return;
  }

  // navigator.serviceWorker.register(url) — service worker hijacking
  if (methName === "register" && node.arguments.length > 0 &&
      _t.isMemberExpression(callee.object) && !callee.object.computed &&
      _t.isIdentifier(callee.object.property, { name: "serviceWorker" })) {
    var _swBase = callee.object.object;
    if (_t.isIdentifier(_swBase, { name: "navigator" }) && !path.scope.getBinding("navigator")) {
      var _swSrc = _traceValueSource(path.get("arguments.0"), 0);
      if (_swSrc.sourceType === "user-controlled") _pushSink(result, node, "eval", "serviceWorker.register", _swSrc, path);
      return;
    }
  }

  // location.assign(value) / location.replace(value) — open redirect
  if ((methName === "assign" || methName === "replace") && node.arguments.length > 0) {
    if (!_isLocationObject(callee.object, path)) return;
    var locSource = _traceValueSource(path.get("arguments.0"), 0);
    if (locSource.sourceType !== "user-controlled") return;
    _pushSink(result, node, "redirect", "location." + methName, locSource, path);
  }
}

// NewExpression sinks: new Function(value), new RegExp(value), new Worker(url), etc.
function _processSecurityNewSink(path, result) {
  var node = path.node;
  var ctorName = _t.isIdentifier(node.callee) ? node.callee.name : null;
  if (!ctorName || path.scope.getBinding(ctorName) || node.arguments.length === 0) return;

  // new Function(code) — only flag user-controlled
  if (ctorName === "Function") {
    var lastArg = node.arguments[node.arguments.length - 1];
    if (!_t.isStringLiteral(lastArg)) {
      var fnSource = _traceValueSource(path.get("arguments." + (node.arguments.length - 1)), 0);
      if (fnSource.sourceType === "user-controlled") _pushSink(result, node, "eval", "new Function", fnSource, path);
    }
    return;
  }

  // new RegExp(dynamicPattern) — ReDoS risk
  if (ctorName === "RegExp") {
    if (!_t.isStringLiteral(node.arguments[0])) {
      var reSource = _traceValueSource(path.get("arguments.0"), 0);
      if (reSource.sourceType === "user-controlled") {
        _pushDangerous(result, node, "regex-dynamic",
          "RegExp constructor with user-controlled pattern (potential ReDoS)", "high", reSource);
      }
    }
    return;
  }

  // new Worker/SharedWorker/WebSocket/EventSource(url) — skip string literals
  if (ctorName === "Worker" || ctorName === "SharedWorker" ||
      ctorName === "WebSocket" || ctorName === "EventSource") {
    if (_t.isStringLiteral(node.arguments[0])) return;
    var _newSrc = _traceValueSource(path.get("arguments.0"), 0);
    if (_newSrc.sourceType !== "user-controlled") return;
    var _isNetwork = ctorName === "WebSocket" || ctorName === "EventSource";
    _pushSink(result, node,
      _isNetwork ? "request-forgery" : "eval",
      "new " + ctorName, _newSrc, path);
  }
}

// ─── Security Analysis: React dangerouslySetInnerHTML Detection ─────────────

// Detect { dangerouslySetInnerHTML: { __html: taintedValue } } in object literals.
// Property names survive minification — "dangerouslySetInnerHTML" and "__html" are string keys.
// Used in React.createElement and JSX-compiled output.
function _processReactDangerousHTML(path, result) {
  var node = path.node;
  if (!node.properties || node.properties.length === 0) return;
  for (var i = 0; i < node.properties.length; i++) {
    var prop = node.properties[i];
    if (!_t.isObjectProperty(prop) || prop.computed) continue;
    if (_getKeyName(prop.key) !== "dangerouslySetInnerHTML") continue;
    if (!_t.isObjectExpression(prop.value)) continue;
    for (var j = 0; j < prop.value.properties.length; j++) {
      var inner = prop.value.properties[j];
      if (!_t.isObjectProperty(inner) || inner.computed) continue;
      if (_getKeyName(inner.key) !== "__html") continue;
      var htmlSrc = _traceValueSource(path.get("properties." + i + ".value.properties." + j + ".value"), 0);
      if (htmlSrc.sourceType === "user-controlled") _pushSink(result, node, "xss", "dangerouslySetInnerHTML", htmlSrc, path);
    }
  }
}

// ─── Security Analysis: Dangerous Pattern Detection ─────────────────────────

function _processDangerousPattern(path, result) {
  var node = path.node;
  var callee = node.callee;

  // addEventListener("message", handler) — classify origin check
  if (_t.isMemberExpression(callee) && _t.isIdentifier(callee.property, { name: "addEventListener" }) &&
      node.arguments.length >= 2 && _t.isStringLiteral(node.arguments[0], { value: "message" })) {
    var handlerFuncPath = _resolveHandlerFunc(path.get("arguments.1"));
    if (handlerFuncPath && handlerFuncPath.node.body) _classifyAndReportMessageHandler(handlerFuncPath, node, result);
    return;
  }

  // postMessage(data, "*") — wildcard target origin
  if (_t.isMemberExpression(callee) && _t.isIdentifier(callee.property, { name: "postMessage" }) &&
      node.arguments.length >= 2 && _t.isStringLiteral(node.arguments[1], { value: "*" })) {
    var _isOpener = _t.isMemberExpression(callee.object) && _t.isIdentifier(callee.object.property, { name: "opener" });
    _pushDangerous(result, node, "postmessage-wildcard-target",
      _isOpener ? "postMessage to opener with wildcard '*' targetOrigin" : "postMessage with wildcard '*' targetOrigin", "high", null);
    return;
  }

  // Object.defineProperty(obj, userControlledKey, desc) — prototype pollution
  if (_t.isMemberExpression(callee) && !callee.computed &&
      _t.isIdentifier(callee.property, { name: "defineProperty" }) &&
      _t.isIdentifier(callee.object, { name: "Object" }) && !path.scope.getBinding("Object") &&
      node.arguments.length >= 3) {
    var _dpKeySrc = _traceValueSource(path.get("arguments.1"), 0);
    if (_dpKeySrc.sourceType === "user-controlled") {
      _pushDangerous(result, node, "prototype-pollution", "Object.defineProperty with user-controlled key", "high", _dpKeySrc);
    }
    return;
  }

  // Reflect.set(obj, userControlledKey, val) — prototype pollution
  if (_t.isMemberExpression(callee) && !callee.computed &&
      _t.isIdentifier(callee.property, { name: "set" }) &&
      _t.isIdentifier(callee.object, { name: "Reflect" }) && !path.scope.getBinding("Reflect") &&
      node.arguments.length >= 3) {
    var _rsKeySrc = _traceValueSource(path.get("arguments.1"), 0);
    if (_rsKeySrc.sourceType === "user-controlled") {
      _pushDangerous(result, node, "prototype-pollution", "Reflect.set with user-controlled key", "high", _rsKeySrc);
    }
    return;
  }

  // Object.assign(target, userControlledSource) — prototype pollution via merge
  if (_t.isMemberExpression(callee) && !callee.computed &&
      _t.isIdentifier(callee.property, { name: "assign" }) &&
      _t.isIdentifier(callee.object, { name: "Object" }) && !path.scope.getBinding("Object") &&
      node.arguments.length >= 2) {
    for (var _oaI = 1; _oaI < node.arguments.length; _oaI++) {
      var _oaSrc = _traceValueSource(path.get("arguments." + _oaI), 0);
      if (_oaSrc.sourceType === "user-controlled") {
        _pushDangerous(result, node, "prototype-pollution-merge", "Object.assign with user-controlled source object", "medium", _oaSrc);
        break;
      }
    }
    return;
  }

  // trustedTypes.createPolicy with passthrough identity functions — defeats Trusted Types
  if (_t.isMemberExpression(callee) && !callee.computed &&
      _t.isIdentifier(callee.property, { name: "createPolicy" }) &&
      _t.isIdentifier(callee.object, { name: "trustedTypes" }) && !path.scope.getBinding("trustedTypes") &&
      node.arguments.length >= 2 && _t.isObjectExpression(node.arguments[1])) {
    var _ttProps = node.arguments[1].properties;
    for (var _tti = 0; _tti < _ttProps.length; _tti++) {
      var _ttProp = _ttProps[_tti];
      if (!_t.isObjectProperty(_ttProp) || _ttProp.computed) continue;
      var _ttKey = _getKeyName(_ttProp.key);
      if (_ttKey !== "createHTML" && _ttKey !== "createScript" && _ttKey !== "createScriptURL") continue;
      // Check if the function is an identity function: (s) => s or function(s) { return s; }
      var _ttFn = _ttProp.value;
      var _isIdentityFn = false;
      if ((_t.isArrowFunctionExpression(_ttFn) || _t.isFunctionExpression(_ttFn)) &&
          _ttFn.params.length === 1 && _t.isIdentifier(_ttFn.params[0])) {
        var _pName = _ttFn.params[0].name;
        // Arrow with expression body: (s) => s
        if (_t.isIdentifier(_ttFn.body, { name: _pName })) _isIdentityFn = true;
        // Block body: (s) => { return s; } or function(s) { return s; }
        if (_t.isBlockStatement(_ttFn.body) && _ttFn.body.body.length === 1 &&
            _t.isReturnStatement(_ttFn.body.body[0]) &&
            _t.isIdentifier(_ttFn.body.body[0].argument, { name: _pName })) _isIdentityFn = true;
      }
      if (_isIdentityFn) {
        _pushDangerous(result, node, "trusted-types-passthrough",
          "Trusted Types policy with passthrough " + _ttKey + " (defeats Trusted Types protection)", "high", null);
        break;
      }
    }
    return;
  }
}

// Resolve handler function from addEventListener argument or identifier
// Returns a Babel path to the resolved function, or null.
function _resolveHandlerFunc(handlerPath) {
  var handler = handlerPath.node;
  if (_t.isFunctionExpression(handler) || _t.isArrowFunctionExpression(handler)) return handlerPath;
  if (_t.isIdentifier(handler)) {
    var hBinding = handlerPath.scope.getBinding(handler.name);
    if (hBinding) {
      if (_t.isFunctionDeclaration(hBinding.path.node)) return hBinding.path;
      if (hBinding.path.node.init && (_t.isFunctionExpression(hBinding.path.node.init) || _t.isArrowFunctionExpression(hBinding.path.node.init)))
        return hBinding.path.get("init");
    }
  }
  // CallExpression: handler is makeHandler(...) — resolve function and find returned function.
  // Handles factory patterns: addEventListener("message", makeHandler(callback))
  if (_t.isCallExpression(handler)) {
    var _rhCallee = handler.callee;
    var _rhFuncPath = null;
    if (_t.isIdentifier(_rhCallee)) {
      var _rhBind = handlerPath.scope.getBinding(_rhCallee.name);
      if (_rhBind) {
        if (_t.isFunctionDeclaration(_rhBind.path.node)) _rhFuncPath = _rhBind.path;
        else if (_rhBind.path.isVariableDeclarator() && _rhBind.path.node.init && _t.isFunction(_rhBind.path.node.init))
          _rhFuncPath = _rhBind.path.get("init");
      }
    }
    if (_rhFuncPath && _rhFuncPath.node.body && _t.isBlockStatement(_rhFuncPath.node.body)) {
      // Find the returned function in the body
      var _rhBody = _rhFuncPath.node.body.body;
      for (var _rhi = 0; _rhi < _rhBody.length; _rhi++) {
        if (_t.isReturnStatement(_rhBody[_rhi]) && _rhBody[_rhi].argument) {
          var _rhRet = _rhBody[_rhi].argument;
          if (_t.isFunctionExpression(_rhRet) || _t.isArrowFunctionExpression(_rhRet)) return _rhFuncPath.get("body.body." + _rhi + ".argument");
        }
      }
    }
  }
  return null;
}

// Classify origin check in message handler and report findings
function _classifyAndReportMessageHandler(handlerFuncPath, eventNode, result) {
  var handlerFunc = handlerFuncPath.node;
  var bodyPath = handlerFuncPath.get("body");
  var classification = _classifyOriginCheck(bodyPath);
  if (classification === "strong") return;

  var loc = _nodeLoc(eventNode);
  // Beautified handler code as context (fall back to raw extraction)
  var ctx = _generateCode(handlerFunc) ||
    _extractCodeContext(eventNode, { sourceLoc: handlerFunc.loc ? { line: handlerFunc.body.loc ? handlerFunc.body.loc.end.line : handlerFunc.loc.end.line } : null });
  var _pmDescs = {
    "none": "postMessage listener without origin check",
    "source-only": "postMessage listener with source check but no origin validation",
    "weak": "postMessage listener with bypassable origin check (use strict === comparison)",
  };
  var _pmType = classification === "weak" ? "postmessage-weak-origin" : "postmessage-no-origin";
  // Store handler line range for post-traversal severity classification
  var handlerStart = handlerFunc.loc ? handlerFunc.loc.start.line : 0;
  var handlerEnd = handlerFunc.loc ? handlerFunc.loc.end.line : 0;
  result.dangerousPatterns.push({
    type: _pmType, description: _pmDescs[classification],
    location: loc, severity: "medium", codeContext: ctx,
    _handlerRange: handlerStart && handlerEnd ? [handlerStart, handlerEnd] : null,
  });
}

// Classify origin check strength in a message handler body
// Returns: "strong" | "weak" | "source-only" | "none"
function _classifyOriginCheck(bodyPath) {
  if (!bodyPath || !bodyPath.node) return "none";
  var hasStrongOrigin = false;
  var hasWeakOrigin = false;
  var hasSourceOnly = false;

  var _originVisitor = {
    BinaryExpression: function(innerPath) {
      if (hasStrongOrigin) { innerPath.stop(); return; }
      var op = innerPath.node.operator;
      if (op === "===" || op === "!==" || op === "==" || op === "!=") {
        if (_hasPropertyMember(innerPath.node.left, "origin") || _hasPropertyMember(innerPath.node.right, "origin")) {
          hasStrongOrigin = true; innerPath.stop(); return;
        }
        if (_hasPropertyMember(innerPath.node.left, "source") || _hasPropertyMember(innerPath.node.right, "source")) {
          hasSourceOnly = true;
        }
      }
    },
    CallExpression: function(innerPath) {
      if (hasStrongOrigin) { innerPath.stop(); return; }
      var callee = innerPath.node.callee;
      if (_t.isMemberExpression(callee) && _t.isIdentifier(callee.property)) {
        var mn = callee.property.name;
        if (mn === "indexOf" || mn === "includes" || mn === "startsWith" || mn === "endsWith") {
          if (_hasPropertyMember(callee.object, "origin")) {
            hasWeakOrigin = true;
          }
        }
      }
      // Trace into function calls that receive .origin as an argument:
      // e.g., c.i(m.origin), validate(event.origin)
      var args = innerPath.node.arguments;
      for (var _oci = 0; _oci < args.length; _oci++) {
        if (_hasPropertyMember(args[_oci], "origin")) {
          var _ocResult = _classifyOriginCheckInCallee(innerPath, _oci);
          if (_ocResult === "strong") { hasStrongOrigin = true; innerPath.stop(); return; }
          if (_ocResult === "weak") hasWeakOrigin = true;
        }
      }
    },
  };

  // Scope-aware traversal using path.traverse (walks all node types)
  bodyPath.traverse(_originVisitor);

  if (hasStrongOrigin) return "strong";
  if (hasWeakOrigin) return "weak";
  if (hasSourceOnly) return "source-only";
  return "none";
}

// Trace into a called function to classify how it checks a parameter.
// callPath: the CallExpression path, argIdx: which argument is .origin.
// Returns: "strong" | "weak" | "none"
function _classifyOriginCheckInCallee(callPath, argIdx) {
  var callee = callPath.node.callee;
  var funcPath = null;

  // Direct identifier: validate(event.origin) → resolve binding
  if (_t.isIdentifier(callee)) {
    var binding = callPath.scope.getBinding(callee.name);
    if (binding) {
      if (_t.isFunctionDeclaration(binding.path.node)) funcPath = binding.path;
      else if (binding.path.isVariableDeclarator() && binding.path.node.init &&
               _t.isFunction(binding.path.node.init)) funcPath = binding.path.get("init");
    }
  }

  // Member expression: c.i(event.origin) → resolve object binding, find method
  if (!funcPath && _t.isMemberExpression(callee) && !callee.computed && _t.isIdentifier(callee.property)) {
    var methodName = callee.property.name;
    var objNode = callee.object;
    var objBinding = _t.isIdentifier(objNode) ? callPath.scope.getBinding(objNode.name) : null;
    if (objBinding && objBinding.path.isVariableDeclarator() && objBinding.path.node.init) {
      var objInit = objBinding.path.node.init;
      if (_t.isObjectExpression(objInit)) {
        for (var pi = 0; pi < objInit.properties.length; pi++) {
          var prop = objInit.properties[pi];
          if (_t.isObjectProperty(prop) && !prop.computed &&
              ((_t.isIdentifier(prop.key) && prop.key.name === methodName) ||
               (_t.isStringLiteral(prop.key) && prop.key.value === methodName)) &&
              _t.isFunction(prop.value)) {
            funcPath = objBinding.path.get("init.properties." + pi + ".value");
            break;
          }
          if (_t.isObjectMethod(prop) && !prop.computed &&
              _t.isIdentifier(prop.key) && prop.key.name === methodName) {
            funcPath = objBinding.path.get("init.properties." + pi);
            break;
          }
        }
      }
    }
  }

  if (!funcPath || !funcPath.node.params || argIdx >= funcPath.node.params.length) return "none";
  var param = funcPath.node.params[argIdx];
  var paramName = _t.isIdentifier(param) ? param.name :
                  (_t.isAssignmentPattern(param) && _t.isIdentifier(param.left)) ? param.left.name : null;
  if (!paramName) return "none";

  // Traverse the function body checking for comparisons/method calls on the parameter
  var innerStrong = false, innerWeak = false;
  try {
    funcPath.get("body").traverse({
      BinaryExpression: function(bp) {
        if (innerStrong) { bp.stop(); return; }
        var op = bp.node.operator;
        if (op === "===" || op === "!==" || op === "==" || op === "!=") {
          if (_t.isIdentifier(bp.node.left, { name: paramName }) || _t.isIdentifier(bp.node.right, { name: paramName })) {
            // Verify via scope that this identifier refers to the parameter, not a shadowed local
            var paramBinding = bp.scope.getBinding(paramName);
            if (paramBinding && paramBinding.kind === "param" && paramBinding.scope === funcPath.scope) {
              innerStrong = true; bp.stop();
            }
          }
        }
      },
      CallExpression: function(cp) {
        if (innerStrong) { cp.stop(); return; }
        var cc = cp.node.callee;
        if (_t.isMemberExpression(cc) && _t.isIdentifier(cc.property) &&
            _t.isIdentifier(cc.object, { name: paramName })) {
          var cmn = cc.property.name;
          if (cmn === "indexOf" || cmn === "includes" || cmn === "startsWith" || cmn === "endsWith") {
            var paramBinding = cp.scope.getBinding(paramName);
            if (paramBinding && paramBinding.kind === "param" && paramBinding.scope === funcPath.scope) {
              innerWeak = true;
            }
          }
        }
      },
    });
  } catch (e) { _resolver.collectError(e, "paramValidationType"); }
  if (innerStrong) return "strong";
  if (innerWeak) return "weak";
  return "none";
}

function _hasPropertyMember(node, propName) {
  if (!node) return false;
  return _t.isMemberExpression(node) && _t.isIdentifier(node.property, { name: propName });
}

// Assignment-based dangerous patterns: prototype pollution, onmessage handler
function _processDangerousAssignment(path, result) {
  var node = path.node;
  if (node.operator !== "=") return;
  var left = node.left;

  // window.onmessage = handler / self.onmessage = handler — postMessage handler
  if (_t.isMemberExpression(left) && !left.computed && _t.isIdentifier(left.property, { name: "onmessage" })) {
    var _omBase = left.object;
    var _isGlobal = (_t.isIdentifier(_omBase, { name: "window" }) && !path.scope.getBinding("window")) ||
                    (_t.isIdentifier(_omBase, { name: "self" }) && !path.scope.getBinding("self"));
    if (_isGlobal) {
      var _omResolved = _resolveHandlerFunc(path.get("right"));
      if (_omResolved && _omResolved.node.body) _classifyAndReportMessageHandler(_omResolved, node, result);
      return;
    }
  }

  // Prototype pollution: obj.__proto__ = tainted
  if (_t.isMemberExpression(left) && !left.computed &&
      _t.isIdentifier(left.property, { name: "__proto__" })) {
    var _protoSrc = _traceValueSource(path.get("right"), 0);
    if (_protoSrc.sourceType === "user-controlled") {
      _pushDangerous(result, node, "prototype-pollution", "Direct __proto__ assignment with user-controlled value", "high", _protoSrc);
    }
    return;
  }

  // Prototype pollution: obj[dynamicKey] = value
  if (_t.isMemberExpression(left) && left.computed) {
    var keyNode = left.property;
    if (!_t.isStringLiteral(keyNode) && !_t.isNumericLiteral(keyNode)) {
      var keySource = _traceValueSource(path.get("left.property"), 0);
      if (keySource.sourceType === "user-controlled") {
        _pushDangerous(result, node, "prototype-pollution", "Dynamic property assignment with user-controlled key", "high", keySource);
      }
    }
  }
}

// ─── Proto Field Detection ──────────────────────────────────────────────────

function _detectProtoFieldAssignment(path, result) {
  var node = path.node;
  if (!_t.isFunctionExpression(node.right) && !_t.isArrowFunctionExpression(node.right)) return;
  if (!_t.isMemberExpression(node.left)) return;

  var memberProp = node.left.property;
  var accessorName = _t.isIdentifier(memberProp) ? memberProp.name : null;
  if (!accessorName) return;

  var leftObj = node.left.object;
  if (!_t.isMemberExpression(leftObj)) return;
  var objProp = leftObj.property;
  if (!(_t.isIdentifier(objProp, { name: "prototype" }) ||
        (_t.isStringLiteral(objProp) && objProp.value === "prototype"))) return;

  _stats.protoMethods++;

  var protoOwner = _t.isIdentifier(leftObj.object) ? leftObj.object.name :
    (_t.isMemberExpression(leftObj.object) && _t.isIdentifier(leftObj.object.property) ? leftObj.object.property.name : "?");

  var fieldNumber = _findFieldNumberInFunction(path.get("right"));
  if (fieldNumber == null) {
    _stats.protoMethodsNoField++;
    return;
  }

  result.protoFieldMaps.push({
    fieldNumber: fieldNumber,
    fieldName: accessorName,
    accessorName: accessorName,
    minified: true,
  });
  console.debug("[AST:proto] Field #%d → %s (%s.prototype.%s)", fieldNumber, accessorName, protoOwner, accessorName);
}

function _findFieldNumberInFunction(funcPath) {
  var found = null;
  try {
    funcPath.traverse({
      CallExpression: function(innerPath) {
        if (found != null) { innerPath.stop(); return; }
        var callee = innerPath.node.callee;
        var args = innerPath.node.arguments;

        // obj.method(this, N)
        if (_t.isMemberExpression(callee) && args.length >= 2 &&
            _t.isThisExpression(args[0]) &&
            _t.isNumericLiteral(args[1]) && args[1].value >= 1) {
          found = args[1].value;
          innerPath.stop();
          return;
        }
        // f(this, N)
        if (_t.isIdentifier(callee) && args.length >= 2 &&
            _t.isThisExpression(args[0]) &&
            _t.isNumericLiteral(args[1]) && args[1].value >= 1) {
          found = args[1].value;
          innerPath.stop();
        }
      },
      MemberExpression: function(innerPath) {
        if (found != null) { innerPath.stop(); return; }
        var node = innerPath.node;
        // this.array[N]
        if (node.computed && _t.isMemberExpression(node.object) &&
            _t.isThisExpression(node.object.object) &&
            _t.isNumericLiteral(node.property) && node.property.value >= 1) {
          found = node.property.value;
          innerPath.stop();
        }
      },
    });
  } catch (e) { _resolver.collectError(e, "findFieldNumber"); }
  return found;
}

// ─── Enum Detection ─────────────────────────────────────────────────────────

function _detectEnumObject(node, result) {
  var props = node.properties;
  if (!props || props.length < 4) return; // minimum: 2 forward + 2 reverse

  // Collect forward (string/identifier key → integer value) and reverse (numeric key → string value)
  var forward = {}; // stringKey → numericValue
  var reverse = {}; // numericValue → stringKey (keyed by the numeric KEY from reverse entries)
  var forwardCount = 0, reverseCount = 0;

  for (var i = 0; i < props.length; i++) {
    var prop = props[i];
    if (!_t.isObjectProperty(prop) || prop.computed) return;

    var key = prop.key;
    var val = prop.value;

    // Forward entry: string/identifier key → numeric literal value
    if ((_t.isIdentifier(key) || _t.isStringLiteral(key)) &&
        (_t.isNumericLiteral(val) || (_t.isUnaryExpression(val, { operator: "-" }) && _t.isNumericLiteral(val.argument)))) {
      var kStr = _t.isIdentifier(key) ? key.name : key.value;
      var kVal = _t.isNumericLiteral(val) ? val.value : -val.argument.value;
      forward[kStr] = kVal;
      forwardCount++;
    }
    // Reverse entry: numeric literal key → string literal value
    else if (_t.isNumericLiteral(key) && _t.isStringLiteral(val)) {
      reverse[key.value] = val.value;
      reverseCount++;
    }
    // Any other property type — not a bidirectional enum
    else {
      return;
    }
  }

  // Require both directions present
  if (forwardCount === 0 || reverseCount === 0) return;
  if (forwardCount !== reverseCount) return;

  // Verify bidirectional consistency: forward[k]=v ↔ reverse[v]=k
  var forwardKeys = Object.keys(forward);
  for (var fi = 0; fi < forwardKeys.length; fi++) {
    var fk = forwardKeys[fi];
    var fv = forward[fk];
    if (reverse[fv] !== fk) return;
  }

  result.protoEnums.push({ values: forward });
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function _getKeyName(node) {
  if (_t.isIdentifier(node)) return node.name;
  if (_t.isStringLiteral(node)) return node.value;
  if (_t.isNumericLiteral(node)) return String(node.value);
  return null;
}

function _getObjectKeys(objNode) {
  var keys = [];
  for (var i = 0; i < objNode.properties.length; i++) {
    var p = objNode.properties[i];
    if (_t.isSpreadElement(p) || (p.computed)) continue;
    var name = _getKeyName(p.key);
    if (name) keys.push(name);
  }
  return keys;
}

// Find the property key name for a binding inside an ObjectPattern.
// Given function f({url, method: m, endpoint: ep = "/default"}) { ... }
// and bindingName "url" → returns "url", "m" → returns "method", "ep" → returns "endpoint"
function _findDestructuredKey(objPattern, bindingName) {
  for (var i = 0; i < objPattern.properties.length; i++) {
    var dp = objPattern.properties[i];
    if (_t.isRestElement(dp)) continue;
    if (!_t.isObjectProperty(dp)) continue;
    var keyName = _t.isIdentifier(dp.key) ? dp.key.name :
      (_t.isStringLiteral(dp.key) ? dp.key.value : null);
    if (!keyName) continue;

    // Shorthand: {url} → key=url, value=url (Identifier)
    // Renamed: {method: m} → key=method, value=m (Identifier)
    // With default: {url = "/default"} → key=url, value=AssignmentPattern(left=url)
    var valName = null;
    if (_t.isIdentifier(dp.value)) {
      valName = dp.value.name;
    } else if (_t.isAssignmentPattern(dp.value) && _t.isIdentifier(dp.value.left)) {
      valName = dp.value.left.name;
    }
    if (valName === bindingName) return keyName;
  }
  return null;
}

function _isJsonStringify(node, path) {
  if (!node || !_t.isCallExpression(node)) return false;
  var c = node.callee;
  if (!_t.isMemberExpression(c) ||
      !_t.isIdentifier(c.object, { name: "JSON" }) ||
      !_t.isIdentifier(c.property, { name: "stringify" })) return false;
  // Verify JSON is the global, not a shadowed local
  if (path && path.scope.getBinding("JSON")) return false;
  return true;
}

function _extractLiteralArray(node) {
  if (!_t.isArrayExpression(node)) return [];
  var values = [];
  for (var i = 0; i < node.elements.length; i++) {
    var el = node.elements[i];
    if (!el) continue;
    if (_t.isStringLiteral(el) || _t.isNumericLiteral(el)) values.push(el.value);
  }
  return values;
}

function _collectIdentifiers(node, set) {
  // Iterative: walk all expression types via explicit stack
  var stack = [node];
  while (stack.length > 0) {
    var n = stack.pop();
    if (!n) continue;
    if (_t.isIdentifier(n)) { set.add(n.name); continue; }
    if (_t.isBinaryExpression(n) || _t.isLogicalExpression(n)) {
      stack.push(n.left, n.right);
    }
    if (_t.isConditionalExpression(n)) {
      stack.push(n.test, n.consequent, n.alternate);
    }
    if (_t.isCallExpression(n)) {
      for (var i = 0; i < n.arguments.length; i++) { stack.push(n.arguments[i]); }
    }
    if (_t.isNewExpression(n)) {
      for (var ni = 0; ni < n.arguments.length; ni++) { stack.push(n.arguments[ni]); }
    }
    if (_t.isTemplateLiteral(n)) {
      for (var j = 0; j < n.expressions.length; j++) { stack.push(n.expressions[j]); }
    }
    if (_t.isMemberExpression(n)) {
      stack.push(n.object);
    }
  }
}

function _describeNode(node) {
  if (_t.isIdentifier(node)) return node.name;
  if (_t.isMemberExpression(node)) {
    var propName = _t.isIdentifier(node.property) ? node.property.name :
      (_t.isStringLiteral(node.property) ? "[" + node.property.value + "]" : "?");
    if (_t.isIdentifier(node.object)) return node.object.name + "." + propName;
    if (_t.isThisExpression(node.object)) return "this." + propName;
    if (_t.isMemberExpression(node.object)) return _describeNode(node.object) + "." + propName;
    return "(" + node.object.type + ")." + propName;
  }
  return "(" + node.type + ")";
}

// ─── CFG Builder + Sanitizer Path Analysis ──────────────────────────────────

// Known sanitizer globals — calling these on tainted data neutralizes it
var _SANITIZER_GLOBALS = { "encodeURIComponent":1, "encodeURI":1, "parseInt":1, "parseFloat":1, "escape":1, "btoa":1 };

// Known sanitizer methods — obj.sanitize(), obj.encode(), DOMPurify.sanitize()
var _SANITIZER_METHODS = { "sanitize":1, "encode":1 };

// Known sanitizer objects — DOMPurify.sanitize()
var _SANITIZER_OBJECTS = { "DOMPurify":1 };

// Check if a single call expression node is a known sanitizer.
// When a path is provided, verifies that sanitizer globals aren't shadowed by local bindings.
function _isSanitizerCall(node, path) {
  if (!_t.isCallExpression(node)) return false;
  var callee = node.callee;
  // Global sanitizer functions: encodeURIComponent, parseInt, etc.
  if (_t.isIdentifier(callee) && _SANITIZER_GLOBALS[callee.name]) {
    // If path available, verify the identifier isn't shadowed
    if (path && path.scope) {
      return !path.scope.getBinding(callee.name);
    }
    return true;
  }
  // Method sanitizers: DOMPurify.sanitize(), obj.encode(), etc.
  if (_t.isMemberExpression(callee) && !callee.computed && _t.isIdentifier(callee.property)) {
    if (_SANITIZER_METHODS[callee.property.name]) {
      // For known sanitizer objects (DOMPurify), verify the object isn't shadowed
      if (_t.isIdentifier(callee.object) && _SANITIZER_OBJECTS[callee.object.name]) {
        if (path && path.scope) return !path.scope.getBinding(callee.object.name);
        return true;
      }
      return true;
    }
    if (_t.isIdentifier(callee.object) && _SANITIZER_OBJECTS[callee.object.name]) {
      if (path && path.scope) return !path.scope.getBinding(callee.object.name);
      return true;
    }
  }
  return false;
}

// Check if a statement path contains a sanitizer call at this level only.
// Does NOT recurse into sub-statements (if/else/for/while) since those are
// represented as separate blocks in the CFG.
function _stmtContainsSanitizer(stmtPath) {
  if (!stmtPath || !stmtPath.node) return false;
  var node = stmtPath.node;
  // For IfStatement: only check the test expression, not consequent/alternate
  // (those are separate blocks in the CFG)
  if (_t.isIfStatement(node)) {
    return _exprContainsSanitizer(stmtPath.get("test"));
  }
  // For loop statements: only check the init/test/update, not body
  if (_t.isForStatement(node)) {
    return _exprContainsSanitizer(stmtPath.get("init")) ||
           _exprContainsSanitizer(stmtPath.get("test")) ||
           _exprContainsSanitizer(stmtPath.get("update"));
  }
  if (_t.isWhileStatement(node) || _t.isDoWhileStatement(node)) {
    return _exprContainsSanitizer(stmtPath.get("test"));
  }
  // For BlockStatement/ExpressionStatement/VariableDeclaration: traverse with scope
  var found = false;
  stmtPath.traverse({
    // Skip nested control flow — those are separate CFG blocks
    IfStatement: function(p) { p.skip(); },
    ForStatement: function(p) { p.skip(); },
    WhileStatement: function(p) { p.skip(); },
    DoWhileStatement: function(p) { p.skip(); },
    SwitchStatement: function(p) { p.skip(); },
    CallExpression: function(innerPath) {
      if (found) { innerPath.stop(); return; }
      if (_isSanitizerCall(innerPath.node, innerPath)) {
        found = true; innerPath.stop();
      }
    },
  });
  return found;
}

// Check if an expression path contains a sanitizer call
function _exprContainsSanitizer(exprPath) {
  if (!exprPath || !exprPath.node) return false;
  if (_isSanitizerCall(exprPath.node, exprPath)) return true;
  var found = false;
  exprPath.traverse({
    CallExpression: function(innerPath) {
      if (found) { innerPath.stop(); return; }
      if (_isSanitizerCall(innerPath.node, innerPath)) {
        found = true; innerPath.stop();
      }
    },
  });
  return found;
}

// Build a basic-block CFG from a function body path (BlockStatement)
// Stores statement paths (not raw nodes) so sanitizer detection can use scope.
function _buildCFG(bodyPath) {
  if (!bodyPath || !bodyPath.node || !Array.isArray(bodyPath.node.body)) return null;
  var blockId = 0;
  var blocks = {};
  var stmts = bodyPath.node.body;

  function makeBlock(stmtPaths) {
    var id = blockId++;
    blocks[id] = { id: id, stmts: stmtPaths || [], succs: [], preds: [] };
    return id;
  }

  // Simple linear CFG: one block per statement (sufficient for sanitizer-before-sink)
  var entryId = makeBlock([]);
  var prevId = entryId;
  for (var i = 0; i < stmts.length; i++) {
    var stmt = stmts[i];
    var stmtPath = bodyPath.get("body." + i);
    var bid = makeBlock([stmtPath]);
    blocks[prevId].succs.push(bid);
    blocks[bid].preds.push(prevId);

    if (_t.isIfStatement(stmt)) {
      // If statement: consequent and alternate branches
      var joinId = makeBlock([]);
      // consequent branch
      var consId = makeBlock(stmt.consequent ? [stmtPath.get("consequent")] : []);
      blocks[bid].succs.push(consId);
      blocks[consId].preds.push(bid);
      blocks[consId].succs.push(joinId);
      blocks[joinId].preds.push(consId);
      // alternate branch
      if (stmt.alternate) {
        var altId = makeBlock([stmtPath.get("alternate")]);
        blocks[bid].succs.push(altId);
        blocks[altId].preds.push(bid);
        blocks[altId].succs.push(joinId);
        blocks[joinId].preds.push(altId);
      } else {
        // No else: direct edge from if-block to join
        blocks[bid].succs.push(joinId);
        blocks[joinId].preds.push(bid);
      }
      prevId = joinId;
    } else {
      prevId = bid;
    }
  }
  var exitId = makeBlock([]);
  blocks[prevId].succs.push(exitId);
  blocks[exitId].preds.push(prevId);

  return { blocks: blocks, entry: entryId, exit: exitId };
}

// Find which block contains a statement at a given line
function _findBlockForLine(cfg, line) {
  if (!cfg) return -1;
  var keys = Object.keys(cfg.blocks);
  for (var i = 0; i < keys.length; i++) {
    var blk = cfg.blocks[keys[i]];
    for (var j = 0; j < blk.stmts.length; j++) {
      var s = blk.stmts[j];
      var sNode = s && s.node ? s.node : s;
      if (sNode && sNode.loc) {
        if (sNode.loc.start.line <= line && sNode.loc.end.line >= line) return blk.id;
      }
    }
  }
  return -1;
}

// Find all blocks that contain sanitizer calls
function _findSanitizerBlocks(cfg) {
  var result = {};
  if (!cfg) return result;
  var keys = Object.keys(cfg.blocks);
  for (var i = 0; i < keys.length; i++) {
    var blk = cfg.blocks[keys[i]];
    for (var j = 0; j < blk.stmts.length; j++) {
      if (_stmtContainsSanitizer(blk.stmts[j])) {
        result[blk.id] = true;
        break;
      }
    }
  }
  return result;
}

// Check if all paths from entry to sinkBlock pass through a sanitizer block
function _hasSanitizerOnAllPaths(cfg, sinkBlockId, sanitizerBlocks) {
  if (!cfg) return false;
  // BFS from entry to sinkBlock, checking if every path passes through a sanitizer
  // Use DFS with path tracking
  var found = false;
  var allSanitized = true;

  function dfs(blockId, visited, sawSanitizer) {
    if (!allSanitized) return;
    if (blockId === sinkBlockId) {
      found = true;
      if (!sawSanitizer) allSanitized = false;
      return;
    }
    var blk = cfg.blocks[blockId];
    if (!blk) return;
    var nextSanitizer = sawSanitizer || !!sanitizerBlocks[blockId];
    for (var i = 0; i < blk.succs.length; i++) {
      var next = blk.succs[i];
      if (visited[next]) continue;
      visited[next] = true;
      dfs(next, visited, nextSanitizer);
      visited[next] = false;
    }
  }

  var visited = {};
  visited[cfg.entry] = true;
  dfs(cfg.entry, visited, !!sanitizerBlocks[cfg.entry]);
  return found && allSanitized;
}

// Check if the sink at the given path is sanitized on all control flow paths
function _checkSanitization(path) {
  // Find the enclosing function
  var funcPath = path.getFunctionParent();
  if (!funcPath) return false;
  var funcBody = funcPath.node.body;
  if (!_t.isBlockStatement(funcBody)) return false;

  // Build CFG from body path (stores statement paths for scope-aware sanitizer detection)
  var bodyPath = funcPath.get("body");
  var cfg = _buildCFG(bodyPath);
  if (!cfg) return false;

  // Find sanitizer blocks
  var sanitizerBlocks = _findSanitizerBlocks(cfg);
  if (Object.keys(sanitizerBlocks).length === 0) return false;

  // Find sink block
  var sinkLine = path.node.loc ? path.node.loc.start.line : -1;
  if (sinkLine === -1) return false;
  var sinkBlockId = _findBlockForLine(cfg, sinkLine);
  if (sinkBlockId === -1) return false;

  return _hasSanitizerOnAllPaths(cfg, sinkBlockId, sanitizerBlocks);
}

function extractSourceMapUrl(code) {
  var tail = code.length > 500 ? code.slice(-500) : code;
  var marker = "sourceMappingURL=";
  var idx = tail.indexOf(marker);
  if (idx === -1) return null;
  var start = idx + marker.length;
  while (start < tail.length && (tail.charCodeAt(start) === 32 || tail.charCodeAt(start) === 9)) start++;
  var end = start;
  while (end < tail.length && tail.charCodeAt(end) > 32) end++;
  return end > start ? tail.substring(start, end) : null;
}
