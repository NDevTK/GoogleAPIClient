// lib/ast.js — AST-based JS bundle analysis engine
// Uses Babel parser + traverse for scope-aware data flow tracing.
// Traces from call sites through wrapper functions to network sinks
// (fetch, XMLHttpRequest) to learn API parameters and valid values.

var _babelParse = BabelBundle.parse;
var _babelTraverse = BabelBundle.traverse;
var _t = BabelBundle.t;

var _HTTP_METHODS_LC = { "get":1, "post":1, "put":1, "delete":1, "patch":1, "head":1, "options":1 };

// Per-analysis state
var _constraints = {};  // scopeUid:varName → { varName, values: Set, sources: [] }
var _stats = null;

function analyzeJSBundle(code, sourceUrl) {
  _constraints = {};
  _stats = { protoMethods: 0, protoMethodsNoField: 0, resolvedUrls: 0, interProcTraces: 0 };

  var result = {
    sourceUrl: sourceUrl,
    protoEnums: [],
    protoFieldMaps: [],
    fetchCallSites: [],
    valueConstraints: [],
    sourceMapUrl: extractSourceMapUrl(code),
  };

  var ast = null;
  try {
    ast = _babelParse(code, { sourceType: "module", plugins: ["jsx"], errorRecovery: true });
  } catch (e1) {
    try {
      ast = _babelParse(code, { sourceType: "script", plugins: ["jsx"], errorRecovery: true });
    } catch (e2) {
      console.debug("[AST] Parse FAILED for %s (%d chars) — %s", sourceUrl, code.length, e2.message);
      return result;
    }
  }

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
          if (keys.length >= 2) {
            _addConstraint(path, path.node.left.name, keys, "in_object");
          }
        }
      }
    },
    CallExpression: function(path) {
      _collectIncludesConstraints(path);
      _processNetworkSink(path, result);
    },
    // ── Proto and enum detection ──
    ObjectExpression: function(path) {
      _detectEnumObject(path.node, result);
    },
    AssignmentExpression: function(path) {
      _detectProtoFieldAssignment(path, result);
    },
  });

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

  // ── Summary ──
  if (result.protoEnums.length || result.protoFieldMaps.length || result.fetchCallSites.length || varNames.length) {
    console.debug("[AST] %s (%d chars) → %d enums, %d fieldMaps, %d fetchSites, %d constraints, %d interProc, sourceMap=%s",
      sourceUrl, code.length, result.protoEnums.length, result.protoFieldMaps.length,
      result.fetchCallSites.length, varNames.length, _stats.interProcTraces,
      result.sourceMapUrl || "none");
  }
  if (_stats.protoMethods > 0) {
    console.debug("[AST:proto] %s — %d prototype methods, %d matched, %d unmatched",
      sourceUrl, _stats.protoMethods, _stats.protoMethods - _stats.protoMethodsNoField, _stats.protoMethodsNoField);
  }

  _constraints = {};
  _stats = null;
  return result;
}

// ─── Network Sink Detection & Inter-Procedural Tracing ──────────────────────

function _processNetworkSink(path, result) {
  var node = path.node;
  var callee = node.callee;

  // ── Identify fetch() / window.fetch() — verify these are actual globals via scope ──
  if (_t.isIdentifier(callee, { name: "fetch" }) && !path.scope.getBinding("fetch")) {
    _extractFetchCall(path, result, "fetch");
    return;
  }
  if (_t.isMemberExpression(callee) &&
      _t.isIdentifier(callee.object, { name: "window" }) && !path.scope.getBinding("window") &&
      _t.isIdentifier(callee.property, { name: "fetch" })) {
    _extractFetchCall(path, result, "fetch");
    return;
  }

  // ── Identify XMLHttpRequest.open(method, url) ──
  if (_t.isMemberExpression(callee) &&
      _t.isIdentifier(callee.property, { name: "open" }) &&
      node.arguments.length >= 2) {
    var methodArg = node.arguments[0];
    if (_t.isStringLiteral(methodArg) && _HTTP_METHODS_LC[methodArg.value.toLowerCase()]) {
      var urlArg = path.get("arguments.1");
      var urls = _resolveAllValues(urlArg, 0);

      // Extract headers and body from .setRequestHeader() and .send() on the same variable
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
            if (memberName === "send" && callPath.node.arguments.length > 0) {
              xhrBodyParams = _extractBodyParams(callPath.node.arguments[0], callPath);
            }
            if (memberName === "setRequestHeader" && callPath.node.arguments.length >= 2) {
              var hdrName = _t.isStringLiteral(callPath.node.arguments[0]) ? callPath.node.arguments[0].value : null;
              var hdrVal = _t.isStringLiteral(callPath.node.arguments[1]) ? callPath.node.arguments[1].value : null;
              if (hdrName) xhrHeaders[hdrName.toLowerCase()] = hdrVal || "(dynamic)";
            }
          }
        }
      }

      for (var i = 0; i < urls.length; i++) {
        var xhrSite = {
          url: urls[i],
          method: methodArg.value.toUpperCase(),
          headers: xhrHeaders,
          type: "xhr",
        };
        if (xhrBodyParams.length > 0) xhrSite.params = xhrBodyParams;
        result.fetchCallSites.push(xhrSite);
        var xhrParamStr = "";
        if (xhrBodyParams.length > 0) {
          xhrParamStr = " params=[" + xhrBodyParams.map(function(p) { return p.name + ":" + (p.location || "body"); }).join(", ") + "]";
        }
        console.debug("[AST:fetch] xhr %s %s%s", methodArg.value.toUpperCase(), urls[i], xhrParamStr);
      }
    }
    return;
  }

  // ── Check if this is a call to a function that contains a network sink ──
  // Inter-procedural: if callee resolves to a function definition that has fetch/XHR inside
  var funcNode = _resolveCalleeToFunction(path);
  if (funcNode) {
    // For wrapper tracing, we need a binding with referencePaths to find callers.
    // Identifier callees have a direct binding; member expression callees don't,
    // so wrapper tracing (finding OTHER callers) only works for identifier callees.
    var calleeBinding = _t.isIdentifier(callee) ? path.scope.getBinding(callee.name) : null;
    if (calleeBinding) {
      _traceWrapperFunction(path, funcNode, calleeBinding, result);
    }
  }
}

// Resolve a call expression's callee to its function node
function _resolveCalleeToFunction(callPath) {
  var callee = callPath.node.callee;

  // Direct identifier: doFetch(url) → resolve doFetch through scope
  if (_t.isIdentifier(callee)) {
    var binding = callPath.scope.getBinding(callee.name);
    if (!binding || !binding.path) return null;
    if (_t.isVariableDeclarator(binding.path.node) && binding.path.node.init) {
      var init = binding.path.node.init;
      if (_t.isFunctionExpression(init) || _t.isArrowFunctionExpression(init)) return init;
    }
    if (_t.isFunctionDeclaration(binding.path.node)) return binding.path.node;
    return null;
  }

  // Member expression: obj.method(url) → resolve obj, find method property
  if (_t.isMemberExpression(callee) && !callee.computed) {
    var propName = _t.isIdentifier(callee.property) ? callee.property.name : null;
    if (!propName) return null;

    // First try: obj is an inline or variable-bound object literal with the method defined inline
    var objNode = _resolveToObject(callPath.get("callee.object"), 0);
    if (objNode) {
      for (var i = 0; i < objNode.properties.length; i++) {
        var prop = objNode.properties[i];
        if (!_t.isObjectProperty(prop) || prop.computed) continue;
        var key = _t.isIdentifier(prop.key) ? prop.key.name :
          (_t.isStringLiteral(prop.key) ? prop.key.value : null);
        if (key === propName) {
          if (_t.isFunctionExpression(prop.value) || _t.isArrowFunctionExpression(prop.value)) {
            return prop.value;
          }
        }
      }
    }

    // Second try: method assigned separately (Closure pattern: a.b = function(url) { ... })
    // Use referencePaths since Babel doesn't track property mutations as constantViolations
    if (_t.isIdentifier(callee.object)) {
      var objBinding = callPath.scope.getBinding(callee.object.name);
      if (objBinding) {
        var refs = objBinding.referencePaths;
        for (var cv = 0; cv < refs.length; cv++) {
          var refParent = refs[cv].parent;
          if (_t.isMemberExpression(refParent) && refParent.object === refs[cv].node &&
              !refParent.computed && _t.isIdentifier(refParent.property, { name: propName })) {
            var assignExpr = refs[cv].parentPath ? refs[cv].parentPath.parent : null;
            if (assignExpr && _t.isAssignmentExpression(assignExpr) && assignExpr.operator === "=" &&
                assignExpr.left === refParent) {
              if (_t.isFunctionExpression(assignExpr.right) || _t.isArrowFunctionExpression(assignExpr.right)) {
                return assignExpr.right;
              }
            }
          }
        }
      }
    }
  }

  return null;
}

function _traceWrapperFunction(callPath, funcNode, funcBinding, result) {
  // Check if the function body contains a direct fetch/XHR call
  var sinkInfo = _findSinkInFunction(funcNode);
  if (!sinkInfo) return;

  _stats.interProcTraces++;

  // Map caller's arguments to function parameters
  var paramBindings = {};
  var callArgs = callPath.node.arguments;
  for (var i = 0; i < funcNode.params.length && i < callArgs.length; i++) {
    var param = funcNode.params[i];
    var paramName = _t.isIdentifier(param) ? param.name :
      (_t.isAssignmentPattern(param) && _t.isIdentifier(param.left) ? param.left.name : null);
    if (paramName) {
      var argPath = callPath.get("arguments." + i);
      var resolved = _resolveAllValues(argPath, 1);
      if (resolved.length > 0) {
        paramBindings[paramName] = resolved;
      }
    }
  }

  // Build call sites using the sink info + resolved parameter values
  var urls = [];
  if (sinkInfo.urlParamName && paramBindings[sinkInfo.urlParamName]) {
    urls = paramBindings[sinkInfo.urlParamName];
  } else if (sinkInfo.urlLiteral) {
    urls = [sinkInfo.urlLiteral];
  }
  if (urls.length === 0) return;

  var method = sinkInfo.method || "GET";
  if (sinkInfo.methodParamName && paramBindings[sinkInfo.methodParamName]) {
    method = paramBindings[sinkInfo.methodParamName][0];
    if (typeof method === "string") method = method.toUpperCase();
    else method = "GET";
  }

  // Get enclosing function name for the CALLER
  var callerFunc = callPath.getFunctionParent();
  var callerName = null;
  if (callerFunc && callerFunc.node.id) callerName = callerFunc.node.id.name;

  for (var u = 0; u < urls.length; u++) {
    var callSite = {
      url: urls[u],
      method: method,
      headers: sinkInfo.headers || {},
      type: "fetch",
      params: sinkInfo.params,
      enclosingFunction: callerName,
    };
    result.fetchCallSites.push(callSite);
    console.debug("[AST:fetch] traced %s %s via %s()", method, urls[u],
      funcBinding.identifier.name || "?");
  }
}

function _findSinkInFunction(funcNode) {
  var sinkInfo = null;
  try {
    // Walk the function body looking for fetch() or XHR.open()
    _babelTraverse(funcNode.body, {
      CallExpression: function(innerPath) {
        if (sinkInfo) { innerPath.stop(); return; }
        var c = innerPath.node.callee;

        // fetch(url, opts) or window.fetch(url, opts) — no scope here (noScope traversal),
        // but this is inside a wrapper function body so fetch/window can't be locally bound
        var isFetch = _t.isIdentifier(c, { name: "fetch" }) ||
          (_t.isMemberExpression(c) && _t.isIdentifier(c.object, { name: "window" }) && _t.isIdentifier(c.property, { name: "fetch" }));

        if (isFetch && innerPath.node.arguments.length >= 1) {
          sinkInfo = _extractSinkInfo(innerPath);
          innerPath.stop();
          return;
        }

        // XHR.open(method, url)
        if (_t.isMemberExpression(c) && _t.isIdentifier(c.property, { name: "open" }) &&
            innerPath.node.arguments.length >= 2 &&
            _t.isStringLiteral(innerPath.node.arguments[0]) &&
            _HTTP_METHODS_LC[innerPath.node.arguments[0].value.toLowerCase()]) {
          sinkInfo = {
            method: innerPath.node.arguments[0].value.toUpperCase(),
            urlParamName: _t.isIdentifier(innerPath.node.arguments[1]) ? innerPath.node.arguments[1].name : null,
            urlLiteral: _t.isStringLiteral(innerPath.node.arguments[1]) ? innerPath.node.arguments[1].value : null,
            headers: {},
          };
          innerPath.stop();
        }
      },
      // Don't descend into nested functions — they have their own scope
      FunctionDeclaration: function(p) { p.skip(); },
      FunctionExpression: function(p) { p.skip(); },
      ArrowFunctionExpression: function(p) { p.skip(); },
    }, null, { noScope: true });
  } catch (_) {}
  return sinkInfo;
}

function _extractSinkInfo(fetchPath) {
  var args = fetchPath.node.arguments;
  var urlNode = args[0];
  var info = {
    urlParamName: _t.isIdentifier(urlNode) ? urlNode.name : null,
    urlLiteral: _t.isStringLiteral(urlNode) ? urlNode.value : null,
    method: null,
    methodParamName: null,
    headers: {},
    params: undefined,
  };

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
      }
      if (key === "headers" && _t.isObjectExpression(val)) {
        info.headers = _extractHeaders(val);
      }
      if (key === "body") {
        info.params = _extractBodyParams(val);
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

  // Completely dynamic → placeholder
  if (urls.length === 0 && args[0]) {
    if (_t.isIdentifier(args[0])) urls = ["${" + args[0].name + "}"];
    else if (_t.isMemberExpression(args[0])) urls = ["${" + _describeNode(args[0]) + "}"];
    else urls = ["(dynamic)"];
  }

  if (urls.length === 0) return;

  // ── Extract method, headers, body from options ──
  var httpMethod = null;
  var headers = {};
  var bodyParams = [];

  // Resolve options object — inline or via variable reference
  var optsNode = args[1] || null;
  var optsPath = args[1] ? path.get("arguments.1") : null;
  if (optsNode && _t.isIdentifier(optsNode) && optsPath) {
    var optsBinding = path.scope.getBinding(optsNode.name);
    if (optsBinding && _t.isVariableDeclarator(optsBinding.path.node) && optsBinding.path.node.init) {
      optsNode = optsBinding.path.node.init;
      optsPath = optsBinding.path.get("init");
    }
  }

  if (optsNode && _t.isObjectExpression(optsNode)) {
    var opts = optsNode.properties;
    for (var o = 0; o < opts.length; o++) {
      if (!_t.isObjectProperty(opts[o]) || opts[o].computed) continue;
      var optName = _getKeyName(opts[o].key);
      var optVal = opts[o].value;

      if (optName === "method") {
        var methodPath = optsPath.get("properties." + o + ".value");
        var methodVals = _resolveAllValues(methodPath, 0);
        if (methodVals.length > 0 && typeof methodVals[0] === "string" && _HTTP_METHODS_LC[methodVals[0].toLowerCase()]) {
          httpMethod = methodVals[0].toUpperCase();
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
        if (loc !== "unknown") {
          funcParams.push({ name: fParam.name, location: loc, required: fParam.required, defaultValue: fParam.defaultValue, source: "function_param" });
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
    var pName = params[vc].source || params[vc].name;
    var constraint = _getConstraint(path, pName);
    if (constraint && constraint.values.size >= 2 && constraint.values.size <= 50) {
      var validValues = [];
      constraint.values.forEach(function(v) { validValues.push(v); });
      params[vc].validValues = validValues;
    }
  }

  // ── Create call sites ──
  for (var u = 0; u < urls.length; u++) {
    var callSite = {
      url: urls[u],
      method: httpMethod || "GET",
      headers: headers,
      type: type,
      params: params.length > 0 ? params : undefined,
      responseType: responseType,
      enclosingFunction: funcInfo ? funcInfo.name : undefined,
    };
    result.fetchCallSites.push(callSite);
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
  if (depth > 3) return [];
  var node = path.node;
  if (!node) return [];

  // String literal
  if (_t.isStringLiteral(node)) return [node.value];

  // Numeric literal (could be a port or version)
  if (_t.isNumericLiteral(node)) return [String(node.value)];

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

  // String concatenation
  if (_t.isBinaryExpression(node, { operator: "+" })) {
    var lefts = _resolveAllValues(path.get("left"), depth);
    var rights = _resolveAllValues(path.get("right"), depth);
    if (lefts.length > 0 && rights.length > 0) {
      return [String(lefts[0]) + String(rights[0])];
    }
  }

  // Conditional expression: a ? b : c — collect values from both branches
  if (_t.isConditionalExpression(node)) {
    var consVals = _resolveAllValues(path.get("consequent"), depth + 1);
    var altVals = _resolveAllValues(path.get("alternate"), depth + 1);
    var ternaryVals = consVals.concat(altVals);
    if (ternaryVals.length > 0) return ternaryVals;
  }

  // Logical OR: a || b — first value or fallback
  if (_t.isLogicalExpression(node, { operator: "||" })) {
    var orLeft = _resolveAllValues(path.get("left"), depth + 1);
    var orRight = _resolveAllValues(path.get("right"), depth + 1);
    var orVals = orLeft.concat(orRight);
    if (orVals.length > 0) return orVals;
  }

  // Variable reference — use Babel scope analysis
  if (_t.isIdentifier(node)) {
    var binding = path.scope.getBinding(node.name);
    if (!binding) return [];

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
    }
  }

  return [];
}

// Resolve an expression to its ObjectExpression node (if it's a variable pointing to one)
function _resolveToObject(path, depth) {
  if (depth > 3) return null;
  var node = path.node;
  if (_t.isObjectExpression(node)) {
    node._path = path;
    return node;
  }
  if (_t.isIdentifier(node)) {
    var binding = path.scope.getBinding(node.name);
    if (!binding) return null;
    if (_t.isVariableDeclarator(binding.path.node) && binding.path.node.init) {
      if (_t.isObjectExpression(binding.path.node.init)) {
        binding.path.node.init._path = binding.path.get("init");
        return binding.path.node.init;
      }
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
}

function _resolveParamFromCallers(binding, depth) {
  if (depth > 2) return [];

  // Find the function that has this parameter
  var funcPath = binding.scope.path;
  if (!_t.isFunction(funcPath.node)) return [];

  // Find parameter index
  var paramIdx = -1;
  for (var i = 0; i < funcPath.node.params.length; i++) {
    var p = funcPath.node.params[i];
    var pName = _t.isIdentifier(p) ? p.name :
      (_t.isAssignmentPattern(p) && _t.isIdentifier(p.left) ? p.left.name : null);
    if (pName === binding.identifier.name) { paramIdx = i; break; }
  }
  if (paramIdx === -1) return [];

  // Find the function's binding (how it's referenced)
  var funcBinding = null;
  if (funcPath.node.id) {
    // Named function: function doFetch(url) { ... }
    funcBinding = funcPath.scope.parent ? funcPath.scope.parent.getBinding(funcPath.node.id.name) : null;
    if (!funcBinding) funcBinding = funcPath.scope.getBinding(funcPath.node.id.name);
  }
  if (!funcBinding && _t.isVariableDeclarator(funcPath.parent)) {
    // const doFetch = function(url) { ... }
    funcBinding = funcPath.scope.parent ? funcPath.scope.parent.getBinding(funcPath.parent.id.name) : null;
  }
  if (!funcBinding && _t.isAssignmentExpression(funcPath.parent) && _t.isIdentifier(funcPath.parent.left)) {
    // doFetch = function(url) { ... }
    funcBinding = funcPath.scope.getBinding(funcPath.parent.left.name);
  }
  if (!funcBinding && _t.isObjectProperty(funcPath.parent)) {
    // { method: function(url) { ... } } — trace via obj.method(...) call sites
    var methodKey = funcPath.parent.key;
    var methodName = _t.isIdentifier(methodKey) ? methodKey.name :
      (_t.isStringLiteral(methodKey) ? methodKey.value : null);
    if (methodName) {
      return _resolveParamFromObjectMethod(funcPath, paramIdx, methodName, depth);
    }
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
        return _resolveParamFromMethodCalls(assignObjBinding, assignMethodName, paramIdx, depth);
      }
    }
    return [];
  }
  if (!funcBinding) return [];

  // Collect values from all call sites
  var values = [];
  var refs = funcBinding.referencePaths;
  for (var r = 0; r < refs.length; r++) {
    var refPath = refs[r];
    if (refPath.parent && _t.isCallExpression(refPath.parent) && refPath.parent.callee === refPath.node) {
      if (paramIdx < refPath.parent.arguments.length) {
        var argPath = refPath.parentPath.get("arguments." + paramIdx);
        var argVals = _resolveAllValues(argPath, depth + 1);
        values = values.concat(argVals);
      }
    }
  }
  return values;
}

// Resolve param from obj.method(...) calls when the function is an object property value
function _resolveParamFromObjectMethod(funcPath, paramIdx, methodName, depth) {
  // Walk up to the ObjectExpression, then find its variable binding
  var objExprPath = funcPath.parentPath ? funcPath.parentPath.parentPath : null;
  if (!objExprPath || !_t.isObjectExpression(objExprPath.node)) return [];

  var declPath = objExprPath.parentPath;
  if (!declPath) return [];

  var objBinding = null;
  if (_t.isVariableDeclarator(declPath.node) && _t.isIdentifier(declPath.node.id)) {
    objBinding = declPath.scope.getBinding(declPath.node.id.name);
  }
  if (!objBinding) return [];

  return _resolveParamFromMethodCalls(objBinding, methodName, paramIdx, depth);
}

// Search an object binding's references for obj.method(...) call sites
function _resolveParamFromMethodCalls(objBinding, methodName, paramIdx, depth) {
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
          var argVals = _resolveAllValues(argPath, depth + 1);
          values = values.concat(argVals);
        }
      }
    }
  }
  return values;
}

// ─── Data Extraction Helpers ────────────────────────────────────────────────

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

function _extractBodyParams(valNode, scopePath) {
  var params = [];
  if (_isJsonStringify(valNode, scopePath)) {
    if (valNode.arguments[0] && _t.isObjectExpression(valNode.arguments[0])) {
      params = _extractObjectProperties(valNode.arguments[0]);
      for (var i = 0; i < params.length; i++) params[i].location = "body";
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
    else if (_t.isMemberExpression(expr)) params.push(_describeNode(expr));
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
    funcPath.traverse({
      CallExpression: function(innerPath) {
        if (found) { innerPath.stop(); return; }
        var c = innerPath.node.callee;
        if (!_t.isMemberExpression(c)) return;
        var mName = _t.isIdentifier(c.property) ? c.property.name : null;
        if (mName === "json") found = "json";
        else if (mName === "arrayBuffer" && !found) found = "arrayBuffer";
        else if (mName === "blob" && !found) found = "blob";
      },
      // Don't descend into nested functions
      FunctionDeclaration: function(p) { p.skip(); },
      FunctionExpression: function(p) { p.skip(); },
      ArrowFunctionExpression: function(p) { p.skip(); },
    });
  } catch (_) {}
  return found;
}

// ─── Value Constraint Collection ────────────────────────────────────────────

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
    (_t.isMemberExpression(disc) ? _describeNode(disc) : null);
  if (!varName) return;

  var values = [];
  var cases = path.node.cases;
  for (var i = 0; i < cases.length; i++) {
    var test = cases[i].test;
    if (!test) continue;
    if (_t.isStringLiteral(test) || _t.isNumericLiteral(test)) values.push(test.value);
  }
  if (values.length >= 2) {
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
    (_t.isMemberExpression(testedArg) ? _describeNode(testedArg) : null);
  if (!testedVar) return;

  var obj = node.callee.object;

  // Inline array: ["json", "xml"].includes(format)
  if (_t.isArrayExpression(obj)) {
    var values = _extractLiteralArray(obj);
    if (values.length >= 2) _addConstraint(path, testedVar, values, "includes_inline");
    return;
  }

  // Named array: FORMATS.includes(type) — resolve through scope
  if (_t.isIdentifier(obj)) {
    var binding = path.scope.getBinding(obj.name);
    if (binding && binding.path.node.init && _t.isArrayExpression(binding.path.node.init)) {
      var arrValues = _extractLiteralArray(binding.path.node.init);
      if (arrValues.length >= 2) _addConstraint(path, testedVar, arrValues, "includes_ref");
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
    if (byVar[varName].length >= 2) {
      _addConstraint(path, varName, byVar[varName], "equality_chain");
    }
  }
}

function _flattenLogicalChain(node, out) {
  if (_t.isLogicalExpression(node)) {
    _flattenLogicalChain(node.left, out);
    _flattenLogicalChain(node.right, out);
    return;
  }
  if (_t.isBinaryExpression(node) &&
      (node.operator === "===" || node.operator === "==" || node.operator === "!==" || node.operator === "!=")) {
    var varName = null, value = null;
    if (_t.isIdentifier(node.left) && (_t.isStringLiteral(node.right) || _t.isNumericLiteral(node.right))) {
      varName = node.left.name; value = node.right.value;
    } else if (_t.isIdentifier(node.right) && (_t.isStringLiteral(node.left) || _t.isNumericLiteral(node.left))) {
      varName = node.right.name; value = node.left.value;
    } else if (_t.isMemberExpression(node.left) && (_t.isStringLiteral(node.right) || _t.isNumericLiteral(node.right))) {
      varName = _describeNode(node.left); value = node.right.value;
    } else if (_t.isMemberExpression(node.right) && (_t.isStringLiteral(node.left) || _t.isNumericLiteral(node.left))) {
      varName = _describeNode(node.right); value = node.left.value;
    }
    if (varName !== null && value !== null) out.push({ varName: varName, value: value });
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
            _t.isNumericLiteral(args[1]) && args[1].value >= 1 && args[1].value <= 10000) {
          found = args[1].value;
          innerPath.stop();
          return;
        }
        // f(this, N)
        if (_t.isIdentifier(callee) && args.length >= 2 &&
            _t.isThisExpression(args[0]) &&
            _t.isNumericLiteral(args[1]) && args[1].value >= 1 && args[1].value <= 10000) {
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
            _t.isNumericLiteral(node.property) && node.property.value >= 1 && node.property.value <= 10000) {
          found = node.property.value;
          innerPath.stop();
        }
      },
    });
  } catch (_) {}
  return found;
}

// ─── Enum Detection ─────────────────────────────────────────────────────────

function _detectEnumObject(node, result) {
  var props = node.properties;
  if (!props || props.length < 2 || props.length > 200) return;

  var allNumeric = true, allString = true;
  var numericValues = [], stringKeys = [], numericKeys = [];

  for (var i = 0; i < props.length; i++) {
    var prop = props[i];
    if (!_t.isObjectProperty(prop) || prop.computed) return;

    var val = prop.value;
    if (_t.isNumericLiteral(val) && Number.isInteger(val.value)) {
      numericValues.push(val.value);
      allString = false;
    } else if (_t.isStringLiteral(val)) {
      allNumeric = false;
    } else if (_t.isUnaryExpression(val, { operator: "-" }) && _t.isNumericLiteral(val.argument)) {
      numericValues.push(-val.argument.value);
      allString = false;
    } else {
      allNumeric = false;
      allString = false;
    }

    var key = prop.key;
    if (_t.isNumericLiteral(key)) numericKeys.push(key.value);
    else if (_t.isStringLiteral(key)) stringKeys.push(key.value);
    else if (_t.isIdentifier(key)) stringKeys.push(key.name);
  }

  // Proto enum: string keys → sequential 0..N integers
  if (allNumeric && numericValues.length >= 2) {
    var sorted = numericValues.slice().sort(function(a, b) { return a - b; });
    var isSeq = sorted[0] === 0;
    for (var s = 1; s < sorted.length && isSeq; s++) {
      if (sorted[s] !== sorted[s - 1] + 1) isSeq = false;
    }
    if (isSeq && stringKeys.length === numericValues.length) {
      var values = {};
      for (var e = 0; e < props.length; e++) {
        var k = props[e].key;
        var v = props[e].value;
        var kName = _t.isIdentifier(k) ? k.name : (_t.isStringLiteral(k) ? k.value : String(k.value));
        var vVal = _t.isNumericLiteral(v) ? v.value : (_t.isUnaryExpression(v) ? -v.argument.value : 0);
        values[kName] = vVal;
      }
      result.protoEnums.push({ values: values });
      return;
    }
  }

  // Reverse map: numeric keys → string values
  if (allString && numericKeys.length >= 2 && numericKeys.length === props.length) {
    var rSorted = numericKeys.slice().sort(function(a, b) { return a - b; });
    var rSeq = rSorted[0] === 0;
    for (var rs = 1; rs < rSorted.length && rSeq; rs++) {
      if (rSorted[rs] !== rSorted[rs - 1] + 1) rSeq = false;
    }
    if (rSeq) {
      var rValues = {};
      for (var re = 0; re < props.length; re++) {
        rValues[props[re].value.value] = props[re].key.value;
      }
      result.protoEnums.push({ values: rValues, isReverseMap: true });
    }
  }
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
  if (!node) return;
  if (_t.isIdentifier(node)) { set.add(node.name); return; }
  if (_t.isBinaryExpression(node) || _t.isLogicalExpression(node)) {
    _collectIdentifiers(node.left, set);
    _collectIdentifiers(node.right, set);
  }
  if (_t.isConditionalExpression(node)) {
    _collectIdentifiers(node.test, set);
    _collectIdentifiers(node.consequent, set);
    _collectIdentifiers(node.alternate, set);
  }
  if (_t.isCallExpression(node)) {
    for (var i = 0; i < node.arguments.length; i++) {
      _collectIdentifiers(node.arguments[i], set);
    }
  }
  if (_t.isNewExpression(node)) {
    for (var ni = 0; ni < node.arguments.length; ni++) {
      _collectIdentifiers(node.arguments[ni], set);
    }
  }
  if (_t.isTemplateLiteral(node)) {
    for (var j = 0; j < node.expressions.length; j++) {
      _collectIdentifiers(node.expressions[j], set);
    }
  }
  if (_t.isMemberExpression(node)) {
    _collectIdentifiers(node.object, set);
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
