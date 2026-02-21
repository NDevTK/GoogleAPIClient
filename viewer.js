"use strict";
// viewer.js — Source code viewer with Prism.js syntax highlighting.
// Opens in a new tab from the popup's security findings panel.
// Fetches original source via background.js, beautifies with Babel,
// highlights with Prism, and scrolls to the target finding line.
// Supports cross-file navigation, click-to-definition, and focused mode
// (tree-shakes irrelevant code, showing only functions reachable from findings).

(function() {

var params = new URLSearchParams(location.search);
var tabId = parseInt(params.get("tabId"), 10) || 0;

var urlEl = document.getElementById("source-url");
var pageUrlEl = document.getElementById("page-url");
var statusEl = document.getElementById("status");
var codeEl = document.getElementById("code-output");
var preEl = document.getElementById("code-pre");
var containerEl = document.getElementById("code-container");
var pickerEl = document.getElementById("file-picker");
var focusBtnEl = document.getElementById("btn-focus");

var _currentUrl = null;
var _defMap = null;       // { name: line } for click-to-definition
var _funcMap = null;      // { name: { line, endLine, calls: Set } } — named only
var _allFuncRanges = null; // [{ line, endLine, calls }] — ALL functions (named + anonymous)

// Focus mode state
var _focusMode = true;    // default: focused
var _fullCode = null;     // cached beautified full source
var _focusedCode = null;  // cached focused source
var _lineRemap = null;    // Map<focusedLine, originalBeautifiedLine>
var _mappedFindings = null;
var _mappedTarget = null;
var _hasFocusableFindings = false;

function showMessage(text, isError) {
  containerEl.innerHTML = '<div class="viewer-message' + (isError ? ' viewer-error' : '') + '">' +
    escHtml(text) + '</div>';
}

function escHtml(s) {
  var d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

// ─── Beautify ────────────────────────────────────────────────────────────────

function beautify(rawCode) {
  console.log("[viewer:beautify] Input length=%d, first 200 chars: %s", rawCode.length, JSON.stringify(rawCode.substring(0, 200)));
  console.log("[viewer:beautify] Char codes at start: %s", Array.from(rawCode.substring(0, 10)).map(function(c) { return c.charCodeAt(0); }).join(", "));
  try {
    var ast;
    var parseOpts = { plugins: ["jsx"], errorRecovery: true, sourceFilename: "input.js" };
    try {
      ast = BabelBundle.parse(rawCode, Object.assign({ sourceType: "module" }, parseOpts));
    } catch (modErr) {
      console.log("[viewer:beautify] Module parse failed: %s", modErr.message);
      ast = BabelBundle.parse(rawCode, Object.assign({ sourceType: "script" }, parseOpts));
    }

    var result = BabelBundle.generate(ast, {
      compact: false,
      concise: false,
      retainLines: false,
      sourceMaps: true,
      sourceFileName: "input.js",
    }, { "input.js": rawCode });

    _vlqState = [0, 0, 0, 0, 0];
    var lineMap = {};      // origLine → first genLine (line-only lookups)
    var colMap = {};       // origLine → [{origCol, genLine}] (column-precise lookups)
    if (result.map && result.map.mappings) {
      var mappings = result.map.mappings;
      var genLine = 0;
      for (var i = 0; i < mappings.length; i++) {
        var ch = mappings.charAt(i);
        if (ch === ";") {
          genLine++;
          _vlqState[0] = 0;
          continue;
        }
        if (ch === ",") continue;
        var decoded = decodeVLQSegment(mappings, i);
        if (decoded && decoded.originalLine != null) {
          var origLine = decoded.originalLine + 1;
          var origCol = decoded.originalColumn || 0;
          if (!lineMap[origLine] || lineMap[origLine] > genLine + 1) {
            lineMap[origLine] = genLine + 1;
          }
          if (!colMap[origLine]) colMap[origLine] = [];
          colMap[origLine].push({ origCol: origCol, genLine: genLine + 1 });
        }
        while (i < mappings.length && mappings.charAt(i) !== "," && mappings.charAt(i) !== ";") i++;
        i--;
      }
    }

    return { code: result.code, lineMap: lineMap, colMap: colMap };
  } catch (e) {
    console.debug("[viewer] Beautify failed:", e.message);
    return { code: rawCode, lineMap: null };
  }
}

// ─── VLQ Decoder ─────────────────────────────────────────────────────────────

var VLQ_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var _vlqLookup = null;
function decodeVLQ(mappings, pos) {
  if (!_vlqLookup) {
    _vlqLookup = {};
    for (var i = 0; i < VLQ_CHARS.length; i++) _vlqLookup[VLQ_CHARS.charAt(i)] = i;
  }
  var result = 0, shift = 0, startPos = pos;
  while (pos < mappings.length) {
    var ch = mappings.charAt(pos);
    var val = _vlqLookup[ch];
    if (val === undefined) break;
    pos++;
    result += (val & 31) << shift;
    shift += 5;
    if ((val & 32) === 0) break;
  }
  var value = (result & 1) ? -(result >> 1) : (result >> 1);
  return { value: value, length: pos - startPos };
}

var _vlqState = [0, 0, 0, 0, 0];
function decodeVLQSegment(mappings, pos) {
  var d0 = decodeVLQ(mappings, pos);
  if (!d0 || d0.length === 0) return null;
  pos += d0.length;
  _vlqState[0] += d0.value;

  if (pos >= mappings.length || mappings.charAt(pos) === "," || mappings.charAt(pos) === ";") {
    return { originalLine: null };
  }

  var d1 = decodeVLQ(mappings, pos);
  if (!d1) return null;
  pos += d1.length;
  _vlqState[1] += d1.value;

  var d2 = decodeVLQ(mappings, pos);
  if (!d2) return null;
  pos += d2.length;
  _vlqState[2] += d2.value;

  var d3 = decodeVLQ(mappings, pos);
  if (!d3) return null;
  pos += d3.length;
  _vlqState[3] += d3.value;

  return { originalLine: _vlqState[2], originalColumn: _vlqState[3] };
}

// ─── Line Mapping & Findings ─────────────────────────────────────────────────

function mapLine(originalLine, lineMap, colMap, originalCol) {
  if (!lineMap) return originalLine;
  // Column-precise lookup for minified code (one source line → many beautified lines)
  if (originalCol != null && colMap && colMap[originalLine]) {
    var entries = colMap[originalLine];
    var best = null;
    for (var ei = 0; ei < entries.length; ei++) {
      if (entries[ei].origCol <= originalCol) {
        if (!best || entries[ei].origCol > best.origCol) {
          best = entries[ei];
        }
      }
    }
    if (best) {
      console.log("[viewer:mapLine] col-precise: orig %d:%d → beautified %d (matched col %d)", originalLine, originalCol, best.genLine, best.origCol);
      return best.genLine;
    }
  }
  if (lineMap[originalLine]) {
    console.log("[viewer:mapLine] exact: orig %d → beautified %d", originalLine, lineMap[originalLine]);
    return lineMap[originalLine];
  }
  for (var l = originalLine; l > 0; l--) {
    if (lineMap[l]) {
      console.log("[viewer:mapLine] fallback: orig %d → nearest orig %d → beautified %d (gap=%d)", originalLine, l, lineMap[l], originalLine - l);
      return lineMap[l];
    }
  }
  console.warn("[viewer:mapLine] no mapping found for orig %d", originalLine);
  return originalLine;
}

function collectFindingLines(findings) {
  var lines = [];
  if (!findings) return lines;
  for (var fi = 0; fi < findings.length; fi++) {
    var f = findings[fi];
    var sinks = f.securitySinks || [];
    var patterns = f.dangerousPatterns || [];
    for (var si = 0; si < sinks.length; si++) {
      if (sinks[si].location) {
        lines.push({ line: sinks[si].location.line, col: sinks[si].location.column, severity: sinks[si].severity || "high" });
      }
    }
    for (var di = 0; di < patterns.length; di++) {
      if (patterns[di].location) {
        lines.push({ line: patterns[di].location.line, col: patterns[di].location.column, severity: patterns[di].severity || "medium" });
      }
    }
  }
  return lines;
}

function markFindingLinesInGutter(mappedLines, remap) {
  var rows = preEl.querySelector(".line-numbers-rows");
  if (!rows) return;
  var spans = rows.children;
  for (var i = 0; i < mappedLines.length; i++) {
    var targetLine = mappedLines[i].line;
    // In focused mode, reverse-map the beautified line to the focused line
    var focusedLine = targetLine;
    if (remap) {
      focusedLine = null;
      remap.forEach(function(origLine, fLine) {
        if (origLine === targetLine) focusedLine = fLine;
      });
      if (focusedLine == null) continue;
    }
    var lineIdx = focusedLine - 1;
    if (lineIdx >= 0 && lineIdx < spans.length) {
      var cls = mappedLines[i].severity === "high" ? "finding-line-high" : "finding-line";
      spans[lineIdx].classList.add(cls);
    }
  }
}

function addFindingOverlays(highlightLines, severities) {
  // Remove old overlays
  var old = preEl.querySelectorAll(".finding-overlay");
  for (var oi = 0; oi < old.length; oi++) old[oi].remove();

  if (!highlightLines.length) return;
  preEl.style.position = "relative";
  var lineHeight = parseFloat(getComputedStyle(codeEl).lineHeight) || 20;
  var padTop = parseFloat(getComputedStyle(preEl).paddingTop) || 0;
  for (var i = 0; i < highlightLines.length; i++) {
    var div = document.createElement("div");
    div.className = "finding-overlay " + (severities[i] === "high" ? "finding-overlay-high" : "finding-overlay-medium");
    div.style.top = (padTop + (highlightLines[i] - 1) * lineHeight) + "px";
    div.style.height = lineHeight + "px";
    preEl.appendChild(div);
  }
}

var _defHighlightEl = null;

function scrollToLine(line, highlight) {
  console.log("[viewer:scrollToLine] Requested line=%s highlight=%s", line, !!highlight);
  if (!line || line < 1) {
    console.warn("[viewer:scrollToLine] Invalid line, skipping");
    return;
  }
  requestAnimationFrame(function() {
    var lineHeight = parseFloat(getComputedStyle(codeEl).lineHeight) || 20;
    var offset = (line - 1) * lineHeight;
    var containerHeight = containerEl.clientHeight;
    var scrollPos = Math.max(0, offset - containerHeight / 3);
    console.log("[viewer:scrollToLine] lineHeight=%d, offset=%d, containerHeight=%d, scrollTop=%d", lineHeight, offset, containerHeight, scrollPos);
    containerEl.scrollTop = scrollPos;

    if (highlight) {
      var prePadTop = parseFloat(getComputedStyle(preEl).paddingTop) || 0;
      var rows = preEl.querySelector(".line-numbers-rows");
      var gutterSpan = rows && rows.children[line - 1];
      var gutterRect = gutterSpan ? gutterSpan.getBoundingClientRect() : null;
      var preRect = preEl.getBoundingClientRect();
      console.log("[viewer:highlight] line=%d, offset=%d, prePaddingTop=%d", line, offset, prePadTop);
      console.log("[viewer:highlight] gutterSpan rect:", gutterRect ? {top: gutterRect.top, height: gutterRect.height} : "null");
      console.log("[viewer:highlight] preEl rect top=%d, gutterSpan relative top=%s", preRect.top, gutterRect ? (gutterRect.top - preRect.top + containerEl.scrollTop) : "null");

      // Clear previous gutter highlight
      var prevGutter = preEl.querySelectorAll(".def-target");
      for (var j = 0; j < prevGutter.length; j++) prevGutter[j].classList.remove("def-target");

      // Highlight gutter
      if (gutterSpan) {
        gutterSpan.classList.add("def-target");
      }

      // Position overlay highlight (no innerHTML mutation)
      if (!_defHighlightEl) {
        _defHighlightEl = document.createElement("div");
        _defHighlightEl.id = "def-highlight";
        preEl.style.position = "relative";
        preEl.appendChild(_defHighlightEl);
      }
      var overlayTop = offset + prePadTop;
      console.log("[viewer:highlight] overlay top=%d (offset=%d + padding=%d), height=%d", overlayTop, offset, prePadTop, lineHeight);
      _defHighlightEl.style.top = overlayTop + "px";
      _defHighlightEl.style.height = lineHeight + "px";
      _defHighlightEl.style.display = "block";
    }
  });
}

// ─── Code Graph ──────────────────────────────────────────────────────────────

// Build code graph from the beautified AST.
// _funcMap:       named functions only { name: { line, endLine, calls } } — for call graph BFS
// _defMap:        { name: line } — for click-to-definition
// _allFuncRanges: ALL function bodies (named + anonymous) — for finding containment
function buildCodeGraph(beautifiedCode) {
  var funcMap = {};
  var defMap = {};
  var allRanges = [];
  try {
    var ast = BabelBundle.parse(beautifiedCode, {
      sourceType: "unambiguous",
      plugins: ["jsx"],
      errorRecovery: true,
    });

    // Helper: collect calls within a function path
    function collectCalls(funcPath) {
      var calls = new Set();
      funcPath.traverse({
        CallExpression: function(inner) {
          var callee = inner.node.callee;
          if (callee.type === "Identifier") {
            calls.add(callee.name);
          } else if (callee.type === "MemberExpression" && callee.property.type === "Identifier") {
            calls.add(callee.property.name);
          }
        },
      });
      return calls;
    }

    // Helper: register a function body (named or anonymous)
    function registerFunc(path, name, funcNode) {
      var loc = funcNode ? funcNode.loc : path.node.loc;
      if (!loc) return;
      var entry = {
        line: loc.start.line,
        endLine: loc.end.line,
        calls: collectCalls(path),
      };
      allRanges.push(entry);
      if (name) {
        funcMap[name] = entry;
        defMap[name] = loc.start.line;
      }
    }

    BabelBundle.traverse(ast, {
      FunctionDeclaration: function(path) {
        var name = path.node.id ? path.node.id.name : null;
        registerFunc(path, name, path.node);
      },
      FunctionExpression: function(path) {
        // Named: var foo = function() {} — handled via VariableDeclarator
        // Also captures anonymous callbacks, IIFEs, etc.
        var name = null;
        if (path.parent.type === "VariableDeclarator" && path.parent.id && path.parent.id.name) {
          name = path.parent.id.name;
        } else if (path.parent.type === "AssignmentExpression" && path.parent.left.type === "Identifier") {
          name = path.parent.left.name;
        }
        registerFunc(path, name, path.node);
      },
      ArrowFunctionExpression: function(path) {
        var name = null;
        if (path.parent.type === "VariableDeclarator" && path.parent.id && path.parent.id.name) {
          name = path.parent.id.name;
        } else if (path.parent.type === "AssignmentExpression" && path.parent.left.type === "Identifier") {
          name = path.parent.left.name;
        }
        registerFunc(path, name, path.node);
      },
      ClassDeclaration: function(path) {
        var name = path.node.id ? path.node.id.name : null;
        registerFunc(path, name, path.node);
      },
      ObjectMethod: function(path) {
        var name = path.node.key && path.node.key.name ? path.node.key.name : null;
        registerFunc(path, name, path.node);
      },
      ClassMethod: function(path) {
        var name = path.node.key && path.node.key.name ? path.node.key.name : null;
        registerFunc(path, name, path.node);
      },
    });
  } catch (e) {
    console.debug("[viewer] Code graph failed:", e.message);
  }
  _funcMap = funcMap;
  _defMap = defMap;
  _allFuncRanges = allRanges;
  console.log("[viewer:buildCodeGraph] _defMap entries:", Object.keys(defMap).length, defMap);
  console.log("[viewer:buildCodeGraph] _funcMap entries:", Object.keys(funcMap).length);
  console.log("[viewer:buildCodeGraph] _allFuncRanges count:", allRanges.length);
}

// ─── Reachability (Focus Mode) ───────────────────────────────────────────────

// Find all function ranges reachable from security findings.
// Uses _allFuncRanges for containment (any function, named or not),
// then BFS through _funcMap (named only) for call-graph expansion.
// Returns array of [startLine, endLine] ranges, or null.
function buildRelevantRanges(mappedFindings) {
  if (!_allFuncRanges || !mappedFindings || !mappedFindings.length) return null;

  // Seed: find the innermost function containing each finding line
  var seedRanges = []; // direct ranges from containment
  var seedNames = new Set(); // named functions for BFS expansion
  for (var fi = 0; fi < mappedFindings.length; fi++) {
    var fLine = mappedFindings[fi].line;
    // Find innermost (smallest range) function containing this line
    var best = null;
    for (var ri = 0; ri < _allFuncRanges.length; ri++) {
      var r = _allFuncRanges[ri];
      if (fLine >= r.line && fLine <= r.endLine) {
        if (!best || (r.endLine - r.line) < (best.endLine - best.line)) {
          best = r;
        }
      }
    }
    if (best) {
      seedRanges.push([best.line, best.endLine]);
      // If this range also has named calls, queue them for BFS
      if (best.calls) {
        best.calls.forEach(function(c) { seedNames.add(c); });
      }
    }
  }

  if (seedRanges.length === 0) return null;

  // BFS through named call graph
  var visitedNames = new Set();
  var queue = [];
  seedNames.forEach(function(s) {
    if (_funcMap[s] && !visitedNames.has(s)) {
      visitedNames.add(s);
      queue.push({ name: s, depth: 0 });
    }
  });
  while (queue.length > 0) {
    var item = queue.shift();
    if (item.depth >= 10) continue;
    var func = _funcMap[item.name];
    if (!func || !func.calls) continue;
    func.calls.forEach(function(callee) {
      if (!visitedNames.has(callee) && _funcMap[callee]) {
        visitedNames.add(callee);
        queue.push({ name: callee, depth: item.depth + 1 });
      }
    });
  }

  // Collect all ranges: seeds + BFS-reached named functions
  var ranges = seedRanges.slice();
  visitedNames.forEach(function(name) {
    var fn = _funcMap[name];
    if (fn) ranges.push([fn.line, fn.endLine]);
  });

  return ranges;
}

// Build focused code: only relevant function lines, with separators.
// Returns { code, lineRemap: Map<focusedLine, beautifiedLine> }
function buildFocusedCode(beautifiedCode, ranges) {
  if (!ranges || ranges.length === 0) return null;

  // Sort by start line
  ranges.sort(function(a, b) { return a[0] - b[0]; });

  // Merge overlapping/adjacent ranges (1-line gap tolerance)
  var merged = [ranges[0]];
  for (var ri = 1; ri < ranges.length; ri++) {
    var last = merged[merged.length - 1];
    if (ranges[ri][0] <= last[1] + 2) {
      last[1] = Math.max(last[1], ranges[ri][1]);
    } else {
      merged.push(ranges[ri]);
    }
  }

  // Extract lines
  var allLines = beautifiedCode.split("\n");
  var focusedLines = [];
  var lineRemap = new Map(); // focusedLineNum (1-based) → beautifiedLineNum (1-based)

  for (var mi = 0; mi < merged.length; mi++) {
    var start = merged[mi][0]; // 1-based
    var end = Math.min(merged[mi][1], allLines.length);

    // Insert separator before this range (not before the first)
    if (mi > 0) {
      var prevEnd = merged[mi - 1][1];
      var gapSize = start - prevEnd - 1;
      focusedLines.push("// \u00b7\u00b7\u00b7 " + gapSize + " lines hidden \u00b7\u00b7\u00b7");
      lineRemap.set(focusedLines.length, -1); // separator marker
    }

    // Add function lines
    for (var li = start; li <= end; li++) {
      focusedLines.push(allLines[li - 1]); // allLines is 0-indexed
      lineRemap.set(focusedLines.length, li); // focusedLines.length is current 1-based line
    }
  }

  // Add trailing separator if there's code after the last range
  if (merged.length > 0) {
    var lastEnd = merged[merged.length - 1][1];
    if (lastEnd < allLines.length) {
      var trailGap = allLines.length - lastEnd;
      focusedLines.push("// \u00b7\u00b7\u00b7 " + trailGap + " lines hidden \u00b7\u00b7\u00b7");
      lineRemap.set(focusedLines.length, -1);
    }
    // Leading separator
    if (merged[0][0] > 1) {
      var leadGap = merged[0][0] - 1;
      focusedLines.unshift("// \u00b7\u00b7\u00b7 " + leadGap + " lines hidden \u00b7\u00b7\u00b7");
      // Rebuild lineRemap since we shifted everything by 1
      var newRemap = new Map();
      lineRemap.forEach(function(v, k) { newRemap.set(k + 1, v); });
      newRemap.set(1, -1); // leading separator
      lineRemap = newRemap;
    }
  }

  return {
    code: focusedLines.join("\n"),
    lineRemap: lineRemap,
  };
}

// ─── Render ──────────────────────────────────────────────────────────────────

function renderCode(code, remap) {
  console.log("[viewer:renderCode] code length=%d, remap=%s, _mappedTarget=%s", code.length, !!remap, _mappedTarget);
  // Restore pre/code structure (showMessage may have replaced container)
  containerEl.innerHTML = "";
  containerEl.appendChild(preEl);

  // Set line highlight data
  var highlightLines = [];
  var highlightSeverities = [];
  if (_mappedFindings) {
    for (var i = 0; i < _mappedFindings.length; i++) {
      var targetLine = _mappedFindings[i].line;
      if (remap) {
        // Find the focused line for this beautified line
        var found = null;
        remap.forEach(function(origLine, fLine) {
          if (origLine === targetLine) found = fLine;
        });
        if (found) {
          highlightLines.push(found);
          highlightSeverities.push(_mappedFindings[i].severity);
        } else {
          console.log("[viewer:renderCode] Finding at beautified %d NOT in focused view", targetLine);
        }
      } else {
        highlightLines.push(targetLine);
        highlightSeverities.push(_mappedFindings[i].severity);
      }
    }
  }
  if (_mappedTarget) {
    var scrollTarget = _mappedTarget;
    if (remap) {
      var mapped = null;
      remap.forEach(function(origLine, fLine) {
        if (origLine === _mappedTarget) mapped = fLine;
      });
      if (mapped) {
        scrollTarget = mapped;
      } else if (highlightLines.length > 0) {
        // Target not in focused view — scroll to first finding instead
        scrollTarget = highlightLines[0];
        console.log("[viewer:renderCode] Target %d not in focused view, using first highlight line %d", _mappedTarget, scrollTarget);
      }
    }
    console.log("[viewer:renderCode] scrollTarget: beautified %d → %s %d", _mappedTarget, remap ? "focused" : "beautified", scrollTarget);
  }
  console.log("[viewer:renderCode] highlightLines (%d): %s", highlightLines.length, highlightLines.join(","));
  // Log what's actually at the scroll target line
  var codeLines = code.split("\n");
  if (scrollTarget && scrollTarget > 0 && scrollTarget <= codeLines.length) {
    console.log("[viewer:renderCode] Content at scroll target line %d: %s", scrollTarget, JSON.stringify(codeLines[scrollTarget - 1].substring(0, 120)));
  }
  // Log content at each highlight line
  for (var _dli = 0; _dli < Math.min(highlightLines.length, 10); _dli++) {
    var _hl = highlightLines[_dli];
    if (_hl > 0 && _hl <= codeLines.length) {
      console.log("[viewer:renderCode] Highlight line %d: %s", _hl, JSON.stringify(codeLines[_hl - 1].substring(0, 120)));
    }
  }

  preEl.removeAttribute("data-line");

  codeEl.textContent = code;
  Prism.highlightElement(codeEl);

  // Fix line numbers in focused mode
  if (remap) {
    fixLineNumbers(remap);
  }

  // Mark finding lines in gutter + background overlays
  markFindingLinesInGutter(_mappedFindings || [], remap);
  addFindingOverlays(highlightLines, highlightSeverities);

  // Attach definition links
  attachDefinitionLinks();

  // Scroll
  scrollToLine(scrollTarget || _mappedTarget);
}

function fixLineNumbers(remap) {
  var rows = preEl.querySelector(".line-numbers-rows");
  if (!rows) return;
  var spans = rows.children;
  for (var i = 0; i < spans.length; i++) {
    var lineNum = i + 1;
    var origLine = remap.get(lineNum);
    if (origLine === -1) {
      // Separator line
      spans[i].classList.add("hidden-separator");
      spans[i].setAttribute("data-line", "\u00b7\u00b7\u00b7");
    } else if (origLine) {
      spans[i].setAttribute("data-line", String(origLine));
    }
  }
}

// ─── Clickable Function Tokens ───────────────────────────────────────────────

function attachDefinitionLinks() {
  var tokens = codeEl.querySelectorAll("span.token.function");
  console.log("[viewer:attachDefLinks] Total .token.function spans:", tokens.length);
  console.log("[viewer:attachDefLinks] _defMap available:", !!_defMap, _defMap ? Object.keys(_defMap).length + " entries" : "null");
  var localCount = 0, crossCount = 0, missCount = 0;
  for (var i = 0; i < tokens.length; i++) {
    var span = tokens[i];
    var name = span.textContent;
    if (_defMap && _defMap[name]) {
      localCount++;
      console.log("[viewer:attachDefLinks] LOCAL match: '%s' → line %d", name, _defMap[name]);
      span.classList.add("def-local");
      span.dataset.defLine = _defMap[name];
      span.addEventListener("click", onLocalDefClick);
    } else if (name.length > 1) {
      crossCount++;
      span.classList.add("def-cross");
      span.dataset.defName = name;
      span.addEventListener("click", onCrossDefClick);
    } else {
      missCount++;
    }
  }
  console.log("[viewer:attachDefLinks] Summary: %d local, %d cross, %d skipped", localCount, crossCount, missCount);
}

function onLocalDefClick(e) {
  e.stopPropagation();
  var clickedName = e.currentTarget.textContent;
  var origLine = parseInt(e.currentTarget.dataset.defLine, 10);
  console.log("[viewer:onLocalDefClick] Clicked '%s', dataset.defLine=%s, parsed origLine=%d", clickedName, e.currentTarget.dataset.defLine, origLine);
  console.log("[viewer:onLocalDefClick] _focusMode=%s, _lineRemap=%s", _focusMode, !!_lineRemap);
  if (!origLine) {
    console.warn("[viewer:onLocalDefClick] No origLine — aborting");
    return;
  }

  // In focused mode, reverse-map beautified line → focused line
  if (_focusMode && _lineRemap) {
    var focusedLine = null;
    _lineRemap.forEach(function(oLine, fLine) {
      if (oLine === origLine) focusedLine = fLine;
    });
    console.log("[viewer:onLocalDefClick] Focus remap: origLine %d → focusedLine %s (remap size=%d)", origLine, focusedLine, _lineRemap.size);
    if (focusedLine) {
      scrollToLine(focusedLine, true);
      return;
    }
    // Definition not in focused view — switch to full, then scroll
    console.log("[viewer:onLocalDefClick] Def not in focused view, switching to full");
    _focusMode = false;
    updateFocusButton();
    renderCode(_fullCode, null);
    scrollToLine(origLine, true);
    return;
  }

  console.log("[viewer:onLocalDefClick] Full mode, scrolling to line %d", origLine);
  scrollToLine(origLine, true);
}

function onCrossDefClick(e) {
  e.stopPropagation();
  var span = e.currentTarget;
  var name = span.dataset.defName;
  if (!name) return;
  span.classList.add("def-searching");
  chrome.runtime.sendMessage({
    type: "FIND_DEFINITION",
    tabId: tabId,
    name: name,
    excludeUrl: _currentUrl,
  }, function(result) {
    span.classList.remove("def-searching");
    if (result && result.sourceUrl) {
      loadScript(result.sourceUrl, result.line || 0);
    }
  });
}

// ─── File Picker ─────────────────────────────────────────────────────────────

function initFilePicker() {
  chrome.runtime.sendMessage({
    type: "GET_TAB_SCRIPTS",
    tabId: tabId,
  }, function(scripts) {
    if (!scripts || !scripts.length) {
      pickerEl.style.display = "none";
      return;
    }
    pickerEl.innerHTML = "";
    for (var i = 0; i < scripts.length; i++) {
      var opt = document.createElement("option");
      opt.value = scripts[i];
      opt.textContent = scripts[i].split("/").pop().split("?")[0] || scripts[i];
      opt.title = scripts[i];
      if (scripts[i] === _currentUrl) opt.selected = true;
      pickerEl.appendChild(opt);
    }
    if (scripts.length <= 1) {
      pickerEl.style.display = "none";
    }
  });
}

pickerEl.addEventListener("change", function() {
  var url = pickerEl.value;
  if (url && url !== _currentUrl) {
    loadScript(url, 0);
  }
});

// ─── Focus Toggle ────────────────────────────────────────────────────────────

function updateFocusButton() {
  if (!_hasFocusableFindings) {
    focusBtnEl.disabled = true;
    focusBtnEl.textContent = "Focus";
    focusBtnEl.classList.remove("active");
    return;
  }
  focusBtnEl.disabled = false;
  if (_focusMode) {
    focusBtnEl.textContent = "Focus";
    focusBtnEl.classList.add("active");
  } else {
    focusBtnEl.textContent = "Full";
    focusBtnEl.classList.remove("active");
  }
}

focusBtnEl.addEventListener("click", function() {
  if (!_hasFocusableFindings) return;
  _focusMode = !_focusMode;
  updateFocusButton();
  if (_focusMode && _focusedCode) {
    renderCode(_focusedCode, _lineRemap);
  } else if (_fullCode) {
    renderCode(_fullCode, null);
  }
});

// ─── Main Load ───────────────────────────────────────────────────────────────

function loadScript(scriptUrl, targetLine) {
  _currentUrl = scriptUrl;
  _defMap = null;
  _funcMap = null;
  _allFuncRanges = null;
  _fullCode = null;
  _focusedCode = null;
  _lineRemap = null;
  _mappedFindings = null;
  _mappedTarget = null;
  _hasFocusableFindings = false;

  // Update UI
  urlEl.textContent = scriptUrl;
  document.title = scriptUrl.split("/").pop() || "Source Viewer";
  history.replaceState(null, "",
    "viewer.html?sourceUrl=" + encodeURIComponent(scriptUrl) +
    "&line=" + (targetLine || 0) + "&tabId=" + tabId);

  if (pickerEl.value !== scriptUrl) {
    pickerEl.value = scriptUrl;
  }

  showMessage("Loading source...");
  statusEl.textContent = "";
  updateFocusButton();

  chrome.runtime.sendMessage({
    type: "GET_SCRIPT_SOURCE",
    tabId: tabId,
    scriptUrl: scriptUrl,
  }, function(response) {
    if (chrome.runtime.lastError) {
      showMessage("Error: " + chrome.runtime.lastError.message, true);
      return;
    }
    if (!response) {
      showMessage("No response from background.", true);
      return;
    }
    if (response.error) {
      showMessage("Error: " + response.error, true);
      return;
    }
    if (!response.code) {
      showMessage("Empty source.", true);
      return;
    }

    var rawCode = response.code;
    var findings = response.findings || [];
    var findingLines = collectFindingLines(findings);

    // Show page context in toolbar
    if (response.pageUrl && response.pageUrl !== scriptUrl) {
      var pageName = response.pageUrl.split("/").pop().split("?")[0] || response.pageUrl;
      pageUrlEl.textContent = "in " + pageName;
      pageUrlEl.title = response.pageUrl;
    } else {
      pageUrlEl.textContent = "";
      pageUrlEl.title = "";
    }

    console.log("[viewer:loadScript] Raw code length=%d, targetLine=%d, findings count=%d", rawCode.length, targetLine, findingLines.length);
    console.log("[viewer:loadScript] Finding lines (original):", findingLines.map(function(f) { return f.line + ":" + (f.col != null ? f.col : "?") + "(" + f.severity + ")"; }).join(", "));

    statusEl.textContent = rawCode.length.toLocaleString() + " chars";
    if (findingLines.length > 0) {
      var highCount = findingLines.filter(function(f) { return f.severity === "high"; }).length;
      statusEl.innerHTML += ' <span class="badge badge-count">' + findingLines.length + ' findings</span>';
      if (highCount > 0) {
        statusEl.innerHTML += ' <span class="badge badge-high">' + highCount + ' high</span>';
      }
    }

    // Beautify
    var result = beautify(rawCode);
    var beautifiedCode = result.code;
    var lineMap = result.lineMap;
    var colMap = result.colMap;
    _fullCode = beautifiedCode;

    // Map finding lines to beautified positions (column-aware for minified code)
    console.log("[viewer:loadScript] lineMap entries: %d, colMap entries: %d", Object.keys(lineMap || {}).length, Object.keys(colMap || {}).length);
    _mappedTarget = mapLine(targetLine, lineMap, colMap);
    _mappedFindings = findingLines.map(function(f) {
      return { line: mapLine(f.line, lineMap, colMap, f.col), severity: f.severity };
    });
    console.log("[viewer:loadScript] Mapped target: %d → %d", targetLine, _mappedTarget);
    console.log("[viewer:loadScript] Mapped findings:", _mappedFindings.map(function(f) { return f.line; }).join(", "));

    // Build code graph (definitions + call references)
    buildCodeGraph(beautifiedCode);

    // Build focused view
    var relevantRanges = buildRelevantRanges(_mappedFindings);
    if (relevantRanges && relevantRanges.length > 0) {
      var focused = buildFocusedCode(beautifiedCode, relevantRanges);
      if (focused) {
        _focusedCode = focused.code;
        _lineRemap = focused.lineRemap;
        _hasFocusableFindings = true;
      }
    }

    updateFocusButton();

    // Render
    if (_focusMode && _hasFocusableFindings && _focusedCode) {
      renderCode(_focusedCode, _lineRemap);
    } else {
      renderCode(beautifiedCode, null);
    }
  });
}

// ─── Init ────────────────────────────────────────────────────────────────────

var initialUrl = params.get("sourceUrl");
var initialLine = parseInt(params.get("line"), 10) || 0;

if (!initialUrl) {
  urlEl.textContent = "(no source URL)";
  showMessage("No source URL provided.");
} else {
  loadScript(initialUrl, initialLine);
  initFilePicker();
}

})();
