// lib/sourcemap.js — Source map recovery engine
// Parses source maps to recover original file paths, variable names,
// proto file references, and TypeScript type definitions.

/**
 * Parse a source map JSON object.
 * We only need metadata arrays, NOT full VLQ mapping decode.
 * @param {object} sourceMapJson - Parsed source map
 * @returns {object} Extracted metadata
 */
function parseSourceMap(sourceMapJson) {
  var result = {
    sources: [],
    sourcesContent: [],
    names: [],
    protoFileNames: [],
    apiClientFiles: [],
  };

  if (!sourceMapJson || typeof sourceMapJson !== "object") return result;

  // Sources array: original file paths
  if (Array.isArray(sourceMapJson.sources)) {
    result.sources = sourceMapJson.sources;
    for (var i = 0; i < sourceMapJson.sources.length; i++) {
      var src = sourceMapJson.sources[i];
      if (typeof src !== "string") continue;
      // Detect proto-related files
      if (/\.proto$/i.test(src) || /_pb\.(js|ts)$/i.test(src) ||
          /_grpc_web_pb\.(js|ts)$/i.test(src) || /\.pb\.(go|cc|h)$/i.test(src)) {
        result.protoFileNames.push(src);
      }
      // Detect API client files
      if (/api[_/\-]?client/i.test(src) || /service[_/\-]?(client|stub)/i.test(src) ||
          /\/api\//i.test(src) || /\/rpc\//i.test(src) || /\/services\//i.test(src)) {
        result.apiClientFiles.push(src);
      }
    }
  }

  // Sources content: embedded original source text
  if (Array.isArray(sourceMapJson.sourcesContent)) {
    result.sourcesContent = sourceMapJson.sourcesContent;
  }

  // Names array: original variable/function names
  if (Array.isArray(sourceMapJson.names)) {
    result.names = sourceMapJson.names;
  }

  return result;
}

/**
 * Extract type definitions from original source content.
 * Uses acorn to parse JS/TS source files and extract interfaces, enums, types.
 * @param {Array} sourcesContent - Array of source text strings
 * @param {Array} sources - Array of source file paths
 * @returns {Array} Extracted type definitions
 */
function extractTypesFromSources(sourcesContent, sources) {
  var types = [];
  if (!sourcesContent || !sources) return types;

  for (var i = 0; i < sourcesContent.length; i++) {
    var content = sourcesContent[i];
    var source = sources[i] || "unknown";
    if (!content || typeof content !== "string") continue;

    // Only process TypeScript/JavaScript files
    if (!/\.(ts|js|tsx|jsx)$/i.test(source) && source !== "unknown") continue;

    // Skip very large files
    if (content.length > 500000) continue;

    // Try to extract types via AST parsing
    var fileTypes = extractTypesFromFile(content, source);
    for (var t = 0; t < fileTypes.length; t++) {
      types.push(fileTypes[t]);
    }
  }

  return types;
}

/**
 * Extract type-like structures from a single source file.
 */
function extractTypesFromFile(code, source) {
  var types = [];

  // Strip TypeScript type annotations that would cause parse errors
  // This is a best-effort approach — not a full TS parser
  var stripped = stripTypeAnnotations(code);

  var ast = null;
  try {
    ast = acorn.parse(stripped, { ecmaVersion: "latest", sourceType: "module" });
  } catch (_) {
    try {
      ast = acorn.parse(stripped, { ecmaVersion: "latest", sourceType: "script" });
    } catch (_2) {
      return types;
    }
  }

  try {
    acorn.walk.simple(ast, {
      // Enum-like const objects: const MyEnum = { A: 0, B: 1 }
      VariableDeclaration: function(node) {
        for (var d = 0; d < node.declarations.length; d++) {
          var decl = node.declarations[d];
          if (!decl.init || decl.init.type !== "ObjectExpression") continue;
          if (!decl.id || decl.id.type !== "Identifier") continue;

          var name = decl.id.name;
          var props = decl.init.properties;
          if (props.length < 2) continue;

          var isEnum = true;
          var values = {};
          for (var p = 0; p < props.length; p++) {
            var prop = props[p];
            if (prop.computed || prop.kind !== "init") { isEnum = false; break; }
            var key = prop.key;
            var val = prop.value;
            var keyName = key.type === "Identifier" ? key.name : (key.type === "Literal" ? String(key.value) : null);
            if (!keyName) { isEnum = false; break; }
            if (val.type === "Literal" && (typeof val.value === "number" || typeof val.value === "string")) {
              values[keyName] = val.value;
            } else {
              isEnum = false;
              break;
            }
          }
          if (isEnum && Object.keys(values).length >= 2) {
            types.push({ name: name, fields: Object.keys(values).map(function(k) { return { name: k, type: typeof values[k] }; }), source: source, kind: "enum" });
          }
        }
      },

      // Class declarations that look like proto message classes
      ClassDeclaration: function(node) {
        if (!node.id) return;
        var className = node.id.name;
        var fields = [];

        // Walk class body for method definitions (getters/setters)
        if (node.body && node.body.body) {
          for (var m = 0; m < node.body.body.length; m++) {
            var member = node.body.body[m];
            if (member.type !== "MethodDefinition") continue;
            var mName = member.key.type === "Identifier" ? member.key.name : null;
            if (!mName) continue;

            var getMatch = /^get([A-Z].*)$/.exec(mName);
            if (getMatch) {
              var fieldName = getMatch[1].charAt(0).toLowerCase() + getMatch[1].slice(1);
              fields.push({ name: fieldName, type: "unknown" });
            }
          }
        }

        if (fields.length >= 1) {
          types.push({ name: className, fields: fields, source: source, kind: "interface" });
        }
      },
    });
  } catch (_) {}

  return types;
}

/**
 * Best-effort TypeScript type annotation stripping.
 * Removes : Type patterns after variable names and function params
 * so acorn can parse the remaining JavaScript.
 */
function stripTypeAnnotations(code) {
  // Remove interface/type declarations (they're TS-only)
  var result = code.replace(/\b(interface|type)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*(<[^>]*>)?\s*\{[^}]*\}/g, "/* stripped */");
  // Remove import type statements
  result = result.replace(/import\s+type\s+\{[^}]*\}\s+from\s+['"][^'"]*['"]\s*;?/g, "");
  // Remove : TypeAnnotation in simple cases (variable declarations, function params)
  result = result.replace(/:\s*[A-Za-z_$][A-Za-z0-9_$<>\[\]|&.]*(\s*[,)\]=;{])/g, "$1");
  // Remove as TypeCast
  result = result.replace(/\bas\s+[A-Za-z_$][A-Za-z0-9_$<>\[\]|&.]*\b/g, "");
  return result;
}
