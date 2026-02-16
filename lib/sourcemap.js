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
 * Uses Babel to parse JS/TS source files and extract interfaces, enums, types.
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
 * Uses Babel parser with TypeScript plugin — no regex stripping needed.
 */
function extractTypesFromFile(code, source) {
  var types = [];
  var isTS = /\.tsx?$/i.test(source);
  var plugins = isTS ? ["typescript", "jsx", "decorators"] : ["jsx"];

  var ast = null;
  try {
    ast = BabelBundle.parse(code, { sourceType: "module", plugins: plugins, errorRecovery: true });
  } catch (_) {
    try {
      ast = BabelBundle.parse(code, { sourceType: "script", plugins: plugins, errorRecovery: true });
    } catch (_2) {
      return types;
    }
  }

  var t = BabelBundle.t;
  try {
    BabelBundle.traverse(ast, {
      // Enum-like const objects: const MyEnum = { A: 0, B: 1 }
      VariableDeclarator: function(path) {
        var node = path.node;
        if (!node.init || !t.isObjectExpression(node.init)) return;
        if (!node.id || !t.isIdentifier(node.id)) return;

        var name = node.id.name;
        var props = node.init.properties;
        if (props.length < 2) return;

        var isEnum = true;
        var values = {};
        for (var p = 0; p < props.length; p++) {
          var prop = props[p];
          if (!t.isObjectProperty(prop) || prop.computed) { isEnum = false; break; }
          var keyName = t.isIdentifier(prop.key) ? prop.key.name :
            (t.isStringLiteral(prop.key) ? prop.key.value : null);
          if (!keyName) { isEnum = false; break; }
          if (t.isNumericLiteral(prop.value)) {
            values[keyName] = prop.value.value;
          } else if (t.isStringLiteral(prop.value)) {
            values[keyName] = prop.value.value;
          } else {
            isEnum = false;
            break;
          }
        }
        if (isEnum && Object.keys(values).length >= 2) {
          types.push({ name: name, fields: Object.keys(values).map(function(k) { return { name: k, type: typeof values[k] }; }), source: source, kind: "enum" });
        }
      },

      // TypeScript enum declarations: enum Status { Active = 1, Inactive = 2 }
      TSEnumDeclaration: function(path) {
        var node = path.node;
        if (!node.id || !t.isIdentifier(node.id)) return;
        var name = node.id.name;
        var fields = [];
        for (var m = 0; m < node.members.length; m++) {
          var member = node.members[m];
          var mName = t.isIdentifier(member.id) ? member.id.name :
            (t.isStringLiteral(member.id) ? member.id.value : null);
          if (mName) {
            fields.push({ name: mName, type: member.initializer ? typeof member.initializer.value : "number" });
          }
        }
        if (fields.length >= 2) {
          types.push({ name: name, fields: fields, source: source, kind: "enum" });
        }
      },

      // TypeScript interface declarations
      TSInterfaceDeclaration: function(path) {
        var node = path.node;
        if (!node.id || !t.isIdentifier(node.id)) return;
        var name = node.id.name;
        var fields = [];
        for (var m = 0; m < node.body.body.length; m++) {
          var prop = node.body.body[m];
          if (t.isTSPropertySignature(prop) && t.isIdentifier(prop.key)) {
            var fieldType = "unknown";
            if (prop.typeAnnotation && prop.typeAnnotation.typeAnnotation) {
              var ta = prop.typeAnnotation.typeAnnotation;
              if (t.isTSStringKeyword(ta)) fieldType = "string";
              else if (t.isTSNumberKeyword(ta)) fieldType = "number";
              else if (t.isTSBooleanKeyword(ta)) fieldType = "boolean";
              else if (t.isTSArrayType(ta)) fieldType = "array";
              else if (t.isTSTypeReference(ta) && t.isIdentifier(ta.typeName)) fieldType = ta.typeName.name;
            }
            fields.push({ name: prop.key.name, type: fieldType, optional: !!prop.optional });
          }
        }
        if (fields.length >= 1) {
          types.push({ name: name, fields: fields, source: source, kind: "interface" });
        }
      },

      // TypeScript type aliases: type MyType = { field: string }
      TSTypeAliasDeclaration: function(path) {
        var node = path.node;
        if (!node.id || !t.isIdentifier(node.id)) return;
        if (!t.isTSTypeLiteral(node.typeAnnotation)) return;
        var name = node.id.name;
        var fields = [];
        for (var m = 0; m < node.typeAnnotation.members.length; m++) {
          var prop = node.typeAnnotation.members[m];
          if (t.isTSPropertySignature(prop) && t.isIdentifier(prop.key)) {
            fields.push({ name: prop.key.name, type: "unknown", optional: !!prop.optional });
          }
        }
        if (fields.length >= 1) {
          types.push({ name: name, fields: fields, source: source, kind: "type" });
        }
      },

      // Class declarations that look like proto message classes
      ClassDeclaration: function(path) {
        var node = path.node;
        if (!node.id) return;
        var className = node.id.name;
        var fields = [];

        if (node.body && node.body.body) {
          for (var m = 0; m < node.body.body.length; m++) {
            var member = node.body.body[m];
            if (!t.isClassMethod(member)) continue;
            var mName = t.isIdentifier(member.key) ? member.key.name : null;
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
