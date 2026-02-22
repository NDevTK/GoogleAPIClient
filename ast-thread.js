// Web Worker thread for AST analysis.
// Loads heavy libs (Babel ~2MB, ast.js, sourcemap.js) and runs all
// parsing/analysis here so no other thread is blocked.

importScripts("lib/babel-bundle.js", "lib/ast.js", "lib/sourcemap.js");

onmessage = function(e) {
  var id = e.data._id;
  var msg = e.data.msg;
  var response;

  if (msg.type === "AST_ANALYZE") {
    try {
      var result = analyzeJSBundle(msg.code, msg.sourceUrl, msg.forceScript);
      response = { success: true, result: result };
    } catch (err) {
      response = { success: false, error: err.message, stack: err.stack };
    }
  } else if (msg.type === "AST_ANALYZE_BATCH") {
    try {
      var results = [];
      for (var i = 0; i < msg.files.length; i++) {
        var f = msg.files[i];
        try {
          var a = analyzeJSBundle(f.code, f.name);
          results.push({
            success: true,
            securitySinks: a.securitySinks || [],
            dangerousPatterns: a.dangerousPatterns || [],
          });
        } catch (err) {
          results.push({ success: false, error: err.message });
        }
      }
      response = { success: true, result: results };
    } catch (err) {
      response = { success: false, error: err.message };
    }
  } else if (msg.type === "AST_PARSE_SOURCEMAP") {
    try {
      var smData = parseSourceMap(msg.sourceMapJson);
      response = { success: true, result: smData };
    } catch (err) {
      response = { success: false, error: err.message, stack: err.stack };
    }
  } else if (msg.type === "AST_EXTRACT_TYPES") {
    try {
      var types = extractTypesFromSources(msg.sourcesContent, msg.sources);
      response = { success: true, result: types };
    } catch (err) {
      response = { success: false, error: err.message, stack: err.stack };
    }
  } else {
    response = { success: false, error: "Unknown message type: " + msg.type };
  }

  postMessage({ _id: id, response: response });
};
