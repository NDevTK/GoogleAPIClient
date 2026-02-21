// test-script-b.js — Cross-file sinks using globals from test-script-a.js
// Simulates app code that consumes tainted globals from another script.

// 66b. Sink using cross-file tainted variable
function vuln_crossFileInnerHTML() {
  document.getElementById("xss-target").innerHTML = crossFilePayload;
}

// 67b. Calling cross-file tainted utility
function vuln_crossFileUtility() {
  var userInput = location.search.substring(1);
  renderUnsafe(userInput);
}

// 68b. Cross-file: config object property -> redirect
function vuln_crossFileRedirect() {
  location.assign(appConfig.redirectUrl);
}

// 68c. Cross-file: config object property -> eval
function vuln_crossFileEval() {
  eval(appConfig.debugCode);
}

// 69b. Cross-file: instantiate class from Script A, pass tainted data
function vuln_crossFileClass() {
  var renderer = new UnsafeRenderer();
  renderer.render(location.hash.substring(1));
}

// 70b. Cross-file: use builder with tainted base -> setAttribute href
function vuln_crossFileSetAttr() {
  var link = document.createElement("a");
  link.setAttribute("href", buildApiUrl("users"));
}

// 71. Cross-file: postMessage handler in separate script from listener setup
function handleCrossMessage(data) {
  document.getElementById("xss-target").innerHTML = data;
}
