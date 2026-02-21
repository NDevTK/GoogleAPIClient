// test-script-c.js — More cross-file patterns (simulates a third-party widget)
// Uses globals from both test-script-a.js and test-script-b.js.

// 71b. Cross-file: window.addEventListener dispatching to handler in Script B
window.addEventListener("message", function(e) {
  handleCrossMessage(e.data);
});

// 72. Cross-file: document.write with tainted value from Script A's config
function vuln_crossFileDocWrite() {
  document.write("<div>" + appConfig.userName + "</div>");
}

// 73. Cross-file: setTimeout with tainted string from Script A's config
function vuln_crossFileSetTimeout() {
  setTimeout(appConfig.debugCode, 100);
}

// 74. Cross-file: new Function with cross-file tainted var
function vuln_crossFileNewFunction() {
  var fn = new Function("return " + crossFilePayload);
}

// 75. Cross-file: createContextualFragment with tainted input
function vuln_crossFileFragment() {
  var range = document.createRange();
  range.selectNode(document.body);
  var frag = range.createContextualFragment(crossFilePayload);
  document.body.appendChild(frag);
}

// 76. Cross-file: fetch URL built from tainted base in Script A
function vuln_crossFileFetch() {
  fetch(buildApiUrl("admin/delete"));
}
