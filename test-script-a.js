// test-script-a.js — Cross-file taint sources and utilities
// Simulates a config/init script that defines tainted globals used by other scripts.

// 66. Cross-file: taint source in one script, sink in another
var crossFilePayload = location.hash.substring(1);

// 67. Cross-file: tainted utility function defined here, called from another script
function renderUnsafe(html) {
  document.getElementById("xss-target").innerHTML = html;
}

// 68. Cross-file: global config object with tainted values
var appConfig = {
  redirectUrl: location.search.split("next=")[1],
  userName: location.hash.substring(1),
  debugCode: location.hash.substring(1),
};

// 69. Cross-file: tainted class method
function UnsafeRenderer() {}
UnsafeRenderer.prototype.render = function(content) {
  document.getElementById("xss-target").outerHTML = content;
};

// 70. Cross-file: API URL builder with tainted base
var apiBase = location.hash.substring(1);
function buildApiUrl(path) {
  return apiBase + "/api/" + path;
}
