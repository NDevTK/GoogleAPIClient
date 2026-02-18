// Offscreen document — thin relay between the service worker and a Web Worker.
// Heavy libs (Babel, ast.js, sourcemap.js) load and run on the Worker thread,
// keeping both the service worker and this document's main thread responsive.

var _worker = new Worker("ast-thread.js");
var _pending = new Map();
var _nextId = 0;

_worker.onmessage = function(e) {
  var cb = _pending.get(e.data._id);
  if (cb) {
    _pending.delete(e.data._id);
    cb(e.data.response);
  }
};

chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
  if (!msg || !msg.type || !msg.type.startsWith("AST_")) return;

  var id = _nextId++;
  _pending.set(id, sendResponse);
  _worker.postMessage({ _id: id, msg: msg });
  return true; // keep sendResponse alive for async Worker response
});
