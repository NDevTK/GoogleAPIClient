// Popup controller: renders captured data, security findings, and sends requests.

/** Extract a flat deduplicated method list from a discovery doc. */
function getDocMethods(doc) {
  if (!doc || !doc.resources) return [];
  const seen = new Set();
  const methods = [];
  function walk(res) {
    for (const rName in res) {
      const r = res[rName];
      if (r.methods) {
        for (const mName in r.methods) {
          const m = r.methods[mName];
          const key = (m.httpMethod || "GET") + " " + m.id;
          if (seen.has(key)) continue;
          seen.add(key);
          methods.push(m);
        }
      }
      if (r.resources) walk(r.resources);
    }
  }
  // Walk probed first so learned wins on dedup (learned is added second, probed filtered by seen)
  if (doc.resources.probed) walk({ probed: doc.resources.probed });
  if (doc.resources.learned) walk({ learned: doc.resources.learned });
  const skip = new Set(["probed", "learned"]);
  const rest = {};
  for (const k in doc.resources) { if (!skip.has(k)) rest[k] = doc.resources[k]; }
  walk(rest);
  return methods;
}

let currentTabId = null;
let tabData = null;
let currentSchema = null;
let currentRequestUrl = "";
let currentRequestMethod = "POST";
let currentContentType = "application/json";
let currentBodyMode = "form"; // "form" | "raw" | "graphql"
let logFilter = "active"; // "active" | "all" | tabId (number)
let allTabsData = null; // { tabId: { meta, requestLog } }
let lastSendResult = null; // Last rendered response for re-render after rename

// Virtual scroll state for request log
const _vs = {
  entries: [],       // full sorted entry list
  heights: new Map(),// measured heights by entry id
  estHeight: 85,     // estimated row height (px)
  buffer: 3,         // extra rows above/below viewport
  scrollHandler: null,
};

function setBodyMode(mode) {
  currentBodyMode = mode;
  document.getElementById("send-form-fields").style.display =
    mode === "form" ? "block" : "none";
  document.getElementById("send-raw-body").style.display =
    mode === "raw" ? "block" : "none";
  document.getElementById("send-graphql-fields").style.display =
    mode === "graphql" ? "block" : "none";
}

// ─── Init ────────────────────────────────────────────────────────────────────

let renderTimer = null;
function throttledLoadState() {
  if (renderTimer) return;
  renderTimer = setTimeout(async () => {
    renderTimer = null;
    await loadState();
  }, 100);
}

document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTabId = tab?.id ?? null;

  for (const btn of document.querySelectorAll(".tab")) {
    btn.addEventListener("click", () => {
      document.querySelector(".tab.active").classList.remove("active");
      document.querySelector(".panel.active").classList.remove("active");
      btn.classList.add("active");
      document
        .getElementById(`panel-${btn.dataset.panel}`)
        .classList.add("active");
    });
  }

  document.getElementById("btn-clear").addEventListener("click", clearState);

  // Data panel
  document
    .getElementById("btn-export-data")
    .addEventListener("click", () => copyToClipboard("data", tabData));

  // Send panel
  document
    .getElementById("send-ep-select")
    .addEventListener("change", onSendEndpointSelected);
  document.getElementById("btn-send").addEventListener("click", sendRequest);
  document
    .getElementById("btn-add-header")
    .addEventListener("click", addHeaderRow);

  // Export buttons
  document.getElementById("btn-copy-curl").addEventListener("click", () => copyAsFormat("curl"));
  document.getElementById("btn-copy-fetch").addEventListener("click", () => copyAsFormat("fetch"));
  document.getElementById("btn-copy-python").addEventListener("click", () => copyAsFormat("python"));

  // Service filter + spec export/import
  document.getElementById("spec-service-select").addEventListener("change", () => {
    renderMethodDropdown();
  });
  document.getElementById("btn-export-spec").addEventListener("click", exportOpenApiSpec);
  document.getElementById("btn-import-spec").addEventListener("click", () => {
    document.getElementById("import-spec-file").click();
  });
  document.getElementById("import-spec-file").addEventListener("change", importOpenApiSpec);

  // Request log tab filter
  document.getElementById("log-tab-filter").addEventListener("change", async (e) => {
    const val = e.target.value;
    logFilter = val === "active" ? "active" : val === "all" ? "all" : parseInt(val, 10);
    await loadRequestLog();
    renderResponsePanel();
  });
  populateTabFilter();

  // Global rename handler
  document.addEventListener("click", async (e) => {
    if (e.target.classList.contains("btn-rename")) {
      const { schema, key } = e.target.dataset;
      const currentName = e.target.previousElementSibling.textContent;
      const newName = prompt(`Rename "${currentName}" to:`, currentName);
      if (newName && newName !== currentName) {
        const select = document.getElementById("send-ep-select");
        const svc = select.dataset.svc;
        const methodId = select.dataset.discoveryId; // This is the ID of the selected method/endpoint
        const url = currentRequestUrl;

        // Preserve current form data
        const currentData = formValuesToInitialData(collectFormValues());

        await chrome.runtime.sendMessage({
          type: "RENAME_FIELD",
          tabId: currentTabId,
          service: svc,
          methodId, // Crucial for reliable lookup
          schemaName: schema,
          fieldKey: key,
          newName,
          url,
        });

        // Refresh tabData so re-renders pick up the new schema
        tabData = await chrome.runtime.sendMessage({
          type: "GET_STATE",
          tabId: currentTabId,
        });

        // Reload form to reflect change, passing preserved data
        loadVirtualSchema(svc, select.dataset.discoveryId, currentData);
        // Re-render response tree so renamed field is immediately visible
        if (lastSendResult) {
          delete lastSendResult.discovery; // Clear stale snapshot so tabData is used
          renderResponse(lastSendResult);
        }
      }
    }
  });

  // ─── Export Functions ──────────────────────────────────────────────────────

  async function buildCurrentRequest() {
    const bodyMode = currentBodyMode;
    let url = currentRequestUrl;
    if (!url) return null;

    const httpMethod = currentRequestMethod;
    const contentType = currentContentType;
    const epKey = document.getElementById("send-ep-select").value;
    const sel = document.getElementById("send-ep-select");
    const selectedOpt = sel.options[sel.selectedIndex];

    const headers = {};
    for (const row of document.querySelectorAll(
      "#send-headers-list .header-row",
    )) {
      const key = row.querySelector(".header-key").value.trim();
      const val = row.querySelector(".header-val").value.trim();
      if (key) headers[key] = val;
    }

    let body;
    if (httpMethod === "GET" || httpMethod === "DELETE") {
      // Collect URL params from form fields even for GET/DELETE
      if (bodyMode === "form") {
        const formValues = collectFormValues();
        if (Object.keys(formValues.params).length > 0) {
          try {
            const urlObj = new URL(url);
            for (const [k, v] of Object.entries(formValues.params)) {
              urlObj.searchParams.set(k, String(v));
            }
            url = urlObj.toString();
          } catch (_) {}
        }
      }
      body = null;
    } else if (bodyMode === "form") {
      const formValues = collectFormValues();
      if (Object.keys(formValues.params).length > 0) {
        try {
          const urlObj = new URL(url);
          for (const [k, v] of Object.entries(formValues.params)) {
            urlObj.searchParams.set(k, String(v));
          }
          url = urlObj.toString();
        } catch (_) {}
      }
      body = {
        mode: "form",
        formData: { fields: formValues.fields },
      };
    } else if (bodyMode === "graphql") {
      body = {
        mode: "graphql",
        query: document.getElementById("send-gql-query").value,
        variables: document.getElementById("send-gql-variables").value,
        operationName: document.getElementById("send-gql-opname").value,
      };
    } else {
      body = {
        mode: "raw",
        rawBody: document.getElementById("send-raw-body").value,
      };
    }

    try {
      return await chrome.runtime.sendMessage({
        type: "BUILD_REQUEST",
        tabId: currentTabId,
        endpointKey: epKey,
        service: selectedOpt?.dataset?.svc,
        methodId: selectedOpt?.dataset?.discoveryId,
        url,
        httpMethod,
        contentType,
        headers,
        body,
      });
    } catch (_) {
      return null;
    }
  }

  function formatCurl(req) {
    const sq = (s) => s.replace(/'/g, "'\\''");
    const parts = [`curl -X '${sq(req.method)}'`];
    for (const [k, v] of Object.entries(req.headers || {})) {
      parts.push(`  -H '${sq(k)}: ${sq(v)}'`);
    }
    if (req.body) {
      const ct = (req.headers || {})["Content-Type"] || "";
      if (ct.includes("protobuf") || ct.includes("grpc")) {
        // Binary body is base64-encoded — pipe through base64 decode
        parts.push(`  --data-binary @- <<< $(echo '${sq(req.body)}' | base64 -d)`);
      } else {
        parts.push(`  -d '${sq(req.body)}'`);
      }
    }
    parts.push(`  '${sq(req.url)}'`);
    return parts.join(" \\\n");
  }

  function formatFetch(req) {
    const opts = { method: req.method };
    if (Object.keys(req.headers || {}).length) opts.headers = req.headers;
    if (req.body) opts.body = req.body;
    return `fetch(${JSON.stringify(req.url)}, ${JSON.stringify(opts, null, 2)});`;
  }

  function formatPython(req) {
    const lines = ["import requests", ""];
    const kwargs = [];
    const ct = (req.headers || {})["Content-Type"] || "";
    const isBinaryBody = ct.includes("protobuf") || ct.includes("grpc");
    const isJson = ct.includes("application/json");
    // For JSON content types, use json= with parsed object.
    // For binary (protobuf/gRPC-Web), body is base64 — decode it.
    // Otherwise use data= with raw string.
    if (isBinaryBody && req.body) {
      lines[0] = "import requests\nimport base64";
      kwargs.push(`    data=base64.b64decode(${JSON.stringify(req.body)})`);
    } else if (isJson && req.body) {
      try {
        const parsed = JSON.parse(req.body);
        kwargs.push(`    json=${JSON.stringify(parsed)}`);
      } catch (_) {
        kwargs.push(`    data=${JSON.stringify(req.body)}`);
      }
    } else if (req.body) {
      kwargs.push(`    data=${JSON.stringify(req.body)}`);
    }
    const headers = { ...(req.headers || {}) };
    // json= sets Content-Type automatically — remove to avoid conflict
    if (isJson && req.body) delete headers["Content-Type"];
    if (Object.keys(headers).length) {
      kwargs.push(`    headers=${JSON.stringify(headers)}`);
    }
    const fn = req.method === "GET" ? "get" : req.method === "POST" ? "post" : req.method === "PUT" ? "put" : req.method === "DELETE" ? "delete" : "request";
    if (fn === "request") {
      kwargs.unshift(`    ${JSON.stringify(req.method)}`);
    }
    const url = `${JSON.stringify(req.url)}`;
    if (kwargs.length) {
      lines.push(`resp = requests.${fn}(`);
      lines.push(`    ${url},`);
      lines.push(kwargs.join(",\n") + ",");
      lines.push(")");
    } else {
      lines.push(`resp = requests.${fn}(${url})`);
    }
    lines.push("print(resp.status_code, resp.text)");
    return lines.join("\n");
  }

  async function copyAsFormat(format) {
    const btn = document.getElementById(`btn-copy-${format}`);
    const req = await buildCurrentRequest();
    if (!req || req.error) {
      btn.textContent = "No request";
      setTimeout(() => { btn.textContent = format === "python" ? "Python" : format; }, 1500);
      return;
    }

    let text;
    if (format === "curl") text = formatCurl(req);
    else if (format === "fetch") text = formatFetch(req);
    else text = formatPython(req);

    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied!";
    } catch (_) {
      btn.textContent = "Failed";
    }
    setTimeout(() => { btn.textContent = format === "python" ? "Python" : format; }, 1500);
  }

  const EXTENSION_ORIGIN = `chrome-extension://${chrome.runtime.id}`;

  // Threat model: popup runs in the extension process (trusted), but broadcast
  // messages are received by all listeners including content scripts. sender.id
  // is spoofable (our content script runs in every renderer), so the real gate
  // is sender.url — set by the browser process, unforgeable by the renderer.
  // See SECURITY.md.
  chrome.runtime.onMessage.addListener((msg, sender) => {
    if (sender.id !== chrome.runtime.id) return;

    const isExtensionPage =
      sender.url && sender.url.startsWith(EXTENSION_ORIGIN + "/");
    if (!isExtensionPage) return;

    if (msg.type === "STATE_UPDATED") {
      if (msg.tabId === currentTabId || logFilter !== "active") {
        throttledLoadState();
      }
    }
  });
  loadState();
});

// ─── State ───────────────────────────────────────────────────────────────────

async function loadState() {
  tabData = await chrome.runtime.sendMessage({
    type: "GET_STATE",
    tabId: currentTabId,
  });
  if (logFilter !== "active") {
    await loadRequestLog();
  }
  render();
}

async function clearState() {
  await chrome.runtime.sendMessage({ type: "CLEAR_TAB", tabId: currentTabId });
  tabData = null;
  allTabsData = null;
  render();
}

async function loadRequestLog() {
  if (logFilter === "active") {
    allTabsData = null;
    return;
  }
  try {
    allTabsData = await chrome.runtime.sendMessage({
      type: "GET_ALL_LOGS",
      filter: logFilter,
    });
  } catch (_) {
    allTabsData = null;
  }
}

async function populateTabFilter() {
  const select = document.getElementById("log-tab-filter");
  if (!select) return;
  try {
    const tabList = await chrome.runtime.sendMessage({ type: "GET_TAB_LIST", tabId: currentTabId });
    // Remove old dynamic options (keep "Active Tab" and "All Tabs")
    while (select.options.length > 2) {
      select.remove(2);
    }
    if (tabList && tabList.length > 1) {
      const divider = document.createElement("option");
      divider.disabled = true;
      divider.textContent = "──────────";
      select.appendChild(divider);

      for (const t of tabList) {
        const opt = document.createElement("option");
        opt.value = String(t.tabId);
        let label = t.title
          ? (t.title.length > 30 ? t.title.slice(0, 30) + "\u2026" : t.title)
          : `Tab ${t.tabId}`;
        if (t.closed) label += " (closed)";
        opt.textContent = `${label} (${t.count})`;
        if (t.tabId === currentTabId) opt.textContent += " \u2605";
        select.appendChild(opt);
      }
    }
    // Restore selection
    if (logFilter !== "active" && logFilter !== "all") {
      select.value = String(logFilter);
    }
  } catch (_) {}
}

// ─── Render ──────────────────────────────────────────────────────────────────

function render() {
  renderDataPanel();
  renderSecurityPanel();
  renderSendPanel();
  renderResponsePanel();
  populateTabFilter();
}

// ─── Data Panel ──────────────────────────────────────────────────────────────

function renderDataPanel() {
  const keysContainer = document.getElementById("data-keys");
  const empty = document.getElementById("data-empty");

  keysContainer.innerHTML = "";

  const keys = tabData?.apiKeys ? Object.entries(tabData.apiKeys) : [];
  const hasData = keys.length > 0;
  empty.style.display = hasData ? "none" : "block";

  // Keys section
  if (keys.length) {
    let html = '<div class="section-header">Discovered API Keys</div>';
    for (const [key, info] of keys) {
      const services = info.services || [];
      const eps = info.endpoints || [];
      const reqCount = info.requestCount || eps.length || 0;

      html += `<div class="card">
        <div class="card-label">${esc(info.name || "API Key")} ${info.source === "page_source" ? '<span class="badge badge-source">page source</span>' : '<span class="badge badge-source">network</span>'}
          ${reqCount > 0 ? `<span class="badge badge-status">${reqCount} req</span>` : ""}
        </div>
        <div class="card-value">${esc(key)}</div>
        <div class="card-meta">
          ${info.origin ? `Origin: <strong>${esc(info.origin)}</strong>` : ""}
        </div>`;

      if (services.length) {
        html += `<div class="card-meta">Services: ${[...services].map((s) => `<code>${esc(s)}</code>`).join(" ")}</div>`;
      }
      html += `</div>`;
    }
    keysContainer.innerHTML = html;
  }
}

// ─── Security Panel ──────────────────────────────────────────────────────────

function renderSecurityPanel() {
  const container = document.getElementById("security-findings");
  const empty = document.getElementById("security-empty");
  container.innerHTML = "";

  const findings = tabData?.securityFindings || [];

  // Flatten all sinks and patterns with their source URL
  var allItems = [];
  for (var fi = 0; fi < findings.length; fi++) {
    var f = findings[fi];
    var srcLabel = f.sourceUrl || "(unknown)";
    for (var si = 0; si < (f.securitySinks || []).length; si++) {
      var s = f.securitySinks[si];
      allItems.push({ kind: "sink", item: s, sourceUrl: f.sourceUrl, srcLabel: srcLabel });
    }
    for (var di = 0; di < (f.dangerousPatterns || []).length; di++) {
      var d = f.dangerousPatterns[di];
      allItems.push({ kind: "pattern", item: d, sourceUrl: f.sourceUrl, srcLabel: srcLabel });
    }
  }

  if (!allItems.length) {
    empty.style.display = "block";
    return;
  }
  empty.style.display = "none";

  // Sort: high first, then medium, then low
  var sevOrder = { high: 0, medium: 1, low: 2 };
  allItems.sort(function(a, b) {
    return (sevOrder[a.item.severity] || 2) - (sevOrder[b.item.severity] || 2);
  });

  var html = '<div class="section-header">Security Findings <span class="badge badge-status">' + allItems.length + '</span></div>';

  for (var i = 0; i < allItems.length; i++) {
    var entry = allItems[i];
    var item = entry.item;
    var sev = item.severity || "low";
    var sevBadge = '<span class="badge badge-' + esc(sev) + '">' + esc(sev.toUpperCase()) + '</span>';
    var loc = item.location ? "L" + item.location.line + ":" + item.location.column : "";

    var codeHtml = item.codeContext
      ? '<div class="code-context">' + esc(item.codeContext) + '</div>'
      : '';

    var srcLink = entry.sourceUrl
      ? '<a href="' + esc(entry.sourceUrl) + '" target="_blank" title="' + esc(entry.sourceUrl) + '">' + esc(entry.srcLabel) + '</a>'
      : esc(entry.srcLabel);

    if (entry.kind === "sink") {
      var typeBadge = "";
      if (item.type === "xss") typeBadge = '<span class="badge badge-xss">XSS</span>';
      else if (item.type === "eval") typeBadge = '<span class="badge badge-eval">EVAL</span>';
      else if (item.type === "redirect") typeBadge = '<span class="badge badge-redirect">REDIRECT</span>';
      else typeBadge = '<span class="badge badge-danger">' + esc(item.type.toUpperCase()) + '</span>';

      var sourceDesc = item.sourceType === "user-controlled"
        ? "user-controlled" + (item.source ? ": " + esc(item.source) : "")
        : item.sourceType === "dynamic" ? "dynamic value" : "literal value";

      html += '<div class="card">'
        + '<div class="card-label">' + typeBadge + ' ' + sevBadge + ' ' + esc(item.sink) + '</div>'
        + '<div class="card-value">' + esc(sourceDesc) + '</div>'
        + codeHtml
        + '<div class="card-meta">' + srcLink + (loc ? " " + esc(loc) : "") + '</div>'
        + '</div>';
    } else {
      var patBadge = '<span class="badge badge-danger">' + esc((item.type || "pattern").toUpperCase().replace(/-/g, " ")) + '</span>';

      html += '<div class="card">'
        + '<div class="card-label">' + patBadge + ' ' + sevBadge + '</div>'
        + '<div class="card-value">' + esc(item.description || item.type) + '</div>'
        + codeHtml
        + '<div class="card-meta">' + srcLink + (loc ? " " + esc(loc) : "") + '</div>'
        + '</div>';
    }
  }

  container.innerHTML = html;
}

// ─── Send Panel ──────────────────────────────────────────────────────────────

function renderSendPanel() {
  // Populate service selector
  const svcSelect = document.getElementById("spec-service-select");
  const prevSvc = svcSelect.value;
  svcSelect.innerHTML = '<option value="">All Services</option>';
  if (tabData?.discoveryDocs) {
    for (const [svcName, svcData] of Object.entries(tabData.discoveryDocs).sort((a, b) => a[0].localeCompare(b[0]))) {
      if (svcData.status === "found" && svcData.doc) {
        const methodCount = getDocMethods(svcData.doc).length;
        const opt = document.createElement("option");
        opt.value = svcName;
        opt.textContent = `${svcName} (${methodCount})`;
        svcSelect.appendChild(opt);
      }
    }
  }
  if (prevSvc) svcSelect.value = prevSvc;

  renderMethodDropdown();
}

function renderMethodDropdown() {
  const svcFilter = document.getElementById("spec-service-select").value;
  const select = document.getElementById("send-ep-select");
  const prev = select.value;

  select.innerHTML = '<option value="">-- select method --</option>';

  if (tabData?.discoveryDocs) {
    const services = Object.entries(tabData.discoveryDocs).sort((a, b) =>
      a[0].localeCompare(b[0]),
    );

    for (const [svcName, svcData] of services) {
      if (svcFilter && svcName !== svcFilter) continue;
      if (svcData.status === "found" && svcData.doc) {
        const methods = getDocMethods(svcData.doc);
        methods.sort((a, b) => a.id.localeCompare(b.id));

        if (methods.length > 0) {
          const group = document.createElement("optgroup");
          group.label = svcData.doc.title || svcName;

          for (const m of methods) {
            const opt = document.createElement("option");
            const key = `DISCOVERY ${m.httpMethod} ${svcName} ${m.id}`;
            opt.value = key;
            opt.textContent = `[${m.httpMethod}] ${m.id}`;
            opt.dataset.method = m.httpMethod;
            opt.dataset.isVirtual = "true";
            opt.dataset.svc = svcName;
            opt.dataset.path = m.path;
            opt.dataset.discoveryId = m.id;
            group.appendChild(opt);
          }
          select.appendChild(group);
        }
      }
    }
  }

  if (prev) select.value = prev;
}

function renderFieldsTable(fields, depth) {
  depth = depth || 0;
  let html = "";
  if (depth === 0) {
    html += `<table class="fields-table"><thead><tr><th>#</th><th>Field</th><th>Type</th><th>Message Type</th><th>Label</th></tr></thead><tbody>`;
  }

  for (const [name, f] of fields) {
    const indent = depth > 0 ? `padding-left:${depth * 16}px` : "";
    const labelClass = f.required
      ? "f-req"
      : f.label === "repeated"
        ? "f-repeated"
        : "";
    const labelText = f.required ? "required" : f.label || "";

    html += `<tr>
      <td class="f-num">${f.number ?? ""}</td>
      <td class="f-name"${indent ? ` data-indent="${depth}"` : ""}>${depth > 0 ? "&#x2514; " : ""}${esc(name)}</td>
      <td class="f-type">${esc(f.type)}</td>
      <td class="f-msg">${esc(f.messageType || "")}</td>
      <td class="${labelClass}">${esc(labelText)}</td>
    </tr>`;

    if (f.children?.length) {
      const childEntries = f.children.map((c) => [
        c.name || `field_${c.number}`,
        c,
      ]);
      html += renderFieldsTable(childEntries, depth + 1);
    }
  }

  if (depth === 0) {
    html += `</tbody></table>`;
  }
  return html;
}

// ─── Send Panel: Endpoint Selection + Schema ─────────────────────────────────

function onSendEndpointSelected() {
  const select = document.getElementById("send-ep-select");
  const epKey = select.value;

  // Handle virtual discovery endpoint
  const selectedOpt = select.options[select.selectedIndex];
  if (selectedOpt?.dataset?.isVirtual === "true") {
    const svc = selectedOpt.dataset.svc;
    const pathTemplate = selectedOpt.dataset.path;
    const validMethod = selectedOpt.dataset.method;
    const discoveryId = selectedOpt.dataset.discoveryId; // Use data-discoveryId
    const svcData = tabData?.discoveryDocs?.[svc];
    const doc = svcData?.doc;

    // baseUrl resolution from doc
    let baseUrl = doc?.baseUrl || doc?.rootUrl;
    if (!baseUrl && doc?.rootUrl) {
      baseUrl = doc.rootUrl + (doc.servicePath || "");
    }
    // Fallback
    if (!baseUrl) {
      console.warn("No baseUrl found for service", svc, svcData);
      // Try to construct from service name if possible, or leave empty
      baseUrl = "";
    }

    // Fix double slashes just in case
    if (baseUrl.endsWith("/") && pathTemplate.startsWith("/")) {
      baseUrl = baseUrl.slice(0, -1);
    }

    currentRequestUrl = baseUrl + pathTemplate;
    currentRequestMethod = validMethod;

    select.dataset.svc = svc;
    select.dataset.discoveryId = discoveryId;

    // Load schema via background
    loadVirtualSchema(svc, discoveryId);
    return;
  }

  // Fallback if no matching endpoint found
  currentRequestUrl = "";
  currentRequestMethod = "POST";
  document.getElementById("send-form-fields").innerHTML =
    '<div class="hint">Select a method to load its schema.</div>';
  renderChainInfo(null);
}

async function loadVirtualSchema(service, methodId, initialData = null) {
  currentSchema = null;
  document.getElementById("send-form-fields").innerHTML =
    '<div class="hint">Loading schema...</div>';

  try {
    const schema = await chrome.runtime.sendMessage({
      type: "GET_ENDPOINT_SCHEMA",
      tabId: currentTabId,
      service,
      methodId,
    });

    if (!schema || !schema.method) {
      document.getElementById("send-form-fields").innerHTML =
        '<div class="hint">Method definition not found.</div>';
      return;
    }

    currentSchema = schema;

    // Auto-determine Content-Type from learned schema
    if (schema.contentTypes?.length) {
      currentContentType = schema.contentTypes[0];
    } else if (schema.endpoint?.contentType) {
      currentContentType = schema.endpoint.contentType;
    } else {
      currentContentType = "application/json";
    }

    // Auto-set body mode: GraphQL if URL matches, otherwise form
    if (isGraphQLUrl(currentRequestUrl)) {
      setBodyMode("graphql");
    } else {
      setBodyMode("form");
    }

    buildFormFields(schema, initialData);
    renderChainInfo(schema.chains);
  } catch (err) {
    console.error("Error loading virtual schema:", err);
    document.getElementById("send-form-fields").innerHTML =
      `<div class="hint">Error loading schema: ${esc(err.message)}</div>`;
  }
}

function renderChainInfo(chains) {
  const container = document.getElementById("send-chain-info");
  if (!container) return;
  if (!chains || (!chains.incoming?.length && !chains.outgoing?.length)) {
    container.classList.add("hidden");
    container.innerHTML = "";
    return;
  }
  container.classList.remove("hidden");
  let html = '<div class="chain-info-box">';
  if (chains.incoming?.length) {
    html += '<div class="chain-section"><span class="chain-section-label">Receives data from:</span>';
    for (const link of chains.incoming) {
      html += `<div class="chain-link chain-incoming">` +
        `<span class="chain-param">${esc(link.paramName)}</span>` +
        `<span class="chain-arrow">&larr;</span>` +
        `<span class="chain-source">${esc(link.sourceMethodId)}</span>` +
        `<span class="chain-field">.${esc(link.sourceFieldPath)}</span>` +
        (link.observedCount > 1 ? `<span class="chain-count">${link.observedCount}x</span>` : "") +
        `</div>`;
    }
    html += '</div>';
  }
  if (chains.outgoing?.length) {
    html += '<div class="chain-section"><span class="chain-section-label">Feeds data to:</span>';
    for (const link of chains.outgoing) {
      html += `<div class="chain-link chain-outgoing">` +
        `<span class="chain-field">${esc(link.sourceFieldPath)}</span>` +
        `<span class="chain-arrow">&rarr;</span>` +
        `<span class="chain-source">${esc(link.targetMethodId)}</span>` +
        `<span class="chain-param">.${esc(link.paramName)}</span>` +
        (link.observedCount > 1 ? `<span class="chain-count">${link.observedCount}x</span>` : "") +
        `</div>`;
    }
    html += '</div>';
  }
  html += '</div>';
  container.innerHTML = html;
}

function pbTreeToMap(nodes) {
  if (!nodes) return null;
  const map = {};
  for (const node of nodes) {
    if (node.message) {
      map[node.field] = pbTreeToMap(node.message);
    } else if (node.isJspb && Array.isArray(node.value)) {
      // For JSPB, we might have mixed arrays. Try to detect messages.
      map[node.field] = node.value.map((item) => {
        if (Array.isArray(item)) return pbTreeToMap(jspbToTree(item));
        return item;
      });
    } else {
      map[node.field] = node.value ?? node.string ?? node.hex ?? node.asFloat;
    }
  }
  return map;
}

function buildFormFields(schema, initialData = null) {
  const container = document.getElementById("send-form-fields");
  container.innerHTML = "";

  if (schema.method && (schema.method.description || schema.method.scopes?.length)) {
    const info = el("div", "card");
    info.style.marginBottom = "8px";
    let html = "";
    if (schema.method.description) {
      html += `<div class="card-meta">${esc(schema.method.description)}</div>`;
    }
    if (schema.method.scopes?.length) {
      html += `<div class="card-meta scopes-row">Scopes: ${schema.method.scopes.map((s) => `<code>${esc(s)}</code>`).join(" ")}</div>`;
    }
    info.innerHTML = html;
    container.appendChild(info);
  }

  if (schema.parameters && Object.keys(schema.parameters).length > 0) {
    const section = el("div", "form-section");
    section.innerHTML = '<div class="form-section-label">URL Parameters</div>';
    for (const [name, param] of Object.entries(schema.parameters)) {
      section.appendChild(
        createFieldInput(
          name,
          {
            name: param.name, // Pass the name (which might be an alias)
            type:
              param.type === "integer"
                ? "int32"
                : param.type === "boolean"
                  ? "bool"
                  : "string",
            required: param.required,
            description: param.description,
            label: param.required ? "required" : "optional",
            number: null,
            messageType: null,
            children: null,
            enum: param.enum || null,
            location: param.location,
            parentSchema: "params",
            _astValidValues: param._astValidValues || null,
            _astValueSource: param._astValueSource || null,
            _detectedEnum: param._detectedEnum || false,
            _defaultValue: param._defaultValue ?? null,
            _defaultConfidence: param._defaultConfidence ?? null,
            _requiredConfidence: param._requiredConfidence ?? null,
            _range: param._range || null,
          },
          "param",
          0,
          initialData && initialData[name] !== undefined
            ? initialData[name]
            : null,
        ),
      );
    }
    container.appendChild(section);
  }

  if (schema.requestBody?.fields?.length > 0) {
    const section = el("div", "form-section");
    const label = schema.requestBody.schemaName
      ? `Request Body (${esc(schema.requestBody.schemaName)})`
      : "Request Body";
    section.innerHTML = `<div class="form-section-label">${label}</div>`;
    for (const field of schema.requestBody.fields) {
      const fieldVal = initialData
        ? (initialData[field.number] ?? initialData[field.name] ?? null)
        : null;
      section.appendChild(
        createFieldInput(
          field.name,
          { ...field, parentSchema: schema.requestBody.schemaName },
          "body",
          0,
          fieldVal,
        ),
      );
    }
    container.appendChild(section);
  }

  if (!schema.parameters && !schema.requestBody?.fields?.length) {
    container.innerHTML = '<div class="hint">No schema available.</div>';
  }

  // Show raw body textarea alongside form when schema has no body fields
  // but the method has a body (POST/PUT/PATCH) — allows editing unknown body formats
  if (!schema.requestBody?.fields?.length) {
    const method = (currentRequestMethod || "").toUpperCase();
    if (method !== "GET" && method !== "DELETE") {
      document.getElementById("send-raw-body").style.display = "block";
    }
  }
}

function createFieldInput(
  name,
  fieldDef,
  category,
  depth,
  initialValue = null,
) {
  depth = depth || 0;
  const wrapper = el("div", "form-field");
  wrapper.style.paddingLeft = depth * 16 + "px";

  wrapper.dataset.name = name;
  wrapper.dataset.type = fieldDef.type || "string";
  wrapper.dataset.category = category;
  if (fieldDef.number) wrapper.dataset.number = fieldDef.number;
  if (fieldDef.label) wrapper.dataset.label = fieldDef.label;
  if (fieldDef.location) wrapper.dataset.location = fieldDef.location;

  const labelEl = el("label", "form-field-label");
  const displayName = fieldDef.name || name;
  let labelHtml = `<span class="field-name">${esc(displayName)}</span>`;

  // Add rename button for learned/indexed fields or parameters
  if (fieldDef.number || name.startsWith("field") || category === "param") {
    labelHtml += ` <span class="btn-rename" title="Rename field" data-schema="${esc(fieldDef.parentSchema || "params")}" data-key="${esc(name)}">✎</span>`;
  }

  if (fieldDef.number)
    labelHtml += ` <span class="field-number">#${fieldDef.number}</span>`;
  labelHtml += ` <span class="field-type">${esc(fieldDef.type || "string")}</span>`;
  if (fieldDef.required)
    labelHtml += ` <span class="field-required">required</span>`;
  if (fieldDef.label === "repeated")
    labelHtml += ` <span class="field-repeated">repeated</span>`;

  // Stats-derived badges
  if (fieldDef._requiredConfidence != null && !fieldDef.required) {
    labelHtml += ` <span class="field-stat badge-optional">seen ${Math.round(fieldDef._requiredConfidence * 100)}%</span>`;
  }
  if (fieldDef._detectedEnum && fieldDef.enum) {
    labelHtml += ` <span class="field-stat badge-enum-detected">enum detected</span>`;
  }
  if (fieldDef._defaultValue != null) {
    labelHtml += ` <span class="field-stat badge-default">default: ${esc(String(fieldDef._defaultValue))}</span>`;
  }
  if (fieldDef._range) {
    labelHtml += ` <span class="field-stat badge-range">${fieldDef._range.min}\u2013${fieldDef._range.max}</span>`;
  }
  if (fieldDef.format && fieldDef.format !== fieldDef.type) {
    labelHtml += ` <span class="field-stat badge-format">${esc(fieldDef.format)}</span>`;
  }

  labelEl.innerHTML = labelHtml;
  wrapper.appendChild(labelEl);

  if (fieldDef.description) {
    const desc = el("div", "field-description");
    desc.textContent = fieldDef.description;
    wrapper.appendChild(desc);
  }

  // Show AST-discovered valid values as clickable chips
  if (fieldDef._astValidValues && fieldDef._astValidValues.length > 0 && !fieldDef.enum) {
    const valHint = el("div", "field-ast-values");
    valHint.innerHTML = '<span class="ast-values-label">Values found in JS:</span> '
      + fieldDef._astValidValues.map(v => '<span class="ast-value-chip">' + esc(String(v)) + '</span>').join(' ');
    valHint.addEventListener("click", function(e) {
      if (!e.target.classList.contains("ast-value-chip")) return;
      var input = wrapper.querySelector(".form-input");
      if (input) { input.value = e.target.textContent; input.dispatchEvent(new Event("input")); }
    });
    wrapper.appendChild(valHint);
  }

  if (fieldDef.type === "message" && fieldDef.children?.length) {
    const details = document.createElement("details");
    details.open = initialValue !== null || depth < 1;
    details.className = "form-message-group";
    const summary = document.createElement("summary");
    summary.textContent = fieldDef.messageType || fieldDef.name || "message";
    details.appendChild(summary);

    const childContainer = el("div", "form-message-children");
    for (const child of fieldDef.children) {
      const childVal = initialValue ? initialValue[child.number] : null;
      childContainer.appendChild(
        createFieldInput(
          child.name,
          {
            ...child,
            parentSchema: fieldDef.messageType || fieldDef.parentSchema,
          },
          category,
          depth + 1,
          childVal,
        ),
      );
    }
    details.appendChild(childContainer);
    wrapper.appendChild(details);
  } else if (fieldDef.label === "repeated" && fieldDef.type !== "message") {
    const listContainer = el("div", "form-repeated-list");
    listContainer.dataset.fieldType = fieldDef.type;

    if (Array.isArray(initialValue) && initialValue.length > 0) {
      for (const val of initialValue) {
        listContainer.appendChild(createSingleInput(fieldDef, val));
      }
    } else {
      listContainer.appendChild(createSingleInput(fieldDef, initialValue));
    }
    wrapper.appendChild(listContainer);

    const addBtn = el("button", "btn-small");
    addBtn.textContent = "+ Add";
    addBtn.type = "button";
    addBtn.addEventListener("click", () => {
      listContainer.appendChild(createSingleInput(fieldDef));
    });
    wrapper.appendChild(addBtn);
  } else if (fieldDef.type !== "message") {
    wrapper.appendChild(createSingleInput(fieldDef, initialValue));
  }

  return wrapper;
}

function createSingleInput(fieldDef, initialValue = null) {
  const type = fieldDef.type || "string";

  if ((type === "enum" || fieldDef.enum) && fieldDef.enum?.length) {
    const sel = document.createElement("select");
    sel.className = "form-input form-input-select";
    const emptyOpt = document.createElement("option");
    emptyOpt.value = "";
    emptyOpt.textContent = "-- select --";
    sel.appendChild(emptyOpt);
    for (let i = 0; i < fieldDef.enum.length; i++) {
      const opt = document.createElement("option");
      opt.value = fieldDef.enum[i];
      opt.textContent =
        fieldDef.enum[i] +
        (fieldDef.enumDescriptions?.[i]
          ? " - " + fieldDef.enumDescriptions[i]
          : "");
      if (
        initialValue !== null &&
        String(initialValue) === String(fieldDef.enum[i])
      ) {
        opt.selected = true;
      }
      sel.appendChild(opt);
    }
    return sel;
  }

  switch (type) {
    case "bool": {
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "form-input form-input-bool";
      if (initialValue === true || initialValue === 1 || initialValue === "1")
        cb.checked = true;
      return cb;
    }
    case "enum": {
      const inp = document.createElement("input");
      inp.type = "number";
      inp.className = "form-input form-input-enum";
      inp.placeholder = "enum value (integer)";
      inp.min = "0";
      if (initialValue !== null) inp.value = initialValue;
      return inp;
    }
    case "int32":
    case "int64":
    case "uint32":
    case "uint64":
    case "sint32":
    case "sint64":
    case "double":
    case "float":
    case "fixed32":
    case "fixed64":
    case "sfixed32":
    case "sfixed64": {
      const inp = document.createElement("input");
      inp.type = "number";
      inp.className = "form-input form-input-number";
      inp.placeholder = type;
      if (type === "double" || type === "float") inp.step = "any";
      if (initialValue !== null) inp.value = initialValue;
      return inp;
    }
    case "bytes": {
      const ta = document.createElement("textarea");
      ta.className = "form-input form-input-bytes";
      ta.placeholder = "base64-encoded bytes";
      ta.rows = 2;
      if (initialValue !== null) ta.value = initialValue;
      return ta;
    }
    default: {
      const inp = document.createElement("input");
      inp.type = "text";
      inp.className = "form-input form-input-string";
      inp.placeholder = type || "value";
      if (initialValue !== null) {
        inp.value =
          typeof initialValue === "object"
            ? JSON.stringify(initialValue)
            : initialValue;
      }
      return inp;
    }
  }
}

// ─── Send Panel: Value Collection + Request ──────────────────────────────────

function formFieldsToMap(fields) {
  const map = {};
  for (const f of fields) {
    if (f.number === null || f.number === undefined) continue;
    if (f.type === "message" && f.children) {
      map[f.number] = formFieldsToMap(f.children);
    } else {
      map[f.number] = f.value;
    }
  }
  return map;
}

function formValuesToInitialData(formValues) {
  if (!formValues) return null;
  const data = { ...formValues.params };
  const fieldMap = formFieldsToMap(formValues.fields);
  Object.assign(data, fieldMap);
  return data;
}

function collectFormValues() {
  const params = {};
  const fields = [];
  const topFields = document.querySelectorAll(
    "#send-form-fields > .form-section > .form-field",
  );

  for (const wrapper of topFields) {
    const result = collectSingleField(wrapper);
    if (!result) continue;
    if (wrapper.dataset.category === "param") {
      if (result.value !== "" && result.value != null)
        params[result.name] = result.value;
    } else {
      fields.push(result);
    }
  }

  return { params, fields };
}

function collectSingleField(wrapper) {
  const name = wrapper.dataset.name;
  const type = wrapper.dataset.type;
  const number = wrapper.dataset.number
    ? parseInt(wrapper.dataset.number)
    : null;
  const label = wrapper.dataset.label || "optional";

  if (type === "message") {
    const childContainer = wrapper.querySelector(
      ":scope > .form-message-group > .form-message-children",
    );
    if (!childContainer) return null;
    const children = [];
    for (const child of childContainer.querySelectorAll(
      ":scope > .form-field",
    )) {
      const cv = collectSingleField(child);
      if (cv) children.push(cv);
    }
    return { name, type, number, label, value: null, children };
  }

  if (label === "repeated") {
    const inputs = wrapper.querySelectorAll(".form-repeated-list .form-input");
    const values = [];
    for (const inp of inputs) {
      const v = getInputValue(inp, type);
      if (v !== "" && v != null) values.push(v);
    }
    if (!values.length) return null;
    return { name, type, number, label, value: values, children: null };
  }

  const input = wrapper.querySelector(":scope > .form-input");
  if (!input) return null;
  const value = getInputValue(input, type);
  if (value === "" || value == null) return null;
  return { name, type, number, label, value, children: null };
}

function getInputValue(input, type) {
  if (type === "bool") return input.checked;
  if (input.value === "") return null;
  if (type === "enum") {
    // Enum values may be strings (AST-detected constraints) or integers (protobuf enums).
    // Return as number only if the value is numeric.
    var numVal = Number(input.value);
    return isNaN(numVal) ? input.value : numVal;
  }
  if (
    [
      "int32",
      "int64",
      "uint32",
      "uint64",
      "double",
      "float",
      "sint32",
      "sint64",
      "fixed32",
      "fixed64",
      "sfixed32",
      "sfixed64",
    ].includes(type)
  ) {
    return Number(input.value);
  }
  return input.value;
}

async function sendRequest() {
  const btn = document.getElementById("btn-send");
  btn.disabled = true;
  btn.textContent = "Sending...";

  const bodyMode = currentBodyMode;
  let url = currentRequestUrl;
  const httpMethod = currentRequestMethod;
  const contentType = currentContentType;
  const epKey = document.getElementById("send-ep-select").value;

  const headers = {};
  for (const row of document.querySelectorAll(
    "#send-headers-list .header-row",
  )) {
    const key = row.querySelector(".header-key").value.trim();
    const val = row.querySelector(".header-val").value.trim();
    if (key) headers[key] = val;
  }

  let body;
  if (httpMethod === "GET" || httpMethod === "DELETE") {
    // Collect URL params from form fields even for GET/DELETE
    if (bodyMode === "form") {
      const formValues = collectFormValues();
      if (Object.keys(formValues.params).length > 0) {
        try {
          const urlObj = new URL(url);
          for (const [k, v] of Object.entries(formValues.params)) {
            urlObj.searchParams.set(k, String(v));
          }
          url = urlObj.toString();
          currentRequestUrl = url;
        } catch (_) {
          console.warn("[Send] URL construction failed:", _);
        }
      }
    }
    body = { mode: "raw", formData: null, rawBody: null, frameId: currentReplayRequest?.frameId };
  } else if (bodyMode === "form") {
    const formValues = collectFormValues();
    if (Object.keys(formValues.params).length > 0) {
      try {
        const urlObj = new URL(url);
        for (const [k, v] of Object.entries(formValues.params)) {
          urlObj.searchParams.set(k, String(v));
        }
        url = urlObj.toString();
        currentRequestUrl = url;
      } catch (_) {
        console.warn("[Send] URL construction failed:", _);
      }
    }
    if (formValues.fields.length === 0) {
      // No body fields in schema — fall back to raw body (e.g. replayed form-urlencoded body)
      const rawFallback = document.getElementById("send-raw-body").value;
      body = rawFallback
        ? { mode: "raw", formData: null, rawBody: rawFallback, frameId: currentReplayRequest?.frameId }
        : { mode: "form", formData: { fields: [] }, rawBody: null, frameId: currentReplayRequest?.frameId };
    } else {
      body = {
        mode: "form",
        formData: { fields: formValues.fields },
        rawBody: null,
        frameId: currentReplayRequest?.frameId,
      };
    }
  } else if (bodyMode === "graphql") {
    body = {
      mode: "graphql",
      query: document.getElementById("send-gql-query").value,
      variables: document.getElementById("send-gql-variables").value,
      operationName: document.getElementById("send-gql-opname").value,
      frameId: currentReplayRequest?.frameId,
    };
  } else {
    body = {
      mode: "raw",
      formData: null,
      rawBody: document.getElementById("send-raw-body").value,
      frameId: currentReplayRequest?.frameId,
    };
  }

  const sel = document.getElementById("send-ep-select");
  const selectedOpt = sel.options[sel.selectedIndex];

  const msg = {
    type: "SEND_REQUEST",
    tabId: currentTabId,
    endpointKey: epKey,
    service: selectedOpt?.dataset?.svc,
    methodId: selectedOpt?.dataset?.discoveryId,
    url,
    httpMethod,
    contentType,
    headers,
    body,
  };

  try {
    const result = await chrome.runtime.sendMessage(msg);
    renderResponse(result);

    // Scroll result into view
    setTimeout(() => {
      document
        .getElementById("send-response")
        .scrollIntoView({ behavior: "smooth", block: "start" });
    }, 100);
  } catch (err) {
    renderResponse({ error: err.message });
  }

  btn.disabled = false;
  btn.textContent = "Send Request";
}

function renderResponse(result) {
  lastSendResult = result;
  const container = document.getElementById("send-response");
  container.style.display = "block";

  // Restore child structure if a previous error replaced it via innerHTML
  if (!document.getElementById("send-response-status")) {
    container.innerHTML =
      '<div class="section-header">Manual Send Result</div>' +
      '<div id="send-response-status"></div>' +
      '<details id="send-response-headers-section"><summary>Response Headers</summary>' +
      '<table id="send-response-headers" class="auth-table"></table></details>' +
      '<div id="send-response-body"></div>';
  }

  if (result.error && !result.status) {
    document.getElementById("send-response-status").innerHTML = "";
    document.getElementById("send-response-headers").innerHTML = "";
    document.getElementById("send-response-body").innerHTML =
      `<div class="card"><div class="card-label">Error</div><div class="card-value">${esc(result.error)}</div></div>`;
    return;
  }

  const statusEl = document.getElementById("send-response-status");
  const statusClass =
    result.ok || (result.status >= 200 && result.status < 300)
      ? "resp-status-ok"
      : "resp-status-error";
  statusEl.innerHTML =
    `<span class="${statusClass}">${esc(String(result.status))} ${esc(result.statusText || "")}</span>` +
    ` <span class="resp-timing">${result.timing || 0}ms</span>` +
    ` <span class="resp-size">${result.body?.size || 0} bytes</span>`;

  const headersTable = document.getElementById("send-response-headers");
  headersTable.innerHTML = "";
  if (result.headers) {
    for (const [k, v] of Object.entries(result.headers)) {
      headersTable.innerHTML += `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`;
    }
  }

  const bodyEl = document.getElementById("send-response-body");
  if (!result.body) {
    bodyEl.innerHTML = '<div class="hint">No response body</div>';
    return;
  }

  bodyEl.innerHTML = renderResultBody(result);

  const dlBtn = document.getElementById("btn-download-response");
  if (dlBtn) {
    dlBtn.onclick = () => {
      saveBinaryResponse(
        result.body.raw,
        result.body.bodyEncoding,
        result.body.contentType,
      ).catch(() => {});
    };
  }
}

function renderResultBody(result) {
  // Use schema-aware rendering if possible
  const methodId =
    result.methodId ||
    document.getElementById("send-ep-select").dataset.discoveryId;
  const svc =
    result.service || document.getElementById("send-ep-select").dataset.svc;
  let respSchema = null;

  // Prioritize discovery info returned in the result (most up-to-date)
  const discoveryInfo = result.discovery || tabData?.discoveryDocs?.[svc];

  // Deterministic schema ID for storing response field renames
  const responseSchemaId = methodId ? `${methodId}.response` : "";

  const doc = discoveryInfo?.doc || null;
  if (svc && methodId && doc) {
    const methodInfo = findMethodById(doc, methodId);
    if (methodInfo?.method?.response?.$ref) {
      respSchema = resolveDiscoverySchema(doc, methodInfo.method.response.$ref);
    }
    // Fallback: check for manually-created schema when no probed schema exists
    if (!respSchema && responseSchemaId && doc.schemas?.[responseSchemaId]) {
      respSchema = doc.schemas[responseSchemaId];
    }
  }

  // Check raw body for async chunked format (takes priority — it wraps JSPB)
  const rawBody = result.body.raw || "";
  const respContentType = result.headers?.["content-type"] || "";

  if (isAsyncChunkedResponse(rawBody)) {
    return renderAsyncResponse(
      rawBody,
      { service: result.service || svc, url: currentRequestUrl },
      discoveryInfo?.doc,
    );
  }

  // gRPC-Web: unwrap frames, render protobuf trees
  if (result.body.format === "grpc_web") {
    const grpcBytes = result.body.bytes || (result.body.bytesB64 ? base64ToUint8(result.body.bytesB64) : null);
    if (grpcBytes) {
      return renderGrpcWebResponse(
        grpcBytes,
        { service: result.service || svc, methodId: result.methodId },
        discoveryInfo?.doc,
      );
    }
  }

  // SSE: split events, render individually
  if (isSSE(respContentType)) {
    return renderSSEResponse(rawBody);
  }

  // NDJSON: split lines, render as records
  if (isNDJSON(respContentType)) {
    return renderNDJSONResponse(rawBody);
  }

  // Multipart batch: parse MIME parts
  if (isMultipartBatch(respContentType)) {
    return renderMultipartBatchResponse(rawBody, respContentType);
  }

  // GraphQL: enhanced display with data/errors/extensions sections
  if (isGraphQLUrl(currentRequestUrl) && result.body.format === "json") {
    const gqlHtml = renderGraphQLResponse(rawBody);
    if (gqlHtml) return gqlHtml;
  }

  // batchexecute: detect by content (wrb.fr markers), not just URL
  if (isBatchExecuteResponse(rawBody)) {
    return renderBatchExecuteResponse(
      rawBody,
      { service: result.service || svc },
      discoveryInfo?.doc,
    );
  }

  if (result.body.format === "binary_download") {
    const ct = result.body.contentType || "application/octet-stream";
    const sizeKB = (result.body.size / 1024).toFixed(1);
    const ext = mimeToExt(ct);
    return `<div class="card card-compact">
      <div class="card-label">Binary Response</div>
      <div class="card-value">${esc(ct)} — ${sizeKB} KB</div>
      <button class="btn-action" id="btn-download-response">Save As${ext ? " (." + ext + ")" : ""}</button>
    </div>`;
  }

  if (result.body.format === "json") {
    const nodes = jsonToTree(result.body.parsed);
    return (
      `<div class="card-label">Decoded JSON</div>` +
      renderPbTree(nodes, respSchema, responseSchemaId, doc)
    );
  } else if (result.body.format === "protobuf_tree") {
    return (
      `<div class="card-label">Decoded Protobuf</div>` +
      renderPbTree(result.body.parsed, respSchema, responseSchemaId, doc)
    );
  } else {
    return `<pre class="resp-body">${esc(result.body.raw || "")}</pre>`;
  }
}

function addHeaderRow(initialKey = "", initialValue = "") {
  const list = document.getElementById("send-headers-list");
  const row = el("div", "header-row");
  row.innerHTML =
    `<input class="header-key" type="text" placeholder="Header-Name" value="${esc(initialKey)}" />` +
    `<input class="header-val" type="text" placeholder="value" value="${esc(initialValue)}" />` +
    `<button class="btn-remove-header" type="button" title="Remove">&times;</button>`;
  row
    .querySelector(".btn-remove-header")
    .addEventListener("click", () => row.remove());
  list.appendChild(row);
}

// ─── Export / Copy ────────────────────────────────────────────────────────────

function copyToClipboard(panelName, data) {
  const btn = document.getElementById(`btn-export-${panelName}`);
  const text = JSON.stringify(data ?? null, null, 2);

  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = "Copy";
      btn.classList.remove("copied");
    }, 1500);
  });
}

// ─── Spec Export / Import ────────────────────────────────────────────────────

async function exportOpenApiSpec() {
  const svcFilter = document.getElementById("spec-service-select").value;

  // Collect services to export
  const services = [];
  if (svcFilter) {
    services.push(svcFilter);
  } else if (tabData?.discoveryDocs) {
    for (const [svcName, svcData] of Object.entries(tabData.discoveryDocs)) {
      if (svcData.status === "found") services.push(svcName);
    }
  }
  if (!services.length) {
    alert("No services discovered yet.");
    return;
  }

  const btn = document.getElementById("btn-export-spec");
  btn.disabled = true;
  btn.textContent = "...";

  try {
    // Collect all specs
    const specs = [];
    for (const svc of services) {
      const result = await chrome.runtime.sendMessage({
        type: "EXPORT_OPENAPI",
        tabId: currentTabId,
        service: svc,
      });
      if (result?.error && services.length === 1) { alert(result.error); return; }
      if (result?.spec) specs.push({ svc, spec: result.spec });
    }
    if (!specs.length) { alert("No specs to export."); return; }

    let combined;
    let filename;
    if (specs.length === 1) {
      combined = specs[0].spec;
      filename = specs[0].svc.replace(/[^a-zA-Z0-9.-]/g, "_") + ".openapi.json";
    } else {
      // Merge all specs into one
      combined = {
        openapi: "3.0.3",
        info: {
          title: "API Security Researcher — Combined Export",
          description: `Merged from ${specs.length} services: ${specs.map(s => s.svc).join(", ")}`,
          version: "v1",
        },
        servers: [],
        paths: {},
        components: { schemas: {} },
      };
      const seenServers = new Set();
      for (const { spec } of specs) {
        for (const srv of spec.servers || []) {
          if (!seenServers.has(srv.url)) {
            seenServers.add(srv.url);
            combined.servers.push(srv);
          }
        }
        Object.assign(combined.paths, spec.paths || {});
        Object.assign(combined.components.schemas, spec.components?.schemas || {});
        if (spec.components?.securitySchemes) {
          combined.components.securitySchemes = {
            ...combined.components.securitySchemes,
            ...spec.components.securitySchemes,
          };
        }
      }
      filename = "combined.openapi.json";
    }
    await downloadJson(combined, filename);
    btn.textContent = "Done!";
    setTimeout(() => { btn.textContent = "Export"; btn.disabled = false; }, 1500);
  } catch (err) {
    alert("Export failed: " + err.message);
    btn.textContent = "Export";
    btn.disabled = false;
  }
}

async function downloadJson(obj, filename) {
  const json = JSON.stringify(obj, null, 2);
  const handle = await window.showSaveFilePicker({
    suggestedName: filename,
    types: [{
      description: "JSON",
      accept: { "application/json": [".json"] },
    }],
  });
  const writable = await handle.createWritable();
  await writable.write(json);
  await writable.close();
}

function mimeToExt(ct) {
  const map = {
    "image/png": "png", "image/jpeg": "jpg", "image/gif": "gif",
    "image/webp": "webp", "image/svg+xml": "svg",
    "video/mp4": "mp4", "video/webm": "webm",
    "audio/mpeg": "mp3", "audio/ogg": "ogg", "audio/wav": "wav",
    "application/pdf": "pdf", "application/zip": "zip",
    "application/octet-stream": "bin",
  };
  for (const [mime, ext] of Object.entries(map)) {
    if (ct.includes(mime)) return ext;
  }
  return "";
}

async function saveBinaryResponse(base64Data, bodyEncoding, contentType) {
  const ext = mimeToExt(contentType);
  const handle = await window.showSaveFilePicker({
    suggestedName: `response${ext ? "." + ext : ""}`,
    types: [{
      description: contentType,
      accept: { [contentType.split(";")[0].trim()]: ext ? ["." + ext] : [] },
    }],
  });
  const writable = await handle.createWritable();
  const bytes = bodyEncoding === "base64"
    ? base64ToUint8(base64Data)
    : new TextEncoder().encode(base64Data);
  await writable.write(bytes);
  await writable.close();
}

async function importOpenApiSpec(e) {
  const file = e.target.files[0];
  if (!file) return;
  e.target.value = "";

  const btn = document.getElementById("btn-import-spec");
  btn.disabled = true;
  btn.textContent = "Importing...";

  try {
    const text = await file.text();
    let spec;
    try {
      spec = JSON.parse(text);
    } catch (_) {
      alert("Only JSON format is supported. Convert YAML to JSON first.");
      btn.textContent = "Import";
      btn.disabled = false;
      return;
    }

    const result = await chrome.runtime.sendMessage({
      type: "IMPORT_OPENAPI",
      tabId: currentTabId,
      spec,
    });

    if (result?.error) {
      alert(result.error);
      btn.textContent = "Import";
      btn.disabled = false;
      return;
    }

    btn.textContent = "Imported!";
    setTimeout(() => { btn.textContent = "Import"; btn.disabled = false; }, 1500);

    // Refresh the UI to show imported methods
    await loadState();
  } catch (err) {
    alert("Import failed: " + err.message);
    btn.textContent = "Import";
    btn.disabled = false;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function esc(s) {
  if (s == null) return "";
  const d = document.createElement("div");
  d.textContent = String(s);
  return d.innerHTML.replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function el(tag, className) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  return e;
}

function renderPbTree(nodes, schema = null, fallbackSchemaId = "", doc = null) {
  if (!nodes || nodes.length === 0)
    return '<div class="pb-empty">Empty body</div>';

  // If passed a full method definition, use its request schema
  if (schema && schema.request) {
    schema = schema.request;
  }

  // Convert schema fields to a map for easier lookup if it's a struct
  // (Discovery format: properties/parameters)
  let fieldMap = null;
  if (schema) {
    if (schema.properties) fieldMap = schema.properties;
    else if (schema.parameters) fieldMap = schema.parameters;
    else fieldMap = schema; // Fallback for raw probed fields
  }


  let html = '<div class="pb-tree">';

  for (const node of nodes) {
    // Find field definition
    let fieldDef = null;
    let fieldName = node.isJson ? String(node.field) : `Field ${node.field}`;

    // Attempt lookup
    if (fieldMap) {
      // Discovery docs use name keys, not ID keys usually.
      // But req2proto/virtual docs might have ID mapping.
      // We need to know if 'fieldMap' keys are names or IDs.

      // Strategy: fieldMap can be an Object (properties) or Array (resolved fields)
      if (Array.isArray(fieldMap)) {
        // Two-pass to prioritize explicit IDs over sequential guesses
        fieldDef = fieldMap.find(
          (f) =>
            !f.isNumberGuessed &&
            (String(f.number) == String(node.field) ||
              String(f.id) == String(node.field)),
        );
        if (!fieldDef) {
          fieldDef = fieldMap.find(
            (f) =>
              String(f.number) == String(node.field) ||
              String(f.id) == String(node.field),
          );
        }
        if (fieldDef) {
          fieldName = fieldDef.name || fieldName;
        }
      } else {
        const entries = Object.entries(fieldMap);
        let foundEntry = entries.find(([k, v]) => {
          return (
            !v.isNumberGuessed &&
            (String(v.id) == String(node.field) ||
              String(v.number) == String(node.field))
          );
        });
        if (!foundEntry) {
          foundEntry = entries.find(([k, v]) => {
            return (
              String(v.id) == String(node.field) ||
              String(v.number) == String(node.field)
            );
          });
        }

        if (foundEntry) {
          fieldName = foundEntry[0];
          fieldDef = foundEntry[1];
          if (fieldDef.name) {
            fieldName = fieldDef.name;
          }
        }
      }
    }

    const typeLabel = fieldDef
      ? `<span class="pb-type-badge">${esc(fieldDef.type || "")}</span>`
      : `<span class="pb-wire-badge">${node.wire === 0 ? "varint" : node.wire === 1 ? "64bit" : node.wire === 2 ? "len" : "32bit"}</span>`;

    const currentSchemaId = schema?.id || (schema?.$ref) || fallbackSchemaId;
    const renameAttr = `data-schema="${esc(currentSchemaId)}" data-key="${esc(fieldDef ? (fieldDef.id || fieldDef.number || fieldName) : node.field)}" data-is-raw="${!fieldDef}"`;
    const renameBtn = currentSchemaId ? ` <span class="btn-rename" title="Rename field" ${renameAttr}>✎</span>` : "";

    html += `<div class="pb-node">
      <span class="pb-field">${esc(fieldName)}</span>${renameBtn}
      ${typeLabel}: `;

    if (node.message) {
      let childrenSchema = fieldDef?.children || null;
      const childFallback = currentSchemaId ? `${currentSchemaId}.${node.field}` : "";
      if (!childrenSchema && childFallback && doc?.schemas?.[childFallback]) {
        childrenSchema = doc.schemas[childFallback];
      }
      html += `<div class="pb-nested">${renderPbTree(node.message, childrenSchema, childFallback, doc)}</div>`;
    } else if (node.packed) {
      // Packed repeated scalars (proto3 default)
      html += '<div class="pb-repeated">';
      for (const val of node.packed) {
        html += `<span class="pb-scalar-item">${esc(String(val))}</span> `;
      }
      html += "</div>";
    } else if (node.isRepeatedScalar && Array.isArray(node.value)) {
      // JSPB repeated scalar (array of primitives)
      html += '<div class="pb-repeated">';
      for (const val of node.value) {
        if (val === null || val === undefined) continue;
        html += `<span class="pb-scalar-item">${esc(JSON.stringify(val))}</span> `;
      }
      html += "</div>";
    } else if (Array.isArray(node.value) && node.isJspb) {
      // JSPB: could be nested message or repeated field
      const isRepeated = fieldDef?.label === "repeated";
      const isMessage = fieldDef?.type === "message";

      if (isRepeated) {
        html += '<div class="pb-repeated">';
        for (const item of node.value) {
          if (item === null || item === undefined) continue;
          if (isMessage && Array.isArray(item)) {
            // Repeated message item
            const itemNodes = jspbToTree(item);
            const childFallback = currentSchemaId ? `${currentSchemaId}.${node.field}` : "";
            html += `<div class="pb-nested-item">${renderPbTree(itemNodes, fieldDef?.children, childFallback, doc)}</div>`;
          } else {
            // Repeated scalar item
            html += `<span class="pb-scalar-item">${esc(JSON.stringify(item))}</span>`;
          }
        }
        html += "</div>";
      } else if (isMessage) {
        // Single nested message
        const nestedNodes = jspbToTree(node.value);
        const childFallback = currentSchemaId ? `${currentSchemaId}.${node.field}` : "";
        html += `<div class="pb-nested">${renderPbTree(nestedNodes, fieldDef?.children, childFallback, doc)}</div>`;
      } else {
        html += `<span class="pb-string">${esc(JSON.stringify(node.value))}</span>`;
      }
    } else if (node.string !== undefined) {
      html += `<span class="pb-string">"${esc(node.string)}"</span>`;
    } else if (node.value !== undefined) {
      if (typeof node.value === "object" && node.value !== null) {
        const childNodes = jsonToTree(node.value);
        let childrenSchema = fieldDef?.children || null;
        const childFallback = currentSchemaId ? `${currentSchemaId}.${node.field}` : "";
        if (!childrenSchema && childFallback && doc?.schemas?.[childFallback]) {
          childrenSchema = doc.schemas[childFallback];
        }
        html += `<div class="pb-nested">${renderPbTree(childNodes, childrenSchema, childFallback, doc)}</div>`;
      } else {
        html += `<span class="pb-number">${esc(String(node.value))}</span>`;
      }
    } else if (node.hex) {
      html += `<span class="pb-hex">0x${esc(node.hex)}</span>`;
    } else if (node.asFloat !== undefined) {
      html += `<span class="pb-number">${node.asFloat.toFixed(4)}</span>`;
    }
    html += "</div>";
  }
  html += "</div>";
  return html;
}

function jsonToTree(obj) {
  if (obj === null || obj === undefined) return [];
  if (Array.isArray(obj)) {
    return obj.map((item, i) => {
      if (item && typeof item === "object") {
        return { field: i, wire: 2, message: jsonToTree(item), isJson: true };
      }
      return typeof item === "string"
        ? { field: i, wire: 2, string: item, isJson: true }
        : { field: i, wire: 0, value: item, isJson: true };
    });
  }
  if (typeof obj !== "object") return [];
  return Object.entries(obj).map(([key, val]) => {
    if (val && typeof val === "object" && !Array.isArray(val)) {
      return { field: key, wire: 2, message: jsonToTree(val), isJson: true };
    }
    if (Array.isArray(val)) {
      return { field: key, wire: 2, message: jsonToTree(val), isJson: true };
    }
    return typeof val === "string"
      ? { field: key, wire: 2, string: val, isJson: true }
      : { field: key, wire: 0, value: val, isJson: true };
  });
}

function findSchemaForRequest(req) {
  if (!tabData?.discoveryDocs || !req.service) return null;
  const svcInfo = tabData.discoveryDocs[req.service];
  if (!svcInfo) return null;

  // We need the full discovery doc
  const doc = svcInfo.doc;
  if (!doc) {
    return null;
  }
  const url = new URL(req.url);

  // 1. Try matching by methodId if background annotated it
  if (req.methodId) {
    const methodMatch = findMethodById(doc, req.methodId);
    if (methodMatch && methodMatch.method.request?.$ref) {
      return resolveDiscoverySchema(doc, methodMatch.method.request.$ref);
    }
  }

  // 2. Fallback: match by URL path
  const match = findDiscoveryMethod(doc, url.pathname, req.method);
  if (match && match.method.request?.$ref) {
    return resolveDiscoverySchema(doc, match.method.request.$ref);
  }

  return null;
}

// ─── Response Panel (Request Log) — Virtual Scroll ──────────────────────────

function _renderLogCard(req, showTabLabel) {
  const hasProto = !!req.decodedBody;
  return `<div class="card request-card clickable-card mb-8" data-id="${esc(String(req.id))}" data-tab-id="${esc(String(req._tabId))}">
    <div class="card-label flex-between">
      <span>
        <span class="badge ${esc(req.method)}">${esc(req.method)}</span>
        <span class="text-timestamp">${new Date(req.timestamp).toLocaleTimeString()}</span>
        ${showTabLabel ? `<span class="badge badge-tab">${esc(req._tabTitle || "Tab " + req._tabId)}</span>` : ""}
      </span>
      ${getStatusBadge(req.status)}
    </div>
    <div class="card-value card-value-mono">${esc(req.url)}</div>
    <div class="card-meta">
      ${req.service ? `Service: <strong>${esc(req.service)}</strong>` : ""}
      ${hasProto ? ' <span class="badge badge-found">PROTOBUF</span>' : ""}
      ${req.url.includes("batchexecute") ? ' <span class="badge badge-batch">BATCHEXECUTE</span>' : ""}
      ${isGrpcWeb(req.mimeType || req.contentType || "") ? ' <span class="badge badge-grpc">gRPC-WEB</span>' : ""}
      ${isSSE(req.mimeType || "") ? ' <span class="badge badge-sse">SSE</span>' : ""}
      ${isNDJSON(req.mimeType || "") ? ' <span class="badge badge-ndjson">NDJSON</span>' : ""}
      ${isGraphQLUrl(req.url) ? ' <span class="badge badge-graphql">GRAPHQL</span>' : ""}
      ${isMultipartBatch(req.mimeType || "") ? ' <span class="badge badge-multipart">MULTIPART</span>' : ""}
      ${/\/async\//.test(req.url) ? ' <span class="badge badge-batch">ASYNC</span>' : ""}
    </div>
  </div>`;
}

function _getRowHeight(idx) {
  return _vs.heights.get(idx) || _vs.estHeight;
}

function _getTotalHeight() {
  let h = 0;
  for (let i = 0; i < _vs.entries.length; i++) h += _getRowHeight(i);
  return h;
}

function _getVisibleRange(scrollEl) {
  const scrollTop = scrollEl.scrollTop;
  const viewH = scrollEl.clientHeight;
  const buf = _vs.buffer;
  let y = 0, startIdx = 0;
  // Find first visible
  for (let i = 0; i < _vs.entries.length; i++) {
    const rh = _getRowHeight(i);
    if (y + rh > scrollTop) { startIdx = i; break; }
    y += rh;
    if (i === _vs.entries.length - 1) startIdx = i;
  }
  // Find last visible
  let endIdx = startIdx;
  let vy = y;
  for (let i = startIdx; i < _vs.entries.length; i++) {
    endIdx = i;
    vy += _getRowHeight(i);
    if (vy >= scrollTop + viewH) break;
  }
  // Add buffer
  startIdx = Math.max(0, startIdx - buf);
  endIdx = Math.min(_vs.entries.length - 1, endIdx + buf);
  // Top offset for positioning
  let topPad = 0;
  for (let i = 0; i < startIdx; i++) topPad += _getRowHeight(i);
  return { startIdx, endIdx, topPad };
}

function _measureRenderedCards(container, startIdx) {
  const cards = container.querySelectorAll(".request-card");
  cards.forEach((card, i) => {
    const h = card.offsetHeight + 8; // include mb-8
    _vs.heights.set(startIdx + i, h);
  });
}

function _renderVisibleSlice() {
  const container = document.getElementById("response-log");
  const scrollEl = document.getElementById("panel-response");
  if (!_vs.entries.length) return;

  const { startIdx, endIdx, topPad } = _getVisibleRange(scrollEl);
  const showTabLabel = logFilter !== "active";

  let html = "";
  for (let i = startIdx; i <= endIdx; i++) {
    html += _renderLogCard(_vs.entries[i], showTabLabel);
  }

  const totalH = _getTotalHeight();
  let bottomPad = 0;
  for (let i = endIdx + 1; i < _vs.entries.length; i++) bottomPad += _getRowHeight(i);

  container.innerHTML =
    `<div style="height:${topPad}px"></div>` +
    html +
    `<div style="height:${bottomPad}px"></div>`;

  // Measure actual rendered heights for refinement
  const inner = container.querySelectorAll(".request-card");
  inner.forEach((card, i) => {
    const rect = card.getBoundingClientRect();
    _vs.heights.set(startIdx + i, rect.height + 8);
  });

  // Attach click handlers
  inner.forEach((c) => {
    c.onclick = () => {
      const sourceTabId = c.dataset.tabId ? parseInt(c.dataset.tabId, 10) : undefined;
      replayRequest(c.dataset.id, sourceTabId);
    };
  });
}

function renderResponsePanel() {
  const container = document.getElementById("response-log");
  const scrollEl = document.getElementById("panel-response");

  // Build entry list based on filter mode
  let entries = [];
  if (logFilter === "active") {
    entries = (tabData?.requestLog || []).map((r) => ({ ...r, _tabId: currentTabId }));
  } else if (allTabsData) {
    for (const [tidStr, data] of Object.entries(allTabsData)) {
      const tid = parseInt(tidStr, 10);
      const meta = data.meta || {};
      for (const req of data.requestLog) {
        entries.push({ ...req, _tabId: tid, _tabTitle: meta.title || `Tab ${tid}` });
      }
    }
    entries.sort((a, b) => b.timestamp - a.timestamp);
  }

  // Detach old scroll handler if entries changed
  if (_vs.scrollHandler) {
    scrollEl.removeEventListener("scroll", _vs.scrollHandler);
    _vs.scrollHandler = null;
  }

  _vs.entries = entries;
  _vs.heights.clear();

  if (entries.length === 0) {
    container.innerHTML = '<div class="empty">No requests captured yet.</div>';
    return;
  }

  // Render initial visible slice
  _renderVisibleSlice();

  // Attach scroll-driven rendering
  let rafPending = false;
  _vs.scrollHandler = () => {
    if (rafPending) return;
    rafPending = true;
    requestAnimationFrame(() => {
      rafPending = false;
      _renderVisibleSlice();
    });
  };
  scrollEl.addEventListener("scroll", _vs.scrollHandler, { passive: true });
}

function renderBatchExecuteResponse(bodyText, req, overrideDoc = null) {
  const calls = parseBatchExecuteResponse(bodyText);
  if (!calls || calls.length === 0)
    return `<pre class="resp-body">${esc(bodyText)}</pre>`;

  let html = '<div class="pb-tree">';
  const svc = req.service;
  const doc = overrideDoc || tabData?.discoveryDocs?.[svc]?.doc;

  for (const call of calls) {
    const nodes = jspbToTree(
      Array.isArray(call.data) ? call.data : [call.data],
    );
    const schemaName = `${call.rpcId}Response`;
    let schema = null;
    if (doc) {
      schema = doc.schemas?.[schemaName];
    }

    html += `<div class="card card-compact">
      <div class="card-label">RPC ID: <strong>${esc(call.rpcId)}</strong></div>
      <div class="pb-container pb-container-inline">
        ${renderPbTree(nodes, schema, schemaName, doc)}
      </div>
    </div>`;
  }
  html += "</div>";
  return html;
}

function renderAsyncResponse(bodyText, req, overrideDoc = null) {
  const chunks = parseAsyncChunkedResponse(bodyText);
  if (!chunks || chunks.length === 0)
    return `<pre class="resp-body">${esc(bodyText)}</pre>`;

  const svc = req.service;
  const doc = overrideDoc || tabData?.discoveryDocs?.[svc]?.doc;
  const url = req.url ? new URL(req.url) : null;
  const asyncPath =
    url?.pathname
      .split("/")
      .filter(Boolean)
      .pop() || "async";

  let html = '<div class="pb-tree">';
  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    if (chunk.type === "jspb" && Array.isArray(chunk.data)) {
      const nodes = jspbToTree(chunk.data);
      const schemaName = `${asyncPath}_chunk${i}Response`;
      let schema = null;
      if (doc) {
        schema = doc.schemas?.[schemaName];
      }
      html += `<div class="card card-compact">
        <div class="card-label">Chunk ${i} <span class="badge badge-found">JSPB</span></div>
        <div class="pb-container pb-container-inline">
          ${renderPbTree(nodes, schema, schemaName, doc)}
        </div>
      </div>`;
    } else if (chunk.type === "html") {
      html += `<div class="card card-compact">
        <div class="card-label">Chunk ${i} <span class="badge badge-pending">HTML</span></div>
        <pre class="resp-body resp-body-scroll">${esc(chunk.raw)}</pre>
      </div>`;
    } else {
      html += `<div class="card card-compact">
        <div class="card-label">Chunk ${i} <span class="badge">text</span></div>
        <pre class="resp-body">${esc(chunk.raw)}</pre>
      </div>`;
    }
  }
  html += "</div>";
  return html;
}

// ─── gRPC-Web Renderer ──────────────────────────────────────────────────────

function renderGrpcWebResponse(bytes, req, overrideDoc = null) {
  const parsed = parseGrpcWebFrames(bytes);
  if (!parsed || parsed.frames.length === 0)
    return `<pre class="resp-body">[gRPC-Web: no frames decoded]</pre>`;

  const svc = req.service;
  const doc = overrideDoc || tabData?.discoveryDocs?.[svc]?.doc;
  const methodId = req.methodId || document.getElementById("send-ep-select")?.dataset?.discoveryId;
  const grpcFallbackId = methodId ? `${methodId}.response` : "";
  let respSchema = null;
  if (doc && methodId) {
    const methodInfo = findMethodById(doc, methodId);
    if (methodInfo?.method?.response?.$ref) {
      respSchema = resolveDiscoverySchema(doc, methodInfo.method.response.$ref);
    }
    if (!respSchema && grpcFallbackId && doc.schemas?.[grpcFallbackId]) {
      respSchema = doc.schemas[grpcFallbackId];
    }
  }

  let html = '<div class="pb-tree">';

  // Trailers summary
  if (Object.keys(parsed.trailers).length > 0) {
    const grpcStatus = parsed.trailers["grpc-status"] || "?";
    const grpcMsg = parsed.trailers["grpc-message"] || "";
    html += `<div class="card card-compact">
      <div class="card-label">gRPC Status: <strong>${esc(grpcStatus)}</strong>
        ${grpcMsg ? ` &mdash; ${esc((() => { try { return decodeURIComponent(grpcMsg); } catch (_) { return grpcMsg; } })())}` : ""}</div>
    </div>`;
  }

  for (let i = 0; i < parsed.frames.length; i++) {
    const frame = parsed.frames[i];
    if (frame.type === "data") {
      const tree = pbDecodeTree(frame.data);
      html += `<div class="card card-compact">
        <div class="card-label">Data Frame ${i} <span class="badge badge-found">protobuf</span>
          <span class="text-muted-sm ml-4">${frame.data.length} bytes</span></div>
        <div class="pb-container pb-container-inline">
          ${renderPbTree(tree, respSchema, grpcFallbackId, doc)}
        </div>
      </div>`;
    } else if (frame.type === "trailers") {
      html += `<div class="card card-compact">
        <div class="card-label">Trailers</div>
        <pre class="resp-body resp-body-scroll-sm">${esc(frame.data)}</pre>
      </div>`;
    }
  }
  html += "</div>";
  return html;
}

// ─── SSE Renderer ───────────────────────────────────────────────────────────

function renderSSEResponse(bodyText) {
  const events = parseSSE(bodyText);
  if (!events || events.length === 0)
    return `<pre class="resp-body">${esc(bodyText)}</pre>`;

  let html = `<div class="card-label">Server-Sent Events (${events.length} events)</div><div class="pb-tree">`;
  for (let i = 0; i < events.length; i++) {
    const evt = events[i];
    const typeBadge = evt.event !== "message"
      ? ` <span class="badge badge-pending">${esc(evt.event)}</span>`
      : "";
    const idBadge = evt.id
      ? ` <span class="text-muted-sm">id: ${esc(evt.id)}</span>`
      : "";

    let bodyHtml;
    if (typeof evt.data === "object" && evt.data !== null) {
      bodyHtml = `<pre class="resp-body">${esc(JSON.stringify(evt.data, null, 2))}</pre>`;
    } else {
      bodyHtml = `<pre class="resp-body">${esc(evt.raw)}</pre>`;
    }

    html += `<div class="card card-compact">
      <div class="card-label">Event ${i}${typeBadge}${idBadge}</div>
      ${bodyHtml}
    </div>`;
  }
  html += "</div>";
  return html;
}

// ─── NDJSON Renderer ────────────────────────────────────────────────────────

function renderNDJSONResponse(bodyText) {
  const objects = parseNDJSON(bodyText);
  if (!objects || objects.length === 0)
    return `<pre class="resp-body">${esc(bodyText)}</pre>`;

  let html = `<div class="card-label">NDJSON (${objects.length} records)</div><div class="pb-tree">`;
  for (let i = 0; i < objects.length; i++) {
    html += `<div class="card card-compact">
      <div class="card-label">Record ${i}</div>
      <pre class="resp-body">${esc(JSON.stringify(objects[i], null, 2))}</pre>
    </div>`;
  }
  html += "</div>";
  return html;
}

// ─── GraphQL Renderer ───────────────────────────────────────────────────────

function renderGraphQLResponse(bodyText) {
  const gql = parseGraphQLResponse(bodyText);
  if (!gql) return null; // Fall through to normal JSON rendering

  let html = '<div class="pb-tree">';

  if (gql.errors) {
    html += `<div class="card card-compact-error">
      <div class="card-label card-label-error">Errors (${gql.errors.length})</div>
      <pre class="resp-body">${esc(JSON.stringify(gql.errors, null, 2))}</pre>
    </div>`;
  }

  if (gql.data) {
    html += `<div class="card card-compact">
      <div class="card-label">Data</div>
      <pre class="resp-body">${esc(JSON.stringify(gql.data, null, 2))}</pre>
    </div>`;
  }

  if (gql.extensions) {
    html += `<div class="card card-compact">
      <div class="card-label card-label-muted">Extensions</div>
      <pre class="resp-body resp-body-scroll">${esc(JSON.stringify(gql.extensions, null, 2))}</pre>
    </div>`;
  }

  html += "</div>";
  return html;
}

// ─── Multipart Batch Renderer ───────────────────────────────────────────────

function renderMultipartBatchResponse(bodyText, contentType) {
  const parts = parseMultipartBatch(bodyText, contentType);
  if (!parts || parts.length === 0)
    return `<pre class="resp-body">${esc(bodyText)}</pre>`;

  let html = `<div class="card-label">Multipart Batch (${parts.length} parts)</div><div class="pb-tree">`;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    const statusBadge = part.status
      ? (part.status >= 200 && part.status < 300
          ? `<span class="badge badge-found">${part.status}</span>`
          : `<span class="badge badge-notfound">${part.status}</span>`)
      : "";

    let bodyHtml;
    try {
      const json = JSON.parse(part.body);
      bodyHtml = `<pre class="resp-body">${esc(JSON.stringify(json, null, 2))}</pre>`;
    } catch (_) {
      bodyHtml = `<pre class="resp-body">${esc(part.body)}</pre>`;
    }

    html += `<div class="card card-compact">
      <div class="card-label">Part ${i} ${statusBadge} ${esc(part.statusText || "")}</div>
      ${bodyHtml}
    </div>`;
  }
  html += "</div>";
  return html;
}

function getStatusBadge(status) {
  if (status === "pending")
    return '<span class="badge badge-pending">pending</span>';
  if (status === "error") return '<span class="badge badge-error">error</span>';
  const code = parseInt(status);
  if (code >= 200 && code < 300)
    return `<span class="badge badge-found">${code}</span>`;
  if (code >= 400) return `<span class="badge badge-notfound">${code}</span>`;
  return `<span class="badge">${code}</span>`;
}

let currentReplayRequest = null;

async function replayRequest(reqId, sourceTabId) {
  // Search the correct log source
  let req;
  if (sourceTabId && allTabsData && allTabsData[sourceTabId]) {
    req = allTabsData[sourceTabId].requestLog.find((r) => String(r.id) === String(reqId));
  }
  if (!req) {
    req = tabData?.requestLog?.find((r) => String(r.id) === String(reqId));
  }
  if (!req) {
    console.error(`[Replay] Request ${reqId} not found in log`);
    return;
  }
  currentReplayRequest = req;

  // Try to find and select the matching endpoint in the dropdown to load the schema
  const epSelect = document.getElementById("send-ep-select");
  let found = false;

  if (epSelect) {
    // Check if it's a batchexecute request
    const isBatch = req.url.includes("batchexecute");
    let targetRpcId = null;

    if (isBatch && req.rawBodyB64) {
      const bytes = base64ToUint8(req.rawBodyB64);
      const text = new TextDecoder().decode(bytes);
      const calls = parseBatchExecuteRequest(text);
      if (calls && calls.length > 0) {
        targetRpcId = calls[0].rpcId;
      }
    }

    // Set current state from the replayed request
    currentRequestUrl = req.url;
    currentRequestMethod = "POST"; // Default for replayed backend requests or detect from req
    if (req.method) currentRequestMethod = req.method;

    for (const opt of epSelect.options) {
      if (opt.dataset.isVirtual === "true" && opt.dataset.svc === req.service) {
        // 1. For batch, attempt strict RPC ID match first
        if (isBatch && targetRpcId) {
          if (
            opt.dataset.discoveryId &&
            opt.dataset.discoveryId.endsWith("." + targetRpcId)
          ) {
            opt.selected = true;
            found = true;
            break;
          }
          // If it's a batch request but this option isn't the right RPC ID,
          // skip further checks for this option to avoid incorrect path matching.
          continue;
        }

        // 2. Match by methodId specifically
        if (req.methodId && opt.dataset.discoveryId === req.methodId) {
          opt.selected = true;
          found = true;
          break;
        }

        // 3. Fallback for path-based matching (Non-batch only)
        if (!isBatch) {
          try {
            const reqPath = new URL(req.url).pathname;
            if (opt.dataset.path && reqPath.endsWith(opt.dataset.path)) {
              opt.selected = true;
              found = true;
              break;
            }
          } catch (e) {
            console.warn("[Replay] URL path resolution failed:", e);
          }
        }
      }
    }

    if (found) {
      const svc = req.service;
      const selectedOpt = epSelect.options[epSelect.selectedIndex];
      const discoveryId = selectedOpt.dataset.discoveryId;

      epSelect.dataset.svc = svc;
      epSelect.dataset.discoveryId = discoveryId;

      // Extract the correct initial data for the selected RPC call
      let initialData = null;
      if (isBatch && req.rawBodyB64) {
        const bytes = base64ToUint8(req.rawBodyB64);
        const text = new TextDecoder().decode(bytes);
        const calls = parseBatchExecuteRequest(text);
        if (calls && calls.length > 0) {
          initialData = jspbToTree(
            Array.isArray(calls[0].data) ? calls[0].data : [calls[0].data],
          );
          initialData = pbTreeToMap(initialData);
        }
      } else if (req.isJson && req.decodedBody) {
        // JSON body — use parsed object directly as named-key initialData
        initialData = req.decodedBody;
      } else if (req.decodedBody) {
        initialData = pbTreeToMap(req.decodedBody) || {};
      } else if (req.rawBodyB64) {
        // Try to extract f.req JSPB from form-urlencoded body
        try {
          const bodyBytes = base64ToUint8(req.rawBodyB64);
          const bodyText = new TextDecoder().decode(bodyBytes);
          const bodyParams = new URLSearchParams(bodyText);
          const fReq = bodyParams.get("f.req");
          if (fReq) {
            const parsed = JSON.parse(fReq);
            if (Array.isArray(parsed)) {
              initialData = pbTreeToMap(jspbToTree(parsed));
            }
          }
        } catch (_) {}
        // Also try plain JSON body
        if (!initialData) {
          try {
            const bodyBytes = base64ToUint8(req.rawBodyB64);
            const bodyText = new TextDecoder().decode(bodyBytes);
            const json = JSON.parse(bodyText);
            if (json && typeof json === "object" && !Array.isArray(json)) {
              initialData = json;
            }
          } catch (_) {}
        }
        if (!initialData) initialData = {};
      } else {
        initialData = {};
      }

      // Merge query parameters from URL for pre-filling
      try {
        const urlObj = new URL(req.url);
        urlObj.searchParams.forEach((val, key) => {
          // Prefer body data if it already provides this key, but for GET it's usually just URL params
          if (initialData[key] === undefined || initialData[key] === null) {
            initialData[key] = val;
          }
        });
      } catch (e) {
        console.warn("[Replay] Failed to extract URL parameters:", e);
      }

      await loadVirtualSchema(svc, discoveryId, initialData);
    }
  }

  // Auto-determine Content-Type from the original request (AFTER schema load)
  if (req.requestHeaders) {
    const ctHeader = Object.keys(req.requestHeaders).find(
      (k) => k.toLowerCase() === "content-type",
    );
    if (ctHeader) {
      currentContentType = req.requestHeaders[ctHeader];
    } else {
      currentContentType = "application/json";
    }
  }

  // Auto-determine body mode
  let gqlDetected = false;
  if (isGraphQLUrl(req.url) && req.rawBodyB64) {
    try {
      const bytes = base64ToUint8(req.rawBodyB64);
      const text = new TextDecoder().decode(bytes);
      const gqlReq = parseGraphQLRequest(text);
      if (gqlReq) {
        gqlDetected = true;
        setBodyMode("graphql");
        document.getElementById("send-gql-query").value = gqlReq.query || "";
        document.getElementById("send-gql-variables").value =
          gqlReq.variables ? JSON.stringify(gqlReq.variables, null, 2) : "";
        document.getElementById("send-gql-opname").value = gqlReq.operationName || "";
      }
    } catch (_) {}
  }
  if (!gqlDetected) {
    // Form mode if schema was loaded, otherwise raw
    setBodyMode(currentSchema ? "form" : "raw");
    document.getElementById("send-gql-query").value = "";
    document.getElementById("send-gql-variables").value = "";
    document.getElementById("send-gql-opname").value = "";
  }
  // Add headers (filtering out Content-Type which is auto-determined)
  const headersList = document.getElementById("send-headers-list");
  headersList.innerHTML = "";
  if (req.requestHeaders) {
    for (const [k, v] of Object.entries(req.requestHeaders)) {
      if (k.toLowerCase() === "content-type") continue;
      addHeaderRow(k, v);
    }
  }

  // Populate raw body textarea with original body as fallback
  document.getElementById("send-raw-body").value = "";
  if (req.rawBodyB64 && !gqlDetected) {
    try {
      const bytes = base64ToUint8(req.rawBodyB64);
      document.getElementById("send-raw-body").value = new TextDecoder().decode(bytes);
    } catch (_) {}
  }
  // Populate historical response if available
  if (req.responseBody || req.status) {
    const historicalResult = {
      ok: parseInt(req.status) < 400,
      status: req.status,
      headers: req.responseHeaders,
      timing: 0,
      service: req.service,
      methodId: req.methodId,
      body: null,
    };

    if (req.responseBody) {
      const mimeType = req.mimeType || "";
      const isBinaryProtobuf =
        (mimeType.includes("protobuf") && !mimeType.includes("json")) ||
        (req.requestHeaders &&
          Object.entries(req.requestHeaders).some(
            ([k, v]) =>
              k.toLowerCase() === "content-type" &&
              v.toLowerCase().includes("protobuf") &&
              !v.toLowerCase().includes("json"),
          ));
      const isJspb = mimeType.includes("json+protobuf") ||
        mimeType.includes("json; protobuf");

      let bodyText = req.responseBody;
      if (req.responseBase64) {
        try {
          const bytes = base64ToUint8(req.responseBody);
          bodyText = new TextDecoder().decode(bytes);
        } catch (e) {}
      }

      if (isGrpcWeb(mimeType)) {
        // gRPC-Web: pass raw bytes for frame parsing
        try {
          let bytes;
          if (isGrpcWebText(mimeType)) {
            bytes = base64ToUint8(
              req.responseBase64 ? req.responseBody : btoa(req.responseBody),
            );
          } else {
            bytes = req.responseBase64
              ? base64ToUint8(req.responseBody)
              : new TextEncoder().encode(req.responseBody);
          }
          historicalResult.body = {
            format: "grpc_web",
            bytes,
            raw: bodyText,
            size: bytes.length,
          };
        } catch (e) {}
      } else if (isJspb) {
        // JSPB (JSON+Protobuf): parse as JSON, convert to protobuf tree
        try {
          const parsed = JSON.parse(bodyText);
          if (Array.isArray(parsed)) {
            historicalResult.body = {
              format: "protobuf_tree",
              parsed: jspbToTree(parsed),
              raw: bodyText,
              size: bodyText.length,
              isJspb: true,
            };
          }
        } catch (e) {}
      } else if (isBinaryProtobuf) {
        try {
          const bytes = req.responseBase64
            ? base64ToUint8(req.responseBody)
            : new TextEncoder().encode(req.responseBody);
          historicalResult.body = {
            format: "protobuf_tree",
            parsed: pbDecodeTree(bytes),
            raw: req.responseBody,
            size: bytes.length,
          };
        } catch (e) {}
      } else if (mimeType.includes("json") || mimeType.includes("text/plain")) {
        try {
          // Strip Google XSSI prefix before parsing
          let jsonText = bodyText;
          if (jsonText.trimStart().startsWith(")]}'")) {
            jsonText = jsonText.trimStart().substring(4).trimStart();
          }
          const parsed = JSON.parse(jsonText);
          // Detect JSPB in text/plain responses (Google returns these)
          if (Array.isArray(parsed) && parsed.length > 0 &&
              parsed.some((item) => item === null || Array.isArray(item) || typeof item !== "object")) {
            historicalResult.body = {
              format: "protobuf_tree",
              parsed: jspbToTree(parsed),
              raw: bodyText,
              size: bodyText.length,
              isJspb: true,
            };
          } else {
            historicalResult.body = {
              format: "json",
              parsed,
              raw: bodyText,
              size: bodyText.length,
            };
          }
        } catch (e) {}
      }

      // SSE, NDJSON, multipart, and async chunked are detected by renderResultBody()
      // via content-type headers and body inspection — just need raw text preserved.
      if (!historicalResult.body) {
        historicalResult.body = {
          format: "text",
          raw: bodyText,
          size: bodyText.length,
        };
      }
    }

    renderResponse(historicalResult);
    document.getElementById("send-response-status").innerHTML +=
      ' <span class="badge badge-source ml-8">Historical</span>';
  } else {
    document.getElementById("send-response").style.display = "none";
  }

  // Switch tab
  document.querySelector(".tab[data-panel='send']").click();
}

document.getElementById("btn-clear-log").addEventListener("click", async () => {
  if (logFilter === "active") {
    if (tabData) tabData.requestLog = [];
    await chrome.runtime.sendMessage({ type: "CLEAR_LOG", tabId: currentTabId });
  } else if (logFilter === "all") {
    allTabsData = null;
    if (tabData) tabData.requestLog = [];
    await chrome.runtime.sendMessage({ type: "CLEAR_LOG", clearAll: true });
  } else {
    // Clearing a specific tab
    const targetTabId = logFilter;
    if (allTabsData && allTabsData[targetTabId]) {
      delete allTabsData[targetTabId];
    }
    if (targetTabId === currentTabId && tabData) {
      tabData.requestLog = [];
    }
    await chrome.runtime.sendMessage({ type: "CLEAR_LOG", tabId: targetTabId });
  }
  renderResponsePanel();
  populateTabFilter();
});
