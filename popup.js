// Popup controller: renders captured data and sends requests.

let currentTabId = null;
let tabData = null;
let currentSchema = null;
let currentRequestUrl = "";
let currentRequestMethod = "POST";

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

  // Fuzz panel
  document
    .getElementById("btn-start-fuzz")
    .addEventListener("click", startFuzzing);

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
        // Reload schema to reflect change
        loadVirtualSchema(svc, select.dataset.discoveryId);
      }
    }
  });

  for (const btn of document.querySelectorAll(
    "#send-body-toggle .toggle-btn",
  )) {
    btn.addEventListener("click", () => {
      document
        .querySelector("#send-body-toggle .toggle-btn.active")
        .classList.remove("active");
      btn.classList.add("active");
      const isForm = btn.dataset.mode === "form";
      document.getElementById("send-form-fields").style.display = isForm
        ? "block"
        : "none";
      document.getElementById("send-raw-body").style.display = isForm
        ? "none"
        : "block";
    });
  }

  async function startFuzzing() {
    const select = document.getElementById("send-ep-select");
    const epKey = select.value;
    if (!epKey) {
      alert("Please select an endpoint first.");
      return;
    }

    const opt = select.options[select.selectedIndex];
    const config = {
      strings: document.getElementById("fuzz-strings").checked,
      numbers: document.getElementById("fuzz-numbers").checked,
      objects: document.getElementById("fuzz-objects").checked,
    };

    const btn = document.getElementById("btn-start-fuzz");
    btn.disabled = true;
    btn.textContent = "Fuzzing...";
    document.getElementById("fuzz-log").innerHTML = "";

    try {
      await chrome.runtime.sendMessage({
        type: "EXECUTE_FUZZ",
        tabId: currentTabId,
        service: opt.dataset.svc,
        methodId: opt.dataset.discoveryId,
        config,
      });
    } catch (err) {
      console.error("Fuzzing failed:", err);
    } finally {
      btn.disabled = false;
      btn.textContent = "Start Fuzzing";
    }
  }

  function renderFuzzUpdate(update) {
    const log = document.getElementById("fuzz-log");
    const card = el("div", "card fuzz-card");
    const statusClass =
      update.status >= 200 && update.status < 300
        ? "badge-found"
        : "badge-error";

    card.innerHTML = `
      <div class="card-label">
        Field: <strong>${esc(update.field)}</strong> &middot; 
        <span class="badge ${statusClass}">${update.status}</span>
      </div>
      <div class="card-meta">Payload: <code>${esc(JSON.stringify(update.payload))}</code></div>
      ${update.error ? `<div class="card-meta error">${esc(update.error)}</div>` : ""}
    `;
    log.prepend(card);
  }

  const EXTENSION_ORIGIN = `chrome-extension://${chrome.runtime.id}`;

  chrome.runtime.onMessage.addListener((msg, sender) => {
    if (sender.id !== chrome.runtime.id) return;

    // Security: Only accept coordination messages from internal extension contexts (e.g. background.js)
    // Content scripts will have the website's URL here, not the extension's origin.
    const isExtensionPage =
      sender.url && sender.url.startsWith(EXTENSION_ORIGIN + "/");
    if (!isExtensionPage) return;

    if (msg.type === "STATE_UPDATED" && msg.tabId === currentTabId)
      throttledLoadState();
    if (msg.type === "FUZZ_UPDATE" && msg.tabId === currentTabId)
      renderFuzzUpdate(msg.update);
  });
  loadState();
});

// ─── State ───────────────────────────────────────────────────────────────────

async function loadState() {
  tabData = await chrome.runtime.sendMessage({
    type: "GET_STATE",
    tabId: currentTabId,
  });
  render();
}

async function clearState() {
  await chrome.runtime.sendMessage({ type: "CLEAR_TAB", tabId: currentTabId });
  tabData = null;
  render();
}

// ─── Render ──────────────────────────────────────────────────────────────────

function render() {
  renderDataPanel();
  renderSendPanel();
  renderResponsePanel();
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
        html += `<div class="card-meta">Interfaces: ${[...services].map((s) => `<code>${esc(s)}</code>`).join(" ")}</div>`;
      }
      html += `</div>`;
    }
    keysContainer.innerHTML = html;
  }
}

// ─── Send Panel ──────────────────────────────────────────────────────────────

function renderSendPanel() {
  const select = document.getElementById("send-ep-select");
  const prev = select.value;

  select.innerHTML = '<option value="">-- select method --</option>';

  // Populate from Discovery Docs
  if (tabData?.discoveryDocs) {
    const services = Object.entries(tabData.discoveryDocs).sort((a, b) =>
      a[0].localeCompare(b[0]),
    );

    for (const [svcName, svcData] of services) {
      if (svcData.status === "found" && svcData.summary?.resources) {
        // Flatten methods from summary
        const methods = [];
        for (const [rName, rMethods] of Object.entries(
          svcData.summary.resources,
        )) {
          methods.push(...rMethods);
        }

        methods.sort((a, b) => a.id.localeCompare(b.id));

        if (methods.length > 0) {
          const group = document.createElement("optgroup");
          group.label = svcData.summary.title || svcName;

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
      <td class="f-name" style="${indent}">${depth > 0 ? "&#x2514; " : ""}${esc(name)}</td>
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
    const summary = svcData?.summary;

    // improved baseUrl resolution using summary
    let baseUrl = summary?.baseUrl;
    if (!baseUrl && summary?.rootUrl) {
      baseUrl = summary.rootUrl + (summary.servicePath || "");
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

    buildFormFields(schema, initialData);
  } catch (err) {
    console.error("Error loading virtual schema:", err);
    document.getElementById("send-form-fields").innerHTML =
      `<div class="hint">Error loading schema: ${err.message}</div>`;
  }
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

  if (schema.method) {
    const info = el("div", "card");
    info.style.marginBottom = "8px";
    let html = `<div class="card-label">${esc(schema.method.id || "method")} <span class="badge badge-source">${esc(schema.source)}</span></div>`;
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
      const fieldVal = initialData ? initialData[field.number] : null;
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
  labelEl.innerHTML = labelHtml;
  wrapper.appendChild(labelEl);

  if (fieldDef.description) {
    const desc = el("div", "field-description");
    desc.textContent = fieldDef.description;
    wrapper.appendChild(desc);
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
          { ...child, parentSchema: fieldDef.$ref || fieldDef.parentSchema },
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
      if (initialValue !== null) inp.value = initialValue;
      return inp;
    }
  }
}

// ─── Send Panel: Value Collection + Request ──────────────────────────────────

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
    if (!children.length) return null;
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
  if (
    [
      "int32",
      "int64",
      "uint32",
      "uint64",
      "double",
      "float",
      "enum",
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

  const isFormMode =
    document.querySelector("#send-body-toggle .toggle-btn.active").dataset
      .mode === "form";
  let url = currentRequestUrl;
  const httpMethod = currentRequestMethod;
  const contentType = document.getElementById("send-ct").value;
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
    body = { mode: "raw", formData: null, rawBody: null };
  } else if (isFormMode) {
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
    body = {
      mode: "form",
      formData: { fields: formValues.fields },
      rawBody: null,
    };
  } else {
    body = {
      mode: "raw",
      formData: null,
      rawBody: document.getElementById("send-raw-body").value,
    };
  }

  const sel = document.getElementById("send-ep-select");
  const selectedOpt = sel.options[sel.selectedIndex];

  try {
    const result = await chrome.runtime.sendMessage({
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
    });
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
  const container = document.getElementById("send-response");
  container.style.display = "block";

  if (result.error && !result.status) {
    container.innerHTML = `<div class="card"><div class="card-label">Error</div><div class="card-value">${esc(result.error)}</div></div>`;
    return;
  }

  const statusEl = document.getElementById("send-response-status");
  const statusClass =
    result.ok || (result.status >= 200 && result.status < 300)
      ? "resp-status-ok"
      : "resp-status-error";
  statusEl.innerHTML =
    `<span class="${statusClass}">${result.status} ${esc(result.statusText || "")}</span>` +
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

  if (svc && methodId && discoveryInfo?.doc) {
    const doc = discoveryInfo.doc;
    const methodInfo = findMethodById(doc, methodId);
    if (methodInfo?.method?.response?.$ref) {
      respSchema = resolveDiscoverySchema(doc, methodInfo.method.response.$ref);
    }
  }

  if (result.body.format === "json") {
    return `<pre class="resp-body">${esc(JSON.stringify(result.body.parsed, null, 2))}</pre>`;
  } else if (currentRequestUrl.includes("batchexecute")) {
    // Force batch rendering for batchexecute requests
    return renderBatchExecuteResponse(
      result.body.raw || "",
      { service: result.service || svc },
      discoveryInfo?.doc,
    );
  } else if (result.body.format === "protobuf_tree") {
    return (
      `<div class="card-label">Decoded Protobuf</div>` +
      renderPbTree(result.body.parsed, respSchema)
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

// ─── Helpers ─────────────────────────────────────────────────────────────────

function esc(s) {
  if (s == null) return "";
  const d = document.createElement("div");
  d.textContent = String(s);
  return d.innerHTML;
}

function el(tag, className) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  return e;
}

function renderPbTree(nodes, schema = null) {
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
    let fieldName = `Field ${node.field}`;

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
        } else {
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
        } else {
        }
      }
    }

    // Fallback: If no ID match, maybe it IS the key? (unlikely for numbers)

    // Debug log for the first 20 fields to avoid spam

    const typeLabel = fieldDef
      ? `<span class="pb-type-badge">${fieldDef.type}</span>`
      : `<span class="pb-wire-badge">${node.wire === 0 ? "varint" : node.wire === 1 ? "64bit" : node.wire === 2 ? "len" : "32bit"}</span>`;

    const renameAttr = fieldDef
      ? `data-schema="${esc(schema.id || "")}" data-key="${esc(fieldName)}"`
      : "";
    const renameBtn = renameAttr
      ? ` <span class="btn-rename" title="Rename field" ${renameAttr}>✎</span>`
      : "";

    html += `<div class="pb-node">
      <span class="pb-field">${esc(fieldName)}</span>${renameBtn}
      ${typeLabel}: `;

    if (node.message) {
      const childrenSchema = fieldDef?.children || null;
      html += `<div class="pb-nested">${renderPbTree(node.message, childrenSchema)}</div>`;
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
            html += `<div class="pb-nested-item">${renderPbTree(itemNodes, fieldDef?.children)}</div>`;
          } else {
            // Repeated scalar item
            html += `<span class="pb-scalar-item">${esc(JSON.stringify(item))}</span>`;
          }
        }
        html += "</div>";
      } else if (isMessage) {
        // Single nested message
        const nestedNodes = jspbToTree(node.value);
        html += `<div class="pb-nested">${renderPbTree(nestedNodes, fieldDef?.children)}</div>`;
      } else {
        html += `<span class="pb-string">${esc(JSON.stringify(node.value))}</span>`;
      }
    } else if (node.string !== undefined) {
      html += `<span class="pb-string">"${esc(node.string)}"</span>`;
    } else if (node.value !== undefined) {
      html += `<span class="pb-number">${node.value}</span>`;
    } else if (node.hex) {
      html += `<span class="pb-hex">0x${node.hex}</span>`;
    } else if (node.asFloat !== undefined) {
      html += `<span class="pb-number">${node.asFloat.toFixed(4)}</span>`;
    }
    html += "</div>";
  }
  html += "</div>";
  return html;
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

// ─── Response Panel (Request Log) ─────────────────────────────────────────────

function renderResponsePanel() {
  const container = document.getElementById("response-log");
  const scrollEl = document.getElementById("panel-response");
  const oldScrollHeight = scrollEl.scrollHeight;
  const oldScrollTop = scrollEl.scrollTop;
  const wasAtTop = oldScrollTop < 15;

  // Stabilize container height during re-render
  container.style.minHeight = container.scrollHeight + "px";

  if (!tabData?.requestLog?.length) {
    container.innerHTML = '<div class="empty">No requests captured yet.</div>';
    container.style.minHeight = "";
    return;
  }

  let html = "";
  for (const req of tabData.requestLog) {
    const hasProto = !!req.decodedBody;

    html += `<div class="card request-card clickable-card" style="margin-bottom:8px;" data-id="${req.id}">
      <div class="card-label" style="display:flex;justify-content:space-between;align-items:center">
        <span>
          <span class="badge ${req.method}">${req.method}</span>
          <span style="color:#aaa;font-size:11px;margin-left:6px">${new Date(req.timestamp).toLocaleTimeString()}</span>
        </span>
        ${getStatusBadge(req.status)}
      </div>
      <div class="card-value" style="font-family:monospace;font-size:11px;word-break:break-all;margin:4px 0">${esc(req.url)}</div>
      <div class="card-meta">
        ${req.service ? `Service: <strong>${esc(req.service)}</strong>` : ""}
        ${hasProto ? ' <span class="badge badge-found">PROTOBUF BODY</span>' : ""}
      </div>
    </div>`;
  }
  container.innerHTML = html;

  // Use requestAnimationFrame to ensure DOM is updated before scroll correction
  requestAnimationFrame(() => {
    if (wasAtTop) {
      scrollEl.scrollTop = 0;
    } else {
      const heightDelta = scrollEl.scrollHeight - oldScrollHeight;
      if (heightDelta !== 0) {
        scrollEl.scrollTop = oldScrollTop + heightDelta;
      }
    }
    // Clear the stabilizer
    container.style.minHeight = "";
  });

  // Attach listeners
  container.querySelectorAll(".request-card").forEach((c) => {
    c.onclick = () => replayRequest(c.dataset.id);
  });
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
    let schema = null;
    if (doc) {
      const schemaName = `${call.rpcId}Response`;
      schema = doc.schemas?.[schemaName];
    }

    html += `<div class="card" style="margin-bottom:4px;border-color:#30363d">
      <div class="card-label">RPC ID: <strong>${esc(call.rpcId)}</strong></div>
      <div class="pb-container" style="margin-bottom:0;box-shadow:none;background:transparent;border:none;padding:0">
        ${renderPbTree(nodes, schema)}
      </div>
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

function replayRequest(reqId) {
  // Use string comparison for IDs
  const req = tabData.requestLog.find((r) => String(r.id) === String(reqId));
  if (!req) {
    console.error(`[Replay] Request ${reqId} not found in log`);
    return;
  }

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
        targetRpcId = calls[0].rpcId; // Primary RPC ID
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
      } else {
        initialData = pbTreeToMap(req.decodedBody) || {};
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

      loadVirtualSchema(svc, discoveryId, initialData);
    }
  }

  // Internal state already updated in replayRequest

  // Handle Content-Type synchronization
  let originalContentType = "";
  if (req.requestHeaders) {
    const ctHeader = Object.keys(req.requestHeaders).find(
      (k) => k.toLowerCase() === "content-type",
    );
    if (ctHeader) {
      originalContentType = req.requestHeaders[ctHeader];
    }
  }

  // Map to dropdown value
  const ctSelect = document.getElementById("send-ct");
  if (originalContentType.includes("json+protobuf")) {
    ctSelect.value = "application/json+protobuf";
  } else if (
    originalContentType.includes("x-protobuf") ||
    originalContentType.includes("application/protobuf")
  ) {
    ctSelect.value = "application/x-protobuf";
  } else if (originalContentType.includes("application/json")) {
    ctSelect.value = "application/json";
  }

  // Add headers (filtering out Content-Type to avoid duplication with dropdown)
  const headersList = document.getElementById("send-headers-list");
  headersList.innerHTML = "";
  if (req.requestHeaders) {
    for (const [k, v] of Object.entries(req.requestHeaders)) {
      if (k.toLowerCase() === "content-type") continue;
      addHeaderRow(k, v);
    }
  }

  // Clear previous body
  document.getElementById("send-raw-body").value = "";

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
      const isProtobuf =
        mimeType.includes("protobuf") ||
        (req.requestHeaders &&
          Object.entries(req.requestHeaders).some(
            ([k, v]) =>
              k.toLowerCase() === "content-type" &&
              v.toLowerCase().includes("protobuf"),
          ));

      let bodyText = req.responseBody;
      if (req.responseBase64) {
        try {
          const bytes = base64ToUint8(req.responseBody);
          bodyText = new TextDecoder().decode(bytes);
        } catch (e) {}
      }

      if (isProtobuf) {
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
      } else if (mimeType.includes("json")) {
        try {
          historicalResult.body = {
            format: "json",
            parsed: JSON.parse(bodyText),
            raw: bodyText,
            size: bodyText.length,
          };
        } catch (e) {}
      }

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
      ' <span class="badge badge-source" style="margin-left:8px">Historical</span>';
  } else {
    document.getElementById("send-response").style.display = "none";
  }

  // Switch tab
  document.querySelector(".tab[data-panel='send']").click();
}

document.getElementById("btn-clear-log").addEventListener("click", async () => {
  // Clear the log in the UI
  tabData.requestLog = [];
  renderResponsePanel();

  // Optionally tell background to clear its log for this tab (if we add that message type)
  // For now, local UI clear is sufficient for the view
});
