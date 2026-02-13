// Discovery document fetcher and parser.
// Tries multiple URL patterns and auth strategies to locate
// the REST discovery document for a given Google API service.
//
// Strategies from the research:
//  - Plain GET (public APIs)
//  - ?labels=PANTHEON (visibility label expansion, "Decoding Google" article)
//  - With API key in URL param or X-Goog-Api-Key header
//  - POST + X-Http-Method-Override: GET (bypasses 405 on some services like youtubei)
//  - Staging sandbox variant (staging-<svc>.sandbox.googleapis.com)
//  - clients6.google.com variant

/**
 * Build candidate discovery URLs for a given hostname.
 * @param {string} hostname - e.g. "people-pa.googleapis.com"
 * @param {string|null} apiKey
 * @returns {Array<{url: string, headers: object, method: string}>}
 */
function buildDiscoveryUrls(hostname, apiKey) {
  const candidates = [];

  // 1. Generic Universal Patterns (OpenAPI / Swagger)
  // These work on almost any modern API domain
  const genericPaths = [
    "/.well-known/openapi.json",
    "/.well-known/swagger.json",
    "/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api/docs",
    "/api/v1/docs",
    "/api-docs",
    "/v1/api-docs",
  ];

  for (const path of genericPaths) {
    candidates.push({
      url: `https://${hostname}${path}#_internal_probe`,
      headers: {},
      method: "GET",
    });
  }

  // 2. Google-Specific Patterns
  // Normalize: if it's a clients6 host, also try the googleapis.com equivalent
  const hosts = [hostname];
  if (hostname.includes(".clients6.google.com")) {
    hosts.push(hostname.replace(".clients6.google.com", ".googleapis.com"));
  } else if (
    hostname.includes(".googleapis.com") &&
    !hostname.includes("sandbox")
  ) {
    hosts.push(hostname.replace(".googleapis.com", ".clients6.google.com"));
  }

  // Common version strings to try — some services require explicit ?version=
  const versions = ["v1", "v2", "v1beta1", "v1alpha1"];

  for (const host of hosts) {
    const base = `https://${host}/$discovery/rest`;

    // Plain GET
    candidates.push({
      url: `${base}#_internal_probe`,
      headers: {},
      method: "GET",
    });

    // Visibility label expansion
    candidates.push({
      url: `${base}?labels=PANTHEON#_internal_probe`,
      headers: {},
      method: "GET",
    });

    // Versions
    for (const ver of versions) {
      candidates.push({
        url: `${base}?version=${ver}#_internal_probe`,
        headers: {},
        method: "GET",
      });
    }

    // With API key
    if (apiKey) {
      candidates.push({
        url: `${base}?key=${apiKey}#_internal_probe`,
        headers: {},
        method: "GET",
      });
      candidates.push({
        url: `${base}#_internal_probe`,
        headers: { "X-Goog-Api-Key": apiKey },
        method: "GET",
      });
    }

    // POST override
    candidates.push({
      url: `${base}#_internal_probe`,
      headers: { "X-Http-Method-Override": "GET" },
      method: "POST",
    });
  }

  return candidates;
}

/**
 * Convert an OpenAPI/Swagger document to our internal Discovery-like format.
 * @param {object} openapi - Parsed OpenAPI JSON
 * @param {string} sourceUrl - The URL it was fetched from
 * @returns {object} Normalized Discovery Doc
 */
function convertOpenApiToDiscovery(openapi, sourceUrl) {
  const u = new URL(sourceUrl);
  const rootUrl = openapi.servers?.[0]?.url || `${u.protocol}//${u.host}/`;

  const doc = {
    kind: "discovery#restDescription",
    name:
      openapi.info?.title?.toLowerCase().replace(/[^a-z0-9]/g, "_") || "api",
    version: openapi.info?.version || "v1",
    title: openapi.info?.title || "Universal API",
    description: openapi.info?.description || "Converted from OpenAPI",
    rootUrl: rootUrl.endsWith("/") ? rootUrl : rootUrl + "/",
    servicePath: "",
    baseUrl: rootUrl,
    resources: {
      openapi: { methods: {} },
    },
    schemas: {},
  };

  // Convert Schemas (Components)
  const components = openapi.components?.schemas || openapi.definitions || {};
  for (const [name, schema] of Object.entries(components)) {
    doc.schemas[name] = {
      id: name,
      type: schema.type || "object",
      properties: {},
    };
    if (schema.properties) {
      for (const [pName, pDef] of Object.entries(schema.properties)) {
        doc.schemas[name].properties[pName] = {
          type: pDef.type || "string",
          description: pDef.description || "",
          $ref: pDef.$ref ? pDef.$ref.split("/").pop() : null,
        };
      }
    }
  }

  // Convert Paths to Methods
  for (const [path, pathDef] of Object.entries(openapi.paths || {})) {
    for (const [method, opDef] of Object.entries(pathDef)) {
      if (
        ["get", "post", "put", "delete", "patch"].includes(method.toLowerCase())
      ) {
        const methodName =
          opDef.operationId ||
          `${method.toLowerCase()}_${path.replace(/[^a-zA-Z0-9]/g, "_")}`;

        doc.resources.openapi.methods[methodName] = {
          id: methodName,
          path: path.startsWith("/") ? path.substring(1) : path,
          httpMethod: method.toUpperCase(),
          description: opDef.description || opDef.summary || "",
          parameters: {},
          request: null,
          response: null,
        };

        const m = doc.resources.openapi.methods[methodName];

        // Parameters (Query/Path)
        const params = [
          ...(pathDef.parameters || []),
          ...(opDef.parameters || []),
        ];
        for (const p of params) {
          m.parameters[p.name] = {
            type: p.schema?.type || "string",
            location: p.in || "query",
            required: !!p.required,
            description: p.description || "",
          };
        }

        // Request Body
        const reqBody =
          opDef.requestBody?.content?.["application/json"]?.schema;
        if (reqBody?.$ref) {
          m.request = { $ref: reqBody.$ref.split("/").pop() };
        }

        // Response Body
        const respBody =
          opDef.responses?.["200"]?.content?.["application/json"]?.schema;
        if (respBody?.$ref) {
          m.response = { $ref: respBody.$ref.split("/").pop() };
        }
      }
    }
  }

  return doc;
}

/**
 * Summarize a discovery document into a compact representation.
 * @param {object} doc - Parsed discovery JSON
 * @returns {object} Summary
 */
function summarizeDiscovery(doc) {
  if (!doc) return null;

  const resources = {};
  function walkResources(res, prefix) {
    for (const [name, r] of Object.entries(res || {})) {
      const fullName = prefix ? `${prefix}.${name}` : name;
      if (r.methods) {
        resources[fullName] = Object.keys(r.methods).map((m) => {
          const method = r.methods[m];
          return {
            id: method.id,
            httpMethod: method.httpMethod,
            path: method.path || method.flatPath,
            scopes: method.scopes,
            parameters: method.parameters ? Object.keys(method.parameters) : [],
            description: method.description,
            request: method.request,
            response: method.response,
          };
        });
      }
      if (r.resources) walkResources(r.resources, fullName);
    }
  }

  walkResources(doc.resources, "");

  return {
    name: doc.name,
    version: doc.version,
    title: doc.title,
    baseUrl: doc.baseUrl || doc.rootUrl,
    documentationLink: doc.documentationLink,
    auth: doc.auth
      ? { scopes: Object.keys(doc.auth.oauth2?.scopes || {}) }
      : null,
    schemas: doc.schemas || {},
    resourceCount: Object.keys(resources).length,
    methodCount: Object.values(resources).reduce((s, m) => s + m.length, 0),
    resources,
  };
}

/**
 * Extract all methods from a discovery document as flat endpoint list.
 * @param {object} doc - Parsed discovery JSON
 * @returns {Array<{id, httpMethod, fullPath, scopes, parameters}>}
 */
function extractMethodsFromDiscovery(doc) {
  if (!doc) return [];

  const methods = [];
  const baseUrl = doc.baseUrl || doc.rootUrl || "";

  function walk(res) {
    for (const [, r] of Object.entries(res || {})) {
      for (const [, m] of Object.entries(r.methods || {})) {
        methods.push({
          id: m.id,
          httpMethod: m.httpMethod,
          fullPath: baseUrl + (m.path || m.flatPath || ""),
          scopes: m.scopes || [],
          parameters: m.parameters ? Object.keys(m.parameters) : [],
          description: m.description,
        });
      }
      if (r.resources) walk(r.resources);
    }
  }

  walk(doc.resources);
  return methods;
}

// ─── Schema Resolution (for Send Request form) ─────────────────────────────

/**
 * Find a discovery method matching an endpoint's path and HTTP method.
 * Walks doc.resources recursively, comparing method paths.
 *
 * @param {object} doc - Full parsed discovery JSON
 * @param {string} endpointPath - URL path (e.g. "/v1/people:search")
 * @param {string} httpMethod - HTTP method (e.g. "POST")
 * @returns {{method: object, resourceName: string}|null}
 */
function findDiscoveryMethod(doc, endpointPath, httpMethod) {
  if (!doc || !doc.resources) return null;

  const baseUrl = doc.baseUrl || doc.rootUrl || "";
  let basePath = "";
  try {
    basePath = new URL(baseUrl).pathname.replace(/\/$/, "");
  } catch (_) {}

  // Strip basePath prefix from endpointPath for comparison
  let normPath = endpointPath;
  if (basePath && normPath.startsWith(basePath)) {
    normPath = normPath.slice(basePath.length);
  }
  normPath = normPath.replace(/^\//, "");

  function normalizePath(p) {
    // Convert {param} placeholders to a wildcard for matching
    return (p || "").replace(/^\//, "").replace(/\{[^}]+\}/g, "*");
  }

  function matchPath(methodPath, target) {
    const a = normalizePath(methodPath);
    const b = target.replace(/\{[^}]+\}/g, "*");
    if (a === b) return true;
    // Also try matching with path params as segments
    const aParts = a.split("/");
    const bParts = b.split("/");
    if (aParts.length !== bParts.length) return false;
    for (let i = 0; i < aParts.length; i++) {
      if (aParts[i] === "*" || bParts[i] === "*") continue;
      if (aParts[i] !== bParts[i]) return false;
    }
    return true;
  }

  let best = null;

  function walk(res, prefix) {
    for (const [name, r] of Object.entries(res || {})) {
      const fullName = prefix ? prefix + "." + name : name;
      for (const [, m] of Object.entries(r.methods || {})) {
        const mMethod = (m.httpMethod || "").toUpperCase();
        const mPath = m.flatPath || m.path || "";
        if (
          mMethod === httpMethod.toUpperCase() &&
          matchPath(mPath, normPath)
        ) {
          best = { method: m, resourceName: fullName };
          return;
        }
      }
      if (r.resources) walk(r.resources, fullName);
      if (best) return;
    }
  }

  walk(doc.resources, "");

  // Fallback: partial match (endsWith) for flexibility
  if (!best) {
    function walkPartial(res, prefix) {
      for (const [name, r] of Object.entries(res || {})) {
        const fullName = prefix ? prefix + "." + name : name;
        for (const [, m] of Object.entries(r.methods || {})) {
          const mPath = normalizePath(m.flatPath || m.path || "");
          if (
            normPath.endsWith(mPath) ||
            mPath.endsWith(normPath.replace(/\{[^}]+\}/g, "*"))
          ) {
            best = { method: m, resourceName: fullName };
            return;
          }
        }
        if (r.resources) walkPartial(r.resources, fullName);
        if (best) return;
      }
    }
    walkPartial(doc.resources, "");
  }

  return best;
}

/**
 * Find a discovery method by its ID (e.g. "people.people.get").
 *
 * @param {object} doc - Full parsed discovery JSON
 * @param {string} methodId - The method ID to find
 * @returns {{method: object, resourceName: string}|null}
 */
function findMethodById(doc, methodId) {
  if (!doc || !doc.resources) return null;

  let best = null;

  function walk(res, prefix) {
    for (const [name, r] of Object.entries(res || {})) {
      const fullName = prefix ? prefix + "." + name : name;
      for (const [, m] of Object.entries(r.methods || {})) {
        if (m.id === methodId) {
          best = { method: m, resourceName: fullName };
          return;
        }
      }
      if (r.resources) walk(r.resources, fullName);
      if (best) return;
    }
  }

  walk(doc.resources, "");
  return best;
}

/**
 * Resolve a discovery document schema into a recursive field list.
 * Follows $ref pointers in doc.schemas to build the full type tree.
 *
 * @param {object} doc - Full parsed discovery JSON
 * @param {string} schemaName - Schema name to resolve (e.g. "Person")
 * @param {number} [maxDepth=5] - Maximum recursion depth
 * @param {Set} [visited] - Circular reference guard
 * @returns {Array<{name, type, required, description, label, children}>}
 */
function resolveDiscoverySchema(doc, schemaName, maxDepth, visited) {
  if (maxDepth == null) maxDepth = 5;
  if (!visited) visited = new Set();
  if (!doc || !doc.schemas || !doc.schemas[schemaName]) return [];
  if (visited.has(schemaName) || maxDepth <= 0) {
    return [
      {
        name: "...",
        type: "message",
        description: "(circular ref: " + schemaName + ")",
        label: "optional",
      },
    ];
  }
  visited.add(schemaName);

  var schema = doc.schemas[schemaName];
  var required = schema.required || [];
  var fields = [];

  var i = 1;
  for (var propName in schema.properties || {}) {
    var prop = schema.properties[propName];
    var field = mapDiscoveryProperty(
      doc,
      propName,
      prop,
      required,
      maxDepth - 1,
      visited,
    );
    if (field) {
      // Automatic indexing for JSPB/Protobuf services if 'id' is missing
      if (field.number == null) {
        field.number = i;
        field.isNumberGuessed = true;
      }
      fields.push(field);
    }
    i++;
  }

  visited.delete(schemaName);
  return fields;
}

/**
 * Map a single discovery document property to a unified field descriptor.
 */
function mapDiscoveryProperty(doc, name, prop, requiredList, depth, visited) {
  var isRequired = (requiredList || []).indexOf(name) >= 0;
  var field = {
    name: name,
    type: "string",
    required: isRequired,
    description: prop.description || null,
    label: isRequired ? "required" : "optional",
    number: prop.id != null ? prop.id : null,
    messageType: null,
    children: null,
  };

  // Handle $ref to another schema
  if (prop.$ref) {
    field.type = "message";
    field.messageType = prop.$ref;
    field.children = resolveDiscoverySchema(
      doc,
      prop.$ref,
      depth,
      new Set(visited),
    );
    return field;
  }

  // Handle arrays (repeated fields)
  if (prop.type === "array" && prop.items) {
    field.label = "repeated";
    if (prop.items.$ref) {
      field.type = "message";
      field.messageType = prop.items.$ref;
      field.children = resolveDiscoverySchema(
        doc,
        prop.items.$ref,
        depth,
        new Set(visited),
      );
    } else {
      field.type = mapJsonSchemaType(prop.items);
    }
    return field;
  }

  // Handle nested object without $ref (inline properties)
  if (prop.type === "object" && prop.properties) {
    field.type = "message";
    field.children = [];
    var nestedRequired = prop.required || [];
    for (var pn in prop.properties) {
      var child = mapDiscoveryProperty(
        doc,
        pn,
        prop.properties[pn],
        nestedRequired,
        depth - 1,
        visited,
      );
      if (child) field.children.push(child);
    }
    return field;
  }

  // Handle additionalProperties (map type)
  if (prop.type === "object" && prop.additionalProperties) {
    field.type = "string";
    field.description =
      (field.description || "") +
      " (map<string, " +
      (prop.additionalProperties.type || "string") +
      ">)";
    return field;
  }

  // Scalar types
  field.type = mapJsonSchemaType(prop);

  // Enum values from discovery doc
  if (prop.enum) {
    field.type = "enum";
    field.enumValues = prop.enum;
    field.enumDescriptions = prop.enumDescriptions || null;
  }

  return field;
}

/**
 * Map a JSON schema type+format to unified protobuf-style type.
 */
function mapJsonSchemaType(prop) {
  if (!prop) return "string";
  var t = prop.type || "string";
  var f = prop.format || "";
  if (t === "string") {
    if (f === "byte") return "bytes";
    if (f === "int64" || f === "uint64") return f;
    return "string";
  }
  if (t === "integer") {
    if (f === "int32" || f === "uint32") return f;
    return "int32";
  }
  if (t === "number") {
    if (f === "float") return "float";
    return "double";
  }
  if (t === "boolean") return "bool";
  return "string";
}
