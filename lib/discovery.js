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

// ─── OpenAPI/Swagger Conversion Helpers ───────────────────────────────────────

/**
 * Resolve a JSON $ref string to a local schema name.
 * Handles #/components/schemas/Foo, #/definitions/Foo, and similar local refs.
 */
function resolveRef(ref) {
  if (!ref || typeof ref !== "string") return ref;
  const hashIdx = ref.indexOf("#");
  if (hashIdx >= 0) {
    return ref.substring(hashIdx + 1).split("/").pop();
  }
  return ref.split("/").pop();
}

/**
 * Flatten allOf/oneOf/anyOf composition into a merged schema.
 * Recursively resolves $ref pointers within composition parts.
 * @param {object} schema - Schema that may contain composition keywords
 * @param {object} components - The components/definitions lookup
 * @returns {object} Flattened schema with merged properties
 */
function flattenComposition(schema, components) {
  if (!schema) return schema;
  const parts = schema.allOf || schema.oneOf || schema.anyOf;
  if (!parts || !Array.isArray(parts)) return schema;

  const merged = {
    type: schema.type || "object",
    properties: {},
    required: [...(schema.required || [])],
    description: schema.description || "",
  };
  if (schema.properties) {
    Object.assign(merged.properties, schema.properties);
  }

  for (const part of parts) {
    let resolved = part;
    if (part.$ref) {
      const name = resolveRef(part.$ref);
      resolved = components[name] || {};
    }
    resolved = flattenComposition(resolved, components);
    if (resolved.properties) {
      Object.assign(merged.properties, resolved.properties);
    }
    if (resolved.required) {
      merged.required.push(...resolved.required);
    }
  }
  return merged;
}

/**
 * Convert an inline OpenAPI schema to our Discovery schema format.
 * Handles nested objects, arrays, composition, and enums.
 */
function convertInlineSchema(schema, name, components, docSchemas) {
  if (!schema) return { id: name, type: "object", properties: {} };
  const resolved = flattenComposition(schema, components);

  const result = {
    id: name,
    type: resolved.type || "object",
    required: resolved.required || [],
    properties: {},
  };

  if (resolved.properties) {
    for (const [pName, pDef] of Object.entries(resolved.properties)) {
      result.properties[pName] = convertSchemaProperty(
        pDef,
        name + "_" + pName.replace(/[^a-zA-Z0-9]/g, ""),
        components,
        docSchemas,
      );
    }
  }
  return result;
}

/**
 * Convert a single OpenAPI property definition to Discovery format.
 */
function convertSchemaProperty(pDef, prefix, components, docSchemas) {
  if (!pDef) return { type: "string", description: "" };

  if (pDef.$ref) {
    return {
      type: pDef.type || "string",
      description: pDef.description || "",
      $ref: resolveRef(pDef.$ref),
    };
  }

  // Composition in property
  if (pDef.allOf || pDef.oneOf || pDef.anyOf) {
    const flat = flattenComposition(pDef, components);
    if (flat.properties && Object.keys(flat.properties).length > 0) {
      docSchemas[prefix] = convertInlineSchema(
        flat,
        prefix,
        components,
        docSchemas,
      );
      return {
        type: "object",
        $ref: prefix,
        description: pDef.description || "",
      };
    }
  }

  // Arrays
  if (pDef.type === "array" && pDef.items) {
    const items = {};
    if (pDef.items.$ref) {
      items.$ref = resolveRef(pDef.items.$ref);
    } else if (pDef.items.properties || pDef.items.allOf) {
      const itemName = prefix + "Item";
      docSchemas[itemName] = convertInlineSchema(
        pDef.items,
        itemName,
        components,
        docSchemas,
      );
      items.$ref = itemName;
    } else {
      items.type = pDef.items.type || "string";
    }
    return { type: "array", items, description: pDef.description || "" };
  }

  // Nested inline objects
  if (pDef.type === "object" && pDef.properties) {
    docSchemas[prefix] = convertInlineSchema(
      pDef,
      prefix,
      components,
      docSchemas,
    );
    return {
      type: "object",
      $ref: prefix,
      description: pDef.description || "",
    };
  }

  // Map types (additionalProperties)
  if (pDef.type === "object" && pDef.additionalProperties) {
    return {
      type: "string",
      description:
        (pDef.description || "") +
        " (map<string, " +
        (pDef.additionalProperties.type || "string") +
        ">)",
    };
  }

  // Scalar types
  const prop = {
    type: pDef.type || "string",
    format: pDef.format || null,
    description: pDef.description || "",
    $ref: null,
  };
  if (pDef.enum) {
    prop.enum = pDef.enum;
    prop.enumDescriptions = pDef["x-enumDescriptions"] || null;
  }
  return prop;
}

// ─── OpenAPI/Swagger → Discovery Converter ────────────────────────────────────

/**
 * Convert an OpenAPI 3.x or Swagger 2.0 document to our internal
 * Discovery-like format.
 *
 * Handles: Swagger 2.0 host/basePath/schemes, OAS 3.x servers with variables,
 * allOf/oneOf/anyOf composition, inline schemas, multiple content types,
 * multiple response codes, security schemes, and tag-based resource grouping.
 *
 * @param {object} openapi - Parsed OpenAPI/Swagger JSON
 * @param {string} sourceUrl - The URL it was fetched from
 * @returns {object} Normalized Discovery Doc
 */
function convertOpenApiToDiscovery(openapi, sourceUrl) {
  const u = new URL(sourceUrl);
  const isSwagger2 = !!openapi.swagger;
  const components = openapi.components?.schemas || openapi.definitions || {};

  // Resolve rootUrl: Swagger 2.0 uses host+basePath+schemes, OAS 3.x uses servers
  let rootUrl;
  if (isSwagger2 && openapi.host) {
    const scheme = (openapi.schemes && openapi.schemes[0]) || "https";
    const basePath = openapi.basePath || "/";
    rootUrl = `${scheme}://${openapi.host}${basePath}`;
  } else if (openapi.servers && openapi.servers.length > 0) {
    rootUrl = openapi.servers[0].url || "";
    // Interpolate server URL variables with their defaults
    const vars = openapi.servers[0].variables;
    if (vars) {
      for (const [vName, vDef] of Object.entries(vars)) {
        rootUrl = rootUrl.split(`{${vName}}`).join(vDef.default || vName);
      }
    }
    // Resolve relative server URLs against source URL
    if (rootUrl && !/^https?:\/\//.test(rootUrl)) {
      try {
        rootUrl = new URL(rootUrl, sourceUrl).toString();
      } catch (_) {
        rootUrl = `${u.protocol}//${u.host}${rootUrl}`;
      }
    }
  } else {
    rootUrl = `${u.protocol}//${u.host}/`;
  }

  // Normalize: ensure trailing slash for consistent URL construction
  if (!rootUrl.endsWith("/")) rootUrl += "/";

  const doc = {
    kind: "discovery#restDescription",
    name:
      openapi.info?.title?.toLowerCase().replace(/[^a-z0-9]/g, "_") || "api",
    version: openapi.info?.version || "v1",
    title: openapi.info?.title || "Universal API",
    description: openapi.info?.description || "Converted from OpenAPI",
    rootUrl,
    servicePath: "",
    baseUrl: rootUrl,
    resources: {},
    schemas: {},
    auth: null,
  };

  // Convert schemas (components/definitions), flattening allOf/oneOf/anyOf
  for (const [name, schema] of Object.entries(components)) {
    const resolved = flattenComposition(schema, components);
    doc.schemas[name] = {
      id: name,
      type: resolved.type || "object",
      required: resolved.required || [],
      properties: {},
    };
    if (resolved.properties) {
      for (const [pName, pDef] of Object.entries(resolved.properties)) {
        doc.schemas[name].properties[pName] = convertSchemaProperty(
          pDef,
          name + "_" + pName.replace(/[^a-zA-Z0-9]/g, ""),
          components,
          doc.schemas,
        );
      }
    }
  }

  // Convert security schemes to auth metadata
  const securitySchemes =
    openapi.components?.securitySchemes || openapi.securityDefinitions || {};
  for (const [, scheme] of Object.entries(securitySchemes)) {
    if (scheme.type === "oauth2") {
      if (!doc.auth) doc.auth = { oauth2: { scopes: {} } };
      // OAS 3.x: flows object; Swagger 2.0: single flow with scopes at top level
      const flows =
        scheme.flows ||
        (isSwagger2 && scheme.scopes
          ? { [scheme.flow || "implicit"]: { scopes: scheme.scopes } }
          : {});
      for (const [, flow] of Object.entries(flows)) {
        if (flow?.scopes) {
          for (const [scope, desc] of Object.entries(flow.scopes)) {
            doc.auth.oauth2.scopes[scope] = {
              description: typeof desc === "string" ? desc : "",
            };
          }
        }
      }
    } else if (scheme.type === "apiKey") {
      if (!doc.auth) doc.auth = {};
      doc.auth.apiKey = { name: scheme.name, in: scheme.in };
    }
  }

  // Convert paths to methods, grouped by tag or path prefix
  for (const [path, pathDef] of Object.entries(openapi.paths || {})) {
    const pathParams = pathDef.parameters || [];

    for (const [method, opDef] of Object.entries(pathDef)) {
      if (
        !["get", "post", "put", "delete", "patch"].includes(
          method.toLowerCase(),
        )
      ) {
        continue;
      }

      const methodName =
        opDef.operationId ||
        `${method.toLowerCase()}_${path.replace(/[^a-zA-Z0-9]/g, "_")}`;

      // Group by first tag or first path segment
      const tag =
        (opDef.tags && opDef.tags[0]) ||
        path.split("/").filter(Boolean)[0] ||
        "default";
      const resourceName = tag.toLowerCase().replace(/[^a-z0-9_]/g, "_");
      if (!doc.resources[resourceName]) {
        doc.resources[resourceName] = { methods: {} };
      }

      const m = {
        id: methodName,
        path: path.startsWith("/") ? path.substring(1) : path,
        httpMethod: method.toUpperCase(),
        description: opDef.description || opDef.summary || "",
        parameters: {},
        request: null,
        response: null,
      };
      doc.resources[resourceName].methods[methodName] = m;

      // Parameters: merge path-level + operation-level, skip body params (Swagger 2.0)
      const allParams = [...pathParams, ...(opDef.parameters || [])];
      for (const p of allParams) {
        if (p.in === "body") continue;
        m.parameters[p.name] = {
          type: p.schema?.type || p.type || "string",
          location: p.in || "query",
          required: !!p.required,
          description: p.description || "",
          enum: p.schema?.enum || p.enum || null,
        };
      }

      // Request body
      let reqSchema = null;
      if (!isSwagger2 && opDef.requestBody?.content) {
        // OAS 3.x: try JSON first, then form types, then any available
        const content = opDef.requestBody.content;
        const preferred = [
          "application/json",
          "application/x-www-form-urlencoded",
          "multipart/form-data",
        ];
        for (const ct of preferred) {
          if (content[ct]?.schema) {
            reqSchema = content[ct].schema;
            break;
          }
        }
        if (!reqSchema) {
          const firstKey = Object.keys(content)[0];
          if (firstKey) reqSchema = content[firstKey]?.schema;
        }
      } else if (isSwagger2) {
        // Swagger 2.0: body parameter
        const bodyParam = allParams.find((p) => p.in === "body");
        if (bodyParam?.schema) reqSchema = bodyParam.schema;
      }

      if (reqSchema) {
        if (reqSchema.$ref) {
          m.request = { $ref: resolveRef(reqSchema.$ref) };
        } else if (
          reqSchema.properties ||
          reqSchema.allOf ||
          reqSchema.oneOf ||
          reqSchema.anyOf ||
          reqSchema.type === "object"
        ) {
          const synName = methodName + "Request";
          doc.schemas[synName] = convertInlineSchema(
            reqSchema,
            synName,
            components,
            doc.schemas,
          );
          m.request = { $ref: synName };
        }
      }

      // Response body: try multiple success codes + default
      let respSchema = null;
      if (opDef.responses) {
        const successCodes = ["200", "201", "202", "203", "204", "default"];
        for (const code of successCodes) {
          const resp = opDef.responses[code];
          if (!resp) continue;
          // OAS 3.x
          if (resp.content) {
            let rSchema = resp.content["application/json"]?.schema;
            if (!rSchema) {
              const rKey = Object.keys(resp.content)[0];
              if (rKey) rSchema = resp.content[rKey]?.schema;
            }
            if (rSchema) {
              respSchema = rSchema;
              break;
            }
          }
          // Swagger 2.0
          if (resp.schema) {
            respSchema = resp.schema;
            break;
          }
        }
      }

      if (respSchema) {
        if (respSchema.$ref) {
          m.response = { $ref: resolveRef(respSchema.$ref) };
        } else if (
          respSchema.properties ||
          respSchema.allOf ||
          respSchema.oneOf ||
          respSchema.anyOf ||
          respSchema.type === "object"
        ) {
          const synName = methodName + "Response";
          doc.schemas[synName] = convertInlineSchema(
            respSchema,
            synName,
            components,
            doc.schemas,
          );
          m.response = { $ref: synName };
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
    name: prop.name || name, // Respect renamed fields
    customName: !!prop.customName,
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
/**
 * Parse a Google BatchExecute request body (f.req=...).
 * @param {string} bodyText - Raw request body
 * @returns {Array<{rpcId: string, data: any}> | null}
 */
function parseBatchExecuteRequest(bodyText) {
  try {
    const params = new URLSearchParams(bodyText);
    const fReq = params.get("f.req");
    if (!fReq) return null;

    const outer = JSON.parse(fReq);
    if (!Array.isArray(outer)) return null;

    const calls = [];
    for (const call of outer[0]) {
      const [rpcId, innerJson] = call;
      let decodedInner = null;
      try {
        decodedInner = JSON.parse(innerJson);
      } catch (e) {
        decodedInner = innerJson;
      }
      calls.push({ rpcId, data: decodedInner });
    }
    return calls;
  } catch (e) {
    return null;
  }
}

/**
 * Parse a Google BatchExecute response body.
 * Strips security prefix and handles length-prefixed chunks.
 * @param {string} bodyText - Raw response body
 * @returns {Array<{rpcId: string, data: any}> | null}
 */
function parseBatchExecuteResponse(bodyText) {
  try {
    let cleaned = bodyText.trim();
    if (cleaned.startsWith(")]}'")) {
      cleaned = cleaned.substring(4).trim();
    }

    const chunks = [];
    const lines = cleaned.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (/^\d+$/.test(line)) {
        if (i + 1 < lines.length) {
          try {
            const chunk = JSON.parse(lines[i + 1]);
            chunks.push(chunk);
            i++;
          } catch (e) {}
        }
      } else if (line.startsWith("[")) {
        try {
          chunks.push(JSON.parse(line));
        } catch (e) {}
      }
    }

    const results = [];
    for (const chunk of chunks) {
      if (!Array.isArray(chunk)) continue;
      for (const item of chunk) {
        if (item[0] === "wrb.fr") {
          const rpcId = item[1];
          const innerJson = item[2];
          let decodedInner = null;
          try {
            decodedInner = JSON.parse(innerJson);
          } catch (e) {
            decodedInner = innerJson;
          }

          // item[3] = error code (null on success)
          // item[6] = error details string (null on success)
          const errorCode = item[3] != null ? item[3] : null;
          let errorDetail = null;
          if (item[6]) {
            try {
              errorDetail = JSON.parse(item[6]);
            } catch (e) {
              errorDetail = item[6];
            }
          }

          const entry = { rpcId, data: decodedInner };
          if (errorCode != null) {
            entry.error = { code: errorCode, detail: errorDetail };
          }
          results.push(entry);
        }
      }
    }
    return results;
  } catch (e) {
    return null;
  }
}
