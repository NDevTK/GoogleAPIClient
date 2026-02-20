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
  const clients6Suffix = ".clients6.google.com";
  const googleapisSuffix = ".googleapis.com";
  const isClients6Host =
    hostname === clients6Suffix ||
    hostname.endsWith(clients6Suffix);
  const isGoogleapisHost =
    hostname === googleapisSuffix ||
    hostname.endsWith(googleapisSuffix);
  if (isClients6Host) {
    hosts.push(hostname.replace(clients6Suffix, googleapisSuffix));
  } else if (isGoogleapisHost && !hostname.includes("sandbox")) {
    hosts.push(hostname.replace(googleapisSuffix, clients6Suffix));
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
    const rawScheme = (openapi.schemes && openapi.schemes[0]) || "https";
    const scheme = (rawScheme === "http" || rawScheme === "https") ? rawScheme : "https";
    const basePath = openapi.basePath || "/";
    // Validate host: must be a hostname with optional port, no protocol/path/special chars
    const host = openapi.host;
    if (!/^[a-zA-Z0-9._-]+(:\d+)?$/.test(host)) {
      rootUrl = `${u.origin}${basePath}`;
    } else {
      rootUrl = `${scheme}://${host}${basePath}`;
    }
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
  fields.id = schemaName; // Tag array with schema name for rename targeting
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
        new Set(visited),
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

  // Preserve repeated label from JSPB-learned schemas
  if (prop.label === "repeated") field.label = "repeated";

  // Enum values from discovery doc
  if (prop.enum) {
    field.type = "enum";
    field.enum = prop.enum;
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

  // Pass through protobuf-native types (from JSPB-learned schemas)
  var pbTypes = [
    "int32", "int64", "uint32", "uint64", "sint32", "sint64",
    "double", "float", "fixed32", "fixed64", "sfixed32", "sfixed64",
    "bool", "bytes", "enum",
  ];
  if (pbTypes.indexOf(t) >= 0) return t;

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

/**
 * Parse a Google async chunked response (used by /async/* endpoints).
 * Format: XSSI prefix `)]}'`, then hex-length-prefixed chunks: `<hex>;<payload>`.
 * Payloads are JSPB arrays, HTML fragments, or plain text.
 * @param {string} bodyText - Raw response body
 * @returns {Array<{type: string, data: any, raw: string}>} Parsed chunks
 */
function parseAsyncChunkedResponse(bodyText) {
  try {
    let text = bodyText;
    // Strip XSSI prefix
    if (text.startsWith(")]}'")) {
      text = text.substring(4);
    }
    // Trim leading whitespace/newlines
    text = text.replace(/^\s+/, "");

    const chunks = [];
    let pos = 0;

    while (pos < text.length) {
      // Read hex length up to semicolon
      const semi = text.indexOf(";", pos);
      if (semi < 0) break;

      const hexStr = text.substring(pos, semi).trim();
      const len = parseInt(hexStr, 16);
      if (isNaN(len)) break;
      if (len === 0) break; // terminator

      const payload = text.substring(semi + 1, semi + 1 + len);
      pos = semi + 1 + len;

      // Skip whitespace between chunks
      while (pos < text.length && (text[pos] === "\n" || text[pos] === "\r"))
        pos++;

      // Classify payload
      const trimmed = payload.trim();
      if (trimmed.startsWith("[")) {
        try {
          const parsed = JSON.parse(trimmed);
          chunks.push({ type: "jspb", data: parsed, raw: payload });
          continue;
        } catch (_) {}
      }
      if (trimmed.startsWith("<")) {
        chunks.push({ type: "html", data: null, raw: payload });
      } else {
        chunks.push({ type: "text", data: null, raw: payload });
      }
    }

    return chunks.length > 0 ? chunks : null;
  } catch (e) {
    return null;
  }
}

/**
 * Detect whether a response body uses Google's async chunked format.
 * @param {string} bodyText - Raw response body
 * @returns {boolean}
 */
function isAsyncChunkedResponse(bodyText) {
  if (!bodyText) return false;
  const stripped = bodyText.trimStart();
  // Must start with XSSI prefix followed by hex;
  if (!stripped.startsWith(")]}'")) return false;
  const after = stripped.substring(4).trimStart();
  // Next token should be a hex number followed by semicolon
  const semi = after.indexOf(";");
  if (semi < 1 || semi > 10) return false;
  const hex = after.substring(0, semi).trim();
  return /^[0-9a-fA-F]+$/.test(hex);
}

/**
 * Detect whether a response body is a batchexecute response (wrb.fr format).
 * Format: optional `)]}'` XSSI prefix, decimal chunk lengths on own lines,
 * JSON arrays containing `["wrb.fr", ...]` items.
 * @param {string} bodyText - Raw response body
 * @returns {boolean}
 */
function isBatchExecuteResponse(bodyText) {
  if (!bodyText) return false;
  let text = bodyText.trimStart();
  if (text.startsWith(")]}'")) text = text.substring(4).trimStart();
  // First non-empty line should be a decimal chunk length
  const firstNewline = text.indexOf("\n");
  if (firstNewline < 1) return false;
  const firstLine = text.substring(0, firstNewline).trim();
  return /^\d+$/.test(firstLine) && bodyText.includes('"wrb.fr"');
}

// ─── gRPC-Web Frame Parser ──────────────────────────────────────────────────

/**
 * Parse gRPC-Web framed response.
 * Each frame: 1-byte flag (0=data, 0x80=trailers) + 4-byte big-endian length + payload.
 * Data frames contain protobuf; trailer frames contain HTTP/2-style headers.
 * @param {Uint8Array} bytes - Raw response bytes
 * @returns {{frames: Array<{type: string, data: Uint8Array|string}>, trailers: Object}|null}
 */
function parseGrpcWebFrames(bytes) {
  try {
    const frames = [];
    const trailers = {};
    let pos = 0;

    while (pos + 5 <= bytes.length) {
      const flag = bytes[pos];
      const len =
        (bytes[pos + 1] << 24) |
        (bytes[pos + 2] << 16) |
        (bytes[pos + 3] << 8) |
        bytes[pos + 4];
      pos += 5;

      if (len < 0 || pos + len > bytes.length) break;
      const payload = bytes.subarray(pos, pos + len);
      pos += len;

      if (flag & 0x80) {
        // Trailer frame — HTTP/2 header block as ASCII
        const text = new TextDecoder().decode(payload);
        for (const line of text.split("\r\n")) {
          const idx = line.indexOf(":");
          if (idx > 0) {
            trailers[line.slice(0, idx).trim().toLowerCase()] =
              line.slice(idx + 1).trim();
          }
        }
        frames.push({ type: "trailers", data: text });
      } else {
        frames.push({ type: "data", data: payload });
      }
    }

    return frames.length > 0 ? { frames, trailers } : null;
  } catch (e) {
    return null;
  }
}

/**
 * Detect gRPC-Web content type.
 * @param {string} contentType
 * @returns {boolean}
 */
function isGrpcWeb(contentType) {
  if (!contentType) return false;
  const ct = contentType.toLowerCase();
  return (
    ct.includes("grpc-web") ||
    (ct.includes("grpc") && !ct.includes("json"))
  );
}

/**
 * Check if gRPC-Web response uses base64 text encoding (grpc-web-text).
 * @param {string} contentType
 * @returns {boolean}
 */
function isGrpcWebText(contentType) {
  return contentType ? contentType.toLowerCase().includes("grpc-web-text") : false;
}

/**
 * Encode a protobuf payload into a gRPC-Web data frame.
 * Frame format: 1-byte flag (0x00=uncompressed) + 4-byte big-endian length + payload.
 * @param {Uint8Array} protobufBytes - Encoded protobuf message
 * @returns {Uint8Array} gRPC-Web framed message
 */
function encodeGrpcWebFrame(protobufBytes) {
  const frame = new Uint8Array(5 + protobufBytes.length);
  frame[0] = 0x00; // Uncompressed
  frame[1] = (protobufBytes.length >> 24) & 0xff;
  frame[2] = (protobufBytes.length >> 16) & 0xff;
  frame[3] = (protobufBytes.length >> 8) & 0xff;
  frame[4] = protobufBytes.length & 0xff;
  frame.set(protobufBytes, 5);
  return frame;
}

// ─── SSE (Server-Sent Events) Parser ────────────────────────────────────────

/**
 * Parse a text/event-stream response into individual events.
 * @param {string} bodyText - Raw SSE response
 * @returns {Array<{event: string, data: any, id: string|null, raw: string}>|null}
 */
function parseSSE(bodyText) {
  try {
    const events = [];
    // Split on double newlines (event boundaries)
    const blocks = bodyText.split(/\n\n+/);

    for (const block of blocks) {
      const trimmed = block.trim();
      if (!trimmed) continue;

      let eventType = "message";
      let dataLines = [];
      let id = null;

      for (const line of trimmed.split("\n")) {
        if (line.startsWith("event:")) {
          eventType = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          dataLines.push(line.slice(5).trimStart());
        } else if (line.startsWith("id:")) {
          id = line.slice(3).trim();
        } else if (line.startsWith(":")) {
          // Comment — skip
        } else if (line.includes(":")) {
          // Unknown field — treat as data
          dataLines.push(line);
        } else if (line.trim()) {
          dataLines.push(line);
        }
      }

      if (dataLines.length === 0) continue;

      const rawData = dataLines.join("\n");
      let parsed = rawData;
      try {
        parsed = JSON.parse(rawData);
      } catch (_) {}

      events.push({ event: eventType, data: parsed, id, raw: rawData });
    }

    return events.length > 0 ? events : null;
  } catch (e) {
    return null;
  }
}

/**
 * Detect SSE content type.
 * @param {string} contentType
 * @returns {boolean}
 */
function isSSE(contentType) {
  return contentType ? contentType.toLowerCase().includes("event-stream") : false;
}

// ─── NDJSON (Newline-Delimited JSON) Parser ─────────────────────────────────

/**
 * Parse NDJSON (one JSON object per line).
 * @param {string} bodyText
 * @returns {Array<any>|null}
 */
function parseNDJSON(bodyText) {
  try {
    const lines = bodyText.split("\n").filter((l) => l.trim());
    if (lines.length < 2) return null; // Need at least 2 lines to be NDJSON
    const objects = [];
    let parsed = 0;
    for (const line of lines) {
      try {
        objects.push(JSON.parse(line));
        parsed++;
      } catch (_) {
        // Allow a few unparseable lines (e.g. trailing newlines)
      }
    }
    // At least 2 valid JSON lines to qualify as NDJSON
    return parsed >= 2 ? objects : null;
  } catch (e) {
    return null;
  }
}

/**
 * Detect NDJSON content type.
 * @param {string} contentType
 * @returns {boolean}
 */
function isNDJSON(contentType) {
  if (!contentType) return false;
  const ct = contentType.toLowerCase();
  return ct.includes("ndjson") || ct.includes("jsonl") || ct.includes("json-seq");
}

// ─── GraphQL Decoder ────────────────────────────────────────────────────────

/**
 * Extract GraphQL structure from a JSON request body.
 * @param {string} bodyText - JSON request body
 * @returns {{query: string, variables: Object|null, operationName: string|null}|null}
 */
function parseGraphQLRequest(bodyText) {
  try {
    const json = JSON.parse(bodyText);
    if (!json.query && !json.mutation) return null;
    return {
      query: json.query || json.mutation || "",
      variables: json.variables || null,
      operationName: json.operationName || null,
    };
  } catch (e) {
    return null;
  }
}

/**
 * Decode a GraphQL response, extracting data, errors, and extensions.
 * @param {string} bodyText - JSON response body
 * @returns {{data: any, errors: Array|null, extensions: Object|null}|null}
 */
function parseGraphQLResponse(bodyText) {
  try {
    const json = JSON.parse(bodyText);
    // Must have at least a data or errors key to be GraphQL
    if (!("data" in json) && !("errors" in json)) return null;
    return {
      data: json.data ?? null,
      errors: json.errors || null,
      extensions: json.extensions || null,
    };
  } catch (e) {
    return null;
  }
}

/**
 * Detect if a URL looks like a GraphQL endpoint.
 * @param {string} url
 * @returns {boolean}
 */
function isGraphQLUrl(url) {
  return /graphql/i.test(url);
}

// ─── Multipart Batch Response Parser ────────────────────────────────────────

/**
 * Parse a multipart/mixed (or multipart/batch) response.
 * Each part contains a full HTTP response (status line, headers, body).
 * @param {string} bodyText - Raw multipart response body
 * @param {string} contentType - Content-Type header (contains boundary)
 * @returns {Array<{status: number, statusText: string, headers: Object, body: string}>|null}
 */
function parseMultipartBatch(bodyText, contentType) {
  try {
    // Extract boundary from content-type
    const boundaryMatch = contentType.match(/boundary=["']?([^"';\s]+)/i);
    if (!boundaryMatch) return null;
    const boundary = boundaryMatch[1];

    const parts = bodyText.split("--" + boundary);
    const results = [];

    for (const part of parts) {
      const trimmed = part.trim();
      if (!trimmed || trimmed === "--") continue; // Preamble or closing

      // Each part: optional part headers, blank line, then HTTP response
      // Find the HTTP response within the part
      const httpStart = trimmed.indexOf("HTTP/");
      if (httpStart < 0) {
        // No HTTP response line — might be a raw body part
        const blankLine = trimmed.indexOf("\r\n\r\n");
        if (blankLine >= 0) {
          results.push({
            status: 0,
            statusText: "",
            headers: {},
            body: trimmed.substring(blankLine + 4),
          });
        }
        continue;
      }

      const responseText = trimmed.substring(httpStart);
      // Split status line from headers+body
      const firstLine = responseText.split(/\r?\n/)[0];
      const statusMatch = firstLine.match(/HTTP\/[\d.]+\s+(\d+)\s*(.*)/);
      const status = statusMatch ? parseInt(statusMatch[1]) : 0;
      const statusText = statusMatch ? statusMatch[2] : "";

      // Parse headers (between status line and blank line)
      const headerEnd = responseText.search(/\r?\n\r?\n/);
      const headers = {};
      if (headerEnd > 0) {
        const headerBlock = responseText.substring(
          responseText.indexOf("\n") + 1,
          headerEnd,
        );
        for (const line of headerBlock.split(/\r?\n/)) {
          const idx = line.indexOf(":");
          if (idx > 0) {
            headers[line.slice(0, idx).trim().toLowerCase()] =
              line.slice(idx + 1).trim();
          }
        }
      }

      // Body is everything after the blank line
      const bodyStart = responseText.search(/\r?\n\r?\n/);
      const body =
        bodyStart >= 0
          ? responseText.substring(
              bodyStart + responseText.substring(bodyStart).match(/\r?\n\r?\n/)[0].length,
            )
          : "";

      results.push({ status, statusText, headers, body });
    }

    return results.length > 0 ? results : null;
  } catch (e) {
    return null;
  }
}

/**
 * Parse a multipart batch REQUEST body (each part is an HTTP request).
 * Google batch APIs send multiple HTTP sub-requests in one body.
 * @param {string} bodyText
 * @param {string} contentType - includes boundary parameter
 * @returns {Array<{method:string, path:string, headers:Object, body:string, contentId:string|null}>|null}
 */
function parseMultipartBatchRequest(bodyText, contentType) {
  try {
    const boundaryMatch = contentType.match(/boundary=["']?([^"';\s]+)/i);
    if (!boundaryMatch) return null;
    const boundary = boundaryMatch[1];
    const parts = bodyText.split("--" + boundary);
    const results = [];

    for (const part of parts) {
      const trimmed = part.trim();
      if (!trimmed || trimmed === "--") continue;

      // Find the HTTP request line: METHOD /path HTTP/1.x
      const reqMatch = trimmed.match(
        /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP\//m,
      );
      if (!reqMatch) continue;

      const method = reqMatch[1];
      const path = reqMatch[2];
      const reqLineIdx = trimmed.indexOf(reqMatch[0]);

      // Everything after the request line
      const afterReqLine = trimmed.substring(
        reqLineIdx + reqMatch[0].length,
      );
      // Skip rest of request line (e.g. "1.1")
      const firstNl = afterReqLine.indexOf("\n");
      const afterFirstLine =
        firstNl >= 0 ? afterReqLine.substring(firstNl + 1) : "";

      // Headers + body separated by blank line
      const blankLine = afterFirstLine.search(/\r?\n\r?\n/);
      const headers = {};
      // If no blank line, all remaining text is headers (no body, e.g. GET requests)
      const headerBlock =
        blankLine >= 0
          ? afterFirstLine.substring(0, blankLine)
          : afterFirstLine;
      for (const line of headerBlock.split(/\r?\n/)) {
        const idx = line.indexOf(":");
        if (idx > 0) {
          headers[line.slice(0, idx).trim().toLowerCase()] = line
            .slice(idx + 1)
            .trim();
        }
      }
      const body =
        blankLine >= 0
          ? afterFirstLine.substring(blankLine).replace(/^[\r\n]+/, "")
          : "";

      // Content-ID from part envelope headers (above the HTTP line)
      const partHeaders = trimmed.substring(0, reqLineIdx);
      const cidMatch = partHeaders.match(/Content-ID:\s*<?([^>\r\n]+)/i);

      results.push({
        method,
        path,
        headers,
        body: body.trim(),
        contentId: cidMatch ? cidMatch[1] : null,
      });
    }

    return results.length > 0 ? results : null;
  } catch (e) {
    return null;
  }
}

/**
 * Detect multipart content type.
 * @param {string} contentType
 * @returns {boolean}
 */
function isMultipartBatch(contentType) {
  if (!contentType) return false;
  const ct = contentType.toLowerCase();
  return (ct.includes("multipart/mixed") || ct.includes("multipart/batch")) &&
    ct.includes("boundary");
}

// ─── VDD → OpenAPI 3.0 Export ───────────────────────────────────────────────

/**
 * Map internal protobuf-style type to JSON Schema type + format.
 */
function discoveryTypeToJsonSchema(type) {
  switch (type) {
    case "string": return { type: "string" };
    case "bytes": return { type: "string", format: "byte" };
    case "bool": return { type: "boolean" };
    case "int32": case "uint32": return { type: "integer", format: type };
    case "int64": case "uint64": return { type: "string", format: type };
    case "float": return { type: "number", format: "float" };
    case "double": case "number": return { type: "number", format: "double" };
    case "enum": return { type: "string" };
    case "array": return { type: "array" };
    case "any": return {};
    default: return { type: "string" };
  }
}

/**
 * Convert a Discovery schema object to OpenAPI 3.0 schema.
 * @param {object} schema - Discovery schema (id, type, properties, required)
 * @param {object} allSchemas - All schemas in the doc (for $ref resolution)
 * @param {Set} visited - Circular reference guard
 * @returns {object} OpenAPI schema object
 */
function discoverySchemaToOpenApi(schema, allSchemas, visited) {
  if (!schema) return { type: "object" };
  if (!visited) visited = new Set();
  if (visited.has(schema.id)) return { $ref: "#/components/schemas/" + schema.id };
  visited.add(schema.id);

  const result = { type: "object", properties: {} };
  const required = [];

  if (schema.properties) {
    for (const [key, prop] of Object.entries(schema.properties)) {
      const fieldName = prop.name || prop.customName || key;

      if (prop.type === "message" || prop.$ref) {
        const refName = prop.$ref || prop.messageType;
        if (refName && allSchemas[refName]) {
          if (prop.label === "repeated") {
            result.properties[fieldName] = {
              type: "array",
              items: { $ref: "#/components/schemas/" + refName },
            };
          } else {
            result.properties[fieldName] = { $ref: "#/components/schemas/" + refName };
          }
        } else {
          result.properties[fieldName] = { type: "object" };
        }
      } else if (prop.label === "repeated" || prop.type === "array") {
        const itemType = prop.items?.$ref
          ? { $ref: "#/components/schemas/" + prop.items.$ref }
          : prop.items?.type
            ? discoveryTypeToJsonSchema(prop.items.type)
            : { type: "string" };
        result.properties[fieldName] = { type: "array", items: itemType };
      } else {
        const ts = discoveryTypeToJsonSchema(prop.type || "string");
        result.properties[fieldName] = { ...ts };
        if (prop.enum) result.properties[fieldName].enum = prop.enum;
      }

      if (prop.description) result.properties[fieldName].description = prop.description;
      if (prop.number) {
        result.properties[fieldName]["x-field-number"] = prop.number;
      }
      if (prop.required) required.push(fieldName);
    }
  }

  if (required.length) result.required = required;
  visited.delete(schema.id);
  return result;
}

/**
 * Convert a Discovery document to OpenAPI 3.0.3 spec.
 * @param {object} doc - Discovery doc (from discoveryDocs Map)
 * @param {string} serviceName - Service key (e.g. "people.googleapis.com")
 * @returns {object} OpenAPI 3.0.3 JSON object
 */
function convertDiscoveryToOpenApi(doc, serviceName) {
  const spec = {
    openapi: "3.0.3",
    info: {
      title: doc.title || serviceName,
      description: doc.description || "Exported from UASR",
      version: doc.version || "v1",
    },
    servers: [{ url: doc.rootUrl || doc.baseUrl || "https://" + serviceName }],
    paths: {},
    components: { schemas: {} },
  };

  // Convert schemas
  if (doc.schemas) {
    for (const [name, schema] of Object.entries(doc.schemas)) {
      spec.components.schemas[name] = discoverySchemaToOpenApi(
        schema, doc.schemas, new Set(),
      );
    }
  }

  // Convert auth
  if (doc.auth?.oauth2?.scopes) {
    spec.components.securitySchemes = {
      oauth2: {
        type: "oauth2",
        flows: {
          implicit: {
            authorizationUrl: "https://accounts.google.com/o/oauth2/auth",
            scopes: {},
          },
        },
      },
    };
    for (const [scope, def] of Object.entries(doc.auth.oauth2.scopes)) {
      spec.components.securitySchemes.oauth2.flows.implicit.scopes[scope] =
        def.description || "";
    }
  }
  if (doc.auth?.apiKey) {
    if (!spec.components.securitySchemes) spec.components.securitySchemes = {};
    spec.components.securitySchemes.apiKey = {
      type: "apiKey",
      name: doc.auth.apiKey.name || "key",
      in: doc.auth.apiKey.in || "query",
    };
  }

  // Walk resources to extract methods
  function walkResources(resources, prefix) {
    if (!resources) return;
    for (const [rName, resource] of Object.entries(resources)) {
      if (resource.methods) {
        for (const [, method] of Object.entries(resource.methods)) {
          const path = "/" + (method.path || "").replace(/^\/?/, "");
          const httpMethod = (method.httpMethod || "POST").toLowerCase();

          if (!spec.paths[path]) spec.paths[path] = {};

          const operation = {
            operationId: method.id,
            description: method.description || "",
            parameters: [],
            responses: { "200": { description: "OK" } },
          };

          // Parameters
          if (method.parameters) {
            for (const [pName, pDef] of Object.entries(method.parameters)) {
              const paramName = pDef.name || pName;
              const paramSchema = {
                type: pDef.type || "string",
                ...(pDef.enum ? { enum: pDef.enum } : {}),
                ...(pDef.format ? { format: pDef.format } : {}),
                ...(pDef._defaultValue != null ? { default: pDef._defaultValue } : {}),
                ...(pDef._range ? { minimum: pDef._range.min, maximum: pDef._range.max } : {}),
              };
              const param = {
                name: paramName,
                in: pDef.location || "query",
                required: !!pDef.required,
                description: pDef.description || "",
                schema: paramSchema,
              };
              if (pDef.number) param["x-field-number"] = pDef.number;
              if (pDef._requiredConfidence != null) param["x-observed-frequency"] = pDef._requiredConfidence;
              operation.parameters.push(param);
            }
          }

          // Request body
          if (method.request?.$ref && doc.schemas?.[method.request.$ref]) {
            const ct = "application/json";
            operation.requestBody = {
              content: {
                [ct]: { schema: { $ref: "#/components/schemas/" + method.request.$ref } },
              },
            };
          }

          // Response body
          if (method.response?.$ref && doc.schemas?.[method.response.$ref]) {
            operation.responses["200"].content = {
              "application/json": {
                schema: { $ref: "#/components/schemas/" + method.response.$ref },
              },
            };
          }

          // Scopes
          if (method.scopes?.length) {
            operation.security = [{ oauth2: method.scopes }];
          }

          // Chain data
          if (method._chains) {
            var chainExport = {};
            if (method._chains.incoming?.length) {
              chainExport.incoming = method._chains.incoming.map(function(c) {
                return { param: c.paramName, from: c.sourceMethodId + "." + c.sourceFieldPath, count: c.observedCount || 1 };
              });
            }
            if (method._chains.outgoing?.length) {
              chainExport.outgoing = method._chains.outgoing.map(function(c) {
                return { field: c.sourceFieldPath, to: c.targetMethodId + "." + c.paramName, count: c.observedCount || 1 };
              });
            }
            if (chainExport.incoming || chainExport.outgoing) {
              operation["x-data-chains"] = chainExport;
            }
          }

          if (!operation.parameters.length) delete operation.parameters;

          spec.paths[path][httpMethod] = operation;
        }
      }
      if (resource.resources) {
        walkResources(resource.resources, prefix + rName + ".");
      }
    }
  }

  walkResources(doc.resources, "");

  return spec;
}
