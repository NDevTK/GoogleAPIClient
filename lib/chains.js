// lib/chains.js — Response-to-request value chaining engine
// Tracks when response values from one API call appear as parameters in another.

const CHAIN_MIN_VALUE_LENGTH = 4;
const CHAIN_MAX_VALUE_LENGTH = 500;
const CHAIN_IGNORE_VALUES = new Set([
  "true", "false", "null", "undefined", "0", "1", "-1",
  "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
  "application/json", "text/plain", "text/html",
  "utf-8", "UTF-8", "en", "en-US", "en-GB",
]);

function createValueIndex() {
  return { strings: new Map(), numbers: new Map() };
}

/**
 * Index values from a parsed response body.
 * @param {object} index - The value index { strings: Map, numbers: Map }
 * @param {*} body - Parsed response body (object, array, or primitive)
 * @param {string} methodId - Source method ID
 * @param {string} prefix - Field path prefix for recursion
 */
function indexResponseValues(index, body, methodId, prefix) {
  if (prefix === undefined) prefix = "";

  if (Array.isArray(body)) {
    for (var i = 0; i < Math.min(body.length, 50); i++) {
      indexResponseValues(index, body[i], methodId, prefix + "[" + i + "]");
    }
    return;
  }

  if (typeof body === "object" && body !== null) {
    for (var keys = Object.keys(body), k = 0; k < keys.length; k++) {
      var key = keys[k];
      var path = prefix ? prefix + "." + key : key;
      indexResponseValues(index, body[key], methodId, path);
    }
    return;
  }

  if (typeof body === "string") {
    if (body.length >= CHAIN_MIN_VALUE_LENGTH &&
        body.length <= CHAIN_MAX_VALUE_LENGTH &&
        !CHAIN_IGNORE_VALUES.has(body)) {
      var entries = index.strings.get(body);
      if (!entries) { entries = []; index.strings.set(body, entries); }
      // Avoid duplicate sources for the same method+field
      var isDupe = false;
      for (var d = 0; d < entries.length; d++) {
        if (entries[d].methodId === methodId && entries[d].fieldPath === prefix) {
          isDupe = true;
          break;
        }
      }
      if (!isDupe) entries.push({ methodId: methodId, fieldPath: prefix, timestamp: Date.now() });
    }
    return;
  }

  if (typeof body === "number" && isFinite(body) && body !== 0 && body !== 1 && body !== -1) {
    var numEntries = index.numbers.get(body);
    if (!numEntries) { numEntries = []; index.numbers.set(body, numEntries); }
    var isNumDupe = false;
    for (var nd = 0; nd < numEntries.length; nd++) {
      if (numEntries[nd].methodId === methodId && numEntries[nd].fieldPath === prefix) {
        isNumDupe = true;
        break;
      }
    }
    if (!isNumDupe) numEntries.push({ methodId: methodId, fieldPath: prefix, timestamp: Date.now() });
  }
}

/**
 * Check request parameter values against the value index to find chains.
 * @param {object} index - The value index
 * @param {object} params - Request query parameters { name: value }
 * @param {object} bodyValues - Flat map of body field paths to values
 * @param {string} targetMethodId - The method being called
 * @returns {Array} chain link objects
 */
function findChainLinks(index, params, bodyValues, targetMethodId) {
  var links = [];

  // Check query/path params
  for (var pNames = Object.keys(params), p = 0; p < pNames.length; p++) {
    var name = pNames[p];
    var found = _lookupValue(index, params[name]);
    if (found) {
      for (var f = 0; f < found.length; f++) {
        if (found[f].methodId !== targetMethodId) {
          links.push({
            paramName: name,
            paramLocation: "query",
            sourceMethodId: found[f].methodId,
            sourceFieldPath: found[f].fieldPath,
            lastSeen: Date.now(),
          });
        }
      }
    }
  }

  // Check body field values
  for (var bKeys = Object.keys(bodyValues), b = 0; b < bKeys.length; b++) {
    var bKey = bKeys[b];
    var bFound = _lookupValue(index, bodyValues[bKey]);
    if (bFound) {
      for (var bf = 0; bf < bFound.length; bf++) {
        if (bFound[bf].methodId !== targetMethodId) {
          links.push({
            paramName: bKey,
            paramLocation: "body",
            sourceMethodId: bFound[bf].methodId,
            sourceFieldPath: bFound[bf].fieldPath,
            lastSeen: Date.now(),
          });
        }
      }
    }
  }

  return links;
}

function _lookupValue(index, value) {
  if (typeof value === "string" && value.length >= CHAIN_MIN_VALUE_LENGTH && value.length <= CHAIN_MAX_VALUE_LENGTH) {
    return index.strings.get(value) || null;
  }
  if (typeof value === "number" && isFinite(value) && value !== 0 && value !== 1) {
    return index.numbers.get(value) || null;
  }
  return null;
}

/**
 * Flatten a JSON object into { "path.to.field": value } map.
 */
function flattenObjectValues(obj, prefix, result) {
  if (!result) result = {};
  if (!prefix) prefix = "";

  if (typeof obj !== "object" || obj === null) {
    if (prefix) result[prefix] = obj;
    return result;
  }

  if (Array.isArray(obj)) {
    for (var i = 0; i < Math.min(obj.length, 20); i++) {
      flattenObjectValues(obj[i], prefix + "[" + i + "]", result);
    }
    return result;
  }

  for (var keys = Object.keys(obj), k = 0; k < keys.length; k++) {
    var key = keys[k];
    flattenObjectValues(obj[key], prefix ? prefix + "." + key : key, result);
  }
  return result;
}

/**
 * Merge new chain links into existing method chain data.
 */
function mergeChainLinks(existing, newLinks) {
  if (!existing) existing = { incoming: [], outgoing: [] };

  for (var i = 0; i < newLinks.length; i++) {
    var link = newLinks[i];
    var match = null;
    for (var j = 0; j < existing.incoming.length; j++) {
      var c = existing.incoming[j];
      if (c.paramName === link.paramName &&
          c.sourceMethodId === link.sourceMethodId &&
          c.sourceFieldPath === link.sourceFieldPath) {
        match = c;
        break;
      }
    }
    if (match) {
      match.observedCount = (match.observedCount || 1) + 1;
      match.lastSeen = link.lastSeen;
    } else {
      existing.incoming.push({
        paramName: link.paramName,
        paramLocation: link.paramLocation,
        sourceMethodId: link.sourceMethodId,
        sourceFieldPath: link.sourceFieldPath,
        observedCount: 1,
        lastSeen: link.lastSeen,
      });
    }
  }

  return existing;
}
