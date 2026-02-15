// lib/stats.js — Parameter statistics engine
// Tracks per-parameter observation counts, value distributions, format hints,
// numeric ranges, and cross-parameter correlations.

const STATS_MAX_UNIQUE_VALUES = 50;
const STATS_MIN_OBS_FOR_REQUIRED = 3;
const STATS_MIN_OBS_FOR_ENUM = 5;
const STATS_MAX_ENUM_VALUES = 20;
const STATS_DEFAULT_THRESHOLD = 0.8;

function createParamStats() {
  return {
    observedCount: 0,
    values: {},
    numericRange: null,
    formatHints: { "date-time": 0, uri: 0, email: 0, uuid: 0, integer: 0 },
  };
}

function updateParamStats(stats, value) {
  stats.observedCount++;

  // Track value frequencies (capped)
  const strVal = String(value);
  if (Object.keys(stats.values).length < STATS_MAX_UNIQUE_VALUES || stats.values[strVal] != null) {
    stats.values[strVal] = (stats.values[strVal] || 0) + 1;
  }

  // Numeric range
  const num = Number(value);
  if (!isNaN(num) && isFinite(num)) {
    if (!stats.numericRange) {
      stats.numericRange = { min: num, max: num };
    } else {
      if (num < stats.numericRange.min) stats.numericRange.min = num;
      if (num > stats.numericRange.max) stats.numericRange.max = num;
    }
  }

  // Format detection — real parsing, not regex
  detectFormat(stats, strVal);
}

function detectFormat(stats, value) {
  // date-time: parseable date with structural indicators
  if (value.length >= 8 && (value.includes("-") || value.includes("T"))) {
    try {
      const d = new Date(value);
      if (!isNaN(d.getTime()) && d.getFullYear() > 1900 && d.getFullYear() < 2200) {
        stats.formatHints["date-time"]++;
      }
    } catch (_) {}
  }

  // uri: valid URL with http(s) protocol
  if (value.length >= 8 && (value.startsWith("http://") || value.startsWith("https://"))) {
    try {
      const u = new URL(value);
      if (u.protocol === "http:" || u.protocol === "https:") {
        stats.formatHints.uri++;
      }
    } catch (_) {}
  }

  // email: exactly one @ with text on both sides and a dot after @
  if (value.includes("@")) {
    const parts = value.split("@");
    if (parts.length === 2 && parts[0].length > 0 && parts[1].includes(".") && parts[1].length > 2) {
      stats.formatHints.email++;
    }
  }

  // uuid: 36 chars, correct dash positions, valid hex
  if (value.length === 36) {
    const segments = value.split("-");
    if (segments.length === 5 &&
        segments[0].length === 8 && segments[1].length === 4 &&
        segments[2].length === 4 && segments[3].length === 4 &&
        segments[4].length === 12) {
      let allHex = true;
      for (let i = 0; i < value.length; i++) {
        const c = value.charCodeAt(i);
        if (value[i] === "-") continue;
        if (!((c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102))) {
          allHex = false;
          break;
        }
      }
      if (allHex) stats.formatHints.uuid++;
    }
  }

  // integer: strictly digits with optional leading sign
  if (value.length > 0) {
    const n = Number(value);
    if (Number.isInteger(n) && String(n) === value) {
      stats.formatHints.integer++;
    }
  }
}

function analyzeRequired(stats, requestCount) {
  if (requestCount < STATS_MIN_OBS_FOR_REQUIRED) {
    return { required: false, confidence: stats.observedCount / Math.max(requestCount, 1) };
  }
  const confidence = stats.observedCount / requestCount;
  return { required: confidence >= 1.0, confidence };
}

function analyzeEnum(stats) {
  if (stats.observedCount < STATS_MIN_OBS_FOR_ENUM) {
    return { isEnum: false, values: [] };
  }
  const uniqueValues = Object.keys(stats.values);
  if (uniqueValues.length >= 2 && uniqueValues.length <= STATS_MAX_ENUM_VALUES) {
    // All observed values fit in a small set — likely an enum
    return { isEnum: true, values: uniqueValues };
  }
  return { isEnum: false, values: [] };
}

function analyzeDefault(stats) {
  if (stats.observedCount < STATS_MIN_OBS_FOR_REQUIRED) {
    return { hasDefault: false, value: null, confidence: 0 };
  }
  let maxCount = 0;
  let maxValue = null;
  for (const [val, count] of Object.entries(stats.values)) {
    if (count > maxCount) {
      maxCount = count;
      maxValue = val;
    }
  }
  const confidence = maxCount / stats.observedCount;
  if (confidence >= STATS_DEFAULT_THRESHOLD) {
    return { hasDefault: true, value: maxValue, confidence };
  }
  return { hasDefault: false, value: null, confidence };
}

function analyzeFormat(stats) {
  if (stats.observedCount < STATS_MIN_OBS_FOR_REQUIRED) return null;

  // Find the dominant format hint (must be >80% of observations)
  const threshold = stats.observedCount * STATS_DEFAULT_THRESHOLD;
  for (const [format, count] of Object.entries(stats.formatHints)) {
    if (count >= threshold) return format;
  }
  return null;
}

function analyzeRange(stats) {
  if (!stats.numericRange) return null;
  if (stats.numericRange.min === stats.numericRange.max) return null;
  return stats.numericRange;
}

/**
 * Detect cross-parameter correlations.
 * @param {object} methodStats - The method's _stats object
 * @returns {Array} correlation entries
 */
function detectCorrelations(methodStats) {
  if (methodStats.requestCount < STATS_MIN_OBS_FOR_ENUM) return [];

  const paramNames = Object.keys(methodStats.params);
  if (paramNames.length < 2) return [];

  const correlations = [];

  // For each pair of params, check if one's presence predicts the other
  for (let i = 0; i < paramNames.length; i++) {
    for (let j = i + 1; j < paramNames.length; j++) {
      const a = methodStats.params[paramNames[i]];
      const b = methodStats.params[paramNames[j]];

      // If both appear in nearly the same proportion, they're correlated
      if (a.observedCount >= 3 && b.observedCount >= 3) {
        const ratio = Math.min(a.observedCount, b.observedCount) / Math.max(a.observedCount, b.observedCount);
        if (ratio >= 0.9) {
          correlations.push({
            paramA: paramNames[i],
            paramB: paramNames[j],
            confidence: ratio,
          });
        }
      }
    }
  }

  return correlations.slice(0, 20);
}

function mergeParamStats(a, b) {
  if (!a) return b;
  if (!b) return a;

  const merged = createParamStats();
  merged.observedCount = a.observedCount + b.observedCount;

  // Merge values
  for (const [val, count] of Object.entries(a.values)) {
    merged.values[val] = (merged.values[val] || 0) + count;
  }
  for (const [val, count] of Object.entries(b.values)) {
    merged.values[val] = (merged.values[val] || 0) + count;
  }
  // Trim if over cap
  const entries = Object.entries(merged.values);
  if (entries.length > STATS_MAX_UNIQUE_VALUES) {
    entries.sort((x, y) => y[1] - x[1]);
    merged.values = {};
    for (let i = 0; i < STATS_MAX_UNIQUE_VALUES; i++) {
      merged.values[entries[i][0]] = entries[i][1];
    }
  }

  // Merge numeric range
  if (a.numericRange && b.numericRange) {
    merged.numericRange = {
      min: Math.min(a.numericRange.min, b.numericRange.min),
      max: Math.max(a.numericRange.max, b.numericRange.max),
    };
  } else {
    merged.numericRange = a.numericRange || b.numericRange;
  }

  // Merge format hints
  for (const key of Object.keys(merged.formatHints)) {
    merged.formatHints[key] = (a.formatHints[key] || 0) + (b.formatHints[key] || 0);
  }

  return merged;
}
