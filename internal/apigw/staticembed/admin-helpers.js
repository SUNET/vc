// Pure helpers for the admin page's document form, unit-tested under Node.
//
// The form edits a document as key-value pairs. A key names one claim: an
// object member adds ".name" and an array element adds "[i]", so
// {"degrees": [{"type": "BSc"}]} is the pair "degrees[0].type" = "BSc". A
// backslash keeps the next character of a name literal, so the member
// "hasClaim[0]" of a type metadata file is the key "hasClaim\[0\]".

/**
 * Flattens a document into key-value pairs. A non-empty array adds one
 * pair per element.
 * @param {Record<string, any>} obj
 * @param {string} prefix
 * @returns {{key: string, value: string}[]}
 */
export function flattenObject(obj, prefix) {
    const entries = [];
    for (const [k, v] of Object.entries(obj)) {
        const name = k.replace(/[\\[\]]/g, "\\$&");
        flattenValue(entries, prefix ? prefix + "." + name : name, v);
    }
    return entries;
}

/**
 * @param {{key: string, value: string}[]} entries
 * @param {string} key
 * @param {any} v
 */
function flattenValue(entries, key, v) {
    if (Array.isArray(v) && v.length > 0) {
        v.forEach((element, i) => flattenValue(entries, key + "[" + i + "]", element));
    } else if (v && typeof v === "object" && !Array.isArray(v)) {
        entries.push(...flattenObject(v, key));
    } else {
        entries.push({ key, value: v == null ? "" : String(v) });
    }
}

/**
 * Rebuilds a document from key-value pairs. An index segment makes an
 * array, and an element no pair names is null.
 * @param {{key: string, value: string}[]} entries
 * @returns {Record<string, any>}
 */
export function unflattenEntries(entries) {
    /** @type {Record<string, any>} */
    const result = {};
    for (const { key, value } of entries) {
        const parts = key.split(".").flatMap(splitIndices);
        /** @type {any} */
        let cur = result;
        for (let i = 0; i < parts.length - 1; i++) {
            const isArray = typeof parts[i + 1] === "number";
            const next = cur[parts[i]];
            if (next === null || typeof next !== "object" || Array.isArray(next) !== isArray) {
                cur[parts[i]] = isArray ? [] : {};
            }
            cur = cur[parts[i]];
        }
        cur[parts[parts.length - 1]] = value;
    }
    return fillHoles(result);
}

/**
 * Splits a key segment such as "m[1][0]" into "m", 1 and 0. Only indices
 * that end the segment and that no backslash keeps literal are indices.
 * @param {string} segment
 * @returns {(string|number)[]}
 */
function splitIndices(segment) {
    const match = /^((?:\\.|[^\\])+?)((?:\[\d+\])+)$/s.exec(segment);
    if (!match) {
        return [segmentName(segment)];
    }
    return [segmentName(match[1]), ...match[2].slice(1, -1).split("][").map(Number)];
}

/**
 * The text of a key segment without the backslashes that keep its
 * characters literal.
 * @param {string} segment
 * @returns {string}
 */
export function segmentName(segment) {
    return segment.replace(/\\(.)/gs, "$1");
}

/**
 * Writes null into each array element no pair names.
 * @param {any} v
 * @returns {any}
 */
function fillHoles(v) {
    if (Array.isArray(v)) {
        return Array.from(v, fillHoles);
    }
    if (v && typeof v === "object") {
        for (const k of Object.keys(v)) {
            v[k] = fillHoles(v[k]);
        }
    }
    return v === undefined ? null : v;
}
