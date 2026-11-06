// Pure helpers for the admin page's document form, unit-tested under Node.
//
// The form edits a document as key-value pairs. A key names one claim: an
// object member adds ".name" and an array element adds "[i]", so
// {"degrees": [{"type": "BSc"}]} is the pair "degrees[0].type" = "BSc". A
// backslash keeps the next character of a name literal, so the member
// "hasClaim[0]" of a type metadata file is the key "hasClaim\[0\]". A pair
// read from a document returns the value it read until its text is edited, so
// an edit leaves each other value as it was.

/**
 * @typedef {object} Pair
 * @property {string} key
 * @property {string} value the text the form shows and edits
 * @property {string} [read] the JSON of the value read from a document
 */

/**
 * Flattens a document into key-value pairs. A non-empty object or array adds
 * one pair per member or element.
 * @param {Record<string, any>} obj
 * @param {string} prefix
 * @returns {Pair[]}
 */
export function flattenObject(obj, prefix) {
    const entries = [];
    for (const [k, v] of Object.entries(obj)) {
        const name = k.replace(/[\\[\].]/g, "\\$&");
        flattenValue(entries, prefix ? prefix + "." + name : name, v);
    }
    return entries;
}

/**
 * @param {Pair[]} entries
 * @param {string} key
 * @param {any} v
 */
function flattenValue(entries, key, v) {
    if (Array.isArray(v) && v.length > 0) {
        v.forEach((element, i) => flattenValue(entries, key + "[" + i + "]", element));
    } else if (v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length > 0) {
        entries.push(...flattenObject(v, key));
    } else {
        entries.push({ key, value: pairText(v), read: JSON.stringify(v) });
    }
}

/**
 * The text a pair shows for a value: an empty field for null and for an empty
 * object or array.
 * @param {any} v
 * @returns {string}
 */
function pairText(v) {
    return v === null || typeof v === "object" ? "" : String(v);
}

/**
 * The value a pair holds: the value it read while its text is unedited.
 * @param {Pair} pair
 * @returns {any}
 */
function pairValue(pair) {
    if (pair.read === undefined) {
        return pair.value;
    }
    const read = JSON.parse(pair.read);
    return pair.value === pairText(read) ? read : pair.value;
}

/**
 * Splits a key at each dot no backslash keeps literal.
 * @param {string} key
 * @returns {string[]}
 */
export function keySegments(key) {
    const segments = [""];
    for (let i = 0; i < key.length; i++) {
        if (key[i] === ".") {
            segments.push("");
            continue;
        }
        const length = key[i] === "\\" ? 2 : 1;
        segments[segments.length - 1] += key.slice(i, i + length);
        i += length - 1;
    }
    return segments;
}

/**
 * Rebuilds a document from key-value pairs. An index segment makes an
 * array, and an element no pair names is null. The objects built have no
 * prototype, so a member named __proto__ is a member.
 * @param {Pair[]} entries
 * @returns {Record<string, any>}
 */
export function unflattenEntries(entries) {
    /** @type {Record<string, any>} */
    const result = Object.create(null);
    for (const pair of entries) {
        const parts = keySegments(pair.key).flatMap(splitIndices);
        /** @type {any} */
        let cur = result;
        for (let i = 0; i < parts.length - 1; i++) {
            const isArray = typeof parts[i + 1] === "number";
            const next = cur[parts[i]];
            if (next === null || typeof next !== "object" || Array.isArray(next) !== isArray) {
                cur[parts[i]] = isArray ? [] : Object.create(null);
            }
            cur = cur[parts[i]];
        }
        cur[parts[parts.length - 1]] = pairValue(pair);
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
 * Returns v with null in each array element no pair names, and with plain
 * objects.
 * @param {any} v
 * @returns {any}
 */
function fillHoles(v) {
    if (Array.isArray(v)) {
        return Array.from(v, element => fillHoles(element));
    }
    if (v && typeof v === "object") {
        return Object.fromEntries(Object.entries(v).map(([k, member]) => [k, fillHoles(member)]));
    }
    return v === undefined ? null : v;
}
