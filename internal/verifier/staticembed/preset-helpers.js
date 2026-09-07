// Preset grouping helpers for the demo verifier UI. Pure logic, extracted so
// it can be unit tested under `node --test` without a DOM or Alpine, matching
// the apigw consent-helpers.js pattern.

/** @typedef {{ label?: string, category?: string, order?: number, featured?: boolean }} PresetLike */
/** @typedef {[string, PresetLike]} PresetEntry */

/** Heading for presets that carry no category of their own. */
export const OTHER_CATEGORY = "Other presets";

/**
 * A preset's display name. The backend keys presets by label and repeats it in
 * the payload, so either source works; the key is the fallback for a payload
 * that predates the label field.
 * @param {PresetEntry} entry
 */
function labelOf(entry) {
    return entry[1].label ?? entry[0];
}

/**
 * Ascending by order, ties broken alphabetically by label.
 *
 * This is the contract UIPreset.Order documents ("ties, including the default
 * 0, broken alphabetically by Label client-side") - the server deliberately
 * does not pre-sort, because JSON object keys serialize alphabetically and
 * would discard any order it applied.
 * @param {PresetEntry} a
 * @param {PresetEntry} b
 */
export function byOrderThenLabel(a, b) {
    const ao = a[1].order ?? 0;
    const bo = b[1].order ?? 0;
    if (ao !== bo) return ao - bo;
    return labelOf(a).localeCompare(labelOf(b));
}

/**
 * Groups presets for progressive rendering: featured presets are shown
 * immediately, the rest are grouped by category behind a "show more" toggle.
 *
 * Falls back to one flat featured list when no preset carries category or
 * featured metadata, preserving the old flat-grid behavior for a simple
 * config.
 *
 * @param {PresetEntry[]} entries
 * @param {string[] | null | undefined} categoryOrder server-supplied category
 *   display order; absent when no preset is categorized, so it is not assumed
 *   to be present or complete.
 * @returns {{ featured: PresetEntry[], groups: { category: string, presets: PresetEntry[] }[] }}
 */
export function groupPresets(entries, categoryOrder) {
    const anyMetadata = entries.some(([, p]) => p.featured || p.category);
    if (!anyMetadata) {
        return { featured: [...entries].sort(byOrderThenLabel), groups: [] };
    }

    const featured = entries.filter(([, p]) => p.featured).sort(byOrderThenLabel);
    const rest = entries.filter(([, p]) => !p.featured);

    /** @type {Map<string, PresetEntry[]>} */
    const byCategory = new Map();
    for (const entry of rest) {
        const category = entry[1].category || OTHER_CATEGORY;
        if (!byCategory.has(category)) byCategory.set(category, []);
        byCategory.get(category)?.push(entry);
    }

    // Only the categories the server actually listed, in its order.
    const ordered = (categoryOrder ?? []).filter((category) => byCategory.has(category));

    // Anything the server did not list still has to render. preset_category_order
    // omits a category whose only presets are featured, and an operator or an
    // older server can leave it incomplete - dropping the group silently would
    // make presets disappear from the UI with nothing in the config looking
    // wrong. Append the leftovers alphabetically instead.
    const listed = new Set(ordered);
    const unlisted = [...byCategory.keys()]
        .filter((category) => category !== OTHER_CATEGORY && !listed.has(category))
        // localeCompare, matching how labels are ordered - a category name is
        // operator-supplied text, so a default UTF-16 sort would put a
        // non-ASCII heading somewhere a reader would not look for it.
        .sort((a, b) => a.localeCompare(b));

    const groups = [...ordered, ...unlisted];
    // The uncategorized catch-all always renders last, under its own heading.
    if (byCategory.has(OTHER_CATEGORY)) groups.push(OTHER_CATEGORY);

    return {
        featured,
        groups: groups.map((category) => ({
            category,
            presets: (byCategory.get(category) ?? []).slice().sort(byOrderThenLabel),
        })),
    };
}
