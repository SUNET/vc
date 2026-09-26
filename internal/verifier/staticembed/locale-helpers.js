// Locale selection for the credential picker. Pure logic, extracted so it can
// be unit tested under `node --test`, matching the preset-helpers.js pattern.

/** The locale the shipped VCTMs and MDDLs populate. */
export const DEFAULT_LOCALE = "en-US";

/**
 * Returns the claim map to offer for a credential, preferring DEFAULT_LOCALE.
 *
 * A VCTM or MDDL may carry claims only under another locale, in which case
 * reading DEFAULT_LOCALE alone yields nothing and the request goes out with no
 * claim paths - disclosing less than the user selected, silently. Any other
 * English variant is preferred next, then the first locale by name so the
 * choice is deterministic.
 *
 * @param {Record<string, Record<string, (string|null)[]>> | undefined} attributes
 * @returns {Record<string, (string|null)[]>}
 */
export function claimsForLocale(attributes) {
    if (!attributes) return {};

    // Non-empty, not merely present: {} is truthy, so a metadata document
    // carrying an empty DEFAULT_LOCALE bucket alongside a populated one would
    // otherwise return the empty one and send no claim paths at all.
    const populated = (locale) => Object.keys(attributes[locale] ?? {}).length > 0;
    if (populated(DEFAULT_LOCALE)) return attributes[DEFAULT_LOCALE];

    const locales = Object.keys(attributes)
        .filter(populated)
        // Collation pinned to "en": the default is the runtime's locale, so
        // an unpinned localeCompare could order the same metadata differently
        // in different browsers and pick a different bucket. SonarCloud wants
        // localeCompare over the raw default sort; this satisfies both.
        .sort((a, b) => a.localeCompare(b, "en"));
    const english = locales.find((l) => l.startsWith("en"));
    return attributes[english ?? locales[0]] ?? {};
}
