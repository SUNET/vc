// Builds the DCQL `meta` constraint for a selected credential. Pure logic,
// extracted so it can be unit tested under `node --test` without a DOM or
// Alpine, matching the preset-helpers.js pattern.

/** @typedef {{ format?: string, vct?: string, vct_values?: string[], type_values?: string[][] }} CredentialAttributes */

/** W3C VC format identifiers, constrained by type_values rather than vct_values. */
const W3C_FORMATS = ["ldp_vc", "vc+ld+json", "jwt_vc_json"];

/**
 * SD-JWT VC format identifiers, constrained by vct_values. Enumerated rather
 * than used as a default: treating every unrecognised format as SD-JWT sent
 * vct_values for a W3C identifier this repo cannot request by, such as
 * jwt_vc_json-ld, which the issuer metadata advertises but nothing issues.
 * "" honours the server's own default of dc+sd-jwt.
 */
const SD_JWT_FORMATS = ["dc+sd-jwt", "vc+sd-jwt", ""];

/** The expanded type every W3C VC carries; an alternative naming only it matches all of them. */
const BASE_VC_TYPE_IRI = "https://www.w3.org/2018/credentials#VerifiableCredential";

/**
 * Drops type_values alternatives that would not narrow the request, mirroring
 * CredentialMetadata.w3cTypeValues on the server.
 *
 * MatchTypeValues returns true for an alternative every credential satisfies,
 * and one true alternative answers the whole constraint - so an empty or
 * base-only alternative alongside a real one makes the real one moot. Neither
 * should ever reach the UI, but malformed metadata must not become a request
 * for every W3C credential in the wallet.
 *
 * @param {string[][]} typeValues
 */
function narrowingAlternatives(typeValues) {
    return typeValues.filter((alternative) =>
        alternative.some((t) => t !== "" && t !== BASE_VC_TYPE_IRI));
}

/**
 * Three formats, three constraints (OpenID4VP 1.0 6.4.1). Returns either the
 * meta object or the reason the credential cannot be requested.
 *
 * mdoc uses doctype_value: no mdoc credential carries a vct, so vct_values
 * would match nothing on the wallet side and the request would always come
 * back empty.
 *
 * SD-JWT uses vct_values, carrying EVERY identifier a wallet might match this
 * type by: the EUDI reference wallet (multipaz) matches the issuer metadata's
 * declared vct (our type-metadata URL), while others (wwWallet) match the
 * credential's own embedded vct claim. DCQL reads vct_values as an
 * acceptable-value list, so sending both satisfies either wallet. It falls
 * back to the single vct for an older server that sends no list.
 *
 * W3C uses type_values, the fully expanded IRIs the server publishes for a
 * scope that configures credential_type_values. There is no fallback: DCQL
 * reads an empty type_values as no constraint at all, and MatchTypeValues
 * reads an empty or base-only alternative the same way, so anything that does
 * not narrow is refused rather than sent - see narrowingAlternatives.
 *
 * @param {CredentialAttributes} attrs
 * @returns {{ meta: object, error?: undefined } | { meta?: undefined, error: string }}
 */
export function dcqlMetaFor(attrs) {
    // Every branch refuses an empty constraint rather than sending one: DCQL
    // reads an empty doctype_value, vct_values or type_values as no constraint
    // at all, so the request would match every credential of that format.
    if (attrs.format === "mso_mdoc") {
        if (!attrs.vct) {
            return { error: "Selected credential has no doctype to request by" };
        }
        return { meta: { doctype_value: attrs.vct } };
    }

    if (W3C_FORMATS.includes(attrs.format ?? "")) {
        const typeValues = narrowingAlternatives(attrs.type_values ?? []);
        if (!typeValues.length) {
            return { error: "Selected credential has no type values to request by" };
        }
        return { meta: { type_values: typeValues } };
    }

    if (!SD_JWT_FORMATS.includes(attrs.format ?? "")) {
        return { error: `Selected credential has an unsupported format: ${attrs.format}` };
    }
    const vctValues = (attrs.vct_values?.length ? attrs.vct_values : [attrs.vct])
        .filter((v) => v);
    if (!vctValues.length) {
        return { error: "Selected credential has no vct to request by" };
    }
    return { meta: { vct_values: vctValues } };
}
