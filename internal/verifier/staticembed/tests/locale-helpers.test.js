// Unit tests for the picker's locale selection. Runs under `node --test`.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { claimsForLocale, DEFAULT_LOCALE } from "../locale-helpers.js";

const claims = (label) => ({ [label]: ["given_name"] });

describe("claimsForLocale", () => {
    it("prefers en-US when present", () => {
        const got = claimsForLocale({ "sv-SE": claims("Förnamn"), [DEFAULT_LOCALE]: claims("First name") });
        assert.deepEqual(got, claims("First name"));
    });

    it("falls back to another locale rather than sending no claims", () => {
        // The reason this exists: reading en-US alone here yielded {}, and the
        // request went out with no claim paths at all.
        const got = claimsForLocale({ "sv-SE": claims("Förnamn") });
        assert.deepEqual(got, claims("Förnamn"));
    });

    it("prefers another English variant over an unrelated locale", () => {
        const got = claimsForLocale({ "sv-SE": claims("Förnamn"), "en-GB": claims("First name") });
        assert.deepEqual(got, claims("First name"));
    });

    it("is deterministic when several unrelated locales are present", () => {
        const attrs = { "sv-SE": claims("Förnamn"), "de-DE": claims("Vorname") };
        assert.deepEqual(claimsForLocale(attrs), claims("Vorname"));
        assert.deepEqual(claimsForLocale(attrs), claimsForLocale({ ...attrs }));
    });

    it("skips an empty default bucket for a populated one", () => {
        // {} is truthy, so a presence check returned the empty en-US bucket
        // and the request went out with no claim paths.
        const got = claimsForLocale({ [DEFAULT_LOCALE]: {}, "sv-SE": claims("Förnamn") });
        assert.deepEqual(got, claims("Förnamn"));
    });

    it("skips empty non-default buckets too", () => {
        const got = claimsForLocale({ "de-DE": {}, "sv-SE": claims("Förnamn") });
        assert.deepEqual(got, claims("Förnamn"));
    });

    it("returns an empty map for absent or empty attributes", () => {
        assert.deepEqual(claimsForLocale(undefined), {});
        assert.deepEqual(claimsForLocale({}), {});
        assert.deepEqual(claimsForLocale({ [DEFAULT_LOCALE]: {} }), {});
    });
});
