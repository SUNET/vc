// Unit tests for the admin document form helpers. Runs under Node's
// built-in test runner (`node --test`, see the Makefile's test-js target).

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { flattenObject, unflattenEntries } from "../admin-helpers.js";

// A document comes back from its key-value pairs unchanged while no pair is
// edited.
describe("unflattenEntries(flattenObject(document))", () => {
    const documents = {
        "objects": { given_name: "Erika", address: { locality: "Stockholm", country: "SE" } },
        "an array of strings": { nationalities: ["SE", "FI"] },
        "an array of objects": { degrees: [{ type: "BSc", university: "KTH" }, { type: "MSc" }] },
        "nested arrays": { matrix: [["a", "b"], ["c"]] },
        "an indexed claim template": { elm: { credentialSubject: { hasClaim: [{ title: "" }] } } },
        "the member name of vctm_elm.json": { elm: { credentialSubject: { "hasClaim[0]": { title: "" } } } },
        "an array under a member name with brackets": { "m[1]": ["a", "b"] },
        "member names with a backslash": { "a\\": { b: "" }, "c\\[0]": "" },
        "member names with dots": { "eu.europa.ec.eudi.pid.1.family_name": "a", b: { "c.d[0]": "e", "f\\.g": "h" } },
        "empty objects and arrays": { a: {}, b: [], c: [{}, [], { d: {} }, "e", {}] },
        "typed values": { number: 1, truth: true, nothing: null, list: [2.5, false, null, ""] },
        "a member named __proto__": JSON.parse('{"__proto__": {"x": "1"}, "k": "v"}'),
    };
    for (const [name, document] of Object.entries(documents)) {
        it(`returns ${name}`, () => {
            assert.deepEqual(unflattenEntries(flattenObject(document, "")), document);
        });
    }

    it("leaves Object.prototype alone", () => {
        unflattenEntries(flattenObject(documents["a member named __proto__"], ""));
        assert.equal(/** @type {any} */ ({}).x, undefined);
    });

    it("returns the text of an edited pair, and each other value as read", () => {
        const pairs = flattenObject({ age: 30, empty: {}, gap: null, keep: 7 }, "");
        for (const pair of pairs.filter(pair => pair.key !== "keep")) {
            pair.value = "typed";
        }
        assert.deepEqual(unflattenEntries(pairs), { age: "typed", empty: "typed", gap: "typed", keep: 7 });
    });

    it("returns the text of a pair the form added", () => {
        assert.deepEqual(unflattenEntries([{ key: "a.b", value: "typed" }]), { a: { b: "typed" } });
    });
});
