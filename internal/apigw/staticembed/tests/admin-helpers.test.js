// Unit tests for the admin document form helpers. Runs under Node's
// built-in test runner (`node --test`, see the Makefile's test-js target).

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { flattenObject, unflattenEntries } from "../admin-helpers.js";

// The form holds string values, so a document of strings in objects and
// non-empty arrays comes back from its key-value pairs unchanged.
describe("unflattenEntries(flattenObject(document))", () => {
    const documents = {
        "objects": { given_name: "Erika", address: { locality: "Stockholm", country: "SE" } },
        "an array of strings": { nationalities: ["SE", "FI"] },
        "an array of objects": { degrees: [{ type: "BSc", university: "KTH" }, { type: "MSc" }] },
        "nested arrays": { matrix: [["a", "b"], ["c"]] },
        "an indexed claim template": { elm: { credentialSubject: { hasClaim: [{ title: "" }] } } },
    };
    for (const [name, document] of Object.entries(documents)) {
        it(`returns ${name}`, () => {
            assert.deepEqual(unflattenEntries(flattenObject(document, "")), document);
        });
    }
});
