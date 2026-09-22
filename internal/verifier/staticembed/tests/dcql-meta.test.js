// Unit tests for the DCQL meta constraint builder. Runs under Node's built-in
// test runner (`node --test`) — no extra dependencies.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { dcqlMetaFor } from "../dcql-meta.js";

// Matches baseVCTypeIRI in pkg/model/config.go.
const BASE = "https://www.w3.org/2018/credentials#VerifiableCredential";

const diplomaTypes = [[
    BASE,
    "https://example.org/diploma#DiplomaCredential",
]];

describe("dcqlMetaFor", () => {
    it("constrains an mdoc by its doctype, never by vct_values", () => {
        const { meta } = dcqlMetaFor({ format: "mso_mdoc", vct: "org.iso.18013.5.1.mDL" });
        assert.deepEqual(meta, { doctype_value: "org.iso.18013.5.1.mDL" });
    });

    it("sends every SD-JWT identifier, not just one", () => {
        // multipaz matches the issuer metadata's declared vct, wwWallet the
        // credential's embedded one; vct_values is an acceptable-value list.
        const { meta } = dcqlMetaFor({
            format: "dc+sd-jwt",
            vct: "urn:eudi:pid:1",
            vct_values: ["urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"],
        });
        assert.deepEqual(meta, {
            vct_values: ["urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"],
        });
    });

    it("falls back to the single vct for a server that sends no list", () => {
        const { meta } = dcqlMetaFor({ format: "dc+sd-jwt", vct: "urn:eudi:pid:1" });
        assert.deepEqual(meta, { vct_values: ["urn:eudi:pid:1"] });
    });

    for (const format of ["ldp_vc", "vc+ld+json", "jwt_vc_json"]) {
        it(`constrains ${format} by type_values`, () => {
            const { meta } = dcqlMetaFor({ format, type_values: diplomaTypes });
            assert.deepEqual(meta, { type_values: diplomaTypes });
        });

        it(`refuses ${format} with nothing that narrows the request`, () => {
            // Each of these matches every W3C credential in the wallet: DCQL
            // reads an empty type_values as no constraint, and MatchTypeValues
            // reads an empty or base-only alternative the same way.
            const unconstrained = [
                { format },
                { format, type_values: [] },
                { format, type_values: [[]] },
                { format, type_values: [[BASE]] },
                { format, type_values: [[""]] },
            ];
            for (const attrs of unconstrained) {
                const { meta, error } = dcqlMetaFor(attrs);
                assert.equal(meta, undefined, `${JSON.stringify(attrs.type_values)} must not be sent`);
                assert.match(error, /no type values/);
            }
        });

        it(`drops a non-narrowing ${format} alternative beside a real one`, () => {
            // One true alternative answers the whole constraint, so keeping the
            // empty one would make the real one moot.
            const { meta } = dcqlMetaFor({
                format,
                type_values: [diplomaTypes[0], [], [BASE]],
            });
            assert.deepEqual(meta, { type_values: diplomaTypes });
        });
    }
});

describe("dcqlMetaFor refuses an empty constraint in every format", () => {
    // DCQL reads an empty doctype_value or vct_values the same way it reads an
    // empty type_values: as no constraint, matching every credential.
    it("refuses an mdoc with no doctype", () => {
        for (const attrs of [{ format: "mso_mdoc" }, { format: "mso_mdoc", vct: "" }]) {
            const { meta, error } = dcqlMetaFor(attrs);
            assert.equal(meta, undefined);
            assert.match(error, /no doctype/);
        }
    });

    it("refuses an SD-JWT with no vct", () => {
        for (const attrs of [{ format: "dc+sd-jwt" }, { format: "dc+sd-jwt", vct: "", vct_values: [] }]) {
            const { meta, error } = dcqlMetaFor(attrs);
            assert.equal(meta, undefined);
            assert.match(error, /no vct/);
        }
    });
});
