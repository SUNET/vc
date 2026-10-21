// Unit tests for the zkp_req `req` schema. Runs under Node's built-in
// test runner (`node --test`).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as v from "valibot";

import { reqSchema } from "../req-schema.js";

// The names Valibot's object schemas drop. v.record excludes the
// prototype-polluting keys from its output, and v.looseObject collects an
// item's extras but not one named like an inherited member - so the
// earlier schema validated these and then silently removed them. A req
// param is an input to a proof: a dropped one is a different pseudonym,
// computed from a request nobody wrote.
const req = [{
    fn_id: "pseudonym",
    return: "nym-1",
    params: {
        config: "known-offender-matching-ssc",
        constructor: "dropped-by-record",
        prototype: "dropped-by-record",
        valueOf: "also-a-prototype-name",
        ordinary: 1,
    },
    toString: "dropped-by-looseObject",
    extension: "kept-either-way",
}];

describe("reqSchema", () => {
    it("keeps every parameter, including the ones Valibot's record drops", () => {
        const result = v.safeParse(reqSchema, req);
        assert.equal(result.success, true);
        assert.deepEqual(
            Object.keys(result.output[0].params).sort(),
            ["config", "constructor", "ordinary", "prototype", "valueOf"],
        );
        assert.equal(result.output[0].params.constructor, "dropped-by-record");
        assert.equal(result.output[0].params.prototype, "dropped-by-record");
    });

    it("keeps item extensions, including ones named like inherited members", () => {
        const result = v.safeParse(reqSchema, req);
        assert.equal(result.success, true);
        assert.deepEqual(
            Object.keys(result.output[0]).sort(),
            ["extension", "fn_id", "params", "return", "toString"],
        );
    });

    // The strongest form of "nothing was rebuilt": the value that comes
    // back IS the value that went in. A schema that reconstructed an
    // equal object would pass the key assertions above and still be the
    // defect, because the next member added to a request would be lost.
    it("hands back the original value rather than a copy", () => {
        const result = v.safeParse(reqSchema, req);
        assert.equal(result.success, true);
        assert.equal(result.output, req);
        assert.equal(result.output[0].params, req[0].params);
    });

    // Validating without rebuilding must not become validating nothing.
    it("still refuses a req that is not an array of well-formed items", () => {
        for (const bad of [
            "not-an-array",
            {},
            [null],
            ["a string item"],
            [{ return: "h" }],                          // no fn_id
            [{ fn_id: "f" }],                           // no return
            [{ fn_id: 7, return: "h" }],                // fn_id not a string
            [{ fn_id: "f", return: 7 }],                // return not a string
            [{ fn_id: "f", return: "h", params: [] }],  // params not an object
            [{ fn_id: "f", return: "h", params: "x" }],
            [{ id: "f", return: "h" }],                 // the pre-v0.4 key
        ]) {
            assert.equal(
                v.safeParse(reqSchema, bad).success,
                false,
                `must refuse ${JSON.stringify(bad)}`,
            );
        }
    });

    it("accepts the shapes a conforming request actually takes", () => {
        for (const good of [
            [],
            [{ fn_id: "f", return: "h" }],
            [{ fn_id: "f", return: "h", params: {} }],
            [{ fn_id: "pseudonym", return: "n", params: { config: "c", ver: 1, prf: "sha-256" } },
             { fn_id: "age_check", return: "a", params: { ge: "2008-10-10" } }],
        ]) {
            assert.equal(
                v.safeParse(reqSchema, good).success,
                true,
                `must accept ${JSON.stringify(good)}`,
            );
        }
    });
});

// The item key moved from `id` to `fn_id` in rulebook v0.4, and this
// fixture was not moved with it - which is the only reason the schema
// kept passing while it validated a shape the server had stopped
// publishing. The live operator UI then threw on /ui/metadata and never
// left its spinner.
//
// Both directions are pinned, because either one alone goes stale the
// same way: the published shape is accepted, and the shape it replaced
// is refused rather than quietly tolerated.
describe("reqSchema and the v0.4 item key", () => {
    const item = { return: "nym", params: { config: "known-offender-matching-ssc" } };

    it("accepts the fn_id the server publishes", () => {
        const result = v.safeParse(reqSchema, [{ fn_id: "pseudonym", ...item }]);
        assert.equal(result.success, true);
    });

    it("refuses the pre-v0.4 id", () => {
        const result = v.safeParse(reqSchema, [{ id: "pseudonym", ...item }]);
        assert.equal(result.success, false);
        assert.match(result.issues[0].message, /fn_id/);
    });
});
