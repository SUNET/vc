// Unit tests for the circuit_zk `req` schema. Runs under Node's built-in
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
    id: "pseudonym-v1-sha256",
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
            ["extension", "id", "params", "return", "toString"],
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
            [{ return: "h" }],                       // no id
            [{ id: "f" }],                           // no return
            [{ id: 7, return: "h" }],                // id not a string
            [{ id: "f", return: 7 }],                // return not a string
            [{ id: "f", return: "h", params: [] }],  // params not an object
            [{ id: "f", return: "h", params: "x" }],
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
            [{ id: "f", return: "h" }],
            [{ id: "f", return: "h", params: {} }],
            [{ id: "pseudonym-v1-sha256", return: "n", params: { config: "c" } },
             { id: "age_check", return: "a", params: { ge: "2008-10-10" } }],
        ]) {
            assert.equal(
                v.safeParse(reqSchema, good).success,
                true,
                `must accept ${JSON.stringify(good)}`,
            );
        }
    });
});
