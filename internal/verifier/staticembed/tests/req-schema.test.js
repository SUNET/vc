// Unit tests for the circuit_zk `req` schema. Runs under Node's built-in
// test runner (`node --test`).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
            // The pre-v0.4 spelling. ReqItem is `fn_id` on the wire and
            // the shared vectors agree, so an item naming the function
            // `id` is one no server sends and no wallet reads.
            [{ id: "f", return: "h" }],
        ]) {
            assert.equal(
                v.safeParse(reqSchema, bad).success,
                false,
                `must refuse ${JSON.stringify(bad)}`,
            );
        }
    });

    // The schema's idea of an item and the server's must be the SAME idea,
    // and this file used to hold its own: every fixture above named the
    // function `id`, so the schema and its tests agreed with each other and
    // both disagreed with ReqItem. The preset list then failed to parse,
    // which reads as a server that sent nothing.
    //
    // Read out of the vendored conformance vector rather than retyped, so
    // the two cannot drift apart again.
    it("accepts the _req of the normative shared vector, as the server sends it", () => {
        const vector = JSON.parse(
            readFileSync(
                new URL("../../../../pkg/openid4vp/testdata/zkp_req/zkp_req/ok_normative_plain.json", import.meta.url),
                "utf8",
            ),
        );
        const items = vector.query._req;
        assert.ok(Array.isArray(items) && items.length > 0, "the vector must carry a _req");
        assert.equal(v.safeParse(reqSchema, items).success, true);

        // And the same items under the obsolete name are refused, so this
        // is a check on the member name and not just on the vector parsing.
        const renamed = items.map((/** @type {any} */ item) => {
            const { fn_id, ...rest } = item;
            return { id: fn_id, ...rest };
        });
        assert.equal(v.safeParse(reqSchema, renamed).success, false);
    });

    it("accepts the shapes a conforming request actually takes", () => {
        for (const good of [
            [],
            [{ fn_id: "f", return: "h" }],
            [{ fn_id: "f", return: "h", params: {} }],
            [{ fn_id: "pseudonym", return: "n", params: { config: "c" } },
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
