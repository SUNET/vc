// Unit tests for the verifier preset grouping helpers. Runs under Node's
// built-in test runner (`node --test`) — no extra dependencies. Pure logic
// only; the Alpine component in presentation-definition.js delegates here.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { dcqlCredentialFromPreset, groupPresets, byOrderThenLabel, OTHER_CATEGORY } from "../preset-helpers.js";

/** @param {string} label @param {object} extra */
const preset = (label, extra = {}) => [label, { label, ...extra }];

const labels = (/** @type {any[]} */ entries) => entries.map((e) => e[0]);

describe("groupPresets", () => {
    it("keeps a metadata-free config as one flat list", () => {
        const entries = [preset("B"), preset("A")];
        const got = groupPresets(entries, undefined);
        assert.deepEqual(got.groups, []);
        assert.deepEqual(labels(got.featured), ["A", "B"]);
    });

    it("sorts by order, not by map key", () => {
        // The server keys presets by label and JSON serializes keys
        // alphabetically, so order is only honoured if the client applies it.
        const entries = [
            preset("Alpha", { category: "C", order: 3 }),
            preset("Beta", { category: "C", order: 1 }),
            preset("Gamma", { category: "C", order: 2 }),
        ];
        const got = groupPresets(entries, ["C"]);
        assert.deepEqual(labels(got.groups[0].presets), ["Beta", "Gamma", "Alpha"]);
    });

    it("breaks order ties alphabetically by label", () => {
        const entries = [
            preset("Zulu", { category: "C" }),
            preset("Alpha", { category: "C" }),
            preset("Mike", { category: "C", order: 0 }),
        ];
        const got = groupPresets(entries, ["C"]);
        assert.deepEqual(labels(got.groups[0].presets), ["Alpha", "Mike", "Zulu"]);
    });

    it("sorts featured presets too", () => {
        const entries = [
            preset("Second", { featured: true, order: 2 }),
            preset("First", { featured: true, order: 1 }),
        ];
        const got = groupPresets(entries, []);
        assert.deepEqual(labels(got.featured), ["First", "Second"]);
    });

    it("honours the server's category order", () => {
        const entries = [
            preset("a", { category: "Late" }),
            preset("b", { category: "Early" }),
        ];
        const got = groupPresets(entries, ["Early", "Late"]);
        assert.deepEqual(got.groups.map((g) => g.category), ["Early", "Late"]);
    });

    // The two regressions Copilot caught: an incomplete category order must
    // not make presets vanish, and an absent one must not throw.
    it("renders a category the server did not list", () => {
        const entries = [
            preset("a", { category: "Listed" }),
            preset("b", { category: "Missing" }),
        ];
        const got = groupPresets(entries, ["Listed"]);
        assert.deepEqual(got.groups.map((g) => g.category), ["Listed", "Missing"]);
        assert.deepEqual(labels(got.groups[1].presets), ["b"]);
    });

    it("survives an absent category order for a featured-only config", () => {
        // preset_category_order is omitempty, so a config with featured but
        // uncategorized presets omits it entirely while still taking the
        // grouping path.
        const entries = [preset("Feat", { featured: true }), preset("Plain")];
        const got = groupPresets(entries, undefined);
        assert.deepEqual(labels(got.featured), ["Feat"]);
        assert.deepEqual(got.groups.map((g) => g.category), [OTHER_CATEGORY]);
        assert.deepEqual(labels(got.groups[0].presets), ["Plain"]);
    });

    it("puts the uncategorized catch-all last", () => {
        const entries = [
            preset("plain", {}),
            preset("sorted", { category: "Named" }),
            preset("feat", { featured: true }),
        ];
        const got = groupPresets(entries, ["Named"]);
        assert.deepEqual(got.groups.map((g) => g.category), ["Named", OTHER_CATEGORY]);
    });

    // An operator may name a category "Other presets" explicitly. It can then
    // appear in preset_category_order AND be appended as the catch-all, which
    // rendered the same presets twice.
    it("renders an explicitly-named Other presets category only once", () => {
        const entries = [
            preset("named", { category: OTHER_CATEGORY }),
            preset("uncategorized", {}),
            preset("feat", { featured: true }),
        ];
        const got = groupPresets(entries, [OTHER_CATEGORY]);
        const headings = got.groups.map((g) => g.category);
        assert.deepEqual(headings, [OTHER_CATEGORY], "the catch-all must appear exactly once");
        assert.deepEqual(labels(got.groups[0].presets), ["named", "uncategorized"]);
    });

    // The defect this flag exists for: gdc categorises both of its ZK
    // presets and features neither, so featured was empty, every preset
    // went into a group, and the groups started collapsed - a heading, an
    // empty button list and a "Show more presets" link. Every preset was
    // one click away and none was visible.
    it("does not collapse the groups when nothing is featured", () => {
        const entries = [
            preset("PID (mdoc) - ZK Proof (Vega)", { category: "ZK Proofs" }),
            preset("Age Over 18 - ZK Proof (Vega)", { category: "ZK Proofs" }),
        ];
        const got = groupPresets(entries, ["ZK Proofs"]);

        assert.deepEqual(got.featured, [], "this test only means anything with nothing featured");
        assert.equal(got.groups.length, 1, "the presets still group by category");
        assert.equal(
            got.collapsible,
            false,
            "with nothing to hide them behind, the groups must render at rest",
        );
    });

    it("collapses the groups once something is featured", () => {
        const entries = [
            preset("everyday", { featured: true }),
            preset("niche", { category: "ZK Proofs" }),
        ];
        const got = groupPresets(entries, ["ZK Proofs"]);

        assert.deepEqual(labels(got.featured), ["everyday"]);
        assert.equal(got.collapsible, true, "the toggle hides the groups behind the featured ones");
    });

    // The flat path has no groups to collapse, so the flag says so rather
    // than leaving the template to infer it from an empty array.
    it("reports a flat preset list as not collapsible", () => {
        const got = groupPresets([preset("a"), preset("b")], []);
        assert.equal(got.groups.length, 0);
        assert.equal(got.collapsible, false);
    });

    it("does not mutate its input", () => {
        const entries = [preset("B", { order: 2 }), preset("A", { order: 1 })];
        const snapshot = labels(entries);
        groupPresets(entries, []);
        assert.deepEqual(labels(entries), snapshot);
    });
});

describe("byOrderThenLabel", () => {
    it("treats a missing order as 0", () => {
        assert.ok(byOrderThenLabel(preset("x"), preset("y", { order: 1 })) < 0);
        assert.ok(byOrderThenLabel(preset("x", { order: -1 }), preset("y")) < 0);
    });
});

describe("dcqlCredentialFromPreset", () => {
    // The metadata endpoint serves `req`; the posted DCQL query names the
    // same list `_req`. The picker built the query with `req`, which
    // pkg/openid4vp refuses as req_missing_or_empty - and a zkp_req query
    // with no list discloses nothing either, so the wallet had nothing to
    // return and the failure read as a wallet that declined.
    it("renames the preset's req to the query's _req", () => {
        const c = dcqlCredentialFromPreset({
            id: "nym_attestation",
            format: "zkp_req",
            meta: { source_format: "mso_mdoc", doctype_value: "eu.europa.ec.eudi.nym_auth.1" },
            req: [{ fn_id: "pseudonym", return: "nym-123", params: { config: "c", ver: 1, prf: "sha-256" } }],
        });
        assert.deepEqual(c._req, [
            { fn_id: "pseudonym", return: "nym-123", params: { config: "c", ver: 1, prf: "sha-256" } },
        ]);
        assert.equal("req" in c, false, "the pre-v0.4 member name must not be posted");
    });

    // The member is the SAME ARRAY, not a copy. A params value is an input
    // to a proof: rebuilding it is how a member added later gets dropped.
    it("passes the list through rather than rebuilding it", () => {
        const req = [{ fn_id: "age_check", return: "a", params: { ge: "2008-10-10" } }];
        const c = dcqlCredentialFromPreset({ id: "q", format: "zkp_req", meta: {}, req });
        assert.equal(c._req, req);
    });

    // A preset for any other format carries no req, and must not grow one.
    it("adds no _req to a credential that has none", () => {
        const c = dcqlCredentialFromPreset({
            id: "pid", format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:arf-1.8:1"] },
            claims: [{ path: ["given_name"] }],
        });
        assert.equal("_req" in c, false);
        assert.equal("req" in c, false);
        assert.deepEqual(c.claims, [{ path: ["given_name"] }]);
    });

    // UI-only members stay server-side: validations never belong in a DCQL
    // query, and label/category are the picker's business.
    it("carries only the DCQL members", () => {
        const c = dcqlCredentialFromPreset({
            id: "q", format: "zkp_req", meta: {},
            req: [{ fn_id: "pseudonym", return: "n" }],
            validations: [{ rule: "eq", path: ["a"], value: 1 }],
            label: "a label",
        });
        assert.deepEqual(Object.keys(c).sort(), ["_req", "format", "id", "meta"]);
    });
});
