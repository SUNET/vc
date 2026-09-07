// Unit tests for the verifier preset grouping helpers. Runs under Node's
// built-in test runner (`node --test`) — no extra dependencies. Pure logic
// only; the Alpine component in presentation-definition.js delegates here.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { groupPresets, byOrderThenLabel, OTHER_CATEGORY } from "../preset-helpers.js";

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
