// Unit tests for the consent-page helpers. Runs under Node's built-in test
// runner (`node --test`) — no extra dependencies. Covers pure logic only;
// DOM/Alpine code in consent.js is not exercised here.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
    base64ToUtf8,
    detectBase64Image,
    escapeHtml,
    keyToLabel,
    renderClaimValueHtml,
    SAFE_IMAGE_SUBTYPES,
    utf8ToBase64,
} from "../consent-helpers.js";

describe("keyToLabel", () => {
    it("capitalizes and spaces a snake_case key", () => {
        assert.equal(keyToLabel("first_name"), "First name");
        assert.equal(keyToLabel("personal_administrative_number"), "Personal administrative number");
    });

    it("passes single-word keys through unchanged", () => {
        assert.equal(keyToLabel("given"), "given");
        assert.equal(keyToLabel("picture"), "picture");
    });

    it("handles empty string", () => {
        assert.equal(keyToLabel(""), "");
    });
});

describe("escapeHtml", () => {
    it("escapes the five core characters", () => {
        assert.equal(escapeHtml(`<>&"'`), "&lt;&gt;&amp;&quot;&#39;");
    });

    it("escapes ampersand before other entities (no double-escape)", () => {
        assert.equal(escapeHtml("&amp;"), "&amp;amp;");
    });

    it("leaves safe characters alone", () => {
        assert.equal(escapeHtml("Hello, world! 1234"), "Hello, world! 1234");
    });

    it("handles non-ASCII characters as-is", () => {
        assert.equal(escapeHtml("Penélope"), "Penélope");
    });
});

describe("utf8ToBase64 / base64ToUtf8", () => {
    it("round-trips ASCII", () => {
        const s = "Hello, world!";
        assert.equal(base64ToUtf8(utf8ToBase64(s)), s);
    });

    it("round-trips Latin Extended", () => {
        const s = "Penélope Cruz";
        assert.equal(base64ToUtf8(utf8ToBase64(s)), s);
    });

    it("round-trips CJK and emoji", () => {
        const s = "日本語 — 🚀 — مرحبا";
        assert.equal(base64ToUtf8(utf8ToBase64(s)), s);
    });

    it("round-trips an empty string", () => {
        assert.equal(base64ToUtf8(utf8ToBase64("")), "");
    });

    it("round-trips a long string without hitting argument-count limits", () => {
        const s = "ø".repeat(50_000);
        assert.equal(base64ToUtf8(utf8ToBase64(s)), s);
    });

    it("produces valid base64 (alphabet only)", () => {
        const encoded = utf8ToBase64("Penélope");
        assert.match(encoded, /^[A-Za-z0-9+/]+={0,2}$/);
    });
});

describe("detectBase64Image", () => {
    // Tiny 1x1 PNG (transparent) used as a known-good base64 PNG sample.
    const tinyPngB64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII=";

    it("accepts a bare base64 PNG", () => {
        const result = detectBase64Image(tinyPngB64);
        assert.equal(result, `data:image/png;base64,${tinyPngB64}`);
    });

    it("accepts bare JPEG / GIF / WebP via magic prefixes", () => {
        // We only check the prefix branch — the rest of the string is valid
        // base64 padding that matches BASE64_RE.
        const jpeg = detectBase64Image("/9j/AAAA");
        assert.ok(jpeg, "expected non-null result for JPEG");
        assert.match(jpeg, /^data:image\/jpeg;base64,/);

        const gif = detectBase64Image("R0lGOAAA");
        assert.ok(gif, "expected non-null result for GIF");
        assert.match(gif, /^data:image\/gif;base64,/);

        const webp = detectBase64Image("UklGRAAA");
        assert.ok(webp, "expected non-null result for WebP");
        assert.match(webp, /^data:image\/webp;base64,/);
    });

    it("accepts an allowlisted data: URL and normalizes its MIME case", () => {
        const result = detectBase64Image(`data:image/PNG;base64,${tinyPngB64}`);
        assert.equal(result, `data:image/png;base64,${tinyPngB64}`);
    });

    it("rejects data:image/svg+xml regardless of encoding", () => {
        assert.equal(detectBase64Image("data:image/svg+xml,<svg onload='x'/>"), null);
        assert.equal(detectBase64Image("data:image/svg+xml;base64,PHN2Zy8+"), null);
    });

    it("rejects non-image data: URLs", () => {
        assert.equal(detectBase64Image("data:text/html;base64,PHNjcmlwdD4="), null);
        assert.equal(detectBase64Image("data:application/javascript;base64,YWxlcnQoMSk="), null);
    });

    it("rejects unknown image subtypes", () => {
        assert.equal(detectBase64Image("data:image/avif;base64,AAAA"), null);
        assert.equal(detectBase64Image("data:image/bmp;base64,AAAA"), null);
    });

    it("rejects data: URLs without base64 encoding", () => {
        assert.equal(detectBase64Image("data:image/png,not-encoded"), null);
        assert.equal(detectBase64Image(`data:image/png;${tinyPngB64}`), null);
    });

    it("rejects base64 with stray characters (whitespace, URL-safe alphabet)", () => {
        assert.equal(detectBase64Image("iVBORw0KGgo with-spaces"), null);
        // URL-safe base64 uses `-` and `_` instead of `+` and `/`.
        assert.equal(detectBase64Image("iVBORw0KGgo-AAA_AAA"), null);
        assert.equal(detectBase64Image("iVBORw0KGgo\nAAAA"), null);
    });

    it("rejects strings that don't match a known image prefix", () => {
        assert.equal(detectBase64Image("SGVsbG8sIHdvcmxkIQ=="), null); // "Hello, world!"
        assert.equal(detectBase64Image(""), null);
        assert.equal(detectBase64Image("nope"), null);
    });

    it("exposes the allowlist for inspection", () => {
        assert.ok(SAFE_IMAGE_SUBTYPES.has("png"));
        assert.ok(SAFE_IMAGE_SUBTYPES.has("jpeg"));
        assert.ok(SAFE_IMAGE_SUBTYPES.has("gif"));
        assert.ok(SAFE_IMAGE_SUBTYPES.has("webp"));
        assert.ok(!SAFE_IMAGE_SUBTYPES.has("svg+xml"));
    });
});

describe("renderClaimValueHtml", () => {
    it("returns an empty string for null/undefined", () => {
        assert.equal(renderClaimValueHtml(null), "");
        assert.equal(renderClaimValueHtml(undefined), "");
    });

    it("renders primitives as escaped text", () => {
        assert.equal(renderClaimValueHtml("hello"), "hello");
        assert.equal(renderClaimValueHtml(42), "42");
        assert.equal(renderClaimValueHtml(true), "true");
    });

    it("escapes dangerous characters in strings", () => {
        assert.equal(
            renderClaimValueHtml("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
    });

    it("returns empty string for empty object/array", () => {
        assert.equal(renderClaimValueHtml({}), "");
        assert.equal(renderClaimValueHtml([]), "");
    });

    it("renders an object as nested <div> rows", () => {
        // Single-word keys pass through keyToLabel unchanged (lowercased);
        // snake_case keys get capitalized + spaced.
        const html = renderClaimValueHtml({ country: "SE", street_address: "Tulegatan" });
        assert.match(html, /^<div class="pl-3 space-y-0\.5">/);
        assert.ok(html.includes("country:"));
        assert.ok(html.includes("Street address:"));
        assert.ok(html.includes("SE"));
        assert.ok(html.includes("Tulegatan"));
    });

    it("renders an array using indices as keys", () => {
        const html = renderClaimValueHtml(["SE", "NO"]);
        assert.match(html, /^<div class="pl-3 space-y-0\.5">/);
        assert.ok(html.includes(">0<"));
        assert.ok(html.includes(">1<"));
        assert.ok(html.includes("SE"));
        assert.ok(html.includes("NO"));
    });

    it("renders nested structures recursively", () => {
        const html = renderClaimValueHtml({
            place_of_birth: { country: "SE", street_address: "Tulegatan" },
        });
        // Outer + inner trees both present.
        const opens = html.match(/<div class="pl-3 space-y-0\.5">/g) || [];
        assert.ok(opens.length >= 2, `expected at least 2 nested trees, got: ${opens.length}`);
        assert.ok(html.includes("Place of birth:"));
        assert.ok(html.includes("Street address:"));
    });

    it("renders base64 PNG strings as <img>", () => {
        const tinyPng = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII=";
        const html = renderClaimValueHtml(tinyPng);
        assert.match(html, /^<img src="data:image\/png;base64,/);
        assert.ok(html.includes("max-h-32"));
    });

    it("renders non-image base64-looking strings as escaped text", () => {
        // Valid base64 but no known image prefix → text.
        const text = "SGVsbG8sIHdvcmxkIQ==";
        assert.equal(renderClaimValueHtml(text), "SGVsbG8sIHdvcmxkIQ==");
    });
});
