// Unit tests for the consent-page helpers. Runs under Node's built-in test
// runner (`node --test`) — no extra dependencies. Covers pure logic only;
// DOM/Alpine code in consent.js is not exercised here.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
    base64ToUtf8,
    detectBase64Image,
    escapeHtml,
    flattenClaims,
    IMAGE_PLACEHOLDERS,
    keyToLabel,
    renderClaimValueHtml,
    SAFE_IMAGE_SUBTYPES,
    utf8ToBase64,
    valueForSvgPlaceholder,
} from "../consent-helpers.js";

import * as v from "../valibot.min.js";

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

    it("escapes existing entities by encoding their leading ampersand", () => {
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

    it("normalizes the common image/jpg alias to image/jpeg", () => {
        // Upstream sometimes emits the non-IANA `image/jpg`. We accept it
        // but normalize the returned URL to the canonical `image/jpeg`.
        const payload = "/9j/AAAA";
        assert.equal(
            detectBase64Image(`data:image/jpg;base64,${payload}`),
            `data:image/jpeg;base64,${payload}`
        );
        assert.equal(
            detectBase64Image(`data:image/JPG;base64,${payload}`),
            `data:image/jpeg;base64,${payload}`
        );
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

describe("valueForSvgPlaceholder", () => {
    const tinyPngB64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII=";

    it("declares `picture` as an image-bearing placeholder", () => {
        assert.ok(IMAGE_PLACEHOLDERS.has("picture"));
    });

    it("accepts a validated base64 image for an image placeholder", () => {
        const result = valueForSvgPlaceholder("picture", tinyPngB64);
        assert.equal(result, `data:image/png;base64,${tinyPngB64}`);
    });

    it("rejects arbitrary URLs in image placeholders (no external fetch)", () => {
        // The whole point: a malicious issuer could put a tracking URL in
        // the picture claim — must NOT end up in <image href=…>.
        assert.equal(valueForSvgPlaceholder("picture", "https://tracker.example/x"), "");
        assert.equal(valueForSvgPlaceholder("picture", "http://10.0.0.1/internal"), "");
        assert.equal(valueForSvgPlaceholder("picture", "javascript:alert(1)"), "");
        assert.equal(valueForSvgPlaceholder("picture", "data:image/svg+xml,<svg onload='x'/>"), "");
        assert.equal(valueForSvgPlaceholder("picture", "not-an-image"), "");
    });

    it("returns empty string for non-string values in image placeholders", () => {
        // Non-string values still need a substitution so the literal
        // `{{picture}}` doesn't end up in the rendered SVG.
        assert.equal(valueForSvgPlaceholder("picture", null), "");
        assert.equal(valueForSvgPlaceholder("picture", undefined), "");
        assert.equal(valueForSvgPlaceholder("picture", 42), "");
        assert.equal(valueForSvgPlaceholder("picture", { foo: "bar" }), "");
    });

    it("passes scalar strings through unchanged for text placeholders", () => {
        assert.equal(valueForSvgPlaceholder("given_name", "Penélope"), "Penélope");
        assert.equal(valueForSvgPlaceholder("issuing_country", "SE"), "SE");
        // Arbitrary URLs are fine here — they'll be rendered as text content
        // inside a <text> element, not fetched.
        assert.equal(
            valueForSvgPlaceholder("document_number", "https://example.com/doc"),
            "https://example.com/doc"
        );
    });

    it("stringifies numbers and booleans for text placeholders", () => {
        assert.equal(valueForSvgPlaceholder("score", 42), "42");
        assert.equal(valueForSvgPlaceholder("score", 7.5), "7.5");
        assert.equal(valueForSvgPlaceholder("valid", true), "true");
        assert.equal(valueForSvgPlaceholder("valid", false), "false");
    });

    it("returns null for non-scalar values in text placeholders", () => {
        assert.equal(valueForSvgPlaceholder("given_name", null), null);
        assert.equal(valueForSvgPlaceholder("given_name", undefined), null);
        assert.equal(valueForSvgPlaceholder("given_name", { foo: "bar" }), null);
        assert.equal(valueForSvgPlaceholder("given_name", [1, 2]), null);
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

    it("renders a primitive array as comma-separated values", () => {
        assert.equal(renderClaimValueHtml(["SE", "NO"]), "SE, NO");
    });

    it("renders an array of objects using indices as keys", () => {
        const html = renderClaimValueHtml([{ name: "a" }, { name: "b" }]);
        assert.match(html, /^<div class="pl-3 space-y-0\.5">/);
        assert.ok(html.includes(">0<"));
        assert.ok(html.includes(">1<"));
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

describe("flattenClaims", () => {
    it("flattens leaf claims into simple rows", () => {
        const claims = {
            given_name: { label: "Given name", value: "Alice" },
            family_name: { label: "Family name", value: "Smith" },
        };
        assert.deepEqual(flattenClaims(claims), [
            { label: "Given name", value: "Alice" },
            { label: "Family name", value: "Smith" },
        ]);
    });

    it("flattens a parent with children into header + indented rows", () => {
        const claims = {
            address: {
                label: "Address",
                children: {
                    street: { label: "Street", value: "123 Main St" },
                    city: { label: "City", value: "Springfield" },
                },
            },
        };
        const rows = flattenClaims(claims);
        assert.deepEqual(rows, [
            { label: "Address", isHeader: true },
            { label: "Street", value: "123 Main St", indent: true },
            { label: "City", value: "Springfield", indent: true },
        ]);
    });

    it("interleaves parents and leaves in declaration order", () => {
        const claims = {
            given_name: { label: "Given name", value: "Bob" },
            address: {
                label: "Address",
                children: {
                    city: { label: "City", value: "Lund" },
                },
            },
            birthdate: { label: "Birthdate", value: "2000-01-01" },
        };
        const rows = flattenClaims(claims);
        assert.equal(rows.length, 4);
        assert.equal(rows[0].label, "Given name");
        assert.equal(rows[1].label, "Address");
        assert.equal(rows[1].isHeader, true);
        assert.equal(rows[2].label, "City");
        assert.equal(rows[2].indent, true);
        assert.equal(rows[3].label, "Birthdate");
    });

    it("returns an empty array for empty claims", () => {
        assert.deepEqual(flattenClaims({}), []);
    });

    it("PID-realistic: address, place_of_birth, nationalities, flat leaves", () => {
        // This is the exact structure Presentation() produces for the PID VCTM.
        const claims = {
            family_name:   { label: "Last name",      value: "Sansen" },
            given_name:    { label: "First name",     value: "Helen" },
            birthdate:     { label: "Date of birth",  value: "1990-01-15" },
            personal_administrative_number: { label: "Personal ID", value: "199001152386" },
            sex:           { label: "Sex",            value: "0" },
            address: {
                label: "Address",
                children: {
                    house_number:   { label: "Residence number",    value: "11" },
                    street_address: { label: "Residence street",    value: "Tulegatan" },
                    locality:       { label: "City of residence",   value: "Stockholm" },
                    region:         { label: "State of residence",  value: "Stockholm" },
                    postal_code:    { label: "Residence ZIP",       value: "11353" },
                    country:        { label: "Country of residence", value: "SE" },
                    formatted:      { label: "Full address",        value: "Tulegatan 11, 11353 Stockholm, SE" },
                },
            },
            place_of_birth: {
                label: "Place of birth",
                children: {
                    locality: { label: "City of birth",    value: "Lund" },
                    region:   { label: "Region of birth",  value: "Skåne" },
                    country:  { label: "Country of birth", value: "SE" },
                },
            },
            nationalities: { label: "Nationalities", value: ["SE"] },
        };

        const rows = flattenClaims(claims);

        // Flat leaves appear as simple rows.
        assert.deepEqual(rows[0], { label: "Last name",     value: "Sansen" });
        assert.deepEqual(rows[1], { label: "First name",    value: "Helen" });
        assert.deepEqual(rows[2], { label: "Date of birth", value: "1990-01-15" });
        assert.deepEqual(rows[3], { label: "Personal ID",   value: "199001152386" });
        assert.deepEqual(rows[4], { label: "Sex",           value: "0" });

        // Address: header row followed by 7 indented children.
        assert.deepEqual(rows[5], { label: "Address", isHeader: true });
        assert.equal(rows[6].label, "Residence number");
        assert.equal(rows[6].value, "11");
        assert.equal(rows[6].indent, true);
        assert.equal(rows[7].value, "Tulegatan");
        assert.equal(rows[8].value, "Stockholm");   // locality
        assert.equal(rows[9].value, "Stockholm");   // region
        assert.equal(rows[10].value, "11353");       // postal_code
        assert.equal(rows[11].value, "SE");          // country
        assert.equal(rows[12].value, "Tulegatan 11, 11353 Stockholm, SE"); // formatted

        // Place of birth: header + 3 children.
        assert.deepEqual(rows[13], { label: "Place of birth", isHeader: true });
        assert.equal(rows[14].label, "City of birth");
        assert.equal(rows[14].value, "Lund");
        assert.equal(rows[14].indent, true);
        assert.equal(rows[15].value, "Skåne");
        assert.equal(rows[16].value, "SE");

        // Nationalities: leaf with array value.
        assert.deepEqual(rows[17], { label: "Nationalities", value: ["SE"] });

        assert.equal(rows.length, 18);
    });
});

describe("PID end-to-end: Valibot schema + flattenClaims + renderClaimValueHtml", () => {
    // Reproduce the exact JSON the Go backend sends for a PID user lookup.
    const pidResponse = {
        svg_template_claims: {
            family_name: { label: "Last name", value: "Sansen" },
            given_name:  { label: "First name", value: "Helen" },
            birth_date:  { label: "Date of birth", value: "1990-01-15" },
            personal_administrative_number: { label: "Personal ID", value: "199001152386" },
            expiry_date: { label: "Expiry date", value: "2030-12-31" },
            issuing_country: { label: "Issuing country", value: "SE" },
            document_number: { label: "Document number", value: "DOC-001" },
        },
        presentation_claims: {
            family_name: { label: "Last name", value: "Sansen" },
            given_name:  { label: "First name", value: "Helen" },
            birthdate:   { label: "Date of birth", value: "1990-01-15" },
            personal_administrative_number: { label: "Personal ID", value: "199001152386" },
            sex:         { label: "Sex", value: "0" },
            address: {
                label: "Address",
                children: {
                    house_number:   { label: "Residence number",     value: "11" },
                    street_address: { label: "Residence street",     value: "Tulegatan" },
                    locality:       { label: "City of residence",    value: "Stockholm" },
                    region:         { label: "State of residence",   value: "Stockholm" },
                    postal_code:    { label: "Residence ZIP",        value: "11353" },
                    country:        { label: "Country of residence", value: "SE" },
                    formatted:      { label: "Full address",         value: "Tulegatan 11, 11353 Stockholm, SE" },
                },
            },
            place_of_birth: {
                label: "Place of birth",
                children: {
                    locality: { label: "City of birth",   value: "Lund" },
                    region:   { label: "Region of birth", value: "Skåne" },
                    country:  { label: "Country of birth", value: "SE" },
                },
            },
            nationalities: { label: "Nationalities", value: ["SE"] },
        },
        redirect_url: "https://example.com/callback?code=abc&state=xyz",
    };

    // Rebuild the same Valibot schemas from consent.js.
    const ClaimValueSchema = v.lazy(() => v.union([
        v.string(), v.number(), v.boolean(), v.null(),
        v.array(ClaimValueSchema),
        v.record(v.string(), ClaimValueSchema),
    ]));
    const LeafClaimSchema = v.object({ label: v.string(), value: ClaimValueSchema });
    const ParentClaimSchema = v.object({
        label: v.string(),
        children: v.record(v.string(), v.object({ label: v.string(), value: ClaimValueSchema })),
    });
    const PresentationClaimSchema = v.union([LeafClaimSchema, ParentClaimSchema]);
    const UserDataSchema = v.required(v.object({
        svg_template_claims: v.record(v.string(), v.object({ label: v.string(), value: ClaimValueSchema })),
        presentation_claims: v.record(v.string(), PresentationClaimSchema),
        redirect_url: v.string(),
    }));

    it("Valibot accepts the full PID response", () => {
        const parsed = v.parse(UserDataSchema, pidResponse);
        assert.equal(parsed.redirect_url, pidResponse.redirect_url);
        assert.deepEqual(Object.keys(parsed.presentation_claims).sort(),
            Object.keys(pidResponse.presentation_claims).sort());
    });

    it("flattenClaims produces correct rows from validated data", () => {
        const parsed = v.parse(UserDataSchema, pidResponse);
        const rows = flattenClaims(parsed.presentation_claims);

        // Collect labels for quick structural checks.
        const headers = rows.filter(r => r.isHeader).map(r => r.label);
        const indented = rows.filter(r => r.indent).map(r => r.label);
        const leaves  = rows.filter(r => !r.isHeader && !r.indent).map(r => r.label);

        assert.deepEqual(headers, ["Address", "Place of birth"]);
        assert.equal(indented.length, 10); // 7 address + 3 place_of_birth
        assert.ok(leaves.includes("Last name"));
        assert.ok(leaves.includes("Nationalities"));
        assert.ok(leaves.includes("Sex"));
    });

    it("renderClaimValueHtml handles every PID value type", () => {
        // String leaf.
        assert.equal(renderClaimValueHtml("Sansen"), "Sansen");
        // Numeric-string value for sex.
        assert.equal(renderClaimValueHtml("0"), "0");
        // Array of primitives (nationalities) — comma-separated, no indices.
        assert.equal(renderClaimValueHtml(["SE"]), "SE");
        assert.equal(renderClaimValueHtml(["SE", "DE"]), "SE, DE");
        // Array of objects — indexed layout preserved.
        const objHtml = renderClaimValueHtml([{ name: "a" }]);
        assert.ok(objHtml.includes("0"), "array of objects shows index");
    });
});
