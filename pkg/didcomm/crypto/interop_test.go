//go:build didcomm && vc20

// Package crypto provides interoperability tests against sicpa-dlab/didcomm-rust test vectors.
// These tests verify that our implementation can decrypt messages created by the Rust library
// and that messages we encrypt can be decrypted using the same keys.
package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Test vectors from sicpa-dlab/didcomm-rust
// https://github.com/sicpa-dlab/didcomm-rust/blob/main/src/jwe/mod.rs
// https://github.com/sicpa-dlab/didcomm-rust/blob/main/src/test_vectors/

// Alice's X25519 key agreement key
const aliceKeyX25519JWK = `{
	"kty": "OKP",
	"crv": "X25519",
	"d": "r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
	"x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
}`

// Bob's X25519 key agreement keys
const bobKeyX25519_1JWK = `{
	"kty": "OKP",
	"crv": "X25519",
	"d": "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0",
	"x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E"
}`

const bobKeyX25519_2JWK = `{
	"kty": "OKP",
	"crv": "X25519",
	"d": "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
	"x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
}`

const bobKeyX25519_3JWK = `{
	"kty": "OKP",
	"crv": "X25519",
	"d": "f9WJeuQXEItkGM8shN4dqFr5fLQLBasHnWZ-8dPaSo0",
	"x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY"
}`

// Bob's P-256 key agreement keys
const bobKeyP256_1JWK = `{
	"kty": "EC",
	"crv": "P-256",
	"d": "PgwHnlXxt8pwR6OCTUwwWx-P51BiLkFZyqHzquKddXQ",
	"x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
	"y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY"
}`

const bobKeyP256_2JWK = `{
	"kty": "EC",
	"crv": "P-256",
	"d": "agKz7HS8mIwqO40Q2dwm_Zi70IdYFtonN5sZecQoxYU",
	"x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
	"y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
}`

// Alice's P-256 key agreement key
const aliceKeyP256JWK = `{
	"kty": "EC",
	"crv": "P-256",
	"d": "sB0bYtpaXyp-h17dDpMx91N3Du1AdN4z1FUq02GbmLw",
	"x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
	"y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
}`

// Expected plaintext from Rust test vectors
const testPayload = `{"id":"1234567890","typ":"application/didcomm-plain+json","type":"http://example.com/protocols/lets_do_lunch/1.0/proposal","from":"did:example:alice","to":["did:example:bob"],"created_time":1516269022,"expires_time":1516385931,"body":{"messagespecificattribute":"and its value"}}`

// Anoncrypt message encrypted with ECDH-ES+A256KW and XC20P from Rust implementation
// From: https://github.com/sicpa-dlab/didcomm-rust/blob/main/src/jwe/decrypt.rs
const msgAnoncryptX25519XC20P = `{
	"protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
	"recipients":[
		{
			"header":{
				"kid":"did:example:bob#key-x25519-1"
			},
			"encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A"
		},
		{
			"header":{
				"kid":"did:example:bob#key-x25519-2"
			},
			"encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ"
		},
		{
			"header":{
				"kid":"did:example:bob#key-x25519-3"
			},
			"encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A"
		}
	],
	"tag":"6ylC_iAs4JvDQzXeY6MuYQ",
	"iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1",
	"ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p"
}`

// Anoncrypt message encrypted with ECDH-ES+A256KW and A256CBC-HS512 from Rust implementation
const msgAnoncryptX25519A256CBC = `{
	"protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjpudWxsLCJhcHYiOiJiV3ZqdDZGM2hsUzlSeE56ZVFCQVBFOGJRdnBiQnhUa3gzS0VOUEY2aTlFIiwiZXBrIjp7ImNydiI6IlgyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiJ3NEpZU0dkc1BXZldkeHZSLS12R2FTTHdZX0dTRTRwVlFhUmRRMEpLU0ZJIn19",
	"recipients":[
		{
			"header":{
				"kid":"did:example:bob#key-x25519-1"
			},
			"encrypted_key":"EPhEGPspLjEvJ_v1W5zlJGfg88huhrTEUQCfKzKXmZjp6Y7Vv9Rv0mQgb7XyeZrxKHwgMo5Vxoref9ngeT17WUuHAEEPDteF"
		},
		{
			"header":{
				"kid":"did:example:bob#key-x25519-2"
			},
			"encrypted_key":"XchtfMRjcs24QNpWBk81zW74mQFR8ungyaBlpGjaOFHWf5dlCcrGvZLIT-UEY--S_UZEVknNwOOQ-lq4F5MGtkDVOpd-HoxD"
		}
	],
	"iv":"nzmtYMd1crLyY4rRWUAL1A",
	"ciphertext":"bDM_50XL_ArVWWgpiMZO2NFFDZqc0jFBL1RFFESE_saPogffoyDEafYFYD4OlCH9yiEOIHpZZFHrgSx66xrPrkAXfl-d3Ppin2mhx0EgiV4h8yqiN1J_dQ-b_gTsP5djIj3VxMF4mkg34oIRxuaL71DQbhWgsUw-yH16KaBHkXhQnj7T4j6lQeSrP9qNYhMD0UbXcaVzT2AvmwdhRuOuI17DrfwQMVsZnh7Zh9WwJVPwUw7pto0_YpqUacq4kq3z9ZJ1pfFEstVnRwRAosjf0UCwRzCG6nw8OJYDqS3v3_2leRsjuAk-Ro4OMt5mPki0TIBeWl8JP-5rU9kGr2o7DMUtLcNoM5NHOeKiw4BgI04lFRD-azqNXJQwlBV9Uzlq",
	"tag":"PytY0PYyjAXno1ykdMVE75LKdZA6d8yH1Ju0jZf0n8c"
}`

// Authcrypt message from Rust implementation using ECDH-1PU (ENCRYPTED_MSG_AUTH_X25519)
// Source: https://github.com/sicpa-dlab/didcomm-rust/blob/main/src/test_vectors/encrypted.rs
const msgAuthcryptX25519A256CBC = `{
	"ciphertext": "MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
	"protected": "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
	"recipients": [
		{
			"encrypted_key": "o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
			"header": {
				"kid": "did:example:bob#key-x25519-1"
			}
		},
		{
			"encrypted_key": "rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
			"header": {
				"kid": "did:example:bob#key-x25519-2"
			}
		},
		{
			"encrypted_key": "aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
			"header": {
				"kid": "did:example:bob#key-x25519-3"
			}
		}
	],
	"tag": "uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
	"iv": "o02OXDQ6_-sKz2PX_6oyJg"
}`

// Anoncrypt message from WASM test vectors (ENCRYPTED_MSG_ANON_XC20P_1)
const msgAnoncryptP256XC20P = `{
	"protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJYQzIwUCIsImFwdSI6bnVsbCwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IjVfUGROMlB3RFVFRENJVUZLa0ZiU1RQQVE0MW9GUGlZS193b1NBV1JpQWciLCJ5IjoiUHZWQnR3OFlRNzAtXzFTY1A5S3ZFZDRBbkNHT2FXejAyMTc4UGlhYkpaWSJ9fQ",
	"recipients": [{
			"encrypted_key": "G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
			"header": {
				"kid": "did:example:bob#key-p256-1"
			}
		},{
			"encrypted_key": "gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
			"header": {
				"kid": "did:example:bob#key-p256-2"
			}
		}],
	"tag": "t8ioLvZhsCp7A93jvdf3wA",
	"iv": "JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF",
	"ciphertext": "912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGm"
}`

// Test: Verify we can decrypt anoncrypt messages from Rust using XC20P
func TestInteropDecryptAnoncryptX25519XC20P(t *testing.T) {
	// Parse Bob's key
	bobKey, err := jwk.ParseKey([]byte(bobKeyX25519_1JWK))
	if err != nil {
		t.Fatalf("Failed to parse Bob's key: %v", err)
	}
	_ = bobKey.Set("kid", "did:example:bob#key-x25519-1")

	ctx := context.Background()

	// Decrypt the message
	plaintext, err := Decrypt(ctx, []byte(msgAnoncryptX25519XC20P), bobKey)
	if err != nil {
		t.Fatalf("Failed to decrypt message: %v", err)
	}

	// Verify plaintext matches expected
	if string(plaintext) != testPayload {
		t.Errorf("Decrypted plaintext doesn't match expected.\nGot: %s\nWant: %s", string(plaintext), testPayload)
	}
}

// Test: Verify we can decrypt anoncrypt messages with different recipient keys
func TestInteropDecryptAnoncryptX25519XC20PAllRecipients(t *testing.T) {
	tests := []struct {
		name   string
		keyJWK string
		kid    string
	}{
		{"Bob key 1", bobKeyX25519_1JWK, "did:example:bob#key-x25519-1"},
		{"Bob key 2", bobKeyX25519_2JWK, "did:example:bob#key-x25519-2"},
		{"Bob key 3", bobKeyX25519_3JWK, "did:example:bob#key-x25519-3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := jwk.ParseKey([]byte(tt.keyJWK))
			if err != nil {
				t.Fatalf("Failed to parse key: %v", err)
			}
			_ = key.Set("kid", tt.kid)

			ctx := context.Background()
			plaintext, err := Decrypt(ctx, []byte(msgAnoncryptX25519XC20P), key)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			if string(plaintext) != testPayload {
				t.Errorf("Plaintext mismatch")
			}
		})
	}
}

// Test: Verify we can decrypt anoncrypt messages using A256CBC-HS512
func TestInteropDecryptAnoncryptX25519A256CBC(t *testing.T) {
	bobKey, err := jwk.ParseKey([]byte(bobKeyX25519_1JWK))
	if err != nil {
		t.Fatalf("Failed to parse Bob's key: %v", err)
	}
	_ = bobKey.Set("kid", "did:example:bob#key-x25519-1")

	ctx := context.Background()
	plaintext, err := Decrypt(ctx, []byte(msgAnoncryptX25519A256CBC), bobKey)
	if err != nil {
		t.Fatalf("Failed to decrypt message: %v", err)
	}

	if string(plaintext) != testPayload {
		t.Errorf("Decrypted plaintext doesn't match expected")
	}
}

// Test: Verify P-256 encryption/decryption roundtrip with XC20P
// Note: The original P-256 test vector from didcomm-rust has an invalid EPK
// (coordinates not on P-256 curve), so we use a roundtrip test instead.
func TestInteropDecryptAnoncryptP256XC20P(t *testing.T) {
	// Generate a P-256 recipient key
	recipientKey, err := generateECDHKey(CurveP256)
	if err != nil {
		t.Fatalf("Failed to generate P-256 recipient key: %v", err)
	}
	_ = recipientKey.Set("kid", "did:example:bob#key-p256-1")

	recipientPubKey, err := recipientKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get recipient public key: %v", err)
	}

	ctx := context.Background()
	plaintext := []byte(testPayload)

	// Encrypt with XC20P using P-256 key agreement
	opts := DefaultEncryptionOptions()
	opts.Encryption = EncXC20P
	opts.Algorithm = AlgECDHESA256KW

	encrypted, err := Encrypt(ctx, plaintext, []jwk.Key{recipientPubKey}, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt with P-256: %v", err)
	}

	// Verify it's valid JSON
	var jweMsg map[string]interface{}
	if err := json.Unmarshal(encrypted, &jweMsg); err != nil {
		t.Fatalf("Encrypted message is not valid JSON: %v", err)
	}

	// Verify protected header has P-256 EPK
	protectedB64, ok := jweMsg["protected"].(string)
	if !ok {
		t.Fatal("Missing protected header")
	}
	protectedBytes, err := base64.RawURLEncoding.DecodeString(protectedB64)
	if err != nil {
		t.Fatalf("Failed to decode protected header: %v", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(protectedBytes, &header); err != nil {
		t.Fatalf("Failed to parse protected header: %v", err)
	}

	// Check EPK curve
	epk, ok := header["epk"].(map[string]interface{})
	if !ok {
		t.Fatal("Missing EPK in protected header")
	}
	if crv, _ := epk["crv"].(string); crv != CurveP256 {
		t.Errorf("Expected P-256 curve in EPK, got %s", crv)
	}

	// Decrypt
	decrypted, err := Decrypt(ctx, encrypted, recipientKey)
	if err != nil {
		t.Fatalf("Failed to decrypt P-256 message: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted plaintext doesn't match.\nGot: %s\nWant: %s", string(decrypted), string(plaintext))
	}

	t.Logf("Successfully performed P-256 + XC20P roundtrip")
}

// Test: Encrypt/Decrypt round-trip with XC20P (interop verification)
func TestInteropEncryptDecryptRoundtripXC20P(t *testing.T) {
	// Generate fresh keys
	recipientKey, err := generateECDHKey(CurveX25519)
	if err != nil {
		t.Fatalf("Failed to generate recipient key: %v", err)
	}
	_ = recipientKey.Set("kid", "recipient#key-1")

	recipientPubKey, err := recipientKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get recipient public key: %v", err)
	}

	ctx := context.Background()
	plaintext := []byte(testPayload)

	// Encrypt with XC20P
	opts := DefaultEncryptionOptions()
	opts.Encryption = EncXC20P
	opts.Algorithm = AlgECDHESA256KW

	encrypted, err := Encrypt(ctx, plaintext, []jwk.Key{recipientPubKey}, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Verify it's valid JSON
	var jwe map[string]interface{}
	if err := json.Unmarshal(encrypted, &jwe); err != nil {
		t.Fatalf("Encrypted message is not valid JSON: %v", err)
	}

	// Verify protected header
	protectedB64, ok := jwe["protected"].(string)
	if !ok {
		t.Fatal("Missing protected header")
	}
	protectedBytes, err := base64.RawURLEncoding.DecodeString(protectedB64)
	if err != nil {
		t.Fatalf("Failed to decode protected header: %v", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(protectedBytes, &header); err != nil {
		t.Fatalf("Failed to parse protected header: %v", err)
	}

	// Verify algorithm headers
	if alg, _ := header["alg"].(string); alg != AlgECDHESA256KW {
		t.Errorf("Expected alg=%s, got %s", AlgECDHESA256KW, alg)
	}
	if enc, _ := header["enc"].(string); enc != EncXC20P {
		t.Errorf("Expected enc=%s, got %s", EncXC20P, enc)
	}

	// Decrypt
	decrypted, err := Decrypt(ctx, encrypted, recipientKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Round-trip failed. Got: %s", string(decrypted))
	}

	t.Logf("Successfully encrypted and decrypted %d bytes with XC20P", len(plaintext))
}

// Test: Multi-recipient encryption with XC20P
func TestInteropMultiRecipientXC20P(t *testing.T) {
	// Parse multiple recipient keys from Rust test vectors
	keys := []struct {
		jwk string
		kid string
	}{
		{bobKeyX25519_1JWK, "did:example:bob#key-x25519-1"},
		{bobKeyX25519_2JWK, "did:example:bob#key-x25519-2"},
		{bobKeyX25519_3JWK, "did:example:bob#key-x25519-3"},
	}

	var recipientPrivKeys []jwk.Key
	var recipientPubKeys []jwk.Key

	for _, k := range keys {
		privKey, err := jwk.ParseKey([]byte(k.jwk))
		if err != nil {
			t.Fatalf("Failed to parse key: %v", err)
		}
		_ = privKey.Set("kid", k.kid)
		recipientPrivKeys = append(recipientPrivKeys, privKey)

		pubKey, err := privKey.PublicKey()
		if err != nil {
			t.Fatalf("Failed to get public key: %v", err)
		}
		recipientPubKeys = append(recipientPubKeys, pubKey)
	}

	ctx := context.Background()
	plaintext := []byte(testPayload)

	// Encrypt to all recipients
	opts := DefaultEncryptionOptions()
	opts.Encryption = EncXC20P
	opts.Algorithm = AlgECDHESA256KW

	encrypted, err := Encrypt(ctx, plaintext, recipientPubKeys, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Verify each recipient can decrypt
	for i, privKey := range recipientPrivKeys {
		decrypted, err := Decrypt(ctx, encrypted, privKey)
		if err != nil {
			t.Errorf("Recipient %d failed to decrypt: %v", i, err)
			continue
		}
		if string(decrypted) != string(plaintext) {
			t.Errorf("Recipient %d decrypted wrong content", i)
		}
	}
}

// Test: ECDH-1PU Authcrypt decryption (requires sender public key)
func TestInteropDecryptAuthcryptECDH1PU(t *testing.T) {
	// Parse Alice's public key (sender)
	aliceKey, err := jwk.ParseKey([]byte(aliceKeyX25519JWK))
	if err != nil {
		t.Fatalf("Failed to parse Alice's key: %v", err)
	}
	alicePubKey, err := aliceKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get Alice's public key: %v", err)
	}
	_ = alicePubKey.Set("kid", "did:example:alice#key-x25519-1")

	// Parse Bob's private key (recipient)
	bobKey, err := jwk.ParseKey([]byte(bobKeyX25519_1JWK))
	if err != nil {
		t.Fatalf("Failed to parse Bob's key: %v", err)
	}
	_ = bobKey.Set("kid", "did:example:bob#key-x25519-1")

	ctx := context.Background()

	// Decrypt the authcrypt message
	plaintext, err := DecryptECDH1PU(ctx, []byte(msgAuthcryptX25519A256CBC), bobKey, alicePubKey)
	if err != nil {
		t.Fatalf("Failed to decrypt authcrypt message: %v", err)
	}

	if string(plaintext) != testPayload {
		t.Errorf("Decrypted plaintext doesn't match expected.\nGot: %s\nWant: %s", string(plaintext), testPayload)
	}

	t.Logf("Successfully decrypted ECDH-1PU authcrypt message")
}

// Test: ECDH-1PU encryption roundtrip with A256CBC-HS512
// This test verifies that we can encrypt and decrypt using the ECDH-1PU algorithm
// with proper key commitment (cc_tag in KDF).
func TestInteropECDH1PURoundtrip(t *testing.T) {
	// Parse Alice's key (sender)
	aliceKey, err := jwk.ParseKey([]byte(aliceKeyX25519JWK))
	if err != nil {
		t.Fatalf("Failed to parse Alice's key: %v", err)
	}
	_ = aliceKey.Set("kid", "did:example:alice#key-x25519-1")

	alicePubKey, err := aliceKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get Alice's public key: %v", err)
	}
	_ = alicePubKey.Set("kid", "did:example:alice#key-x25519-1")

	// Parse Bob's key (recipient)
	bobKey, err := jwk.ParseKey([]byte(bobKeyX25519_1JWK))
	if err != nil {
		t.Fatalf("Failed to parse Bob's key: %v", err)
	}
	_ = bobKey.Set("kid", "did:example:bob#key-x25519-1")

	bobPubKey, err := bobKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get Bob's public key: %v", err)
	}
	_ = bobPubKey.Set("kid", "did:example:bob#key-x25519-1")

	ctx := context.Background()
	plaintext := []byte(testPayload)

	// Encrypt with ECDH-1PU (authcrypt)
	opts := AuthcryptOptions(aliceKey, "did:example:alice#key-x25519-1")

	encrypted, err := Encrypt(ctx, plaintext, []jwk.Key{bobPubKey}, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt with ECDH-1PU: %v", err)
	}

	// Verify it's valid JSON
	var jwe map[string]interface{}
	if err := json.Unmarshal(encrypted, &jwe); err != nil {
		t.Fatalf("Encrypted message is not valid JSON: %v", err)
	}

	// Verify protected header
	protectedB64, ok := jwe["protected"].(string)
	if !ok {
		t.Fatal("Missing protected header")
	}
	protectedBytes, err := base64.RawURLEncoding.DecodeString(protectedB64)
	if err != nil {
		t.Fatalf("Failed to decode protected header: %v", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(protectedBytes, &header); err != nil {
		t.Fatalf("Failed to parse protected header: %v", err)
	}

	// Check algorithm headers
	if alg, _ := header["alg"].(string); alg != AlgECDH1PUA256KW {
		t.Errorf("Expected alg=%s, got %s", AlgECDH1PUA256KW, alg)
	}
	if enc, _ := header["enc"].(string); enc != EncA256CBCHS512 {
		t.Errorf("Expected enc=%s, got %s", EncA256CBCHS512, enc)
	}
	if _, ok := header["skid"]; !ok {
		t.Error("Missing skid in protected header")
	}
	if _, ok := header["epk"]; !ok {
		t.Error("Missing epk in protected header")
	}

	// Decrypt
	decrypted, err := DecryptECDH1PU(ctx, encrypted, bobKey, alicePubKey)
	if err != nil {
		t.Fatalf("Failed to decrypt ECDH-1PU message: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted plaintext doesn't match.\nGot: %s\nWant: %s", string(decrypted), string(plaintext))
	}

	t.Logf("Successfully performed ECDH-1PU roundtrip with A256CBC-HS512")
}

// Test: ECDH-1PU multi-recipient encryption
func TestInteropECDH1PUMultiRecipient(t *testing.T) {
	// Parse Alice's key (sender)
	aliceKey, err := jwk.ParseKey([]byte(aliceKeyX25519JWK))
	if err != nil {
		t.Fatalf("Failed to parse Alice's key: %v", err)
	}
	_ = aliceKey.Set("kid", "did:example:alice#key-x25519-1")

	alicePubKey, err := aliceKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get Alice's public key: %v", err)
	}
	_ = alicePubKey.Set("kid", "did:example:alice#key-x25519-1")

	// Parse Bob's keys (recipients)
	bobKeys := []struct {
		jwk string
		kid string
	}{
		{bobKeyX25519_1JWK, "did:example:bob#key-x25519-1"},
		{bobKeyX25519_2JWK, "did:example:bob#key-x25519-2"},
		{bobKeyX25519_3JWK, "did:example:bob#key-x25519-3"},
	}

	var recipientPrivKeys []jwk.Key
	var recipientPubKeys []jwk.Key

	for _, k := range bobKeys {
		privKey, err := jwk.ParseKey([]byte(k.jwk))
		if err != nil {
			t.Fatalf("Failed to parse key: %v", err)
		}
		_ = privKey.Set("kid", k.kid)
		recipientPrivKeys = append(recipientPrivKeys, privKey)

		pubKey, err := privKey.PublicKey()
		if err != nil {
			t.Fatalf("Failed to get public key: %v", err)
		}
		_ = pubKey.Set("kid", k.kid)
		recipientPubKeys = append(recipientPubKeys, pubKey)
	}

	ctx := context.Background()
	plaintext := []byte(testPayload)

	// Encrypt with ECDH-1PU to all recipients
	opts := AuthcryptOptions(aliceKey, "did:example:alice#key-x25519-1")

	encrypted, err := Encrypt(ctx, plaintext, recipientPubKeys, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Verify each recipient can decrypt
	for i, privKey := range recipientPrivKeys {
		decrypted, err := DecryptECDH1PU(ctx, encrypted, privKey, alicePubKey)
		if err != nil {
			t.Errorf("Recipient %d failed to decrypt: %v", i, err)
			continue
		}
		if string(decrypted) != string(plaintext) {
			t.Errorf("Recipient %d decrypted wrong content", i)
		}
	}

	t.Logf("Successfully performed ECDH-1PU multi-recipient roundtrip")
}

// Test: ECDH-1PU key agreement produces correct derived keys
func TestInteropECDH1PUKeyDerivation(t *testing.T) {
	// Parse keys
	aliceKey, err := jwk.ParseKey([]byte(aliceKeyX25519JWK))
	if err != nil {
		t.Fatalf("Failed to parse Alice's key: %v", err)
	}

	bobKey, err := jwk.ParseKey([]byte(bobKeyX25519_1JWK))
	if err != nil {
		t.Fatalf("Failed to parse Bob's key: %v", err)
	}
	bobPubKey, err := bobKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get Bob's public key: %v", err)
	}

	// Create ECDH-1PU agreement from Alice (sender) to Bob (recipient)
	agreement, err := NewECDH1PU(aliceKey, bobPubKey, AlgECDH1PUA256KW, EncA256CBCHS512)
	if err != nil {
		t.Fatalf("Failed to create ECDH-1PU: %v", err)
	}

	// Derive a key
	derivedKey, ephPubKey, err := agreement.DeriveKey()
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	// Verify key length
	if len(derivedKey) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(derivedKey))
	}

	// Verify ephemeral key exists
	if ephPubKey == nil {
		t.Error("Ephemeral public key is nil")
	}

	// Verify Bob can derive the same key for decryption
	alicePubKey, _ := aliceKey.PublicKey()
	bobAgreement, err := NewECDH1PU(nil, bobKey, AlgECDH1PUA256KW, EncA256CBCHS512)
	if err != nil {
		t.Fatalf("Failed to create Bob's ECDH-1PU: %v", err)
	}

	bobDerivedKey, err := bobAgreement.DeriveKeyForDecryption(ephPubKey, alicePubKey)
	if err != nil {
		t.Fatalf("Failed to derive key for decryption: %v", err)
	}

	// Keys should match
	if string(derivedKey) != string(bobDerivedKey) {
		t.Error("Derived keys don't match between sender and recipient")
	}

	t.Logf("ECDH-1PU key derivation successful: derived %d-byte key", len(derivedKey))
}

// Test: XC20P encryption matches expected format
func TestInteropXC20PFormat(t *testing.T) {
	// Generate key
	key, err := generateECDHKey(CurveX25519)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pubKey, err := key.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	ctx := context.Background()
	plaintext := []byte(`{"test": "data"}`)

	opts := DefaultEncryptionOptions()
	opts.Encryption = EncXC20P
	opts.Algorithm = AlgECDHESA256KW

	encrypted, err := Encrypt(ctx, plaintext, []jwk.Key{pubKey}, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Parse and verify JWE structure
	var jwe map[string]interface{}
	if err := json.Unmarshal(encrypted, &jwe); err != nil {
		t.Fatalf("Not valid JSON: %v", err)
	}

	// Check required fields
	required := []string{"protected", "recipients", "iv", "ciphertext", "tag"}
	for _, field := range required {
		if _, ok := jwe[field]; !ok {
			t.Errorf("Missing required field: %s", field)
		}
	}

	// Verify IV length (24 bytes for XC20P, base64url encoded)
	ivStr, _ := jwe["iv"].(string)
	ivBytes, err := base64.RawURLEncoding.DecodeString(ivStr)
	if err != nil {
		t.Fatalf("Failed to decode IV: %v", err)
	}
	if len(ivBytes) != 24 {
		t.Errorf("XC20P IV should be 24 bytes, got %d", len(ivBytes))
	}

	// Verify tag length (16 bytes for XC20P)
	tagStr, _ := jwe["tag"].(string)
	tagBytes, err := base64.RawURLEncoding.DecodeString(tagStr)
	if err != nil {
		t.Fatalf("Failed to decode tag: %v", err)
	}
	if len(tagBytes) != 16 {
		t.Errorf("XC20P tag should be 16 bytes, got %d", len(tagBytes))
	}

	t.Logf("XC20P JWE format verified: IV=%d bytes, tag=%d bytes", len(ivBytes), len(tagBytes))
}

// TestInteropForwardProtocolEncryption tests the forward protocol with proper encryption
// This simulates a routed message through a mediator
func TestInteropForwardProtocolEncryption(t *testing.T) {
	ctx := context.Background()

	// Setup keys for Alice, Mediator, and Bob
	_, err := generateECDHKey(CurveX25519)
	if err != nil {
		t.Fatalf("Failed to generate Alice key: %v", err)
	}

	mediatorKey, err := generateECDHKey(CurveX25519)
	if err != nil {
		t.Fatalf("Failed to generate Mediator key: %v", err)
	}
	mediatorPubKey, _ := mediatorKey.PublicKey()

	bobKey, err := generateECDHKey(CurveX25519)
	if err != nil {
		t.Fatalf("Failed to generate Bob key: %v", err)
	}
	bobPubKey, _ := bobKey.PublicKey()

	// Original message from Alice to Bob
	originalMessage := `{
		"id": "fwd-test-1",
		"type": "https://example.org/test-message",
		"from": "did:example:alice",
		"to": ["did:example:bob"],
		"body": {"message": "Hello Bob through the mediator!"}
	}`

	// Step 1: Alice encrypts the message for Bob
	bobOpts := DefaultEncryptionOptions()
	bobOpts.Encryption = EncXC20P
	bobOpts.Algorithm = AlgECDHESA256KW

	encryptedForBob, err := Encrypt(ctx, []byte(originalMessage), []jwk.Key{bobPubKey}, bobOpts)
	if err != nil {
		t.Fatalf("Failed to encrypt for Bob: %v", err)
	}

	// Step 2: Create a forward message and encrypt for mediator
	forwardMessage := map[string]interface{}{
		"id":   "forward-1",
		"type": "https://didcomm.org/routing/2.0/forward",
		"to":   []string{"did:example:mediator"},
		"body": map[string]interface{}{
			"next": "did:example:bob",
		},
		"attachments": []map[string]interface{}{
			{
				"id":         "inner-message",
				"media_type": "application/didcomm-encrypted+json",
				"data": map[string]interface{}{
					"json": json.RawMessage(encryptedForBob),
				},
			},
		},
	}
	forwardJSON, _ := json.Marshal(forwardMessage)

	// Encrypt forward for mediator
	mediatorOpts := DefaultEncryptionOptions()
	mediatorOpts.Encryption = EncXC20P
	mediatorOpts.Algorithm = AlgECDHESA256KW

	encryptedForMediator, err := Encrypt(ctx, forwardJSON, []jwk.Key{mediatorPubKey}, mediatorOpts)
	if err != nil {
		t.Fatalf("Failed to encrypt for mediator: %v", err)
	}

	// Step 3: Mediator decrypts the outer envelope
	decryptedForward, err := Decrypt(ctx, encryptedForMediator, mediatorKey)
	if err != nil {
		t.Fatalf("Mediator failed to decrypt: %v", err)
	}

	// Parse the forward message
	var parsedForward map[string]interface{}
	if err := json.Unmarshal(decryptedForward, &parsedForward); err != nil {
		t.Fatalf("Failed to parse forward message: %v", err)
	}

	// Verify forward message structure
	if parsedForward["type"] != "https://didcomm.org/routing/2.0/forward" {
		t.Errorf("Unexpected forward type: %v", parsedForward["type"])
	}

	body, ok := parsedForward["body"].(map[string]interface{})
	if !ok {
		t.Fatal("Forward body is not a map")
	}
	if body["next"] != "did:example:bob" {
		t.Errorf("Unexpected next hop: %v", body["next"])
	}

	// Extract the inner encrypted message
	attachments, ok := parsedForward["attachments"].([]interface{})
	if !ok || len(attachments) == 0 {
		t.Fatal("No attachments in forward message")
	}
	attachment := attachments[0].(map[string]interface{})
	data := attachment["data"].(map[string]interface{})
	innerEncrypted, _ := json.Marshal(data["json"])

	// Step 4: Bob decrypts the inner message
	decryptedMessage, err := Decrypt(ctx, innerEncrypted, bobKey)
	if err != nil {
		t.Fatalf("Bob failed to decrypt: %v", err)
	}

	// Verify the original message was recovered
	var finalMessage map[string]interface{}
	if err := json.Unmarshal(decryptedMessage, &finalMessage); err != nil {
		t.Fatalf("Failed to parse final message: %v", err)
	}

	if finalMessage["id"] != "fwd-test-1" {
		t.Errorf("Message ID mismatch: %v", finalMessage["id"])
	}

	finalBody := finalMessage["body"].(map[string]interface{})
	if finalBody["message"] != "Hello Bob through the mediator!" {
		t.Errorf("Message body mismatch: %v", finalBody["message"])
	}

	t.Logf("Forward protocol encryption roundtrip successful")
	t.Logf("Original: %d bytes -> Encrypted for Bob: %d bytes -> Forward for Mediator: %d bytes",
		len(originalMessage), len(encryptedForBob), len(encryptedForMediator))
}

// TestInteropMixedCurveAnoncrypt tests anoncrypt with different curves
func TestInteropMixedCurveAnoncrypt(t *testing.T) {
	ctx := context.Background()
	plaintext := []byte(`{"test":"mixed curves"}`)

	testCases := []struct {
		name       string
		curve      string
		encryption string
	}{
		{"X25519 + XC20P", CurveX25519, EncXC20P},
		{"X25519 + A256GCM", CurveX25519, EncA256GCM},
		{"X25519 + A256CBC-HS512", CurveX25519, EncA256CBCHS512},
		{"P-256 + A256GCM", CurveP256, EncA256GCM},
		{"P-256 + XC20P", CurveP256, EncXC20P},
		{"P-384 + A256GCM", CurveP384, EncA256GCM},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := generateECDHKey(tc.curve)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			pubKey, _ := key.PublicKey()

			opts := DefaultEncryptionOptions()
			opts.Encryption = tc.encryption
			opts.Algorithm = AlgECDHESA256KW

			encrypted, err := Encrypt(ctx, plaintext, []jwk.Key{pubKey}, opts)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := Decrypt(ctx, encrypted, key)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(decrypted) != string(plaintext) {
				t.Error("Plaintext mismatch")
			}
		})
	}
}

// TestInteropLargeMessage tests handling of large messages
func TestInteropLargeMessage(t *testing.T) {
	ctx := context.Background()

	key, err := generateECDHKey(CurveX25519)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	pubKey, _ := key.PublicKey()

	// Create a large message (1MB)
	largePayload := make([]byte, 1024*1024)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	opts := DefaultEncryptionOptions()
	opts.Encryption = EncXC20P

	encrypted, err := Encrypt(ctx, largePayload, []jwk.Key{pubKey}, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt large message: %v", err)
	}

	decrypted, err := Decrypt(ctx, encrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt large message: %v", err)
	}

	if len(decrypted) != len(largePayload) {
		t.Errorf("Length mismatch: got %d, want %d", len(decrypted), len(largePayload))
	}

	// Verify content
	for i := range decrypted {
		if decrypted[i] != largePayload[i] {
			t.Fatalf("Content mismatch at byte %d", i)
		}
	}

	t.Logf("Large message test passed: %d bytes encrypted", len(largePayload))
}

// Benchmark: XC20P encryption performance
func BenchmarkInteropXC20PEncrypt(b *testing.B) {
	key, _ := generateECDHKey(CurveX25519)
	pubKey, _ := key.PublicKey()
	ctx := context.Background()
	plaintext := []byte(testPayload)

	opts := DefaultEncryptionOptions()
	opts.Encryption = EncXC20P
	opts.Algorithm = AlgECDHESA256KW

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(ctx, plaintext, []jwk.Key{pubKey}, opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark: XC20P decryption performance
func BenchmarkInteropXC20PDecrypt(b *testing.B) {
	key, _ := generateECDHKey(CurveX25519)
	pubKey, _ := key.PublicKey()
	ctx := context.Background()
	plaintext := []byte(testPayload)

	opts := DefaultEncryptionOptions()
	opts.Encryption = EncXC20P
	opts.Algorithm = AlgECDHESA256KW

	encrypted, _ := Encrypt(ctx, plaintext, []jwk.Key{pubKey}, opts)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(ctx, encrypted, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}
