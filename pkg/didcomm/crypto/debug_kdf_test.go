package crypto

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestDebugECDH1PUKeyDerivation(t *testing.T) {
	// Parse protected header from the correct Rust test vector
	protectedB64 := "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ"

	protectedJSON, err := base64.RawURLEncoding.DecodeString(protectedB64)
	if err != nil {
		t.Fatalf("Failed to decode protected: %v", err)
	}
	t.Logf("Protected Header JSON: %s", protectedJSON)

	var header JWEHeader
	if err := json.Unmarshal(protectedJSON, &header); err != nil {
		t.Fatalf("Failed to parse header: %v", err)
	}

	t.Logf("Algorithm: %s", header.Algorithm)
	t.Logf("Encryption: %s", header.Encryption)
	t.Logf("APU (base64): %s", header.AgreementPartyUInfo)
	t.Logf("APV (base64): %s", header.AgreementPartyVInfo)

	// Decode APU and APV
	apu, err := base64.RawURLEncoding.DecodeString(header.AgreementPartyUInfo)
	if err != nil {
		t.Fatalf("Failed to decode APU: %v", err)
	}
	apv, err := base64.RawURLEncoding.DecodeString(header.AgreementPartyVInfo)
	if err != nil {
		t.Fatalf("Failed to decode APV: %v", err)
	}

	t.Logf("APU decoded: %s (%d bytes)", string(apu), len(apu))
	t.Logf("APV decoded (hex): %x (%d bytes)", apv, len(apv))

	// Decode the authentication tag from the test vector
	tagB64 := "uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U"
	ccTag, err := base64.RawURLEncoding.DecodeString(tagB64)
	if err != nil {
		t.Fatalf("Failed to decode tag: %v", err)
	}
	t.Logf("Authentication tag: %x (%d bytes)", ccTag, len(ccTag))

	// Parse EPK from header
	epkJSON, err := json.Marshal(header.EphemeralPublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal EPK: %v", err)
	}
	t.Logf("EPK JSON: %s", epkJSON)

	epk, err := jwk.ParseKey(epkJSON)
	if err != nil {
		t.Fatalf("Failed to parse EPK: %v", err)
	}

	// Parse keys
	aliceKey, err := jwk.ParseKey([]byte(aliceKeyX25519JWK))
	if err != nil {
		t.Fatalf("Failed to parse Alice's key: %v", err)
	}
	bobKey, err := jwk.ParseKey([]byte(bobKeyX25519_1JWK))
	if err != nil {
		t.Fatalf("Failed to parse Bob's key: %v", err)
	}
	alicePub, _ := aliceKey.PublicKey()

	// Extract ECDH keys
	var bobPrivRaw any
	if err := jwk.Export(bobKey, &bobPrivRaw); err != nil {
		t.Fatalf("Failed to export Bob's key: %v", err)
	}
	bobPriv := bobPrivRaw.(*ecdh.PrivateKey)

	var alicePubRaw any
	if err := jwk.Export(alicePub, &alicePubRaw); err != nil {
		t.Fatalf("Failed to export Alice's public key: %v", err)
	}
	alicePubEC := alicePubRaw.(*ecdh.PublicKey)

	var epkRaw any
	if err := jwk.Export(epk, &epkRaw); err != nil {
		t.Fatalf("Failed to export EPK: %v", err)
	}
	epkPub := epkRaw.(*ecdh.PublicKey)

	// Compute Z_es = ECDH(bob_private, epk)
	zES, err := bobPriv.ECDH(epkPub)
	if err != nil {
		t.Fatalf("Failed to compute Z_es: %v", err)
	}
	t.Logf("Z_es: %x (%d bytes)", zES, len(zES))

	// Compute Z_ss = ECDH(bob_private, alice_public)
	zSS, err := bobPriv.ECDH(alicePubEC)
	if err != nil {
		t.Fatalf("Failed to compute Z_ss: %v", err)
	}
	t.Logf("Z_ss: %x (%d bytes)", zSS, len(zSS))

	// Z = Z_es || Z_ss
	z := append(zES, zSS...)
	t.Logf("Z (combined): %x (%d bytes)", z, len(z))

	// Derive key using Concat KDF (without tag - should fail)
	algorithm := "ECDH-1PU+A256KW"
	keySize := 32

	t.Logf("\n=== Testing WITHOUT cc_tag ===")
	derivedKeyNoTag, err := concatKDF(z, algorithm, apu, apv, keySize)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	t.Logf("Derived key (no tag): %x (%d bytes)", derivedKeyNoTag, len(derivedKeyNoTag))

	// Wrapped key from recipient 1 (did:example:bob#key-x25519-1)
	wrappedKeyB64 := "o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB"
	wrappedKey, err := base64.RawURLEncoding.DecodeString(wrappedKeyB64)
	if err != nil {
		t.Fatalf("Failed to decode wrapped key: %v", err)
	}
	t.Logf("Wrapped key: %x (%d bytes)", wrappedKey, len(wrappedKey))

	// Try to unwrap without tag
	cek, err := unwrapKeyAES(wrappedKey, derivedKeyNoTag)
	if err != nil {
		t.Logf("Failed to unwrap CEK without tag (expected): %v", err)
	} else {
		t.Logf("Successfully unwrapped CEK without tag: %x (%d bytes)", cek, len(cek))
	}

	t.Logf("\n=== Testing WITH cc_tag (ECDH-1PU key commitment) ===")
	derivedKeyWithTag, err := concatKDF1PU(z, algorithm, apu, apv, ccTag, keySize)
	if err != nil {
		t.Fatalf("Failed to derive key with tag: %v", err)
	}
	t.Logf("Derived key (with tag): %x (%d bytes)", derivedKeyWithTag, len(derivedKeyWithTag))

	// Build OtherInfo for debugging
	otherInfo := buildOtherInfoWithTag(algorithm, apu, apv, ccTag, keySize)
	t.Logf("OtherInfo with tag: %x", otherInfo)

	// Try to unwrap with tag
	cek, err = unwrapKeyAES(wrappedKey, derivedKeyWithTag)
	if err != nil {
		t.Logf("Failed to unwrap CEK with tag: %v", err)
	} else {
		t.Logf("Successfully unwrapped CEK with tag: %x (%d bytes)", cek, len(cek))
	}
}

// Helper function to build OtherInfo with tag for debugging
func buildOtherInfoWithTag(algorithm string, apu, apv, ccTag []byte, keySize int) []byte {
	algorithmBytes := []byte(algorithm)

	// Calculate buffer size
	bufSize := 4 + len(algorithmBytes) + 4 + len(apu) + 4 + len(apv) + 4
	if len(ccTag) > 0 {
		bufSize += 4 + len(ccTag)
	}

	otherInfo := make([]byte, 0, bufSize)

	// AlgorithmID
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(algorithmBytes)))
	otherInfo = append(otherInfo, length...)
	otherInfo = append(otherInfo, algorithmBytes...)

	// PartyUInfo (APU)
	binary.BigEndian.PutUint32(length, uint32(len(apu)))
	otherInfo = append(otherInfo, length...)
	otherInfo = append(otherInfo, apu...)

	// PartyVInfo (APV)
	binary.BigEndian.PutUint32(length, uint32(len(apv)))
	otherInfo = append(otherInfo, length...)
	otherInfo = append(otherInfo, apv...)

	// SuppPubInfo: keydatalen (key length in bits, big-endian)
	keySizeBits := make([]byte, 4)
	binary.BigEndian.PutUint32(keySizeBits, uint32(keySize*8))
	otherInfo = append(otherInfo, keySizeBits...)

	// SuppPubInfo: ccTag (if present)
	if len(ccTag) > 0 {
		binary.BigEndian.PutUint32(length, uint32(len(ccTag)))
		otherInfo = append(otherInfo, length...)
		otherInfo = append(otherInfo, ccTag...)
	}

	return otherInfo
}
