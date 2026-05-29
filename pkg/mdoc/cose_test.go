package mdoc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestNewCOSEKeyFromECDSA(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
		crv   int64
	}{
		{"P-256", elliptic.P256(), CurveP256},
		{"P-384", elliptic.P384(), CurveP384},
		{"P-521", elliptic.P521(), CurveP521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			coseKey, err := NewCOSEKeyFromECDSA(&priv.PublicKey)
			if err != nil {
				t.Fatalf("NewCOSEKeyFromECDSA() error = %v", err)
			}

			if coseKey.Kty != KeyTypeEC2 {
				t.Errorf("Kty = %d, want %d", coseKey.Kty, KeyTypeEC2)
			}
			if coseKey.Crv != tt.crv {
				t.Errorf("Crv = %d, want %d", coseKey.Crv, tt.crv)
			}
			if len(coseKey.X) == 0 {
				t.Error("X is empty")
			}
			if len(coseKey.Y) == 0 {
				t.Error("Y is empty")
			}
		})
	}
}

func TestNewCOSEKeyFromEd25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	coseKey := NewCOSEKeyFromEd25519(pub)

	if coseKey.Kty != KeyTypeOKP {
		t.Errorf("Kty = %d, want %d", coseKey.Kty, KeyTypeOKP)
	}
	if coseKey.Crv != CurveEd25519 {
		t.Errorf("Crv = %d, want %d", coseKey.Crv, CurveEd25519)
	}
	if len(coseKey.X) != ed25519.PublicKeySize {
		t.Errorf("X length = %d, want %d", len(coseKey.X), ed25519.PublicKeySize)
	}
}

func TestNewCOSEKeyFromCoordinates(t *testing.T) {
	tests := []struct {
		name    string
		kty     string
		crv     string
		wantKty int64
		wantCrv int64
		wantErr bool
	}{
		{"P-256", "EC", "P-256", KeyTypeEC2, CurveP256, false},
		{"P-384", "EC", "P-384", KeyTypeEC2, CurveP384, false},
		{"P-521", "EC", "P-521", KeyTypeEC2, CurveP521, false},
		{"Ed25519", "OKP", "Ed25519", KeyTypeOKP, CurveEd25519, false},
		{"Invalid kty", "RSA", "P-256", 0, 0, true},
		{"Invalid crv", "EC", "secp256k1", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xBytes := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
			yBytes := []byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

			coseKey, err := NewCOSEKeyFromCoordinates(tt.kty, tt.crv, xBytes, yBytes)
			if tt.wantErr {
				if err == nil {
					t.Error("NewCOSEKeyFromCoordinates() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewCOSEKeyFromCoordinates() error = %v", err)
			}

			if coseKey.Kty != tt.wantKty {
				t.Errorf("Kty = %d, want %d", coseKey.Kty, tt.wantKty)
			}
			if coseKey.Crv != tt.wantCrv {
				t.Errorf("Crv = %d, want %d", coseKey.Crv, tt.wantCrv)
			}
			if len(coseKey.X) == 0 {
				t.Error("X is empty")
			}
		})
	}
}

func TestNewCOSEKeyFromCoordinates_RoundTrip(t *testing.T) {
	// Generate a real key and verify round-trip
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	byteLen := (priv.Curve.Params().BitSize + 7) / 8
	x := priv.PublicKey.X.Bytes()
	y := priv.PublicKey.Y.Bytes()

	// Pad to correct length
	if len(x) < byteLen {
		x = append(make([]byte, byteLen-len(x)), x...)
	}
	if len(y) < byteLen {
		y = append(make([]byte, byteLen-len(y)), y...)
	}

	coseKey, err := NewCOSEKeyFromCoordinates("EC", "P-256", x, y)
	if err != nil {
		t.Fatalf("NewCOSEKeyFromCoordinates() error = %v", err)
	}

	// Convert back to public key
	pub, err := coseKey.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey() error = %v", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("ToPublicKey() did not return *ecdsa.PublicKey")
	}

	if ecdsaPub.X.Cmp(priv.PublicKey.X) != 0 || ecdsaPub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("Round-trip returned different key")
	}
}

func TestCOSEKey_ToPublicKey_ECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	coseKey, err := NewCOSEKeyFromECDSA(&priv.PublicKey)
	if err != nil {
		t.Fatalf("NewCOSEKeyFromECDSA() error = %v", err)
	}

	pub, err := coseKey.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey() error = %v", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("ToPublicKey() did not return *ecdsa.PublicKey")
	}

	if ecdsaPub.X.Cmp(priv.PublicKey.X) != 0 || ecdsaPub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("ToPublicKey() returned different key")
	}
}

func TestCOSEKey_ToPublicKey_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	coseKey := NewCOSEKeyFromEd25519(pub)

	recovered, err := coseKey.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey() error = %v", err)
	}

	ed25519Pub, ok := recovered.(ed25519.PublicKey)
	if !ok {
		t.Fatal("ToPublicKey() did not return ed25519.PublicKey")
	}

	if !pub.Equal(ed25519Pub) {
		t.Error("ToPublicKey() returned different key")
	}
}

func TestCOSEKey_Bytes(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	coseKey, err := NewCOSEKeyFromECDSA(&priv.PublicKey)
	if err != nil {
		t.Fatalf("NewCOSEKeyFromECDSA() error = %v", err)
	}

	data, err := coseKey.Bytes()
	if err != nil {
		t.Fatalf("Bytes() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Bytes() returned empty data")
	}
}

func TestSign1AndVerify1_ECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	payload := []byte("test payload")

	signed, err := Sign1(payload, priv, AlgorithmES256, nil, nil)
	if err != nil {
		t.Fatalf("Sign1() error = %v", err)
	}

	if signed == nil {
		t.Fatal("Sign1() returned nil")
	}
	if len(signed.Signature) == 0 {
		t.Error("Sign1() returned empty signature")
	}
	if len(signed.Protected) == 0 {
		t.Error("Sign1() returned empty protected headers")
	}

	// Verify
	if err := Verify1(signed, nil, &priv.PublicKey, nil); err != nil {
		t.Errorf("Verify1() error = %v", err)
	}
}

func TestSign1AndVerify1_EdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	payload := []byte("test payload for EdDSA")

	signed, err := Sign1(payload, priv, AlgorithmEdDSA, nil, nil)
	if err != nil {
		t.Fatalf("Sign1() error = %v", err)
	}

	if err := Verify1(signed, nil, pub, nil); err != nil {
		t.Errorf("Verify1() error = %v", err)
	}
}

func TestSign1Detached(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	payload := []byte("detached payload")

	signed, err := Sign1Detached(payload, priv, AlgorithmES256, nil, nil)
	if err != nil {
		t.Fatalf("Sign1Detached() error = %v", err)
	}

	if signed.Payload != nil {
		t.Error("Sign1Detached() should have nil payload")
	}

	// Verify with detached payload
	if err := Verify1(signed, payload, &priv.PublicKey, nil); err != nil {
		t.Errorf("Verify1() with detached payload error = %v", err)
	}
}

func TestSign1WithCertificateChain(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Create a self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	payload := []byte("payload with cert")
	x5chain := [][]byte{certDER}

	signed, err := Sign1(payload, priv, AlgorithmES256, x5chain, nil)
	if err != nil {
		t.Fatalf("Sign1() error = %v", err)
	}

	// Extract certificate chain
	certs, err := GetCertificateChainFromSign1(signed)
	if err != nil {
		t.Fatalf("GetCertificateChainFromSign1() error = %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("GetCertificateChainFromSign1() returned %d certs, want 1", len(certs))
	}
}

func TestVerify1_InvalidSignature(t *testing.T) {
	priv1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	payload := []byte("test payload")

	signed, err := Sign1(payload, priv1, AlgorithmES256, nil, nil)
	if err != nil {
		t.Fatalf("Sign1() error = %v", err)
	}

	// Verify with wrong key should fail
	if err := Verify1(signed, nil, &priv2.PublicKey, nil); err == nil {
		t.Error("Verify1() should fail with wrong key")
	}
}

func TestCOSESign1_MarshalUnmarshal(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte("test")

	signed, err := Sign1(payload, priv, AlgorithmES256, nil, nil)
	if err != nil {
		t.Fatalf("Sign1() error = %v", err)
	}

	// Marshal
	data, err := signed.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR() error = %v", err)
	}

	// Unmarshal
	var decoded COSESign1
	if err := decoded.UnmarshalCBOR(data); err != nil {
		t.Fatalf("UnmarshalCBOR() error = %v", err)
	}

	if string(decoded.Payload) != string(signed.Payload) {
		t.Error("Payload mismatch after round trip")
	}
}

func TestMac0AndVerifyCOSEMac0(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}

	payload := []byte("MAC payload")

	mac0, err := Mac0(payload, key, AlgorithmHMAC256, nil)
	if err != nil {
		t.Fatalf("Mac0() error = %v", err)
	}

	if mac0 == nil {
		t.Fatal("Mac0() returned nil")
	}
	if len(mac0.Tag) == 0 {
		t.Error("Mac0() returned empty tag")
	}

	// Verify
	if err := VerifyCOSEMac0(mac0, key, nil); err != nil {
		t.Fatalf("VerifyCOSEMac0() error = %v", err)
	}
}

func TestVerifyCOSEMac0_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	payload := []byte("MAC payload")

	mac0, err := Mac0(payload, key1, AlgorithmHMAC256, nil)
	if err != nil {
		t.Fatalf("Mac0() error = %v", err)
	}

	// Verify with wrong key should fail
	if err := VerifyCOSEMac0(mac0, key2, nil); err == nil {
		t.Error("VerifyCOSEMac0() should fail with wrong key")
	}
}

func TestCOSEMac0_MarshalUnmarshal(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	mac0, err := Mac0([]byte("test"), key, AlgorithmHMAC256, nil)
	if err != nil {
		t.Fatalf("Mac0() error = %v", err)
	}

	data, err := mac0.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR() error = %v", err)
	}

	var decoded COSEMac0
	if err := decoded.UnmarshalCBOR(data); err != nil {
		t.Fatalf("UnmarshalCBOR() error = %v", err)
	}

	if string(decoded.Payload) != string(mac0.Payload) {
		t.Error("Payload mismatch after round trip")
	}
}

func TestCOSEMac0_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm int64
		keyLen    int
	}{
		{"HMAC-SHA256", AlgorithmHMAC256, 32},
		{"HMAC-SHA384", AlgorithmHMAC384, 48},
		{"HMAC-SHA512", AlgorithmHMAC512, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			rand.Read(key)

			payload := []byte("Test message from SUNET")

			mac0, err := Mac0(payload, key, tt.algorithm, nil)
			if err != nil {
				t.Fatalf("Mac0() error = %v", err)
			}

			if mac0 == nil {
				t.Fatal("Mac0() returned nil")
			}

			if err := VerifyCOSEMac0(mac0, key, nil); err != nil {
				t.Fatalf("VerifyCOSEMac0() error = %v", err)
			}
		})
	}
}

func TestCOSEMac0_WithExternalAAD(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	payload := []byte("payload data")
	externalAAD := []byte("external additional authenticated data")

	mac0, err := Mac0(payload, key, AlgorithmHMAC256, externalAAD)
	if err != nil {
		t.Fatalf("Mac0() error = %v", err)
	}

	// Verify with correct AAD
	if err := VerifyCOSEMac0(mac0, key, externalAAD); err != nil {
		t.Fatalf("VerifyCOSEMac0() with correct AAD error = %v", err)
	}

	// Verify with wrong AAD should fail
	if err := VerifyCOSEMac0(mac0, key, []byte("wrong AAD")); err == nil {
		t.Error("VerifyCOSEMac0() should fail with wrong AAD")
	}

	// Verify with nil AAD should fail
	if err := VerifyCOSEMac0(mac0, key, nil); err == nil {
		t.Error("VerifyCOSEMac0() should fail with nil AAD when original had AAD")
	}
}

func TestCOSEMac0_TamperedPayload(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	payload := []byte("original payload")

	mac0, err := Mac0(payload, key, AlgorithmHMAC256, nil)
	if err != nil {
		t.Fatalf("Mac0() error = %v", err)
	}

	// Tamper with payload
	mac0.Payload = []byte("tampered payload")

	if err := VerifyCOSEMac0(mac0, key, nil); err == nil {
		t.Error("VerifyCOSEMac0() should fail with tampered payload")
	}
}

func TestCOSEMac0_UnsupportedAlgorithm(t *testing.T) {
	key := make([]byte, 32)
	payload := []byte("test")

	_, err := Mac0(payload, key, 9999, nil) // Invalid algorithm
	if err == nil {
		t.Error("Mac0() should fail with unsupported algorithm")
	}
}

func TestAlgorithmForKey(t *testing.T) {
	tests := []struct {
		name      string
		curve     elliptic.Curve
		wantAlg   int64
		wantError bool
	}{
		{"P-256", elliptic.P256(), AlgorithmES256, false},
		{"P-384", elliptic.P384(), AlgorithmES384, false},
		{"P-521", elliptic.P521(), AlgorithmES512, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, _ := ecdsa.GenerateKey(tt.curve, rand.Reader)
			alg, err := AlgorithmForKey(&priv.PublicKey)

			if tt.wantError && err == nil {
				t.Error("AlgorithmForKey() should return error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("AlgorithmForKey() error = %v", err)
			}
			if alg != tt.wantAlg {
				t.Errorf("AlgorithmForKey() = %d, want %d", alg, tt.wantAlg)
			}
		})
	}
}

func TestAlgorithmForKey_Ed25519(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	alg, err := AlgorithmForKey(pub)
	if err != nil {
		t.Fatalf("AlgorithmForKey() error = %v", err)
	}

	if alg != AlgorithmEdDSA {
		t.Errorf("AlgorithmForKey() = %d, want %d", alg, AlgorithmEdDSA)
	}
}

func TestNewCOSEHeaders(t *testing.T) {
	headers := NewCOSEHeaders()

	if headers == nil {
		t.Fatal("NewCOSEHeaders() returned nil")
	}
	if headers.Protected == nil {
		t.Error("Protected map is nil")
	}
	if headers.Unprotected == nil {
		t.Error("Unprotected map is nil")
	}
}
