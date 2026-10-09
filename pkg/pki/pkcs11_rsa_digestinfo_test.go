package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

// The proof that does not need an HSM.
//
// CKM_RSA_PKCS adds PKCS#1 v1.5 padding and nothing else, which is exactly
// what rsa.SignPKCS1v15 does when given crypto.Hash(0): it treats its input
// as an already-formed DigestInfo and only pads. So signing
// pkcs1v15DigestInfo(...) that way reproduces the HSM's mechanism bit for
// bit - and a standard RS256 verifier either accepts it or the DigestInfo
// is wrong.
//
// Before this, the bare digest went to the mechanism and the result failed
// every RS256/384/512 verifier while looking perfectly well-formed.
func TestPKCS1v15DigestInfoVerifiesAsRSASignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		hash   crypto.Hash
		digest []byte
	}{
		"SHA-256": {crypto.SHA256, digestOf(sha256.New(), "payload")},
		"SHA-384": {crypto.SHA384, digestOf(sha512.New384(), "payload")},
		"SHA-512": {crypto.SHA512, digestOf(sha512.New(), "payload")},
	} {
		t.Run(name, func(t *testing.T) {
			wrapped, err := pkcs1v15DigestInfo(tc.digest, tc.hash)
			if err != nil {
				t.Fatalf("pkcs1v15DigestInfo() error = %v", err)
			}

			// crypto.Hash(0): pad only, exactly as CKM_RSA_PKCS does.
			sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.Hash(0), wrapped)
			if err != nil {
				t.Fatalf("signing the DigestInfo: %v", err)
			}

			if err := rsa.VerifyPKCS1v15(&key.PublicKey, tc.hash, tc.digest, sig); err != nil {
				t.Errorf("a standard verifier rejects the signature: %v", err)
			}
		})
	}
}

// The bare digest - what the binding used to send - must NOT verify. This
// is the half that shows the test above is measuring something.
func TestBareDigestDoesNotVerifyAsRSASignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	digest := digestOf(sha256.New(), "payload")

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.Hash(0), digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest, sig); err == nil {
		t.Fatal("a bare-digest signature verified; the DigestInfo would not be load-bearing")
	}
}

func TestPKCS1v15DigestInfoRefusesWhatItCannotSign(t *testing.T) {
	digest := digestOf(sha256.New(), "payload")

	t.Run("PSS", func(t *testing.T) {
		// CKM_RSA_PKCS cannot produce a PSS signature, and padding one as
		// v1.5 produces something that verifies as neither.
		_, err := pkcs1v15DigestInfo(digest, &rsa.PSSOptions{Hash: crypto.SHA256})
		if err == nil {
			t.Fatal("expected PSS to be refused")
		}
	})

	t.Run("unknown hash", func(t *testing.T) {
		if _, err := pkcs1v15DigestInfo(digest, crypto.SHA1); err == nil {
			t.Fatal("expected a hash with no prefix to be refused")
		}
	})

	t.Run("digest of the wrong length", func(t *testing.T) {
		if _, err := pkcs1v15DigestInfo(digest[:16], crypto.SHA256); err == nil {
			t.Fatal("expected a short digest to be refused")
		}
	})
}

func digestOf(h interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}, s string,
) []byte {
	_, _ = h.Write([]byte(s))
	return h.Sum(nil)
}
