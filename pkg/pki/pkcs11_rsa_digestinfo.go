package pki

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

// CKM_RSA_PKCS adds PKCS#1 v1.5 PADDING and nothing else. The DigestInfo
// structure that says WHICH hash produced the digest - an ASN.1 SEQUENCE
// wrapping the algorithm identifier and the digest, RFC 8017 §9.2 step 2 -
// is the caller's to supply.
//
// Handing it a bare digest therefore produces a signature that is
// well-formed, verifies as nothing, and fails every RS256/RS384/RS512
// verifier. Go's rsa.SignPKCS1v15 builds the same structure internally,
// which is why the software path never had to think about it; its table of
// prefixes is unexported, so here is the same one.
//
// Only the hashes this repo signs with. A hash with no entry is refused
// rather than signed without its identifier: a signature nobody can verify
// is worse than an error at the point of signing.
var pkcs1v15DigestInfoPrefix = map[crypto.Hash][]byte{
	crypto.SHA256: {
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
		0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
	},
	crypto.SHA384: {
		0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
		0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
	},
	crypto.SHA512: {
		0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
		0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
	},
}

// pkcs1v15DigestInfo wraps digest in the DigestInfo structure CKM_RSA_PKCS
// expects, for the hash named by opts.
func pkcs1v15DigestInfo(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
		// CKM_RSA_PKCS cannot produce a PSS signature, and padding one as
		// v1.5 would produce a signature that verifies as neither. The
		// mechanism for PSS is CKM_RSA_PKCS_PSS, which this binding does
		// not select; refuse rather than sign something wrong.
		return nil, fmt.Errorf("RSA-PSS is not supported by this PKCS#11 binding (it signs with CKM_RSA_PKCS)")
	}

	hash := opts.HashFunc()
	prefix, ok := pkcs1v15DigestInfoPrefix[hash]
	if !ok {
		return nil, fmt.Errorf("no PKCS#1 v1.5 DigestInfo prefix for hash %v", hash)
	}
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("digest is %d bytes, want %d for %v", len(digest), hash.Size(), hash)
	}

	out := make([]byte, 0, len(prefix)+len(digest))
	out = append(out, prefix...)
	out = append(out, digest...)
	return out, nil
}
