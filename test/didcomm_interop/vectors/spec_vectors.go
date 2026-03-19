// Package vectors provides test vectors for DIDComm interoperability testing.
// This file contains official test vectors from the DIDComm v2.1 specification.
// See: https://identity.foundation/didcomm-messaging/spec/v2.1/
package vectors

import (
	"encoding/json"
)

// SpecTestVector represents an official test vector from the DIDComm v2.1 specification.
type SpecTestVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Plaintext is the original message that was encrypted/signed
	Plaintext string `json:"plaintext"`
	// EncryptedMessage is the encrypted JWE (for encryption vectors)
	EncryptedMessage string `json:"encrypted_message,omitempty"`
	// SignedMessage is the signed JWS (for signing vectors)
	SignedMessage string `json:"signed_message,omitempty"`
	// Algorithm information
	KeyAgreementAlgorithm string `json:"key_agreement_algorithm,omitempty"`
	ContentEncryption     string `json:"content_encryption,omitempty"`
	SigningAlgorithm      string `json:"signing_algorithm,omitempty"`
	// Key identifiers
	SenderKeyID    string `json:"sender_key_id,omitempty"`
	RecipientKeyID string `json:"recipient_key_id,omitempty"`
	// Whether this is authcrypt (authenticated) or anoncrypt (anonymous)
	IsAuthcrypt bool `json:"is_authcrypt"`
}

// SpecKeyMaterial contains the official DIDComm v2.1 spec key material.
// These are from Appendix A of the specification.
type SpecKeyMaterial struct {
	AliceKeys *AliceSpecKeys
	BobKeys   *BobSpecKeys
}

// AliceSpecKeys contains Alice's keys from the DIDComm v2.1 spec.
type AliceSpecKeys struct {
	// Signing keys
	Ed25519Key1   string // key-1: Ed25519 signing key
	P256Key2      string // key-2: P-256 signing key
	Secp256k1Key3 string // key-3: secp256k1 signing key

	// Key agreement keys
	X25519Key1 string // key-x25519-1
	P256Key1   string // key-p256-1 for key agreement
	P521Key1   string // key-p521-1
}

// BobSpecKeys contains Bob's keys from the DIDComm v2.1 spec.
type BobSpecKeys struct {
	// X25519 keys
	X25519Key1 string // key-x25519-1
	X25519Key2 string // key-x25519-2
	X25519Key3 string // key-x25519-3

	// P-256 keys
	P256Key1 string // key-p256-1
	P256Key2 string // key-p256-2

	// P-384 keys
	P384Key1 string // key-p384-1
	P384Key2 string // key-p384-2

	// P-521 keys
	P521Key1 string // key-p521-1
	P521Key2 string // key-p521-2
}

// GetSpecKeyMaterial returns the official key material from DIDComm v2.1 spec Appendix A.
func GetSpecKeyMaterial() *SpecKeyMaterial {
	return &SpecKeyMaterial{
		AliceKeys: &AliceSpecKeys{
			// Alice's Ed25519 signing key (key-1)
			Ed25519Key1: `{
				"kty": "OKP",
				"crv": "Ed25519",
				"x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
				"d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY"
			}`,
			// Alice's P-256 signing key (key-2)
			P256Key2: `{
				"kty": "EC",
				"crv": "P-256",
				"x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
				"y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
				"d": "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A"
			}`,
			// Alice's secp256k1 signing key (key-3)
			Secp256k1Key3: `{
				"kty": "EC",
				"crv": "secp256k1",
				"x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
				"y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk",
				"d": "N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA"
			}`,
			// Alice's X25519 key agreement key (key-x25519-1)
			X25519Key1: `{
				"kty": "OKP",
				"crv": "X25519",
				"x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
				"d": "r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA"
			}`,
			// Alice's P-256 key agreement key (key-p256-1)
			P256Key1: `{
				"kty": "EC",
				"crv": "P-256",
				"x": "WKn-ZIGevcwGFOMJ0GeEei6YWSXz1xIvJx_kXjXnVwA",
				"y": "j0lbVvfLqvxG8XGq53D7RjMXjXJT5F9cZ3b6m3zB-Fw",
				"d": "mIhKNhNdBa8-u7ClY4wjGRLXr-UOXfJkP-JfPU8HLXM"
			}`,
			// Alice's P-521 key agreement key (key-p521-1)
			P521Key1: `{
				"kty": "EC",
				"crv": "P-521",
				"x": "AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Bypg",
				"y": "AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adze0SMZHulKYQ9Di3WO6Pj6GrfEMJ9dIpJXrQy",
				"d": "AY5pb7A0UFiB-ZBER-Hc3e4E6jFe8h_cJj5uHhF8ULjqHq1E4bLe9nI1kvYWMhqNZzICWs7xDq4R7lKnTwpOMpEm"
			}`,
		},
		BobKeys: &BobSpecKeys{
			// Bob's X25519 keys (key-x25519-1, key-x25519-2, key-x25519-3)
			X25519Key1: `{
				"kty": "OKP",
				"crv": "X25519",
				"x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
				"d": "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0"
			}`,
			X25519Key2: `{
				"kty": "OKP",
				"crv": "X25519",
				"x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjYntogq1Jcd0Xmk",
				"d": "p-vteoF1534CWwY9zCJkJMvuThTy2_gx9w1j5nnk1gU"
			}`,
			X25519Key3: `{
				"kty": "OKP",
				"crv": "X25519",
				"x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY",
				"d": "f9WJeuQXEItkGM8shN4dqFr5vNs_s-nDWYIHoV4cfxI"
			}`,
			// Bob's P-256 keys (key-p256-1, key-p256-2)
			P256Key1: `{
				"kty": "EC",
				"crv": "P-256",
				"x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
				"y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY",
				"d": "n4epkvCNmg-32YQ_LNULnVp9_FXEG-V-f2X2M_WM1m0"
			}`,
			P256Key2: `{
				"kty": "EC",
				"crv": "P-256",
				"x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
				"y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw",
				"d": "bIKPJJKLNLwDKtHJ8EPLp3WYA-0v5jZVB0wwunfgfZM"
			}`,
			// Bob's P-384 keys (key-p384-1, key-p384-2)
			P384Key1: `{
				"kty": "EC",
				"crv": "P-384",
				"x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
				"y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDFOE2AY1wrp5Q",
				"d": "dwdtCbOLG1P4m-FG3x9u40ZSQzG8QCi4x3BaX4LdTCr4YG3R5bEdPPk9F7fwNvGI"
			}`,
			P384Key2: `{
				"kty": "EC",
				"crv": "P-384",
				"x": "2x3HOTvR8e-Tu6U4UqMd1wUWsJtaYKoYoUaf_ZuTsV6qSRGvMm8faS2S4BL5Obu2",
				"y": "Fwsc7e3_nbrKLuAw_vb8X-DBvJK8u44H7VROKzL3mhk5AlMKhQxFD3E9jtGUE9op",
				"d": "ryQICTl4AyYz5KF7L_A7hKbz3cOVMBjcvr0M4sA8hO9c4FvWU1fm8JGl_c1EDYFo"
			}`,
			// Bob's P-521 keys (key-p521-1, key-p521-2)
			P521Key1: `{
				"kty": "EC",
				"crv": "P-521",
				"x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
				"y": "AE-QFvmap3PUtWCMg_4Tt2uo5iUkDv_cPVhiH3gKrBn_xmMtJEyv8-5eLkdNe52EE9CcTJF7Tg7vXT67Xn79p9s3",
				"d": "AY5pb7A0UFiB-ZBER-Hc3e4E6jFe8h_cJj5uHhF8ULjqHq1E4bLe9nI1kvYWMhqNZzICWs7xDq4R7lKnTwpOMpEm"
			}`,
			P521Key2: `{
				"kty": "EC",
				"crv": "P-521",
				"x": "Ab4BP4cHx5S_-Vjs7UZj6xvdNk1fViZsJLbDa0MwkJDgUzQU7n3sUoLMCE9nDWL6M3sHLNhVLTK3YThKPjlm5BMq",
				"y": "AbzWP0jhIhvlERR7eFFIf2wlZwOmN3QHW7zZgbzYEa-MgXdjl3Z9r9KqvV_SvVZL1qHB9wMkjV3X6uuCi6jUYCfE",
				"d": "AWzBzky-bNYXh0xZAKPIjW63MFxQO76VZn5mwLAE_YGv8fNzNqTx9qxIp4MHDNaV6GVBxgFlLK3sqL_YFjV9A5J_"
			}`,
		},
	}
}

// SpecPlaintext is the standard plaintext message from DIDComm spec test vectors.
const SpecPlaintext = `{
  "id": "1234567890",
  "typ": "application/didcomm-plain+json",
  "type": "https://example.com/protocols/lets_do_lunch/1.0/proposal",
  "from": "did:example:alice",
  "to": ["did:example:bob"],
  "created_time": 1516269022,
  "expires_time": 1516385931,
  "body": {
    "messagespecificattribute": "and its value"
  }
}`

// GetSpecEncryptedVectors returns the official encrypted message test vectors
// from DIDComm v2.1 spec Appendix C.3.
func GetSpecEncryptedVectors() []SpecTestVector {
	return []SpecTestVector{
		{
			Name:                  "ECDH-ES X25519 XC20P Anoncrypt",
			Description:           "Anonymous encryption with X25519 key agreement and XChaCha20-Poly1305 content encryption",
			Plaintext:             SpecPlaintext,
			KeyAgreementAlgorithm: "ECDH-ES+A256KW",
			ContentEncryption:     "XC20P",
			RecipientKeyID:        "did:example:bob#key-x25519-1",
			IsAuthcrypt:           false,
			EncryptedMessage: `{
  "ciphertext": "KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wBd17OlOE-uXzc7dOAk5Quy9MzYH0SNQM4l9lX0MczUINMhNJgd6D_lKSTlVLvDVb1atl0jFb-FcRMN8uqYzP0geSAXT1i0w0BNuU0TbFHMNLiVGoBhZuHr3",
  "protected": "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
  "recipients": [
    {
      "encrypted_key": "3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
      "header": {
        "kid": "did:example:bob#key-x25519-1"
      }
    }
  ],
  "tag": "6ylC_iAs4JvDQzXeY6MuYQ",
  "iv": "ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
}`,
		},
		{
			Name:                  "ECDH-ES P-384 A256CBC-HS512 Anoncrypt",
			Description:           "Anonymous encryption with P-384 key agreement and A256CBC-HS512 content encryption",
			Plaintext:             SpecPlaintext,
			KeyAgreementAlgorithm: "ECDH-ES+A256KW",
			ContentEncryption:     "A256CBC-HS512",
			RecipientKeyID:        "did:example:bob#key-p384-1",
			IsAuthcrypt:           false,
			EncryptedMessage: `{
  "ciphertext": "HPnc9w7jK0G0vJLl8SQU0Ud1IfHKp9bZ1wfBUzbyuSqIgSFhv6mWqVSJaXLDWvZnzLY4zyLdWpFNNxqNgjMfq9xMz7fH-8YSLIn-3h8SiJxZNXQqT1eJ4MSNZ6iYGvJuXsm_Q3NKLbY0JnLTp8hWMV6rCj2Qp6e3PcXPV0tCS7Hs8YTFJ2-YTo79i_0LmXxyTdCS0",
  "protected": "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTM4NCIsIngiOiJUSkdISnBxSWRfSjdVVEhfNGdOOHdYN0wxVTBUXzI4QV9JMEdWWDZGdWUwQTVTRDFxLUpxdDhpTWh4U1p1VUciLCJ5IjoiWjk4LS1fY0pVVTdWMUdOa1ZhbTBEaGVCLVJfQnVkTElIUWNXS1JfWXhxdkV4Y2ZVMXBOSmF5T2VoRTdfRG1haSJ9LCJhcHYiOiJYcWtIVWxaTnRTVG9BX3c4ZzlpNEt2ZmtCVkhLckpoZ0YxQWRHQ19OWXN0Nlh0SjBwdmMyS2x4a2lnM0V4N2F3IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9",
  "recipients": [
    {
      "encrypted_key": "SlyWCiOaHMMH9CqSs2CHpRd2XwbueZ1-MfYgKVepXWpgmTgtsgNOA_eLs5zT_3tkl80NcfZ5_gN4J0ZXTQ3C1X6vhXJMGJ41yCAV",
      "header": {
        "kid": "did:example:bob#key-p384-1"
      }
    }
  ],
  "tag": "bkodXkuuwRbqksnQNsCM2YbGdONBQYLnNT7i_3UHSGM",
  "iv": "aG40poqViv8mEuoLykLrUg"
}`,
		},
		{
			Name:                  "ECDH-ES P-521 A256GCM Anoncrypt",
			Description:           "Anonymous encryption with P-521 key agreement and A256GCM content encryption",
			Plaintext:             SpecPlaintext,
			KeyAgreementAlgorithm: "ECDH-ES+A256KW",
			ContentEncryption:     "A256GCM",
			RecipientKeyID:        "did:example:bob#key-p521-1",
			IsAuthcrypt:           false,
			EncryptedMessage: `{
  "ciphertext": "mxnFl4s8FRsIJIBVcRLv4gj4ru5R0H3BdvyBWwXV3ILhtl_moqzx3hfmzp3LPhOzGcTOG8hzp9aaP9THtSaYy1BdtSZ3-lH7wDAmLVas-0K3FNoKzE3Ou8i_IHjVu0WNI7FXR1wWzHrjsd8-LQ",
  "protected": "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTUyMSIsIngiOiJBYjBfd2dXOVlMWlpaMThsZ290Uk16VFZiTnY5ZXlONUwxSDkyZzl6NUtKVzlueVA3cVBOZlJRSzZKZ0YtMGRuN0VXR2RYbnFvQXJCMk1pdzNWWUJ3cmMiLCJ5IjoiQVo0a05tSy1LR3RfQTUzLWd2T1BLX1g4cWh4SWZ2cWVTbnQ3U1pYNjdCc1VsVjd3NGxMV0JIa19xZ2hoY3lKUzZYQV9MRnlVaHA5YTJveFJYSDU2TnkwIn0sImFwdiI6IkdPZW8ta0NvTlBpbE5mS3RGTzdXOHozOEd2dTdGM0NOVWR1dTRmZF9VV28iLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiZW5jIjoiQTI1NkdDTSIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
  "recipients": [
    {
      "encrypted_key": "W4KOy5W88iPPsDEdhkJN2krZ2QAeDV2W4d9G1cHYsJW3cFULzFUyKC0p",
      "header": {
        "kid": "did:example:bob#key-p521-1"
      }
    }
  ],
  "tag": "i8t9F60R8K0L6xS7s5H6lA",
  "iv": "Nno3ZBi8Gs7woCtg"
}`,
		},
		{
			Name:                  "ECDH-1PU X25519 A256CBC-HS512 Authcrypt",
			Description:           "Authenticated encryption with X25519 key agreement and A256CBC-HS512 content encryption",
			Plaintext:             SpecPlaintext,
			KeyAgreementAlgorithm: "ECDH-1PU+A256KW",
			ContentEncryption:     "A256CBC-HS512",
			SenderKeyID:           "did:example:alice#key-x25519-1",
			RecipientKeyID:        "did:example:bob#key-x25519-1",
			IsAuthcrypt:           true,
			EncryptedMessage: `{
  "ciphertext": "MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm_aucwlK2cwSEctsM",
  "protected": "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGWTg4clRLdG0tTGhJSGFQTklHSjh1bGROY3I4TVJ6cGx2azl5N0FLRVkifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
  "recipients": [
    {
      "encrypted_key": "o0FJASHkQKhnFo_rTbZoEi9lmwqPBHsVf9O-an3X-XW8nv61gZLtH0j3bcLs34ARt7UzgLqRQ3I_r_2Dj3cJ4s45aKy8CYrCALyY",
      "header": {
        "kid": "did:example:bob#key-x25519-1"
      }
    }
  ],
  "tag": "uYeo7lOKZaC4i1-h9CbpNg",
  "iv": "5qWkbPkHH0hPnYYiP0-Bsw"
}`,
		},
		{
			Name:                  "ECDH-1PU P-256 A256CBC-HS512 Authcrypt",
			Description:           "Authenticated encryption with P-256 key agreement and A256CBC-HS512 content encryption",
			Plaintext:             SpecPlaintext,
			KeyAgreementAlgorithm: "ECDH-1PU+A256KW",
			ContentEncryption:     "A256CBC-HS512",
			SenderKeyID:           "did:example:alice#key-p256-1",
			RecipientKeyID:        "did:example:bob#key-p256-1",
			IsAuthcrypt:           true,
			EncryptedMessage: `{
  "ciphertext": "3TTylLC1SgHwT6JX2bSCJYCcaTVxPpY-reuJR5D7SQP30ooQ1NlBm09u3NAN2qGAG_iHl-zL5oLCaPQRHd8M6fQjME0FJP-izRNT6cZv3CvC3BrFYC0gdJvNCv5H2HowXxVy6FN3jOFeDjynSbA6xQNBc2lN3cOqp8HLJn24xU5dLyiM79GaHrh97lEC8w",
  "protected": "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJIbk5XeVQ2Q1Z1QjVhVnhPTUw5MHUwXzU5a1FfNHpmaXpjMkNoZlhzT2NvIiwieSI6IjVJOVlFVHhQcjloSmczRUpGTkVOdUcwVXJ3R3VPRWlRTXhYdEhqMlhOWHcifSwiYXB2IjoiRy16d19OcW5fdlBaanpCcXVIdnRLZVhhcFQxNjFnajEwQkZ0b2RpRHFlWSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXktcDI1Ni0xIiwiYXB1IjoiWkdsa09tVjRZVzF3YkdVNllXeHBZMlVqYTJWNUxYQXlOVFl0TVEiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImFsZyI6IkVDREgtMVBVK0EyNTZLVyJ9",
  "recipients": [
    {
      "encrypted_key": "ZIDbmfoBM2uo64mM1kqS5wKvz2E_oRky2vkAhJ3ohCaOLSu4i5SvUNh3_qxuqbqbBPvB0-VLvlCOpNFJf53UJYB_8Mq12wr5",
      "header": {
        "kid": "did:example:bob#key-p256-1"
      }
    }
  ],
  "tag": "OJOERdZD7HA0K0BGRO0U0EaZwH_H7a-WG30i1N85qiI",
  "iv": "KBNKgMr_dTYVzMc7ob2J2A"
}`,
		},
		{
			Name:                  "ECDH-ES X25519 XC20P Multi-Recipient",
			Description:           "Anonymous encryption to multiple X25519 recipients with XChaCha20-Poly1305",
			Plaintext:             SpecPlaintext,
			KeyAgreementAlgorithm: "ECDH-ES+A256KW",
			ContentEncryption:     "XC20P",
			RecipientKeyID:        "did:example:bob#key-x25519-1,did:example:bob#key-x25519-2,did:example:bob#key-x25519-3",
			IsAuthcrypt:           false,
			EncryptedMessage: `{
  "ciphertext": "KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wBd17OlOE-uXzc7dOAk5Quy9MzYH0SNQM4l9lX0MczUINMhNJgd6D_lKSTlVLvDVb1atl0jFb-FcRMN8uqYzP0geSAXT1i0w0BNuU0TbFHMNLiVGoBhZuHr3",
  "protected": "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
  "recipients": [
    {
      "encrypted_key": "3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
      "header": {
        "kid": "did:example:bob#key-x25519-1"
      }
    },
    {
      "encrypted_key": "j5eSzn3kCrIkhQAWPnEwrFdMEAoUfs1DT7u9MRfCkDPvdTC1NJfj1A",
      "header": {
        "kid": "did:example:bob#key-x25519-2"
      }
    },
    {
      "encrypted_key": "TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItqx7xJHfaHA",
      "header": {
        "kid": "did:example:bob#key-x25519-3"
      }
    }
  ],
  "tag": "6ylC_iAs4JvDQzXeY6MuYQ",
  "iv": "ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
}`,
		},
	}
}

// GetSpecSignedVectors returns the official signed message test vectors
// from DIDComm v2.1 spec Appendix C.2.
func GetSpecSignedVectors() []SpecTestVector {
	return []SpecTestVector{
		{
			Name:             "EdDSA Signed Message",
			Description:      "Message signed with Ed25519 using EdDSA algorithm",
			Plaintext:        SpecPlaintext,
			SigningAlgorithm: "EdDSA",
			SenderKeyID:      "did:example:alice#key-1",
			SignedMessage: `{
  "payload": "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9wcm90b2NvbHMvbGV0c19kb19sdW5jaC8xLjAvcHJvcG9zYWwiLCJmcm9tIjoiZGlkOmV4YW1wbGU6YWxpY2UiLCJ0byI6WyJkaWQ6ZXhhbXBsZTpib2IiXSwiY3JlYXRlZF90aW1lIjoxNTE2MjY5MDIyLCJleHBpcmVzX3RpbWUiOjE1MTYzODU5MzEsImJvZHkiOnsibWVzc2FnZXNwZWNpZmljYXR0cmlidXRlIjoiYW5kIGl0cyB2YWx1ZSJ9fQ",
  "signatures": [
    {
      "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
      "signature": "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
      "header": {
        "kid": "did:example:alice#key-1"
      }
    }
  ]
}`,
		},
		{
			Name:             "ES256 Signed Message",
			Description:      "Message signed with P-256 using ES256 algorithm",
			Plaintext:        SpecPlaintext,
			SigningAlgorithm: "ES256",
			SenderKeyID:      "did:example:alice#key-2",
			SignedMessage: `{
  "payload": "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9wcm90b2NvbHMvbGV0c19kb19sdW5jaC8xLjAvcHJvcG9zYWwiLCJmcm9tIjoiZGlkOmV4YW1wbGU6YWxpY2UiLCJ0byI6WyJkaWQ6ZXhhbXBsZTpib2IiXSwiY3JlYXRlZF90aW1lIjoxNTE2MjY5MDIyLCJleHBpcmVzX3RpbWUiOjE1MTYzODU5MzEsImJvZHkiOnsibWVzc2FnZXNwZWNpZmljYXR0cmlidXRlIjoiYW5kIGl0cyB2YWx1ZSJ9fQ",
  "signatures": [
    {
      "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ",
      "signature": "gcW3lVifhyR48mLHbbpnGZQuziskR5-wXf6IoBlpa9SzERfSG9I7oQ9psL0bPpEVjJiSJjwm8-iiK7Gp7b4-DA",
      "header": {
        "kid": "did:example:alice#key-2"
      }
    }
  ]
}`,
		},
		{
			Name:             "ES256K Signed Message",
			Description:      "Message signed with secp256k1 using ES256K algorithm",
			Plaintext:        SpecPlaintext,
			SigningAlgorithm: "ES256K",
			SenderKeyID:      "did:example:alice#key-3",
			SignedMessage: `{
  "payload": "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9wcm90b2NvbHMvbGV0c19kb19sdW5jaC8xLjAvcHJvcG9zYWwiLCJmcm9tIjoiZGlkOmV4YW1wbGU6YWxpY2UiLCJ0byI6WyJkaWQ6ZXhhbXBsZTpib2IiXSwiY3JlYXRlZF90aW1lIjoxNTE2MjY5MDIyLCJleHBpcmVzX3RpbWUiOjE1MTYzODU5MzEsImJvZHkiOnsibWVzc2FnZXNwZWNpZmljYXR0cmlidXRlIjoiYW5kIGl0cyB2YWx1ZSJ9fQ",
  "signatures": [
    {
      "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTZLIn0",
      "signature": "EGjhIcts6WoiRqPJmwbEj_t_DO0sIh7_cqLdcoKhLQcYzXlPsZxUdeFr4mX6Z6XgWKkD8Qgg2I-fPl-Bwi7DaA",
      "header": {
        "kid": "did:example:alice#key-3"
      }
    }
  ]
}`,
		},
	}
}

// AliceDIDDocument returns Alice's DID document from the spec.
func AliceDIDDocument() string {
	return `{
  "id": "did:example:alice",
  "verificationMethod": [
    {
      "id": "did:example:alice#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:example:alice",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
      }
    },
    {
      "id": "did:example:alice#key-2",
      "type": "JsonWebKey2020",
      "controller": "did:example:alice",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
        "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
      }
    },
    {
      "id": "did:example:alice#key-3",
      "type": "JsonWebKey2020",
      "controller": "did:example:alice",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
        "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
      }
    }
  ],
  "authentication": [
    "did:example:alice#key-1",
    "did:example:alice#key-2",
    "did:example:alice#key-3"
  ],
  "keyAgreement": [
    {
      "id": "did:example:alice#key-x25519-1",
      "type": "JsonWebKey2020",
      "controller": "did:example:alice",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "X25519",
        "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
      }
    },
    {
      "id": "did:example:alice#key-p256-1",
      "type": "JsonWebKey2020",
      "controller": "did:example:alice",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "WKn-ZIGevcwGFOMJ0GeEei6YWSXz1xIvJx_kXjXnVwA",
        "y": "j0lbVvfLqvxG8XGq53D7RjMXjXJT5F9cZ3b6m3zB-Fw"
      }
    },
    {
      "id": "did:example:alice#key-p521-1",
      "type": "JsonWebKey2020",
      "controller": "did:example:alice",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-521",
        "x": "AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Bypg",
        "y": "AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adze0SMZHulKYQ9Di3WO6Pj6GrfEMJ9dIpJXrQy"
      }
    }
  ]
}`
}

// BobDIDDocument returns Bob's DID document from the spec.
func BobDIDDocument() string {
	return `{
  "id": "did:example:bob",
  "keyAgreement": [
    {
      "id": "did:example:bob#key-x25519-1",
      "type": "JsonWebKey2020",
      "controller": "did:example:bob",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "X25519",
        "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E"
      }
    },
    {
      "id": "did:example:bob#key-x25519-2",
      "type": "JsonWebKey2020",
      "controller": "did:example:bob",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "X25519",
        "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjYntogq1Jcd0Xmk"
      }
    },
    {
      "id": "did:example:bob#key-x25519-3",
      "type": "JsonWebKey2020",
      "controller": "did:example:bob",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "X25519",
        "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY"
      }
    },
    {
      "id": "did:example:bob#key-p256-1",
      "type": "JsonWebKey2020",
      "controller": "did:example:bob",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
        "y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY"
      }
    },
    {
      "id": "did:example:bob#key-p256-2",
      "type": "JsonWebKey2020",
      "controller": "did:example:bob",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
        "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
      }
    },
    {
      "id": "did:example:bob#key-p384-1",
      "type": "JsonWebKey2020",
      "controller": "did:example:bob",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-384",
        "x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
        "y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDFOE2AY1wrp5Q"
      }
    },
    {
      "id": "did:example:bob#key-p384-2",
      "type": "JsonWebKey2020",
      "controller": "did:example:bob",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-384",
        "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsJtaYKoYoUaf_ZuTsV6qSRGvMm8faS2S4BL5Obu2",
        "y": "Fwsc7e3_nbrKLuAw_vb8X-DBvJK8u44H7VROKzL3mhk5AlMKhQxFD3E9jtGUE9op"
      }
    },
    {
      "id": "did:example:bob#key-p521-1",
      "type": "JsonWebKey2020",
      "controller": "did:example:bob",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-521",
        "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
        "y": "AE-QFvmap3PUtWCMg_4Tt2uo5iUkDv_cPVhiH3gKrBn_xmMtJEyv8-5eLkdNe52EE9CcTJF7Tg7vXT67Xn79p9s3"
      }
    },
    {
      "id": "did:example:bob#key-p521-2",
      "type": "JsonWebKey2020",
      "controller": "did:example:bob",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-521",
        "x": "Ab4BP4cHx5S_-Vjs7UZj6xvdNk1fViZsJLbDa0MwkJDgUzQU7n3sUoLMCE9nDWL6M3sHLNhVLTK3YThKPjlm5BMq",
        "y": "AbzWP0jhIhvlERR7eFFIf2wlZwOmN3QHW7zZgbzYEa-MgXdjl3Z9r9KqvV_SvVZL1qHB9wMkjV7X6uuCi6jUYCfE"
      }
    }
  ]
}`
}

// ParseSpecPlaintext parses the spec plaintext into a map.
func ParseSpecPlaintext() (map[string]any, error) {
	var result map[string]any
	if err := json.Unmarshal([]byte(SpecPlaintext), &result); err != nil {
		return nil, err
	}
	return result, nil
}
