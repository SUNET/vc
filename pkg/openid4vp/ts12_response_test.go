package openid4vp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func vectorByName(t *testing.T, name string) ts12Vector {
	t.Helper()
	for _, v := range loadTS12Vectors(t) {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("vector %q not found", name)
	return ts12Vector{}
}

var goodAMR = []any{
	map[string]any{"knowledge": "pin_6_or_more_digits"},
	map[string]any{"possession": "key_in_local_external_wscd"},
}

// ts12Case is one KB-JWT against one request.
type ts12Case struct {
	entries []string
	queryID string
	modes   []string
	claims  map[string]any // merged over a good base; a nil value deletes the claim
}

func (c ts12Case) validate(t *testing.T) error {
	t.Helper()
	_, err := c.run(t)
	return err
}

func (c ts12Case) run(t *testing.T) (*VPTokenValidator, error) {
	t.Helper()
	holder := testHolderKey(t)
	kb := map[string]any{
		"nonce":         "n-1",
		"aud":           "x509_hash:verifier",
		"iat":           time.Now().Unix(),
		"jti":           "jti-" + time.Now().Format(time.RFC3339Nano),
		"response_mode": "direct_post.jwt",
		"amr":           goodAMR,
	}
	for k, v := range c.claims {
		if v == nil {
			delete(kb, k)
		} else {
			kb[k] = v
		}
	}
	tok := testPresentation(t, testCredentialNaming(t, holder, nil), holder, kb)
	modes := c.modes
	if modes == nil {
		modes = []string{"direct_post.jwt", "dc_api.jwt"}
	}
	v := &VPTokenValidator{
		Nonce: "n-1", ClientID: "x509_hash:verifier",
		TransactionData: c.entries, CredentialQueryID: c.queryID,
		ResponseModes: modes,
	}
	return v, v.Validate(tok)
}

func requireTxError(t *testing.T, err error, contains string) {
	t.Helper()
	require.Error(t, err)
	var er *ErrorResponse
	require.True(t, errors.As(err, &er), "want an ErrorResponse, got %v", err)
	assert.Equal(t, ErrorInvalidTransactionData, er.ErrorCode)
	assert.Contains(t, er.ErrorDescription, contains)
}

// The vector's wallet-side hashes (computed with Python, over the raw string)
// are accepted for a non-canonical entry, and the one a re-serializing wallet
// would produce is not.
func TestTS12Response_GoldenVectorHashes(t *testing.T) {
	for _, name := range []string{"conforming_compact", "conforming_pretty_printed", "conforming_non_canonical_number", "conforming_escapes"} {
		v := vectorByName(t, name)
		t.Run(name, func(t *testing.T) {
			ok := ts12Case{entries: []string{v.Raw}, queryID: "pay", claims: map[string]any{
				"transaction_data_hashes": []string{v.Hashes["sha-256"]},
			}}
			require.NoError(t, ok.validate(t))

			// What a wallet that decodes and re-serializes the entry would send.
			var generic map[string]any
			require.NoError(t, json.Unmarshal([]byte(v.JSON), &generic))
			re, err := json.Marshal(generic)
			require.NoError(t, err)
			reHash, err := HashTransactionData([]string{base64.RawURLEncoding.EncodeToString(re)}, "sha-256")
			require.NoError(t, err)
			require.NotEqual(t, v.Hashes["sha-256"], reHash[0], "vector must be non-canonical for this test to mean anything")
			bad := ts12Case{entries: []string{v.Raw}, queryID: "pay", claims: map[string]any{"transaction_data_hashes": reHash}}
			requireTxError(t, bad.validate(t), "mismatch")
		})
	}
}

func TestTS12Response_HashAlgNegotiation(t *testing.T) {
	v := vectorByName(t, "conforming_hash_alg_array_with_optionals") // request lists sha-256, sha-384
	entries := []string{v.Raw}
	with := func(alg any, hash string) ts12Case {
		c := map[string]any{"transaction_data_hashes": []string{hash}}
		c["transaction_data_hashes_alg"] = alg
		return ts12Case{entries: entries, queryID: "pay", claims: c}
	}
	require.NoError(t, with("sha-256", v.Hashes["sha-256"]).validate(t))
	require.NoError(t, with("sha-384", v.Hashes["sha-384"]).validate(t))
	requireTxError(t, with("sha-512", v.Hashes["sha-512"]).validate(t), "not one the request allowed")
	requireTxError(t, with([]string{"sha-256"}, v.Hashes["sha-256"]).validate(t), "must be a string")
	requireTxError(t, with(nil, v.Hashes["sha-256"]).validate(t), "transaction_data_hashes_alg missing")
	// Right alg named, hash of another alg.
	requireTxError(t, with("sha-384", v.Hashes["sha-256"]).validate(t), "mismatch")

	// No list in the request: the claim may be omitted and defaults to sha-256 (OID4VP B.3.3.1).
	plain := vectorByName(t, "conforming_compact")
	require.NoError(t, ts12Case{entries: []string{plain.Raw}, queryID: "pay", claims: map[string]any{
		"transaction_data_hashes": []string{plain.Hashes["sha-256"]},
	}}.validate(t))
	requireTxError(t, ts12Case{entries: []string{plain.Raw}, queryID: "pay", claims: map[string]any{
		"transaction_data_hashes": []string{plain.Hashes["sha-384"]}, "transaction_data_hashes_alg": "sha-384",
	}}.validate(t), "not one the request allowed")
}

func TestTS12Response_HashesMissingCountAndOrder(t *testing.T) {
	a := vectorByName(t, "conforming_compact")
	b := vectorByName(t, "conforming_escapes")
	entries := []string{a.Raw, b.Raw}
	// both reference "pay"
	both := func(h ...string) ts12Case {
		return ts12Case{entries: entries, queryID: "pay", claims: map[string]any{"transaction_data_hashes": h}}
	}
	require.NoError(t, both(a.Hashes["sha-256"], b.Hashes["sha-256"]).validate(t))
	requireTxError(t, both(b.Hashes["sha-256"], a.Hashes["sha-256"]).validate(t), "mismatch")
	requireTxError(t, both(a.Hashes["sha-256"]).validate(t), "count mismatch")
	requireTxError(t, ts12Case{entries: entries, queryID: "pay"}.validate(t), "transaction_data_hashes missing")
}

// A presentation of a credential no entry references owes no hashes; one an
// entry does reference owes exactly its own, not the other credential's.
func TestTS12Response_ScopedToTheCredentialsEntries(t *testing.T) {
	pay := vectorByName(t, "conforming_compact") // credential_ids ["pay"]
	other := decodedFor(t, `{"type":"urn:eudi:sca:payment:1","credential_ids":["age"],"payload":{}}`)
	entries := []string{other, pay.Raw}

	require.NoError(t, ts12Case{entries: entries, queryID: "pay", claims: map[string]any{
		"transaction_data_hashes": []string{pay.Hashes["sha-256"]},
	}}.validate(t))
	// Including the other credential's hash too is a count mismatch.
	oh, _ := HashTransactionData([]string{other}, "sha-256")
	requireTxError(t, ts12Case{entries: entries, queryID: "pay", claims: map[string]any{
		"transaction_data_hashes": []string{oh[0], pay.Hashes["sha-256"]},
	}}.validate(t), "count mismatch")
	// Nothing references this query: nothing to check.
	require.NoError(t, ts12Case{entries: entries, queryID: "unrelated"}.validate(t))
}

func decodedFor(t *testing.T, js string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(js))
}

func ts12Entry(t *testing.T) (string, string) {
	v := vectorByName(t, "conforming_compact")
	return v.Raw, v.Hashes["sha-256"]
}

func TestTS12Response_AMR(t *testing.T) {
	raw, h := ts12Entry(t)
	run := func(amr any) error {
		return ts12Case{entries: []string{raw}, queryID: "pay", claims: map[string]any{
			"transaction_data_hashes": []string{h}, "amr": amr,
		}}.validate(t)
	}
	require.NoError(t, run(goodAMR))
	require.NoError(t, run([]any{
		map[string]any{"possession": "key_in_remote_wscd"}, map[string]any{"inherence": "face_device"}, map[string]any{"possession": "other"},
	}))

	requireTxError(t, run(nil), "amr missing")
	requireTxError(t, run([]any{"hwk", "pop"}), "exactly one member") // RFC 8176 strings, what the WSCD manager emitted
	requireTxError(t, run([]any{map[string]any{"possession": "key_in_local_external_wscd"}}), "at least 2")
	requireTxError(t, run([]any{
		map[string]any{"possession": "key_in_local_external_wscd"}, map[string]any{"possession": "key_in_remote_wscd"},
	}), "at least 2")
	requireTxError(t, run([]any{
		map[string]any{"knowledge": "pin_6_or_more_digits", "possession": "other"},
	}), "exactly one member")
	requireTxError(t, run([]any{
		map[string]any{"knowledge": "pin_6_or_more_digits"}, map[string]any{"biometric": "other"},
	}), "unknown category")
	requireTxError(t, run([]any{
		map[string]any{"knowledge": "pin_6_or_more_digits"}, map[string]any{"possession": "pin_6_or_more_digits"},
	}), "not a TS12 possession")
	requireTxError(t, run([]any{
		map[string]any{"knowledge": "pin_6_or_more_digits"}, map[string]any{"possession": 1},
	}), "not a TS12 possession")
}

func TestTS12Response_JTIAndResponseMode(t *testing.T) {
	raw, h := ts12Entry(t)
	base := func() ts12Case {
		return ts12Case{entries: []string{raw}, queryID: "pay", claims: map[string]any{"transaction_data_hashes": []string{h}}}
	}

	c := base()
	c.claims["jti"] = nil
	requireTxError(t, c.validate(t), "jti missing")
	c = base()
	c.claims["jti"] = "  "
	requireTxError(t, c.validate(t), "jti missing")

	// The validator reports the jti for the caller to claim after issuer
	// authentication; it never records it itself.
	c = base()
	c.claims["jti"] = "fixed-jti"
	v, err := c.run(t)
	require.NoError(t, err)
	assert.Equal(t, "fixed-jti", v.PresentedJTI)

	// A refused presentation reports nothing to claim.
	c = base()
	c.claims["jti"] = "refused-jti"
	c.claims["amr"] = nil
	v, err = c.run(t)
	require.Error(t, err)
	assert.Empty(t, v.PresentedJTI)

	c = base()
	c.claims["response_mode"] = nil
	requireTxError(t, c.validate(t), "response_mode missing")
	c = base()
	c.claims["response_mode"] = "direct_post"
	requireTxError(t, c.validate(t), "not one this request was issued with")
	c = base()
	c.modes = []string{}
	requireTxError(t, c.validate(t), "cannot verify response_mode")
	c = base()
	c.claims["response_mode"] = "dc_api.jwt"
	require.NoError(t, c.validate(t), "the DC API variant of the same request is a legitimate channel")
}

// A reused validator must not carry the previous presentation's jti.
//
// PresentedJTI is an output, and the caller CLAIMS a non-empty one in a
// JTIStore after issuer authentication - a state change that refuses any
// later presentation reusing that jti. So a stale value is not a cosmetic
// leak: validate an SCA presentation, then reuse the validator for an
// unrelated one that sets no jti, and the caller claims the first jti a
// second time and rejects a valid presentation as a replay.
func TestTS12Response_ReusedValidatorDoesNotCarryTheJTI(t *testing.T) {
	holder := testHolderKey(t)
	cred := testCredentialNaming(t, holder, nil)

	scaEntry, hash := ts12Entry(t)
	v := &VPTokenValidator{
		Nonce: "n-1", ClientID: "x509_hash:verifier",
		TransactionData: []string{scaEntry}, CredentialQueryID: "pay",
		ResponseModes: []string{"direct_post.jwt"},
	}

	sca := testPresentation(t, cred, holder, map[string]any{
		"nonce": "n-1", "aud": "x509_hash:verifier", "iat": time.Now().Unix(),
		"response_mode": "direct_post.jwt", "amr": goodAMR,
		"jti": "first-jti", "transaction_data_hashes": []string{hash},
	})
	require.NoError(t, v.Validate(sca))
	require.Equal(t, "first-jti", v.PresentedJTI, "the premise: the first presentation reports a jti to claim")

	// The same validator, now pointed at an unrelated query with no SCA
	// entry. Nothing writes PresentedJTI on this path.
	other := decodedFor(t, `{"type":"https://example.com/other","credential_ids":["age"]}`)
	hashes, err := HashTransactionData([]string{other}, "sha-256")
	require.NoError(t, err)
	v.TransactionData = []string{other}
	v.CredentialQueryID = "age"

	second := testPresentation(t, cred, holder, map[string]any{
		"nonce": "n-1", "aud": "x509_hash:verifier", "iat": time.Now().Unix(),
		"transaction_data_hashes": hashes,
	})
	require.NoError(t, v.Validate(second))
	assert.Empty(t, v.PresentedJTI,
		"a presentation that reports no jti must leave nothing for the caller to claim")
}

// A non-SCA transaction type keeps the generic OID4VP rules only.
func TestTS12Response_NonSCATypeNeedsNoSCAClaims(t *testing.T) {
	raw := decodedFor(t, `{"type":"https://example.com/other","credential_ids":["pay"]}`)
	hs, _ := HashTransactionData([]string{raw}, "sha-256")
	v, err := ts12Case{entries: []string{raw}, queryID: "pay", claims: map[string]any{
		"transaction_data_hashes": hs, "amr": nil, "jti": nil, "response_mode": nil,
	}}.run(t)
	require.NoError(t, err)
	assert.Empty(t, v.PresentedJTI)
}

func TestTransactionDataCoverage(t *testing.T) {
	a := decodedFor(t, `{"type":"urn:eudi:sca:payment:1","credential_ids":["pay"]}`)
	b := decodedFor(t, `{"type":"urn:eudi:sca:payment:1","credential_ids":["age","other"]}`)
	un, err := UncoveredTransactionData([]string{a, b}, []string{"pay"})
	require.NoError(t, err)
	assert.Equal(t, []string{b}, un)
	un, err = UncoveredTransactionData([]string{a, b}, []string{"pay", "other"})
	require.NoError(t, err)
	assert.Empty(t, un)
	_, err = UncoveredTransactionData([]string{"!!"}, nil)
	assert.Error(t, err, "an entry that cannot be read is an error, not an uncovered-nothing")
}
