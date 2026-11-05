package openid4vp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The vectors are copied from sirosfoundation WMP spec repo
// (leifj/wmp), vectors/openid4x/transaction-data-hashes.json at main
// 952237a (conforming_* vectors added in 2c67902). Hashes there were computed
// with Python hashlib, independent of any wallet or verifier.
type ts12Vector struct {
	Name         string            `json:"name"`
	Note         string            `json:"note"`
	JSON         string            `json:"json"`
	Raw          string            `json:"raw"`
	Noncanonical bool              `json:"noncanonical"`
	Hashes       map[string]string `json:"hashes"`
}

func loadTS12Vectors(t *testing.T) []ts12Vector {
	t.Helper()
	b, err := os.ReadFile("testdata/ts12/transaction-data-hashes.json")
	require.NoError(t, err)
	var f struct {
		Vectors []ts12Vector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(b, &f))
	require.NotEmpty(t, f.Vectors)
	return f.Vectors
}

func TestHashTransactionData_WMPGoldenVectors(t *testing.T) {
	for _, v := range loadTS12Vectors(t) {
		for alg, want := range v.Hashes {
			t.Run(v.Name+"/"+alg, func(t *testing.T) {
				got, err := HashTransactionData([]string{v.Raw}, alg)
				require.NoError(t, err)
				assert.Equal(t, []string{want}, got, "hash is over the raw base64url string as received")

				// The raw string must really be the base64url of the documented JSON, or the vector is not what it says.
				dec, err := base64.RawURLEncoding.DecodeString(v.Raw)
				require.NoError(t, err)
				assert.Equal(t, v.JSON, string(dec))
			})
		}
	}
}

// Conforming vectors are what a spec-exact verifier could send: their payload
// must be accepted by our own payload type, with no member we do not model.
func TestTS12PaymentPayload_ConformingVectors(t *testing.T) {
	n := 0
	for _, v := range loadTS12Vectors(t) {
		if len(v.Name) < 10 || v.Name[:10] != "conforming" {
			continue
		}
		var td struct {
			Type    string          `json:"type"`
			Payload json.RawMessage `json:"payload"`
		}
		require.NoError(t, json.Unmarshal([]byte(v.JSON), &td))
		assert.Equal(t, TS12TypePayment, td.Type)

		dec := json.NewDecoder(bytes.NewReader(td.Payload))
		dec.DisallowUnknownFields()
		var p TS12PaymentPayload
		if err := dec.Decode(&p); err != nil {
			// Optional members this verifier does not send (pisp, date_time, ...) are fine to receive.
			require.Contains(t, v.Name, "optionals", v.Name)
			continue
		}
		require.NoError(t, p.Validate(), v.Name)
		n++
	}
	assert.GreaterOrEqual(t, n, 4)
}

func TestTS12PaymentPayload_AmountKeepsItsText(t *testing.T) {
	var p TS12PaymentPayload
	require.NoError(t, json.Unmarshal([]byte(`{"transaction_id":"t","payee":{"name":"n","id":"i"},"currency":"EUR","amount":49.990}`), &p))
	out, err := json.Marshal(p)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"amount":49.990}`)
}

func TestNewTS12PaymentTransactionData(t *testing.T) {
	good := TS12PaymentPayload{TransactionID: "tx-1", Payee: TS12Payee{Name: "Shop AB", ID: "SE1"}, Currency: "EUR", Amount: "49.99"}

	td, err := NewTS12PaymentTransactionData(good, []string{"sca"}, nil)
	require.NoError(t, err)
	enc, err := td.Base64Encode()
	require.NoError(t, err)
	dec, err := base64.RawURLEncoding.DecodeString(enc)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(dec, &m))
	assert.Equal(t, "urn:eudi:sca:payment:1", m["type"])
	assert.Equal(t, []any{"sca"}, m["credential_ids"])
	assert.Equal(t, []any{"sha-256"}, m["transaction_data_hashes_alg"], "TS12 4.2: REQUIRED, and an array in the request")
	assert.Contains(t, string(dec), `"amount":49.99`, "amount is a JSON number, not a string")

	bad := map[string]func(p *TS12PaymentPayload){
		"empty tx id":      func(p *TS12PaymentPayload) { p.TransactionID = "" },
		"tx id too long":   func(p *TS12PaymentPayload) { p.TransactionID = string(make([]byte, 37)) },
		"no payee name":    func(p *TS12PaymentPayload) { p.Payee.Name = " " },
		"no payee id":      func(p *TS12PaymentPayload) { p.Payee.ID = "" },
		"lowercase ccy":    func(p *TS12PaymentPayload) { p.Currency = "eur" },
		"long ccy":         func(p *TS12PaymentPayload) { p.Currency = "EURO" },
		"negative amount":  func(p *TS12PaymentPayload) { p.Amount = "-1" },
		"zero amount":      func(p *TS12PaymentPayload) { p.Amount = "0.00" },
		"exponent amount":  func(p *TS12PaymentPayload) { p.Amount = "1e3" },
		"injection amount": func(p *TS12PaymentPayload) { p.Amount = "1,\"x\":2" },
		"empty amount":     func(p *TS12PaymentPayload) { p.Amount = "" },
		"leading zero":     func(p *TS12PaymentPayload) { p.Amount = "01.5" },
	}
	for name, mut := range bad {
		t.Run(name, func(t *testing.T) {
			p := good
			mut(&p)
			_, err := NewTS12PaymentTransactionData(p, []string{"sca"}, nil)
			assert.Error(t, err)
		})
	}

	t.Run("transaction_id length counts characters, not bytes", func(t *testing.T) {
		p := good
		p.TransactionID = strings.Repeat("é", 36) // 72 bytes
		_, err := NewTS12PaymentTransactionData(p, []string{"sca"}, nil)
		assert.NoError(t, err)
		p.TransactionID = strings.Repeat("é", 37)
		_, err = NewTS12PaymentTransactionData(p, []string{"sca"}, nil)
		assert.Error(t, err)
	})
	for _, c := range []string{"EUR", "SEK", "USD", "JPY", "XOF"} {
		p := good
		p.Currency = c
		_, err := NewTS12PaymentTransactionData(p, []string{"sca"}, nil)
		assert.NoError(t, err, c)
	}

	_, err = NewTS12PaymentTransactionData(good, nil, nil)
	assert.Error(t, err, "credential_ids required")
	_, err = NewTS12PaymentTransactionData(good, []string{"sca"}, []string{"md5"})
	assert.Error(t, err, "unsupported alg refused")
}
