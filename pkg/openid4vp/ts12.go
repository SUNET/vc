package openid4vp

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// EC TS12 v1.0.1 ("Specification of Strong Customer Authentication (SCA)
// Implementation with the Wallet") transaction data support: request side.

const (
	// TS12TypePayment is the built-in payment transaction data type (TS12 section 4.3.1).
	TS12TypePayment = "urn:eudi:sca:payment:1"

	// TransactionDataHashAlgDefault is the algorithm OpenID4VP 1.0 Appendix B.3.3.1 mandates when a request names none, and the one every implementation MUST support.
	TransactionDataHashAlgDefault = "sha-256"

	// MaxTS12TransactionIDLength is the longest payload.transaction_id the TS12 payment JSON Schema allows (minLength 1, maxLength 36 per the schema as reproduced in the WMP conformance vectors).
	MaxTS12TransactionIDLength = 36
)

var (
	// ts12AmountRE: TS12 4.3.1 says amount is a JSON number "consisting of major currency units as the integer component and an optional fraction part". A plain non-negative decimal, no exponent, no sign.
	ts12AmountRE = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?$`)
	ts12ZeroRE   = regexp.MustCompile(`^0+(\.0+)?$`)
)

// TS12Payee is payload.payee of the payment type. name and id are REQUIRED by the TS12 payment schema.
type TS12Payee struct {
	Name    string `json:"name"`
	ID      string `json:"id"`
	Website string `json:"website,omitempty"`
}

// TS12PaymentPayload is the payload of a urn:eudi:sca:payment:1 transaction
// data object. Only members evidenced by the TS12 payment schema are modelled;
// the schema sets additionalProperties:false, so unknown members must never be
// added here.
type TS12PaymentPayload struct {
	TransactionID string    `json:"transaction_id"`
	Payee         TS12Payee `json:"payee"`
	Currency      string    `json:"currency"`
	// Amount is a JSON number. It is carried as the decimal text the operator gave so that it is neither rounded nor rewritten; it is marshalled as a bare number.
	Amount RawNumber `json:"amount"`
}

// RawNumber is a JSON number kept as text.
type RawNumber string

// MarshalJSON emits the text as a bare JSON number. The text is validated by
// TS12PaymentPayload.Validate before it can reach a request.
func (n RawNumber) MarshalJSON() ([]byte, error) {
	if !ts12AmountRE.MatchString(string(n)) {
		return nil, fmt.Errorf("amount %q is not a plain decimal number", string(n))
	}
	return []byte(n), nil
}

// UnmarshalJSON keeps the number's literal text (49.990 stays 49.990).
func (n *RawNumber) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || b[0] == '"' || b[0] == 'n' {
		return fmt.Errorf("amount must be a JSON number")
	}
	*n = RawNumber(b)
	return nil
}

// Validate applies the TS12 payment schema constraints this verifier can check, failing closed.
func (p *TS12PaymentPayload) Validate() error {
	// JSON Schema maxLength counts Unicode code points, not UTF-8 bytes.
	if l := utf8.RuneCountInString(p.TransactionID); l < 1 || l > MaxTS12TransactionIDLength {
		return fmt.Errorf("transaction_id must be 1..%d characters", MaxTS12TransactionIDLength)
	}
	if strings.TrimSpace(p.Payee.Name) == "" {
		return fmt.Errorf("payee.name is required")
	}
	if strings.TrimSpace(p.Payee.ID) == "" {
		return fmt.Errorf("payee.id is required")
	}
	if !iso4217Currencies[p.Currency] {
		return fmt.Errorf("currency %q is not an ISO 4217 alpha-3 currency code", p.Currency)
	}
	if !ts12AmountRE.MatchString(string(p.Amount)) {
		return fmt.Errorf("amount must be a plain decimal number")
	}
	if ts12ZeroRE.MatchString(string(p.Amount)) {
		return fmt.Errorf("amount must be greater than zero")
	}
	return nil
}

// NewTS12PaymentTransactionData builds a TS12 payment transaction data object
// bound to the given DCQL credential query ids. hashAlgs defaults to
// ["sha-256"]: TS12 4.2 makes transaction_data_hashes_alg REQUIRED, so it is
// always sent. Unsupported algorithms are refused.
func NewTS12PaymentTransactionData(payload TS12PaymentPayload, credentialIDs []string, hashAlgs []string) (*TransactionData, error) {
	if err := payload.Validate(); err != nil {
		return nil, fmt.Errorf("invalid payment payload: %w", err)
	}
	if len(credentialIDs) == 0 {
		return nil, fmt.Errorf("credential_ids must not be empty")
	}
	for _, id := range credentialIDs {
		if id == "" {
			return nil, fmt.Errorf("credential_ids must not contain an empty id")
		}
	}
	if len(hashAlgs) == 0 {
		hashAlgs = []string{TransactionDataHashAlgDefault}
	}
	for _, a := range hashAlgs {
		if _, err := newHash(a); err != nil {
			return nil, err
		}
	}
	return &TransactionData{
		Type:                     TS12TypePayment,
		CredentialIDS:            credentialIDs,
		TransactionDataHashesAlg: hashAlgs,
		Payload:                  payload,
	}, nil
}

// iso4217Currencies is a snapshot of the ISO 4217 alpha-3 codes of currencies
// in circulation (no precious metals, test or "no currency" codes, which are
// not payment currencies). A code missing here is refused: fail closed beats
// sending a code no wallet or payment system can interpret. BGN and HRK are
// not listed (both withdrawn for the euro).
var iso4217Currencies = func() map[string]bool {
	codes := strings.Fields(`AED AFN ALL AMD AOA ARS AUD AWG AZN BAM BBD BDT BHD BIF BMD BND BOB BRL BSD BTN BWP BYN BZD
		CAD CDF CHF CLP CNY COP CRC CUP CVE CZK DJF DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL GHS GIP GMD GNF GTQ GYD
		HKD HNL HTG HUF IDR ILS INR IQD IRR ISK JMD JOD JPY KES KGS KHR KMF KPW KRW KWD KYD KZT LAK LBP LKR LRD LSL LYD
		MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MYR MZN NAD NGN NIO NOK NPR NZD OMR PAB PEN PGK PHP PKR PLN PYG
		QAR RON RSD RUB RWF SAR SBD SCR SDG SEK SGD SHP SLE SOS SRD SSP STN SVC SYP SZL THB TJS TMT TND TOP TRY TTD TWD
		TZS UAH UGX USD UYU UZS VES VND VUV WST XAF XCD XCG XOF XPF YER ZAR ZMW ZWG`)
	m := make(map[string]bool, len(codes))
	for _, c := range codes {
		m[c] = true
	}
	return m
}()
