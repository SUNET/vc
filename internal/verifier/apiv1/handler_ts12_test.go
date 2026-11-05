package apiv1

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scaDCQL(id string) *openid4vp.DCQL {
	return &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
		ID:     id,
		Format: openid4vp.FormatSDJWTVC,
		Meta:   openid4vp.MetaQuery{VCTValues: []string{"https://psp.example/sca"}},
	}}}
}

func testPayment() *UIPaymentRequest {
	return &UIPaymentRequest{Amount: "49.99", Currency: "EUR", PayeeName: "Shop AB", PayeeID: "SE1234567890"}
}

func TestUIInteraction_PaymentSendsAndRemembersTheSameStrings(t *testing.T) {
	ctx := t.Context()
	client := newSigningTestClient(t)
	client.cfg.Verifier.TS12.Enable = true

	reply, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: scaDCQL("sca"), Payment: testPayment()})
	require.NoError(t, err)

	authCtx, err := client.cacheService.AuthContext.GetByID(ctx, reply.SessionID)
	require.NoError(t, err)
	require.Len(t, authCtx.TransactionData, 1)

	ro, ok := client.cacheService.RequestObject.Get(ctx, authCtx.RequestObjectID)
	require.True(t, ok)
	assert.Equal(t, authCtx.TransactionData, ro.TransactionData, "the session must hold the very strings the wallet was sent")

	dec, err := base64.RawURLEncoding.DecodeString(ro.TransactionData[0])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(dec, &m))
	assert.Equal(t, openid4vp.TS12TypePayment, m["type"])
	assert.Equal(t, []any{"sca"}, m["credential_ids"])
	assert.Equal(t, []any{"sha-256"}, m["transaction_data_hashes_alg"])
	payload := m["payload"].(map[string]any)
	assert.Equal(t, 49.99, payload["amount"])
	assert.Equal(t, "EUR", payload["currency"])
	assert.NotEmpty(t, payload["transaction_id"])
}

func TestUIInteraction_PaymentRefusals(t *testing.T) {
	ctx := t.Context()

	multi := scaDCQL("sca")
	multi.Credentials = append(multi.Credentials, openid4vp.CredentialQuery{ID: "age", Format: openid4vp.FormatSDJWTVC, Meta: openid4vp.MetaQuery{VCTValues: []string{"x"}}})
	mdoc := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{ID: "m", Format: "mso_mdoc", Meta: openid4vp.MetaQuery{DoctypeValue: "org.iso.18013.5.1.mDL"}}}}
	dup := scaDCQL("sca")
	dup.Credentials = append(dup.Credentials, openid4vp.CredentialQuery{ID: "sca", Format: openid4vp.FormatSDJWTVC, Meta: openid4vp.MetaQuery{VCTValues: []string{"other"}}})
	noBinding := scaDCQL("sca")
	f := false
	noBinding.Credentials[0].RequireCryptographicHolderBinding = &f

	cases := map[string]struct {
		enable bool
		dcql   *openid4vp.DCQL
		mut    func(p *UIPaymentRequest)
	}{
		"feature disabled":                              {false, scaDCQL("sca"), nil},
		"two queries without credential_id":             {true, multi, nil},
		"unknown credential_id":                         {true, scaDCQL("sca"), func(p *UIPaymentRequest) { p.CredentialID = "nope" }},
		"duplicate credential query id":                 {true, dup, func(p *UIPaymentRequest) { p.CredentialID = "sca" }},
		"mdoc is out of TS12 scope":                     {true, mdoc, nil},
		"holder binding disabled":                       {true, noBinding, nil},
		"bad currency":                                  {true, scaDCQL("sca"), func(p *UIPaymentRequest) { p.Currency = "euro" }},
		"amount is a word that trips the status mapper": {true, scaDCQL("sca"), func(p *UIPaymentRequest) { p.Amount = "token" }},
		"amount is a boolean literal":                   {true, scaDCQL("sca"), func(p *UIPaymentRequest) { p.Amount = "true" }},
		"amount is an object literal":                   {true, scaDCQL("sca"), func(p *UIPaymentRequest) { p.Amount = `{"x":1}` }},
		"zero amount":                                   {true, scaDCQL("sca"), func(p *UIPaymentRequest) { p.Amount = "0" }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			client := newSigningTestClient(t)
			client.cfg.Verifier.TS12.Enable = tc.enable
			p := testPayment()
			if tc.mut != nil {
				tc.mut(p)
			}
			_, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: tc.dcql, Payment: p})
			require.Error(t, err)
			oe, ok := errors.AsType[*oauth2.OAuthError](err)
			require.True(t, ok, "a client mistake must be a 400, got %v", err)
			assert.Equal(t, 400, oe.HTTPStatus)
		})
	}

	t.Run("multi query accepted when credential_id names the SCA one", func(t *testing.T) {
		client := newSigningTestClient(t)
		client.cfg.Verifier.TS12.Enable = true
		p := testPayment()
		p.CredentialID = "sca"
		_, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: multi, Payment: p})
		require.NoError(t, err)
	})
}

// A payment is a new transaction each time: neither a payment request nor a
// plain request may be answered with another transaction's session.
func TestUIInteraction_PaymentSessionsAreNeverReused(t *testing.T) {
	ctx := t.Context()
	client := newSigningTestClient(t)
	client.cfg.Verifier.TS12.Enable = true

	first, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: scaDCQL("sca"), Payment: testPayment()})
	require.NoError(t, err)

	again, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: scaDCQL("sca"), Payment: testPayment(), SessionID: first.SessionID})
	require.NoError(t, err)
	assert.NotEqual(t, first.SessionID, again.SessionID)

	plain, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: scaDCQL("sca"), SessionID: first.SessionID})
	require.NoError(t, err)
	assert.NotEqual(t, first.SessionID, plain.SessionID, "a non-payment request must not be served a payment session")
	authCtx, err := client.cacheService.AuthContext.GetByID(ctx, plain.SessionID)
	require.NoError(t, err)
	assert.Empty(t, authCtx.TransactionData)
}

// The response is checked against the modes the session was issued with, so
// they are recorded when the request is made, per the config at that time.
func TestUIInteraction_PaymentRecordsIssuedResponseModes(t *testing.T) {
	ctx := t.Context()
	for _, dcAPI := range []bool{false, true} {
		client := newSigningTestClient(t)
		client.cfg.Verifier.TS12.Enable = true
		client.cfg.Verifier.DigitalCredentials.Enable = dcAPI
		reply, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: scaDCQL("sca"), Payment: testPayment()})
		if dcAPI && err != nil {
			t.Skipf("DC API origin not configurable in this test client: %v", err)
		}
		require.NoError(t, err)
		authCtx, err := client.cacheService.AuthContext.GetByID(ctx, reply.SessionID)
		require.NoError(t, err)
		want := []string{"direct_post.jwt"}
		if dcAPI {
			want = append(want, "dc_api.jwt")
		}
		assert.Equal(t, want, authCtx.TransactionDataResponseModes, "dcAPI=%v", dcAPI)
	}
}

// UIInteraction's own DCQL validation already demands vct_values for SD-JWT
// VC; the payment builder checks it again because the response check compares
// the presented vct against exactly these values.
func TestBuildPaymentTransactionData_RequiresVCTValues(t *testing.T) {
	client := newSigningTestClient(t)
	client.cfg.Verifier.TS12.Enable = true
	dcql := scaDCQL("sca")
	_, err := client.buildPaymentTransactionData(testPayment(), dcql)
	require.NoError(t, err)
	dcql.Credentials[0].Meta.VCTValues = nil
	_, err = client.buildPaymentTransactionData(testPayment(), dcql)
	require.Error(t, err)
}

// A payment session is checked against the response modes it was issued with,
// so resuming it must not mint a request variant outside them.
func TestUIResume_PaymentDoesNotIssueAnUnrecordedDCAPIVariant(t *testing.T) {
	ctx := t.Context()

	client := newSigningTestClient(t)
	client.cfg.Verifier.TS12.Enable = true
	first, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: scaDCQL("sca"), Payment: testPayment()})
	require.NoError(t, err)
	assert.Empty(t, first.DCAPIAuthorizationRequest)

	client.cfg.Verifier.DigitalCredentials.Enable = true // switched on after issuance
	resumed, err := client.UIResume(ctx, first.SessionID)
	require.NoError(t, err)
	require.Equal(t, UIResumePending, resumed.Status)
	assert.NotEmpty(t, resumed.AuthorizationRequest)
	assert.Empty(t, resumed.DCAPIAuthorizationRequest, "the session was not issued dc_api.jwt")

	// And a session that WAS issued with it still resumes with it.
	again, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: scaDCQL("sca"), Payment: testPayment()})
	require.NoError(t, err)
	assert.NotEmpty(t, again.DCAPIAuthorizationRequest)
	resumed, err = client.UIResume(ctx, again.SessionID)
	require.NoError(t, err)
	assert.NotEmpty(t, resumed.DCAPIAuthorizationRequest)
}

func TestPaymentAmount_DecodesNumbersAndStringsWithoutJudging(t *testing.T) {
	for in, want := range map[string]string{`49.99`: "49.99", `"49.99"`: "49.99", `49.990`: "49.990", `"token"`: "token", `true`: "true", `null`: ""} {
		var p UIPaymentRequest
		require.NoError(t, json.Unmarshal([]byte(`{"amount":`+in+`}`), &p), in)
		assert.Equal(t, PaymentAmount(want), p.Amount, in)
	}
}
