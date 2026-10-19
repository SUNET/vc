package apiv1

import (
	"net/http"
	"testing"

	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A caller must not be able to choose the status code of its own refusal.
//
// An unstructured error carries no status, so httphelpers.StatusCode
// INFERS one from the message text. The message names the credential
// query id, which the caller chose: "credential query \"token\" is
// invalid: ..." matches the "unauthorized, authentication, token" case
// and is answered 401 - before the "invalid" case is reached - so a
// malformed request reads as an authentication failure and the
// description is dropped on the way out.
//
// The payment path makes it worse, because the operator page handles a
// structured payment error and nothing else: a payment refused by this
// loop, before buildPaymentTransactionData ever runs, looked like a
// different class of failure than the same request refused one step
// later.
func TestUIInteraction_AnInvalidCredentialQueryIsA400(t *testing.T) {
	client := newSigningTestClient(t)

	// Named to hit the inference: "token" is one of the substrings it
	// reads as an authentication failure.
	bad := func(id string) *openid4vp.DCQL {
		return &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     id,
			Format: openid4vp.FormatSDJWTVC,
			// No meta: an SD-JWT VC query with no vct_values matches
			// every credential of the format, which ValidateCredentialQuery
			// refuses.
		}}}
	}

	for _, tc := range []struct {
		name    string
		req     *UIInteractionRequest
		wantMsg string
	}{
		{
			name:    "an ordinary interaction request",
			req:     &UIInteractionRequest{DCQLQuery: bad("token")},
			wantMsg: "credential query \"token\" is invalid",
		},
		{
			name: "a payment request refused before the payment is built",
			req: &UIInteractionRequest{
				DCQLQuery: bad("token"),
				Payment: &UIPaymentRequest{
					Amount: PaymentAmount("49.99"), Currency: "EUR",
					PayeeName: "Shop", PayeeID: "shop-1",
				},
			},
			wantMsg: "payment: credential query \"token\" is invalid",
		},
		{
			name:    "a DCQL asking for nothing at all",
			req:     &UIInteractionRequest{DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{}}},
			wantMsg: "at least one credential",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.UIInteraction(t.Context(), tc.req)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg,
				"the refusal must say what was wrong with the request")
			assert.Equal(t, http.StatusBadRequest, httphelpers.StatusCode(t.Context(), err),
				"a malformed request is a 400; a caller-chosen identifier must not change that")
		})
	}
}

// A request with no query at all must refuse, not panic.
//
// The HTTP binding skips decoding a body of zero length entirely - no
// decode, no validation, no error - so a caller that POSTs an empty
// body arrives here with a zero-valued request. Everything in
// UIInteraction dereferences the query, so this used to be a nil
// pointer dereference: a stack trace and a 500 where a structured 400
// was owed, and on a server without recovery middleware, worse.
func TestUIInteraction_ARequestWithNoQueryRefusesInsteadOfPanicking(t *testing.T) {
	client := newSigningTestClient(t)

	for _, tc := range []struct {
		name string
		req  *UIInteractionRequest
	}{
		{"a zero-valued request, which is what an empty body produces", &UIInteractionRequest{}},
		{"no request at all", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := client.UIInteraction(t.Context(), tc.req)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "dcql_query is required")
				assert.Equal(t, http.StatusBadRequest, httphelpers.StatusCode(t.Context(), err),
					"a request that carries nothing is the caller's mistake")
			})
		})
	}
}
