package apiv1

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// Stable refusal codes for the zkp_req presentation path.
//
// A refused presentation is the WALLET'S business. It arrived as a 500
// "internal_server_error" with nothing but a req_id, which tells a wallet
// author that this verifier broke - so the first live Pixel round spent
// its time looking at the wallet for a refusal the verifier had decided
// and could name.
//
// These are codes, not messages: content-free, stable across releases,
// and safe to branch on. The human sentence stays in the detail, where it
// can be reworded without breaking anybody. The naming follows the shared
// matcher vectors, whose reason codes this path already passes through
// unchanged for shape refusals - one vocabulary, not two.
//
// What is NOT here is as deliberate. A verifier that is misconfigured or
// built without the zknative tag has not refused a presentation: it
// cannot judge one. Those stay 5xx and unclassified, because telling a
// wallet "your presentation is bad" when the fault is ours sends its
// author hunting for a defect that is not there.
const (
	// The presentation, as it arrived.
	CodeZkpReqNoPresentation      = "zkp_req_no_presentation"
	CodeZkpReqProofTimeMissing    = "zkp_req_proof_time_missing"
	CodeZkpReqProofTimeOutOfRange = "zkp_req_proof_time_out_of_range"
	CodeZkpReqWrongChannel        = "zkp_req_wrong_channel"

	// The issuer key set it carries.
	CodeZkpReqIssuerKeySetEmpty   = "zkp_req_issuer_key_set_empty"
	CodeZkpReqIssuerKeySetSize    = "zkp_req_issuer_key_set_size"
	CodeZkpReqIssuerKeyNotACert   = "zkp_req_issuer_key_not_a_certificate"
	CodeZkpReqIssuerNotTrusted    = "zkp_req_issuer_not_trusted"
	CodeZkpReqIssuerKeyWrongCurve = "zkp_req_issuer_key_wrong_curve"
	CodeZkpReqIssuerKeyNotECDSA   = "zkp_req_issuer_key_not_ecdsa"

	// The proof itself.
	CodeZkpReqProofDidNotVerify = "zkp_req_proof_did_not_verify"
	CodeZkpReqNoPseudonym       = "zkp_req_no_pseudonym_for_handle"
	CodeZkpReqNothingChecked    = "zkp_req_nothing_checked"
)

// zkpReqRefusal is a presentation this verifier refuses, with the code it
// refuses it under.
//
// It carries the underlying error so a log line and a test can still see
// the whole story, and renders as a *helpers.Error so the HTTP layer
// returns the code with a 4xx instead of redacting it behind a req_id.
type zkpReqRefusal struct {
	Code   string
	Detail string
	Err    error
}

func (r *zkpReqRefusal) Error() string {
	if r.Err != nil {
		return fmt.Sprintf("%s: %s: %v", r.Code, r.Detail, r.Err)
	}
	return fmt.Sprintf("%s: %s", r.Code, r.Detail)
}

func (r *zkpReqRefusal) Unwrap() error { return r.Err }

// HTTPError renders the refusal for the client.
//
// 400 and never 500: the presentation is the thing being judged, and a
// judgement is not a server fault. The detail is the sentence this
// verifier already wrote; it names no holder data, because nothing in
// this path has any - a zkp_req presentation discloses no attribute.
func (r *zkpReqRefusal) HTTPError() *helpers.Error {
	return helpers.NewErrorDetailsWithStatus(r.Code, r.Detail, http.StatusBadRequest)
}

// refuseZkpReq builds a refusal.
func refuseZkpReq(code, detail string, err error) *zkpReqRefusal {
	return &zkpReqRefusal{Code: code, Detail: detail, Err: err}
}

// zkpReqRefusalFrom recovers the refusal from an error chain, so a caller
// that wrapped one with %w can still be classified.
func zkpReqRefusalFrom(err error) (*zkpReqRefusal, bool) {
	var refusal *zkpReqRefusal
	if errors.As(err, &refusal) {
		return refusal, true
	}
	return nil, false
}

// zkpReqShapeRefusal turns the shared response validator's own reason
// code into a refusal, unchanged.
//
// The matcher vectors and every other implementation already name these;
// inventing a second spelling here would mean a wallet author comparing
// two vocabularies for the same refusal.
func zkpReqShapeRefusal(err error) (*zkpReqRefusal, bool) {
	var shape *openid4vp.ZkpReqResponseError
	if !errors.As(err, &shape) {
		return nil, false
	}
	return &zkpReqRefusal{Code: shape.Reason, Detail: shape.Detail, Err: err}, true
}
