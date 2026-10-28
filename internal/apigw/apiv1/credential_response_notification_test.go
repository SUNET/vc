package apiv1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/openid4vci"
)

// A Credential Response that delivers an opening carries a
// notification_id.
//
// It is how the wallet reports a failed commitment check, and a wallet
// that fails closed on a secret-bearing response without one refuses the
// whole delivery - so without this every auxiliary-data issuance is
// rejected by the client, with nothing wrong on the wire to point at.
//
// The seed-delivery path this replaces minted one. Credential Auxiliary
// Data moved the delivery and did not bring it; this is the test that
// would have caught that, which is why it is at the
// newCredentialResponse level: that function exists so the response is
// assembled in ONE place a test can call.
func TestACredentialResponseDeliveringAnOpeningCarriesANotificationID(t *testing.T) {
	c := credMetaClient(t, true)
	credentials := []openid4vci.Credential{{Credential: "a-credential"}}
	toWallet := []openid4vci.AuxiliaryDataEntry{{
		Type:    openid4vci.AuxiliaryDataTypeHashCommitment,
		Alg:     openid4vci.HashCommitmentAlgSHA256,
		Path:    []string{"eu.europa.ec.eudi.nym_auth.1", "ssc"},
		Opening: "T3BlbmluZw",
	}}

	response := c.newCredentialResponse(credentials, "pid", "pid", toWallet)

	require.NotNil(t, response.CredentialMetadata, "the opening travels in credential_metadata")
	require.Len(t, response.CredentialMetadata.AuxiliaryData, 1)
	assert.NotEmptyf(t, response.NotificationID,
		"a response carrying an opening needs a notification_id; without one a fail-closed wallet refuses the delivery")
}

// And a response that delivers nothing does not invent one: the
// parameter is tied to a Credential and a wallet has nothing to report
// about a delivery that did not happen.
func TestACredentialResponseWithoutAnOpeningHasNoNotificationID(t *testing.T) {
	c := credMetaClient(t, false)

	response := c.newCredentialResponse([]openid4vci.Credential{{Credential: "a-credential"}}, "pid", "pid", nil)

	assert.Empty(t, response.NotificationID)
	assert.Nil(t, response.CredentialMetadata)
}

// Two deliveries are two notifications: reusing an id would make the
// wallet's report ambiguous about which issuance it refers to.
func TestEachDeliveryGetsItsOwnNotificationID(t *testing.T) {
	c := credMetaClient(t, true)
	toWallet := []openid4vci.AuxiliaryDataEntry{{
		Type: openid4vci.AuxiliaryDataTypeHashCommitment,
		Alg:  openid4vci.HashCommitmentAlgSHA256,
		Path: []string{"eu.europa.ec.eudi.nym_auth.1", "ssc"},
	}}

	first := c.newCredentialResponse(nil, "pid", "pid", toWallet)
	second := c.newCredentialResponse(nil, "pid", "pid", toWallet)

	require.NotEmpty(t, first.NotificationID)
	assert.NotEqual(t, first.NotificationID, second.NotificationID)
}
