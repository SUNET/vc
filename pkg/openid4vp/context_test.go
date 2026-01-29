package openid4vp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateAuthorizationRequestURI(t *testing.T) {
	ctx := t.Context()

	authRequest := &RequestObject{
		ClientID: "x509_san_dns:vc-interops-3.sunet.se",
	}

	got, err := authRequest.CreateAuthorizationRequestURI(ctx, "https://vc-interops-3.sunet.se:444", "test-1234")
	assert.NoError(t, err)

	expectedURI := "openid4vp://cb?client_id=x509_san_dns%3Avc-interops-3.sunet.se&request_uri=https%3A%2F%2Fvc-interops-3.sunet.se%3A444%2Fverification%2Frequest-object%3Fid%3Dtest-1234"
	assert.Equal(t, expectedURI, got)
}
