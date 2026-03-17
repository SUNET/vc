package openid4vp

import (
	"net/url"
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

func TestCreateAuthorizationRequestURIWithoutScheme(t *testing.T) {
	ctx := t.Context()

	authRequest := &RequestObject{
		ClientID: "x509_san_dns:vc-interop-3.sunet.se:444",
	}

	// Test with host:port WITH scheme (config ensures all URLs have schemes)
	got, err := authRequest.CreateAuthorizationRequestURI(ctx, "https://vc-interop-3.sunet.se:444", "0d62594e-9bf9-4051-9ae5-207cbf8bea4d")
	assert.NoError(t, err)

	expectedURI := "openid4vp://cb?client_id=x509_san_dns%3Avc-interop-3.sunet.se%3A444&request_uri=https%3A%2F%2Fvc-interop-3.sunet.se%3A444%2Fverification%2Frequest-object%3Fid%3D0d62594e-9bf9-4051-9ae5-207cbf8bea4d"
	assert.Equal(t, expectedURI, got)

	// Verify the request_uri parameter contains https:// when decoded
	u, err := url.Parse(got)
	assert.NoError(t, err)
	requestURI := u.Query().Get("request_uri")
	assert.Contains(t, requestURI, "https://vc-interop-3.sunet.se:444/verification/request-object")
}
