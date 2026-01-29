package vcclient

import (
	"crypto/tls"
	"net/http"
	"testing"
	"vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
)

func TestAuthorize(t *testing.T) {
	tts := []struct {
		name         string
		req          *openid4vci.PARRequest
		wantResponse *openid4vci.AuthorizationResponse
		wantHTTP     *http.Response
	}{
		{
			name: "success",
			req: &openid4vci.PARRequest{
				ResponseType:         "",
				ClientID:             "",
				RedirectURI:          "",
				Scope:                "",
				State:                "state_12345",
				AuthorizationDetails: []openid4vci.AuthorizationDetailsParameter{},
				CodeChallenge:        "",
				CodeChallengeMethod:  "",
				WalletIssuer:         "",
				UserHint:             "",
				IssuingState:         "",
			},
			wantResponse: &openid4vci.AuthorizationResponse{
				Code:  "code_12345",
				State: "state_12345",
			},
			wantHTTP: &http.Response{
				Status:           "",
				StatusCode:       302,
				Proto:            "",
				ProtoMajor:       0,
				ProtoMinor:       0,
				Header:           map[string][]string{},
				Body:             nil,
				ContentLength:    0,
				TransferEncoding: []string{},
				Close:            false,
				Uncompressed:     false,
				Trailer:          map[string][]string{},
				Request:          &http.Request{},
				TLS:              &tls.ConnectionState{},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			httpServer := mockHappyHttServer(t)
			defer httpServer.Close()

			client := mockClient(ctx, t, httpServer.URL)
			got, httpResp, err := client.OIDC.Authorize(ctx, tt.req)
			assert.NoError(t, err)

			assert.Equal(t, tt.wantResponse, got)
			assert.Equal(t, tt.wantHTTP.StatusCode, httpResp.StatusCode)
		})
	}
}

func TestPar(t *testing.T) {
	tts := []struct {
		name         string
		req          *openid4vci.PARRequest
		wantResponse *openid4vci.AuthorizationResponse
		wantHTTP     *http.Response
	}{
		{
			name: "success",
			req: &openid4vci.PARRequest{
				ResponseType:         "",
				ClientID:             "",
				RedirectURI:          "",
				Scope:                "",
				State:                "state_12345",
				AuthorizationDetails: []openid4vci.AuthorizationDetailsParameter{},
				CodeChallenge:        "",
				CodeChallengeMethod:  "",
				WalletIssuer:         "",
				UserHint:             "",
				IssuingState:         "",
			},
			wantResponse: &openid4vci.AuthorizationResponse{
				Code:  "code_12345",
				State: "state_12345",
			},
			wantHTTP: &http.Response{
				StatusCode: 200,
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			httpServer := mockHappyHttServer(t)
			defer httpServer.Close()

			client := mockClient(ctx, t, httpServer.URL)
			got, httpResp, err := client.OIDC.Par(ctx, tt.req)
			assert.NoError(t, err)

			assert.Equal(t, tt.wantResponse, got)
			assert.Equal(t, tt.wantHTTP.StatusCode, httpResp.StatusCode)
		})
	}
}
