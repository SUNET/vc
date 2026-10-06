package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testJWT = "eyJ0eXAiOiJvcGVuaWR2Y2ktaXNzdWVyLW1ldGFkYXRhK2p3dCJ9.eyJzdWIiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.c2ln"

// metadataServer answers /.well-known/openid-credential-issuer the way a
// given deployment would. signed is served as application/jwt when the
// caller asks for it; embedded, when set, is put in the JSON document the
// draft-era way.
func metadataServer(t *testing.T, signed, embedded, jwtContentType string) string {
	t.Helper()
	if jwtContentType == "" {
		jwtContentType = mediaTypeJWT
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if signed != "" && strings.Contains(r.Header.Get("Accept"), mediaTypeJWT) {
			w.Header().Set("Content-Type", jwtContentType)
			_, _ = w.Write([]byte(signed))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body := `{"credential_issuer":"https://issuer.example"`
		if embedded != "" {
			body += `,"signed_metadata":"` + embedded + `"`
		}
		_, _ = w.Write([]byte(body + "}"))
	}))
	t.Cleanup(server.Close)
	return server.URL + "/.well-known/openid-credential-issuer"
}

// The §12.2.2 shape: the signed metadata is the whole response, typed
// application/jwt, and reached only by asking for it.
//
// The spelling varies because media type tokens are case-insensitive
// (RFC 9110 §8.3.1) and a conforming issuer may send any of these.
func TestFetchSignedMetadata_FromTheJWTResponse(t *testing.T) {
	for _, spelling := range []string{"application/jwt", "Application/JWT", "application/JWT; charset=utf-8"} {
		t.Run(spelling, func(t *testing.T) {
			got, source := fetchSignedMetadata(metadataServer(t, testJWT, "", spelling), "")

			if got != testJWT {
				t.Fatalf("got %q, want the JWT the issuer served", got)
			}
			if !strings.Contains(source, mediaTypeJWT) {
				t.Fatalf("source %q should say where it came from", source)
			}
		})
	}
}

// The draft-era shape, which a deployment can still turn on: the JWT rides
// in the JSON document and no application/jwt response exists.
func TestFetchSignedMetadata_FromTheEmbeddedMember(t *testing.T) {
	got, source := fetchSignedMetadata(metadataServer(t, "", testJWT, ""), testJWT)

	if got != testJWT {
		t.Fatalf("got %q, want the embedded JWT", got)
	}
	if !strings.Contains(source, "draft-era") {
		t.Fatalf("source %q should say which shape answered", source)
	}
}

// An issuer with no signing key configured answers with the unsigned
// document, which is conformant - the signed form is a MAY. The tool says
// so rather than reporting a JWT it does not have.
func TestFetchSignedMetadata_NoneAvailable(t *testing.T) {
	got, source := fetchSignedMetadata(metadataServer(t, "", "", ""), "")

	if got != "" {
		t.Fatalf("got %q, want nothing", got)
	}
	if !strings.Contains(source, "does not serve signed metadata") {
		t.Fatalf("source %q should explain why", source)
	}
}
