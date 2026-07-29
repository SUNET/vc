package oauth2_test

import (
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/oauth2"
)

func ExampleCreateCodeChallenge() {
	// Using a known verifier for deterministic output (S256 method)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := oauth2.CreateCodeChallenge(oauth2.CodeChallengeMethodS256, verifier)
	fmt.Println("challenge:", challenge)
	// Output:
	// challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
}

func ExampleCreateCodeChallenge_plain() {
	verifier := "my-plain-verifier"
	challenge := oauth2.CreateCodeChallenge(oauth2.CodeChallengeMethodPlain, verifier)
	fmt.Println("challenge:", challenge)
	// Output:
	// challenge: my-plain-verifier
}

func ExampleValidatePKCE() {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := oauth2.CreateCodeChallenge(oauth2.CodeChallengeMethodS256, verifier)

	err := oauth2.ValidatePKCE(verifier, challenge, oauth2.CodeChallengeMethodS256)
	fmt.Println("valid:", err == nil)

	err = oauth2.ValidatePKCE("wrong-verifier", challenge, oauth2.CodeChallengeMethodS256)
	fmt.Println("invalid:", err)
	// Output:
	// valid: true
	// invalid: invalid_grant
}

func ExampleClients_Get() {
	clients := oauth2.Clients{
		"wallet-app": &oauth2.Client{
			Type:         oauth2.ClientTypePublic,
			RedirectURIs: oauth2.RedirectURIs{"https://wallet.example.com/callback"},
			Scopes:       []string{"openid", "pid"},
		},
	}

	client, err := clients.Get("wallet-app")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("type:", client.Type)
	fmt.Println("redirect_uri:", client.RedirectURIs[0])

	_, err = clients.Get("unknown")
	fmt.Println("unknown client:", err)
	// Output:
	// type: public
	// redirect_uri: https://wallet.example.com/callback
	// unknown client: client not found in config
}

func ExampleClients_Allow() {
	clients := oauth2.Clients{
		"wallet-app": &oauth2.Client{
			Type:         oauth2.ClientTypePublic,
			RedirectURIs: oauth2.RedirectURIs{"https://wallet.example.com/callback"},
			Scopes:       []string{"openid", "pid"},
		},
	}

	client, err := clients.Allow("wallet-app", "https://wallet.example.com/callback", "openid")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("allowed type:", client.Type)

	_, err = clients.Allow("wallet-app", "https://wallet.example.com/callback", "admin")
	fmt.Println("disallowed scope:", err)
	// Output:
	// allowed type: public
	// disallowed scope: requested scope is not allowed for this client
}

func ExampleDPoP_ValidateJTI() {
	dpop := &oauth2.DPoP{
		JTI: "abcdefghijklmnop",
		HTM: "POST",
		HTU: "https://server.example.com/token",
		IAT: time.Now().Unix(),
	}

	err := dpop.ValidateJTI()
	fmt.Println("valid JTI:", err == nil)

	short := &oauth2.DPoP{JTI: "short"}
	err = short.ValidateJTI()
	fmt.Println("short JTI:", err)
	// Output:
	// valid JTI: true
	// short JTI: invalid JTI: must be at least 12 characters
}

func ExampleDPoP_ValidateHTM() {
	dpop := &oauth2.DPoP{HTM: "POST"}
	fmt.Println("POST valid:", dpop.ValidateHTM() == nil)

	dpop.HTM = "GET"
	fmt.Println("GET valid:", dpop.ValidateHTM() == nil)

	dpop.HTM = ""
	fmt.Println("empty:", dpop.ValidateHTM())
	// Output:
	// POST valid: true
	// GET valid: true
	// empty: missing required HTM claim
}

func ExampleDPoP_ValidateHTU() {
	dpop := &oauth2.DPoP{HTU: "https://server.example.com/token"}
	fmt.Println("valid HTU:", dpop.ValidateHTU() == nil)

	dpop.HTU = ""
	fmt.Println("empty:", dpop.ValidateHTU())
	// Output:
	// valid HTU: true
	// empty: missing required HTU claim
}
