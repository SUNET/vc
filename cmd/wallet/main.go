package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/SUNET/vc/internal/wallet/apiv1"
	"github.com/SUNET/vc/internal/wallet/config"
	"github.com/SUNET/vc/internal/wallet/credential"
)

const usage = `vc_wallet - OpenID4VCI/VP CLI test tool

Usage:
  vc_wallet vci [flags]    Run an OpenID4VCI credential issuance flow
  vc_wallet vp  [flags]    Run an OpenID4VP credential presentation flow

Run "vc_wallet <command> -help" for flag details.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "vci":
		runVCI(os.Args[2:])
	case "vp":
		runVP(os.Args[2:])
	case "-h", "-help", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(1)
	}
}

func runVCI(args []string) {
	fs := flag.NewFlagSet("vci", flag.ExitOnError)

	issuerURL := fs.String("issuer-url", "", "Issuer base URL (used to fetch metadata)")
	offerURI := fs.String("credential-offer-uri", "", "Credential offer URI to resolve")
	offer := fs.String("credential-offer", "", "Inline credential offer JSON")
	configID := fs.String("credential-config-id", "", "Credential configuration ID to request")
	clientID := fs.String("client-id", "", "OAuth2 client_id")
	redirectURI := fs.String("redirect-uri", "http://localhost:8080/callback", "OAuth2 redirect URI")
	scope := fs.String("scope", "", "OAuth2 scope to request")
	useDPoP := fs.Bool("use-dpop", false, "Use DPoP token binding")
	usePAR := fs.Bool("use-par", false, "Use Pushed Authorization Requests")
	preAuthCode := fs.String("pre-authorized-code", "", "Pre-authorized code (skip authorization step)")
	txCode := fs.String("tx-code", "", "Transaction code for pre-authorized flow")
	proofType := fs.String("proof-type", "jwt", "Proof type: jwt, none")
	notify := fs.Bool("send-notification", false, "Send notification after receipt")
	notifyEvent := fs.String("notification-event", "credential_accepted", "Notification event type")
	keyPath := fs.String("key-path", "", "Path to PEM private key (default: generate ephemeral EC P-256)")
	saveTo := fs.String("save", "", "Save received credential to file (for piping to vp)")
	verbose := fs.Bool("v", false, "Verbose output (debug logging)")

	fs.Parse(args)

	log := newLogger(*verbose)
	ctx := context.Background()

	cfg := &config.Config{
		Wallet: config.WalletIdentity{
			KeyPath:      *keyPath,
			KeyAlgorithm: "ES256",
			ClientID:     *clientID,
		},
		Scenarios: []config.Scenario{{
			Name: "cli-vci",
			Type: "vci",
			VCI: &config.VCIScenario{
				IssuerURL:                 *issuerURL,
				CredentialOfferURI:        *offerURI,
				CredentialOffer:           *offer,
				CredentialConfigurationID: *configID,
				RedirectURI:               *redirectURI,
				Scope:                     *scope,
				UseDPoP:                   *useDPoP,
				UsePAR:                    *usePAR,
				PreAuthorizedCode:         *preAuthCode,
				TXCode:                    *txCode,
				ProofType:                 *proofType,
				SendNotification:          *notify,
				NotificationEvent:         *notifyEvent,
			},
		}},
	}

	client, err := apiv1.New(ctx, cfg, log)
	if err != nil {
		fatal("init failed: %v", err)
	}

	result, err := client.RunScenario(ctx, "cli-vci")
	if err != nil {
		printResult(result)
		fatal("vci failed: %v", err)
	}

	printResult(result)

	// Optionally save credential for piping to vp command
	if *saveTo != "" {
		creds := client.Store().List()
		if len(creds) > 0 {
			if err := os.WriteFile(*saveTo, []byte(creds[len(creds)-1].RawCredential), 0600); err != nil {
				fatal("saving credential: %v", err)
			}
			fmt.Fprintf(os.Stderr, "credential saved to %s\n", *saveTo)
		}
	}
}

func runVP(args []string) {
	fs := flag.NewFlagSet("vp", flag.ExitOnError)

	requestURI := fs.String("request-uri", "", "Request URI to fetch the request object from")
	authReqURI := fs.String("authorization-request-uri", "", "Full openid4vp:// authorization request URI")
	credFile := fs.String("credential", "", "Credential to present (raw string or @filepath)")
	malformed := fs.Bool("malformed", false, "Send a malformed VP token (negative test)")
	wrongSig := fs.Bool("wrong-signature", false, "Sign VP with wrong key (negative test)")
	keyPath := fs.String("key-path", "", "Path to PEM private key (default: generate ephemeral EC P-256)")
	verbose := fs.Bool("v", false, "Verbose output (debug logging)")

	fs.Parse(args)

	log := newLogger(*verbose)
	ctx := context.Background()

	// Load credential to present
	rawCred, err := loadCredential(*credFile)
	if err != nil {
		fatal("loading credential: %v", err)
	}
	if rawCred == "" {
		fatal("no credential to present; use -credential <raw|@file>")
	}

	cfg := &config.Config{
		Wallet: config.WalletIdentity{
			KeyPath:      *keyPath,
			KeyAlgorithm: "ES256",
		},
		Scenarios: []config.Scenario{{
			Name: "cli-vp",
			Type: "vp",
			VP: &config.VPScenario{
				AuthorizationRequestURI: *authReqURI,
				RequestURI:              *requestURI,
				SkipConsentCheck:        true,
				MalformedVP:             *malformed,
				WrongSignature:          *wrongSig,
			},
		}},
	}

	client, err := apiv1.New(ctx, cfg, log)
	if err != nil {
		fatal("init failed: %v", err)
	}

	// Pre-load the credential into the wallet store
	client.Store().Add(&credential.StoredCredential{
		RawCredential: rawCred,
		Format:        detectFormat(rawCred),
	})

	result, err := client.RunScenario(ctx, "cli-vp")
	if err != nil {
		printResult(result)
		fatal("vp failed: %v", err)
	}

	printResult(result)
}

// loadCredential loads a credential string from flag value.
// If the value starts with "@", it reads from the file path that follows.
func loadCredential(val string) (string, error) {
	if val == "" {
		return "", nil
	}
	if strings.HasPrefix(val, "@") {
		data, err := os.ReadFile(val[1:])
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	return val, nil
}

func detectFormat(raw string) string {
	if strings.Contains(raw, "~") {
		return "vc+sd-jwt"
	}
	parts := strings.Split(raw, ".")
	if len(parts) == 3 {
		return "jwt_vc_json"
	}
	return "unknown"
}

func printResult(r *apiv1.ScenarioResult) {
	if r == nil {
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(r)
}

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
