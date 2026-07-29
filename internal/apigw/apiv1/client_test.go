package apiv1

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateCredentialOfferLookupMetadata(t *testing.T) {
	ctx := t.Context()

	// Create a test client with sample credential constructors and wallet configs
	client := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{
			Common: &model.Common{
				CredentialMetadata: map[string]*model.CredentialMetadata{
					"diploma": {
						VCTMFilePath: "../../../metadata/vctm_diploma.json",
					},
					"ehic": {
						VCTMFilePath: "../../../metadata/vctm_ehic.json",
					},
					"elm": {
						VCTMFilePath: "../../../metadata/vctm_elm.json",
					},
					"micro_credential": {
						VCTMFilePath: "../../../metadata/vctm_microcredential.json",
					},
					"openbadge_basic": {
						VCTMFilePath: "../../../metadata/vctm_elm.json", // Reusing elm for test
					},
					"openbadge_complete": {
						VCTMFilePath: "../../../metadata/vctm_elm.json", // Reusing elm for test
					},
					"openbadge_endorsements": {
						VCTMFilePath: "../../../metadata/vctm_elm.json", // Reusing elm for test
					},
					"pda1": {
						VCTMFilePath: "../../../metadata/vctm_pda1.json",
					},
					"pid": {
						VCTMFilePath: "../../../metadata/vctm_pid.json",
					},
				},
			},
			APIGW: &model.APIGW{
				Delivery: model.APIGWDelivery{
					CredentialOffers: model.CredentialOffers{
						Wallets: map[string]model.CredentialOfferWallets{
							"dc4eu": {
								Label: "DC4EU Wallet",
							},
							"funke": {
								Label: "Funke Wallet",
							},
							"siros_sunet": {
								Label: "Siros SUNET Wallet",
							},
							"sunet_dev": {
								Label: "SUNET Dev Wallet",
							},
							"vanilla": {
								Label: "Vanilla wwWallet",
							},
						},
					},
				},
			},
		},
		CredentialOfferLookupMetadata: &CredentialOfferLookupMetadata{},
	}

	// Load VCTMs (normally done by configuration.New)
	for scope, cc := range client.cfg.Common.CredentialMetadata {
		require.NoError(t, cc.LoadVCTMetadata(context.Background(), scope))
	}

	// Execute the function
	err := client.CreateCredentialOfferLookupMetadata(ctx)
	require.NoError(t, err)

	// Verify the credential types were loaded
	metadata := client.CredentialOfferLookupMetadata
	require.NotNil(t, metadata)

	// Define the complete expected structure
	expected := &CredentialOfferLookupMetadata{
		CredentialTypes: map[string]CredentialOfferTypeData{
			"diploma": {
				Name:        "Diploma Credential",
				Description: "European Learning Model Diploma Credential.",
			},
			"ehic": {
				Name:        "DC4EU EHIC SD-JWT VCTM",
				Description: "DC4EU European Health Insurance Card (EHIC) SD-JWT Verifiable Credential Type Metadata, based on ietf-oauth-sd-jwt-vc (draft 09), using a single language tag (en-US).",
			},
			"elm": {
				Name:        "ELM Credential",
				Description: "European Learning Model (ELM) Credential.",
			},
			"micro_credential": {
				Name:        "MicroCredential",
				Description: "MicroCredential based on the OBv3 schema.",
			},
			"openbadge_basic": {
				Name:        "ELM Credential",
				Description: "European Learning Model (ELM) Credential.",
			},
			"openbadge_complete": {
				Name:        "ELM Credential",
				Description: "European Learning Model (ELM) Credential.",
			},
			"openbadge_endorsements": {
				Name:        "ELM Credential",
				Description: "European Learning Model (ELM) Credential.",
			},
			"pda1": {
				Name:        "DC4EU PDA1 SD-JWT VCTM",
				Description: "DC4EU Portable Document A1 (PDA1) SD-JWT Verifiable Credential Type Metadata, based on ietf-oauth-sd-jwt-vc (draft 09), using a single language tag (en-US).",
			},
			"pid": {
				Name:        "PID SD-JWT VC Type Metadata",
				Description: "Person Identification Data per EUDI ARF PID Rulebook v1.0 (urn:eudi:pid:1).",
			},
		},
		Wallets: map[string]string{
			"dc4eu":       "DC4EU Wallet",
			"funke":       "Funke Wallet",
			"siros_sunet": "Siros SUNET Wallet",
			"sunet_dev":   "SUNET Dev Wallet",
			"vanilla":     "Vanilla wwWallet",
		},
	}

	// Compare the entire structure
	assert.Equal(t, expected.CredentialTypes, metadata.CredentialTypes, "Credential types should match expected structure")
	assert.Equal(t, expected.Wallets, metadata.Wallets, "Wallets should match expected structure")
}

func TestCreateCredentialOfferLookupMetadata_EmptyConfig(t *testing.T) {
	ctx := t.Context()

	// Create a client with no credential constructors or wallets
	client := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{
			Common: &model.Common{
				CredentialMetadata: map[string]*model.CredentialMetadata{},
			},
			APIGW: &model.APIGW{
				Delivery: model.APIGWDelivery{
					CredentialOffers: model.CredentialOffers{
						Wallets: map[string]model.CredentialOfferWallets{},
					},
				},
			},
		},
		CredentialOfferLookupMetadata: &CredentialOfferLookupMetadata{},
	}

	// Execute the function
	err := client.CreateCredentialOfferLookupMetadata(ctx)
	require.NoError(t, err)

	// Verify empty but initialized maps
	metadata := client.CredentialOfferLookupMetadata
	require.NotNil(t, metadata)
	assert.Empty(t, metadata.CredentialTypes)
	assert.Empty(t, metadata.Wallets)
}

func TestCreateCredentialOfferLookupMetadata_MissingVCTM(t *testing.T) {
	ctx := t.Context()

	// Simulate a constructor with VCTMFilePath set but VCTM not loaded.
	// This should now return an error because VCTM is nil.
	client := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{
			Common: &model.Common{
				CredentialMetadata: map[string]*model.CredentialMetadata{
					"diploma": {
						VCTMFilePath: "../../../metadata/vctm_diploma.json",
						// VCTM intentionally NOT loaded
					},
				},
			},
			APIGW: &model.APIGW{
				Delivery: model.APIGWDelivery{
					CredentialOffers: model.CredentialOffers{
						Wallets: map[string]model.CredentialOfferWallets{},
					},
				},
			},
		},
		CredentialOfferLookupMetadata: &CredentialOfferLookupMetadata{},
	}

	err := client.CreateCredentialOfferLookupMetadata(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `credential constructor for scope "diploma" has no VCTM or MDDL configured`)
}

func TestCreateCredentialOfferLookupMetadata_NilVCTMNoFilePath(t *testing.T) {
	ctx := t.Context()

	// A constructor without VCTMFilePath still has nil VCTM and must error.
	client := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{
			Common: &model.Common{
				CredentialMetadata: map[string]*model.CredentialMetadata{
					"empty_scope": {
						// No VCTMFilePath, no VCTM – must still be caught
					},
				},
			},
			APIGW: &model.APIGW{
				Delivery: model.APIGWDelivery{
					CredentialOffers: model.CredentialOffers{
						Wallets: map[string]model.CredentialOfferWallets{},
					},
				},
			},
		},
		CredentialOfferLookupMetadata: &CredentialOfferLookupMetadata{},
	}

	err := client.CreateCredentialOfferLookupMetadata(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `credential constructor for scope "empty_scope" has no VCTM or MDDL configured`)
}

func TestCreateCredentialOfferLookupMetadata_MixedValidAndNilVCTM(t *testing.T) {
	ctx := t.Context()

	// One constructor with a loaded VCTM and one without – should still error.
	diplomaCC := &model.CredentialMetadata{
		VCTMFilePath: "../../../metadata/vctm_diploma.json",
	}
	require.NoError(t, diplomaCC.LoadVCTMetadata(context.Background(), "diploma"))

	client := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{
			Common: &model.Common{
				CredentialMetadata: map[string]*model.CredentialMetadata{
					"diploma": diplomaCC,
					"broken_scope": {
						VCTMFilePath: "nonexistent.json",
						// VCTM not loaded
					},
				},
			},
			APIGW: &model.APIGW{
				Delivery: model.APIGWDelivery{
					CredentialOffers: model.CredentialOffers{
						Wallets: map[string]model.CredentialOfferWallets{},
					},
				},
			},
		},
		CredentialOfferLookupMetadata: &CredentialOfferLookupMetadata{},
	}

	err := client.CreateCredentialOfferLookupMetadata(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has no VCTM or MDDL configured")
}

func TestCreateCredentialOfferLookupMetadata_JSONOutput(t *testing.T) {
	ctx := t.Context()

	// Create a test client matching the expected output format
	client := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{
			Common: &model.Common{
				CredentialMetadata: map[string]*model.CredentialMetadata{
					"diploma":                {VCTMFilePath: "../../../metadata/vctm_diploma.json"},
					"ehic":                   {VCTMFilePath: "../../../metadata/vctm_ehic.json"},
					"elm":                    {VCTMFilePath: "../../../metadata/vctm_elm.json"},
					"micro_credential":       {VCTMFilePath: "../../../metadata/vctm_microcredential.json"},
					"openbadge_basic":        {VCTMFilePath: "../../../metadata/vctm_elm.json"},
					"openbadge_complete":     {VCTMFilePath: "../../../metadata/vctm_elm.json"},
					"openbadge_endorsements": {VCTMFilePath: "../../../metadata/vctm_elm.json"},
					"pda1":                   {VCTMFilePath: "../../../metadata/vctm_pda1.json"},
					"pid":                    {VCTMFilePath: "../../../metadata/vctm_pid.json"},
				},
			},
			APIGW: &model.APIGW{
				Delivery: model.APIGWDelivery{
					CredentialOffers: model.CredentialOffers{
						Wallets: map[string]model.CredentialOfferWallets{
							"dc4eu":       {Label: "DC4EU Wallet"},
							"funke":       {Label: "Funke Wallet"},
							"siros_sunet": {Label: "Siros SUNET Wallet"},
							"sunet_dev":   {Label: "SUNET Dev Wallet"},
							"vanilla":     {Label: "Vanilla wwWallet"},
						},
					},
				},
			},
		},
		CredentialOfferLookupMetadata: &CredentialOfferLookupMetadata{},
	}

	// Load VCTMs (normally done by configuration.New)
	for scope, cc := range client.cfg.Common.CredentialMetadata {
		require.NoError(t, cc.LoadVCTMetadata(context.Background(), scope))
	}

	// Execute the function
	err := client.CreateCredentialOfferLookupMetadata(ctx)
	require.NoError(t, err)

	// Marshal to JSON to verify output format
	output := struct {
		Credentials map[string]CredentialOfferTypeData `json:"credentials"`
		Wallets     map[string]string                  `json:"wallets"`
	}{
		Credentials: client.CredentialOfferLookupMetadata.CredentialTypes,
		Wallets:     client.CredentialOfferLookupMetadata.Wallets,
	}

	jsonBytes, err := json.MarshalIndent(output, "", "    ")
	require.NoError(t, err)

	// Print for visual verification (optional, comment out if not needed)
	t.Logf("Generated JSON output:\n%s", string(jsonBytes))

	// Verify structure
	assert.Len(t, output.Credentials, 9, "Should have 9 credential types")
	assert.Len(t, output.Wallets, 5, "Should have 5 wallets")

	// Spot check a few entries
	assert.Equal(t, "DC4EU EHIC SD-JWT VCTM", output.Credentials["ehic"].Name)
	assert.Equal(t, "DC4EU Wallet", output.Wallets["dc4eu"])
}
