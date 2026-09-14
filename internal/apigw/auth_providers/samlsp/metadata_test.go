package samlsp

import (
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/model"
)

const baseMetadata = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/samlsp/metadata">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"/>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/samlsp/acs" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>`

func TestAugmentSPMetadata_NilPassthrough(t *testing.T) {
	out, err := augmentSPMetadata([]byte(baseMetadata), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != baseMetadata {
		t.Fatal("nil meta must return input bytes unchanged")
	}
}

func TestAugmentSPMetadata_AllFields(t *testing.T) {
	meta := &model.SAMLSPMetadata{
		Organization: &model.SAMLOrganization{
			Name:        "SUNET",
			DisplayName: "SUNET",
			URL:         "https://sunet.se/",
		},
		ContactPersons: []model.SAMLContactPerson{
			{Type: "technical", GivenName: "Tech", SurName: "Team", Email: "tech@sunet.se"},
			{Type: "administrative", GivenName: "Admin", SurName: "Team", Email: "admin@sunet.se"},
		},
		UIInfo: &model.SAMLUIInfo{
			DisplayName:         "SUNET VC Issuer",
			Description:         "SUNET verifiable credentials issuer.",
			InformationURL:      "https://vc.sunet.se/",
			PrivacyStatementURL: "https://vc.sunet.se/privacy",
			Logo:                &model.SAMLUILogo{URL: "https://vc.sunet.se/logo.png", Height: 100, Width: 100},
		},
	}
	out, err := augmentSPMetadata([]byte(baseMetadata), meta)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(out)

	for _, needle := range []string{
		`<Extensions>`,
		`<mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">`,
		`<mdui:DisplayName xml:lang="en">SUNET VC Issuer</mdui:DisplayName>`,
		`<mdui:Description xml:lang="en">SUNET verifiable credentials issuer.</mdui:Description>`,
		`<mdui:InformationURL xml:lang="en">https://vc.sunet.se/</mdui:InformationURL>`,
		`<mdui:PrivacyStatementURL xml:lang="en">https://vc.sunet.se/privacy</mdui:PrivacyStatementURL>`,
		`<mdui:Logo height="100" width="100" xml:lang="en">https://vc.sunet.se/logo.png</mdui:Logo>`,
		`<Organization>`,
		`<OrganizationName xml:lang="en">SUNET</OrganizationName>`,
		`<OrganizationDisplayName xml:lang="en">SUNET</OrganizationDisplayName>`,
		`<OrganizationURL xml:lang="en">https://sunet.se/</OrganizationURL>`,
		`<ContactPerson contactType="technical">`,
		`<ContactPerson contactType="administrative">`,
		`<EmailAddress>mailto:tech@sunet.se</EmailAddress>`,
		`<EmailAddress>mailto:admin@sunet.se</EmailAddress>`,
	} {
		if !strings.Contains(got, needle) {
			t.Errorf("output missing %q\n---\n%s", needle, got)
		}
	}

	// Extensions must sit before KeyDescriptor per SAML schema order.
	if strings.Index(got, "<Extensions>") > strings.Index(got, "<KeyDescriptor") {
		t.Errorf("Extensions must precede KeyDescriptor")
	}
}

func TestAugmentSPMetadata_EmailMailtoIdempotent(t *testing.T) {
	meta := &model.SAMLSPMetadata{
		ContactPersons: []model.SAMLContactPerson{
			{Type: "technical", Email: "mailto:tech@sunet.se"},
		},
	}
	out, err := augmentSPMetadata([]byte(baseMetadata), meta)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(out), "mailto:mailto:") {
		t.Errorf("email already prefixed with mailto: must not be double-prefixed\n%s", string(out))
	}
}
