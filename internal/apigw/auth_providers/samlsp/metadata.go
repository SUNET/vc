package samlsp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/SUNET/vc/pkg/model"
	"github.com/beevik/etree"
)

const mduiNamespace = "urn:oasis:names:tc:SAML:metadata:ui"

// augmentSPMetadata rewrites crewjam/saml's SP metadata XML to include the
// federation-facing descriptors SWAMID demands (mdui:UIInfo under
// SPSSODescriptor/Extensions, top-level md:Organization, and one or more
// md:ContactPerson). Returns the input unchanged when meta is nil.
func augmentSPMetadata(xmlBytes []byte, meta *model.SAMLSPMetadata) ([]byte, error) {
	if meta == nil {
		return xmlBytes, nil
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("parse SP metadata: %w", err)
	}
	ed := doc.SelectElement("EntityDescriptor")
	if ed == nil {
		return nil, fmt.Errorf("SP metadata missing EntityDescriptor")
	}

	if meta.UIInfo != nil {
		spsso := ed.SelectElement("SPSSODescriptor")
		if spsso == nil {
			return nil, fmt.Errorf("SP metadata missing SPSSODescriptor")
		}
		injectUIInfoExtensions(spsso, meta.UIInfo)
	}

	if meta.Organization != nil {
		appendOrganization(ed, meta.Organization)
	}

	for i := range meta.ContactPersons {
		appendContactPerson(ed, &meta.ContactPersons[i])
	}

	doc.Indent(2)
	return doc.WriteToBytes()
}

// injectUIInfoExtensions inserts <md:Extensions><mdui:UIInfo>... as the first
// child of the SPSSODescriptor, which is the schema-required position (before
// KeyDescriptor). If an Extensions element already exists, UIInfo is appended
// into it rather than duplicating the wrapper.
func injectUIInfoExtensions(spsso *etree.Element, ui *model.SAMLUIInfo) {
	lang := ui.Lang
	if lang == "" {
		lang = "en"
	}

	var ext *etree.Element
	if existing := spsso.SelectElement("Extensions"); existing != nil {
		ext = existing
	} else {
		ext = etree.NewElement("Extensions")
		spsso.InsertChildAt(0, ext)
	}

	uiInfo := ext.CreateElement("mdui:UIInfo")
	uiInfo.CreateAttr("xmlns:mdui", mduiNamespace)
	addLocalized(uiInfo, "mdui:DisplayName", ui.DisplayName, lang)
	addLocalized(uiInfo, "mdui:Description", ui.Description, lang)
	addLocalized(uiInfo, "mdui:InformationURL", ui.InformationURL, lang)
	addLocalized(uiInfo, "mdui:PrivacyStatementURL", ui.PrivacyStatementURL, lang)
	if ui.Logo != nil {
		logo := uiInfo.CreateElement("mdui:Logo")
		logo.CreateAttr("height", strconv.Itoa(ui.Logo.Height))
		logo.CreateAttr("width", strconv.Itoa(ui.Logo.Width))
		logo.CreateAttr("xml:lang", lang)
		logo.SetText(ui.Logo.URL)
	}
}

func appendOrganization(ed *etree.Element, org *model.SAMLOrganization) {
	lang := org.Lang
	if lang == "" {
		lang = "en"
	}
	o := ed.CreateElement("Organization")
	addLocalized(o, "OrganizationName", org.Name, lang)
	addLocalized(o, "OrganizationDisplayName", org.DisplayName, lang)
	addLocalized(o, "OrganizationURL", org.URL, lang)
}

func appendContactPerson(ed *etree.Element, cp *model.SAMLContactPerson) {
	c := ed.CreateElement("ContactPerson")
	c.CreateAttr("contactType", cp.Type)
	if cp.Company != "" {
		c.CreateElement("Company").SetText(cp.Company)
	}
	if cp.GivenName != "" {
		c.CreateElement("GivenName").SetText(cp.GivenName)
	}
	if cp.SurName != "" {
		c.CreateElement("SurName").SetText(cp.SurName)
	}
	if cp.Email != "" {
		// SWAMID Tech 6.1.22 requires the mailto: scheme prefix.
		email := cp.Email
		if !strings.HasPrefix(email, "mailto:") {
			email = "mailto:" + email
		}
		c.CreateElement("EmailAddress").SetText(email)
	}
	if cp.Phone != "" {
		c.CreateElement("TelephoneNumber").SetText(cp.Phone)
	}
}

func addLocalized(parent *etree.Element, tag, value, lang string) {
	if value == "" {
		return
	}
	el := parent.CreateElement(tag)
	el.CreateAttr("xml:lang", lang)
	el.SetText(value)
}
