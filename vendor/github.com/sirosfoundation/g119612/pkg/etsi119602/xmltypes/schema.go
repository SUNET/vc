package xmltypes

import (
	"encoding/xml"
	"io"
	"strings"
)

// Helper types needed by xgen-generated code.

// Lang represents the xml:lang attribute type.
type Lang string

// FindByLanguage looks up a name by language tag, returning dflt if not found.
func FindByLanguage(names *InternationalNamesType, lang string, dflt string) string {
	if names == nil {
		return dflt
	}
	for _, n := range names.Name {
		if n.XmlLangAttr != nil && string(*n.XmlLangAttr) == lang {
			if n.NonEmptyNormalizedString != nil {
				return string(*n.NonEmptyNormalizedString)
			}
		}
	}
	return dflt
}

// UnmarshalXML handles both standard XSD simpleContent (direct chardata) and
// implementations that serialize NonEmptyNormalizedString as a child element.
func (m *MultiLangNormStringType) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		if attr.Name.Local == "lang" {
			lang := Lang(attr.Value)
			m.XmlLangAttr = &lang
		}
	}

	var chardata string
	var childValue string
	for {
		tok, err := d.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		switch t := tok.(type) {
		case xml.CharData:
			chardata += string(t)
		case xml.StartElement:
			if t.Name.Local == "NonEmptyNormalizedString" {
				var s string
				if err := d.DecodeElement(&s, &t); err != nil {
					return err
				}
				childValue = s
			} else {
				if err := d.Skip(); err != nil {
					return err
				}
			}
		case xml.EndElement:
			if childValue != "" {
				v := NonEmptyNormalizedString(childValue)
				m.NonEmptyNormalizedString = &v
			} else {
				trimmed := strings.TrimSpace(chardata)
				if trimmed != "" {
					v := NonEmptyNormalizedString(trimmed)
					m.NonEmptyNormalizedString = &v
				}
			}
			return nil
		}
	}
	return nil
}

// UnmarshalXML handles both standard XSD simpleContent (direct chardata) and
// implementations that serialize NonEmptyString as a child element.
func (m *MultiLangStringType) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		if attr.Name.Local == "lang" {
			lang := Lang(attr.Value)
			m.XmlLangAttr = &lang
		}
	}

	var chardata string
	var childValue string
	for {
		tok, err := d.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		switch t := tok.(type) {
		case xml.CharData:
			chardata += string(t)
		case xml.StartElement:
			if t.Name.Local == "NonEmptyString" {
				var s string
				if err := d.DecodeElement(&s, &t); err != nil {
					return err
				}
				childValue = s
			} else {
				if err := d.Skip(); err != nil {
					return err
				}
			}
		case xml.EndElement:
			if childValue != "" {
				v := NonEmptyString(childValue)
				m.NonEmptyString = &v
			} else {
				trimmed := strings.TrimSpace(chardata)
				if trimmed != "" {
					v := NonEmptyString(trimmed)
					m.NonEmptyString = &v
				}
			}
			return nil
		}
	}
	return nil
}
