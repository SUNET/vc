package etsi119612

// some stuff needed by xgen
type SignaturePolicyImplied AnyType
type AllSignedDataObjects AnyType
type Lang string

// FindByLanguage returns the name for lang, or dflt when names is nil or no
// entry carries a matching xml:lang attribute and a value. The xml:lang
// attribute is optional in the schema, so entries without it are skipped.
func FindByLanguage(names *InternationalNamesType, lang string, dflt string) string {
	if names == nil {
		return dflt
	}
	for _, n := range names.Name {
		if n != nil && n.XmlLangAttr != nil && string(*n.XmlLangAttr) == lang &&
			n.NonEmptyNormalizedString != nil {
			return string(*n.NonEmptyNormalizedString)
		}
	}
	return dflt
}
