package etsi119612

// some stuff needed by xgen
type SignaturePolicyImplied AnyType
type AllSignedDataObjects AnyType
type Lang string

func FindByLanguage(names *InternationalNamesType, lang string, dflt string) string {
	for _, n := range names.Name {
		if string(*n.XmlLangAttr) == lang {
			return string(*n.NonEmptyNormalizedString)
		}
	}
	return dflt
}
