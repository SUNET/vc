package primitives

import (
	"time"

	"github.com/biter777/countries"
)

// CountryAlpha2 maps a country name or alpha-3 code to its ISO 3166-1 alpha-2
// code. Unknown inputs are returned unchanged so an unrecognised value does
// not silently become empty.
func CountryAlpha2(s string) string {
	cc := countries.ByName(s)
	if cc == countries.Unknown {
		return s
	}
	return cc.Alpha2()
}

// CountryAlpha3 maps a country name or alpha-2 code to its ISO 3166-1 alpha-3
// code. Unknown inputs are returned unchanged.
func CountryAlpha3(s string) string {
	cc := countries.ByName(s)
	if cc == countries.Unknown {
		return s
	}
	return cc.Alpha3()
}

// CountryAlpha2Args configures the country_alpha2 primitive.
// Unknown inputs pass through unchanged; applied element-wise on []string.
type CountryAlpha2Args struct {
	Input  string `yaml:"input" validate:"required" doc_example:"nationalities"`
	Output string `yaml:"output,omitempty" doc_example:"nationalities"`
}

// Apply implements Applier.
func (a *CountryAlpha2Args) Apply(claims map[string]any, _ time.Time) (map[string]any, error) {
	return applyStringElementwise(a.Input, a.Output, claims, CountryAlpha2)
}

// CountryAlpha3Args configures the country_alpha3 primitive.
type CountryAlpha3Args struct {
	Input  string `yaml:"input" validate:"required" doc_example:"nationalities"`
	Output string `yaml:"output,omitempty" doc_example:"nationalities"`
}

// Apply implements Applier.
func (a *CountryAlpha3Args) Apply(claims map[string]any, _ time.Time) (map[string]any, error) {
	return applyStringElementwise(a.Input, a.Output, claims, CountryAlpha3)
}
