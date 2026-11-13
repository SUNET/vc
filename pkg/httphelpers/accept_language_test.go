package httphelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAcceptedLanguages(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   []string
	}{
		{
			name:   "no header at all",
			header: "",
			want:   []string{},
		},
		{
			name:   "a single tag, as every browser sends for its primary language",
			header: "sv-SE",
			want:   []string{"sv-se"},
		},
		{
			name:   "qualities order the list, highest first",
			header: "de;q=0.5, sv-SE;q=0.9, en;q=0.7",
			want:   []string{"sv-se", "en", "de"},
		},
		{
			name:   "equal qualities keep header order",
			header: "sv-SE, da, nb",
			want:   []string{"sv-se", "da", "nb"},
		},
		{
			name:   "an implicit quality of 1 outranks an explicit lower one",
			header: "de;q=0.8, sv-SE",
			want:   []string{"sv-se", "de"},
		},
		{
			name:   "q=0 means not acceptable, so the tag is dropped",
			header: "sv-SE, de;q=0",
			want:   []string{"sv-se"},
		},
		{
			name:   "the wildcard carries no preference and is dropped",
			header: "sv-SE, *;q=0.1",
			want:   []string{"sv-se"},
		},
		{
			name:   "a header of nothing but a wildcard yields nothing",
			header: "*",
			want:   []string{},
		},
		{
			name:   "surrounding whitespace and case do not matter",
			header: "  SV-se ,  EN-GB ",
			want:   []string{"sv-se", "en-gb"},
		},
		{
			name:   "an unparsable quality falls back to 1 rather than dropping the tag",
			header: "sv-SE;q=high",
			want:   []string{"sv-se"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, AcceptedLanguages(tc.header))
		})
	}
}
