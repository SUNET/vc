package apiv1

import (
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/httphelpers"
)

func bigHeader(ranges int, shape string) string {
	parts := make([]string, 0, ranges)
	for range ranges {
		parts = append(parts, shape)
	}
	return strings.Join(parts, ",")
}

func BenchmarkSelectionUnderALargeHeader(b *testing.B) {
	entries := localeEntries("en-US", "sv-SE", "de-DE")
	for _, c := range []struct {
		name  string
		shape string
	}{
		{"1-subtag", "zz"},
		{"5-subtag", "zz-aa-bb-cc-dd"},
	} {
		h := bigHeader(50000, c.shape)
		b.Run(c.name, func(b *testing.B) {
			acc := httphelpers.AcceptedLanguages(h)
			rej := httphelpers.RejectedLanguages(h)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				displayForLocales(entries, acc, rej, func(e localeEntry) string { return e.locale })
			}
		})
	}
}
