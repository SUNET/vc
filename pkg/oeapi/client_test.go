package oeapi

import (
	"net/url"
	"testing"
)

func TestQueryOptions(t *testing.T) {
	q := buildQuery([]QueryOption{
		WithPageSize(50),
		WithPageNumber(2),
		WithRole("student"),
		WithState("associated"),
	})
	want := url.Values{
		"pageSize":   {"50"},
		"pageNumber": {"2"},
		"role":       {"student"},
		"state":      {"associated"},
	}
	if q.Encode() != want.Encode() {
		t.Errorf("buildQuery = %q, want %q", q.Encode(), want.Encode())
	}
}
