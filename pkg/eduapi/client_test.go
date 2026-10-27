package eduapi

import (
	"testing"
)

func TestQueryOptions(t *testing.T) {
	q := buildQuery([]QueryOption{
		WithLimit(10),
		WithOffset(20),
		WithFilter("role='student'"),
		WithSort("familyName"),
		WithOrderBy("asc"),
	})

	if q.Get("limit") != "10" {
		t.Errorf("limit = %q, want 10", q.Get("limit"))
	}
	if q.Get("offset") != "20" {
		t.Errorf("offset = %q, want 20", q.Get("offset"))
	}
	if q.Get("filter") != "role='student'" {
		t.Errorf("filter = %q, want role='student'", q.Get("filter"))
	}
	if q.Get("sort") != "familyName" {
		t.Errorf("sort = %q, want familyName", q.Get("sort"))
	}
	if q.Get("orderBy") != "asc" {
		t.Errorf("orderBy = %q, want asc", q.Get("orderBy"))
	}
}
