package credential

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAdd_AssignsDeterministicID_WhenEmpty(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id1 := s.Add(&StoredCredential{RawCredential: "a"})
	id2 := s.Add(&StoredCredential{RawCredential: "b"})
	id3 := s.Add(&StoredCredential{RawCredential: "c"})

	if id1 != "cred-1" {
		t.Errorf("first credential: got ID %q, want %q", id1, "cred-1")
	}
	if id2 != "cred-2" {
		t.Errorf("second credential: got ID %q, want %q", id2, "cred-2")
	}
	if id3 != "cred-3" {
		t.Errorf("third credential: got ID %q, want %q", id3, "cred-3")
	}
}

func TestAdd_PreservesProvidedID(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id := s.Add(&StoredCredential{ID: "my-custom-id", RawCredential: "x"})

	if id != "my-custom-id" {
		t.Errorf("got ID %q, want %q", id, "my-custom-id")
	}
	cred, ok := s.Get("my-custom-id")
	if !ok {
		t.Fatal("credential not found by provided ID")
	}
	if cred.RawCredential != "x" {
		t.Errorf("got RawCredential %q, want %q", cred.RawCredential, "x")
	}
}

func TestAdd_CounterIncrementsEvenWhenIDProvided(t *testing.T) {
	t.Parallel()
	s := NewStore()

	// First Add with a provided ID still increments the counter to 1.
	s.Add(&StoredCredential{ID: "custom"})
	// Second Add without an ID should use counter=2, producing "cred-2".
	id := s.Add(&StoredCredential{})

	if id != "cred-2" {
		t.Errorf("got ID %q, want %q – counter should have incremented past the custom-ID add", id, "cred-2")
	}
}

func TestAdd_SetsIssuedAt(t *testing.T) {
	t.Parallel()
	s := NewStore()

	before := time.Now()
	id := s.Add(&StoredCredential{RawCredential: "r"})
	after := time.Now()

	cred, _ := s.Get(id)
	if cred.IssuedAt.Before(before) || cred.IssuedAt.After(after) {
		t.Errorf("IssuedAt %v not in [%v, %v]", cred.IssuedAt, before, after)
	}
}

func TestAdd_OverwritesExistingIssuedAt(t *testing.T) {
	t.Parallel()
	s := NewStore()

	original := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	id := s.Add(&StoredCredential{IssuedAt: original})

	cred, _ := s.Get(id)
	if cred.IssuedAt.Equal(original) {
		t.Error("IssuedAt was not overwritten; still equals the original value")
	}
}

func TestGet_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := NewStore()

	_, ok := s.Get("nonexistent")
	if ok {
		t.Error("expected ok=false for missing credential")
	}
}

func TestDelete_RemovesCredential(t *testing.T) {
	t.Parallel()
	s := NewStore()
	id := s.Add(&StoredCredential{RawCredential: "del"})

	deleted := s.Delete(id)
	if !deleted {
		t.Error("Delete returned false for existing credential")
	}
	if _, ok := s.Get(id); ok {
		t.Error("credential still accessible after Delete")
	}
}

func TestDelete_ReturnsFalseForMissing(t *testing.T) {
	t.Parallel()
	s := NewStore()

	if s.Delete("no-such-id") {
		t.Error("Delete returned true for non-existent credential")
	}
}

func TestCount_ReflectsAddAndDelete(t *testing.T) {
	t.Parallel()
	s := NewStore()

	if s.Count() != 0 {
		t.Fatalf("empty store: got Count=%d, want 0", s.Count())
	}

	id1 := s.Add(&StoredCredential{})
	s.Add(&StoredCredential{})
	if s.Count() != 2 {
		t.Fatalf("after 2 adds: got Count=%d, want 2", s.Count())
	}

	s.Delete(id1)
	if s.Count() != 1 {
		t.Fatalf("after delete: got Count=%d, want 1", s.Count())
	}
}

func TestList_ReturnsAllCredentials(t *testing.T) {
	t.Parallel()
	s := NewStore()

	s.Add(&StoredCredential{RawCredential: "a"})
	s.Add(&StoredCredential{RawCredential: "b"})

	list := s.List()
	if len(list) != 2 {
		t.Fatalf("got %d credentials, want 2", len(list))
	}

	raws := map[string]bool{}
	for _, c := range list {
		raws[c.RawCredential] = true
	}
	if !raws["a"] || !raws["b"] {
		t.Errorf("missing expected credentials in List: %v", raws)
	}
}

func TestList_EmptyStore(t *testing.T) {
	t.Parallel()
	s := NewStore()

	list := s.List()
	if list == nil {
		t.Fatal("List returned nil, want non-nil empty slice")
	}
	if len(list) != 0 {
		t.Errorf("got %d credentials, want 0", len(list))
	}
}

func TestFindByVCT_FiltersCorrectly(t *testing.T) {
	t.Parallel()
	s := NewStore()

	s.Add(&StoredCredential{VCT: "urn:credential:diploma", Format: "vc+sd-jwt"})
	s.Add(&StoredCredential{VCT: "urn:credential:pid", Format: "vc+sd-jwt"})
	s.Add(&StoredCredential{VCT: "urn:credential:diploma", Format: "mso_mdoc"})

	results := s.FindByVCT("urn:credential:diploma")
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, c := range results {
		if c.VCT != "urn:credential:diploma" {
			t.Errorf("unexpected VCT %q in results", c.VCT)
		}
	}
}

func TestFindByVCT_NoMatch(t *testing.T) {
	t.Parallel()
	s := NewStore()
	s.Add(&StoredCredential{VCT: "urn:credential:diploma"})

	results := s.FindByVCT("urn:credential:nonexistent")
	if len(results) != 0 {
		t.Errorf("got %d results, want 0", len(results))
	}
}

func TestFindByFormat_FiltersCorrectly(t *testing.T) {
	t.Parallel()
	s := NewStore()

	s.Add(&StoredCredential{Format: "vc+sd-jwt", VCT: "a"})
	s.Add(&StoredCredential{Format: "mso_mdoc", VCT: "b"})
	s.Add(&StoredCredential{Format: "vc+sd-jwt", VCT: "c"})

	results := s.FindByFormat("vc+sd-jwt")
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, c := range results {
		if c.Format != "vc+sd-jwt" {
			t.Errorf("unexpected Format %q in results", c.Format)
		}
	}
}

func TestFindByFormat_NoMatch(t *testing.T) {
	t.Parallel()
	s := NewStore()
	s.Add(&StoredCredential{Format: "vc+sd-jwt"})

	results := s.FindByFormat("jwt_vc_json")
	if len(results) != 0 {
		t.Errorf("got %d results, want 0", len(results))
	}
}

func TestStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	s := NewStore()
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			id := s.Add(&StoredCredential{RawCredential: fmt.Sprintf("cred-%d", n)})
			s.Get(id)
			s.List()
			s.FindByVCT("x")
			s.FindByFormat("y")
			s.Count()
		}(i)
	}

	wg.Wait()

	if s.Count() != goroutines {
		t.Errorf("after %d concurrent adds: got Count=%d", goroutines, s.Count())
	}
}
