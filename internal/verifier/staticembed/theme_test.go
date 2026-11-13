package staticembed

import (
	"bytes"
	"io/fs"
	"testing"
)

// Bulma ships @media (prefers-color-scheme: dark), but defines .theme-light
// afterwards at the same specificity, so a page that pins the class can never
// reach the dark palette whatever the viewer's system is set to. The class was
// on every page here, which made the framework's dark theme unreachable in
// every deployment (SUNET/vc#930).
func TestNoPagePinsTheLightTheme(t *testing.T) {
	pages, err := fs.Glob(FS, "*.html")
	if err != nil {
		t.Fatalf("glob embedded pages: %v", err)
	}
	if len(pages) == 0 {
		t.Fatal("no embedded pages found, so this guard proves nothing")
	}

	for _, name := range pages {
		body, err := fs.ReadFile(FS, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if bytes.Contains(body, []byte(`class="theme-light"`)) {
			t.Errorf("%s pins the light theme, so it can never follow the viewer's system setting", name)
		}
	}
}
