package webvendor

import (
	"errors"
	"io/fs"
	"os"
	"sort"
)

// Overlay serves base, falling back to the shared vendored assets for any
// path base does not have.
//
// Both services mount their own staticembed at /static and need the vendored
// bundles to appear there too. Registering a second gin StaticFS under the
// same prefix is not possible - the wildcard routes collide - and moving the
// bundles to their own URL prefix would mean every page referencing them
// depends on which service served it. Overlaying keeps /static/dc-api.js
// meaning the same thing everywhere.
//
// base wins on conflict, so a service can still override a vendored file by
// shipping its own copy of that name.
func Overlay(base fs.FS) fs.FS {
	return overlayFS{base: base, vendor: FS}
}

type overlayFS struct {
	base   fs.FS
	vendor fs.FS
}

func (o overlayFS) Open(name string) (fs.File, error) {
	f, err := o.base.Open(name)
	if err == nil {
		return f, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	return o.vendor.Open(name)
}

// ReadDir merges both filesystems, so that walking the overlay finds every
// file the overlay can serve.
//
// Without this, fs.WalkDir sees only the base: fs.ReadDir falls back to
// opening the directory and reading it, Open(".") returns the BASE's root,
// and the vendored entries are simply not in that listing. A caller that
// walks to build an index - webvendor.StaticETags does exactly this - then
// produces an index missing every vendored asset, while Open still serves
// them. That is the worst shape for a bug: the file is served, and the
// thing the index was for silently does not apply to it.
//
// base wins on a name conflict, matching Open.
func (o overlayFS) ReadDir(name string) ([]fs.DirEntry, error) {
	baseEntries, baseErr := fs.ReadDir(o.base, name)
	vendorEntries, vendorErr := fs.ReadDir(o.vendor, name)

	// A path one filesystem does not have is normal - the whole point of an
	// overlay - and must not take the listing down with it. Anything ELSE
	// is reported, matching Open, which also falls back only on
	// ErrNotExist.
	//
	// The distinction matters because the caller cannot see it: silently
	// treating a permission or I/O error as "absent" returns a listing that
	// is short some files Open will still happily serve, and a caller
	// building an index from it gets a quietly incomplete one. That is the
	// same shape as the bug this ReadDir exists to fix.
	if baseErr != nil && !errors.Is(baseErr, fs.ErrNotExist) {
		return nil, baseErr
	}
	if vendorErr != nil && !errors.Is(vendorErr, fs.ErrNotExist) {
		return nil, vendorErr
	}
	if baseErr != nil && vendorErr != nil {
		return nil, baseErr
	}

	merged := make([]fs.DirEntry, 0, len(baseEntries)+len(vendorEntries))
	seen := make(map[string]struct{}, len(baseEntries))
	for _, entry := range baseEntries {
		seen[entry.Name()] = struct{}{}
		merged = append(merged, entry)
	}
	for _, entry := range vendorEntries {
		if _, shadowed := seen[entry.Name()]; shadowed {
			continue
		}
		merged = append(merged, entry)
	}

	// fs.ReadDir's contract is "sorted by filename", and callers are
	// entitled to rely on it even though WalkDir sorts again itself.
	sort.Slice(merged, func(i, j int) bool { return merged[i].Name() < merged[j].Name() })
	return merged, nil
}
