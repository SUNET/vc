package webvendor

import (
	"io/fs"
	"os"
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
