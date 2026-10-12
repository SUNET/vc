package webvendor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
)

// StaticETags gives every file in fsys a strong ETag derived from its
// contents, so a browser can be told to revalidate cheaply instead of being
// told to trust what it already has.
//
// The problem this solves is specific to an embedded filesystem. embed.FS
// reports a ZERO modification time, so net/http's file server emits no
// Last-Modified, and with no ETag either there is no validator at all - a
// conditional request is impossible, and the only thing governing staleness
// is the freshness lifetime. apigw set that to 24 hours on the reasoning
// that these assets "only change on redeployment", which is exactly the
// case it cannot handle: after a deploy, a browser that loaded the page in
// the previous 24 hours keeps running the old JavaScript against the new
// server-rendered HTML, and does not ask.
//
// That is not hypothetical. It shipped a consent page whose template
// rendered a credential's type from a field the cached script never set,
// so the type read "N/A" until a hard reload - a bug in neither the
// template nor the script, only in the pairing.
//
// Hashing every file once at startup is affordable because the set is
// embedded, small and fixed: there is nothing to invalidate and no
// filesystem to watch.
func StaticETags(fsys fs.FS) (map[string]string, error) {
	etags := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := fsys.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()

		sum := sha256.New()
		if _, err := io.Copy(sum, f); err != nil {
			return err
		}
		// Half a SHA-256 is 128 bits, which is as much collision
		// resistance as a cache validator can use. Strong, not weak: the
		// bytes are compared exactly, so a byte-range request stays valid.
		etags["/"+name] = fmt.Sprintf("%q", hex.EncodeToString(sum.Sum(nil))[:32])
		return nil
	})
	if err != nil {
		return nil, err
	}
	return etags, nil
}
