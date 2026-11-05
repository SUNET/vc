// migrate_claim_paths rewrites the claim spellings of earlier releases in
// service configuration files and presentation request files, in place.
// Each dotted claim name becomes a claims path pointer (OpenID4VP 1.0
// section 7), each map keyed by dotted names becomes the list form, and a
// claim_mappings map of one credential query becomes the keyed form.
//
// It keeps every comment. It prints a line per claim_mappings it leaves
// as written, because the keyed form would map other claims, and a line
// per file it rewrites. A second run changes nothing.
//
// A configuration names its credential schemas by deployment paths, such
// as /metadata/pid_mdoc.mdoc.json. -schemas maps such a prefix to a local
// directory: -schemas /metadata=./metadata.
//
// Usage:
//
//	migrate_claim_paths [-schemas PREFIX=DIR]... [-n] FILE...
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/SUNET/vc/pkg/configuration"
	"github.com/SUNET/vc/pkg/legacyclaims"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "migrate_claim_paths:", err)
		os.Exit(1)
	}
}

// run migrates each file the arguments name, and writes its report to out.
func run(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("migrate_claim_paths", flag.ContinueOnError)
	var schemas prefixes
	flags.Var(&schemas, "schemas", "map a schema path prefix of the configuration to a local directory, as /metadata=./metadata; repeat for several")
	dryRun := flags.Bool("n", false, "report the rewrites and write no file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() == 0 {
		return errors.New("name at least one configuration or presentation request file")
	}
	for _, file := range flags.Args() {
		if err := migrate(ctx, file, schemas, *dryRun, out); err != nil {
			return err
		}
	}
	return nil
}

// migrate rewrites one file.
func migrate(ctx context.Context, file string, schemas prefixes, dryRun bool, out io.Writer) error {
	info, err := os.Stat(file)
	if err != nil {
		return err
	}
	src, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return err
	}
	upgraded, rewrites, err := upgrade(ctx, file, src, schemas.apply)
	if err != nil {
		return err
	}
	kept := 0
	for _, rewrite := range rewrites {
		if rewrite.Note == "" {
			continue
		}
		kept++
		if _, err := fmt.Fprintln(out, rewrite); err != nil {
			return err
		}
	}
	if bytes.Equal(upgraded, src) {
		return nil
	}
	if _, err := fmt.Fprintf(out, "%s: rewrote %d claim spellings\n", file, len(rewrites)-kept); err != nil {
		return err
	}
	if dryRun {
		return nil
	}
	return os.WriteFile(file, upgraded, info.Mode().Perm())
}

// upgrade returns the text of a file with its claim spellings upgraded,
// and the upgraded spellings.
func upgrade(ctx context.Context, file string, src []byte, schemaPath func(string) string) ([]byte, []legacyclaims.Rewrite, error) {
	doc, err := legacyclaims.Parse(file, src)
	if err != nil {
		return nil, nil, err
	}
	if !legacyclaims.IsTemplateFile(doc) {
		return configuration.UpgradeFile(ctx, file, src, schemaPath)
	}
	if err := legacyclaims.UpgradeTemplates(doc, true); err != nil {
		return nil, nil, err
	}
	text, err := doc.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return text, doc.Rewrites(), nil
}

// prefixes maps path prefixes to local directories.
type prefixes []prefix

// prefix maps the schema paths under from to the same paths under to.
type prefix struct{ from, to string }

func (p *prefixes) String() string {
	parts := make([]string, len(*p))
	for i, m := range *p {
		parts[i] = m.from + "=" + m.to
	}
	return strings.Join(parts, ",")
}

func (p *prefixes) Set(value string) error {
	from, to, ok := strings.Cut(value, "=")
	if !ok || from == "" || to == "" {
		return fmt.Errorf("%q is no PREFIX=DIR mapping", value)
	}
	*p = append(*p, prefix{from: from, to: to})
	return nil
}

// apply maps a schema path through the first prefix that holds it.
func (p prefixes) apply(path string) string {
	for _, m := range p {
		if rest, ok := strings.CutPrefix(path, m.from); ok {
			return filepath.Join(m.to, rest)
		}
	}
	return path
}
