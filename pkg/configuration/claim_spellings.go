package configuration

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/SUNET/vc/pkg/legacyclaims"
	"github.com/SUNET/vc/pkg/model"

	"github.com/creasty/defaults"
	ts11client "github.com/sirosfoundation/go-ts11client"
	"gopkg.in/yaml.v2"
)

// configType is the type a configuration file decodes into.
var configType = reflect.TypeFor[model.Cfg]()

// fileDataSources is the part of a configuration file decodeDataSources
// decodes.
type fileDataSources struct {
	APIGW struct {
		DataSources model.DataSources `yaml:"data_sources"`
	} `yaml:"apigw"`
}

// decodeShared decodes a configuration file into cfg. The claim spellings
// of earlier releases outside apigw.data_sources are upgraded, and
// apigw.data_sources is emptied: decodeDataSources reads it once the
// credential schemas are loaded.
func decodeShared(file string, src []byte, cfg *model.Cfg) ([]legacyclaims.Rewrite, error) {
	doc, err := legacyclaims.Resolve(file, src, configType)
	if err != nil {
		return nil, err
	}
	if err := legacyclaims.UpgradeShared(doc); err != nil {
		return nil, err
	}
	if err := legacyclaims.ClearDataSources(doc); err != nil {
		return nil, err
	}
	text, err := doc.Bytes()
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(text, cfg); err != nil {
		return nil, err
	}
	return doc.Rewrites(), nil
}

// decodeDataSources decodes apigw.data_sources of a configuration file.
// Each claim spelling of an earlier release is upgraded in the shape of
// the credential that holds it, which cfg's credential metadata gives.
func decodeDataSources(file string, src []byte, cfg *model.Cfg) (model.DataSources, []legacyclaims.Rewrite, error) {
	doc, err := legacyclaims.Resolve(file, src, reflect.TypeFor[fileDataSources]())
	if err != nil {
		return model.DataSources{}, nil, err
	}
	if err := legacyclaims.UpgradeDataSources(doc, credentialShapes{cfg: cfg}, false); err != nil {
		return model.DataSources{}, nil, err
	}
	text, err := doc.Bytes()
	if err != nil {
		return model.DataSources{}, nil, err
	}
	var decoded fileDataSources
	if err := yaml.Unmarshal(text, &decoded); err != nil {
		return model.DataSources{}, nil, err
	}
	return decoded.APIGW.DataSources, doc.Rewrites(), nil
}

// credentialShapes reads the shapes of the credentials of
// common.credential_metadata. load, when set, loads the schema of a
// credential before its document shape is read.
type credentialShapes struct {
	cfg  *model.Cfg
	load func(scope string, meta *model.CredentialMetadata) error
}

// Presented returns the reading of a dotted claim name of a presented
// credential of scope.
func (s credentialShapes) Presented(scope string) (legacyclaims.Shape, error) {
	meta := s.cfg.GetCredentialMetadata(scope)
	if meta == nil {
		return legacyclaims.Nested(), nil
	}
	return legacyclaims.Presented(meta.Format), nil
}

// Document returns the reading of a dotted claim name of the document of a
// credential of scope.
func (s credentialShapes) Document(scope string) (legacyclaims.Shape, error) {
	if meta := s.cfg.GetCredentialMetadata(scope); meta != nil && s.load != nil {
		if err := s.load(scope, meta); err != nil {
			return legacyclaims.Shape{}, err
		}
	}
	shape, err := s.cfg.DocumentShape(scope)
	if err != nil {
		return legacyclaims.Shape{}, err
	}
	return legacyclaims.DocumentData(shape), nil
}

// UpgradeFile rewrites the claim spellings of earlier releases in the text
// of a configuration file, keeping every comment. It leaves as written a
// dotted name a role looked up as one top-level key first, where its
// pointer reads another key, and records why. It loads the schema of a
// credential whose document shape a data source claim needs; schemaPath
// maps the schema file path of the credential metadata to the file to
// read, and nil reads each path as written. The rewrite of a file with a
// YAML alias, merge key or repeated key must decode as the file does and
// hold no earlier spelling it upgrades; otherwise UpgradeFile refuses the
// file with legacyclaims.ErrInPlace.
func UpgradeFile(ctx context.Context, file string, src []byte, schemaPath func(string) string) ([]byte, []legacyclaims.Rewrite, error) {
	doc, err := legacyclaims.Parse(file, src)
	if err != nil {
		return nil, nil, err
	}
	if !doc.Flattens() {
		return upgradeConfig(ctx, file, src, doc, schemaPath, true)
	}
	want, err := decodeConfig(ctx, file, src, schemaPath)
	if err != nil {
		return nil, nil, err
	}
	want.Deprecations = nil
	// A rewrite in place that fails, or whose text decodes otherwise, met
	// a spelling an alias, a merge key or a repeated key reads.
	text, rewrites, err := upgradeConfig(ctx, file, src, doc, schemaPath, true)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, legacyclaims.ErrInPlace)
	}
	got, err := decodeConfig(ctx, file, text, schemaPath)
	if err != nil || slices.ContainsFunc(got.Deprecations, upgradable) {
		return nil, nil, fmt.Errorf("%s: %w", file, legacyclaims.ErrInPlace)
	}
	got.Deprecations = nil
	if !reflect.DeepEqual(want, got) {
		return nil, nil, fmt.Errorf("%s: %w", file, legacyclaims.ErrInPlace)
	}
	return text, rewrites, nil
}

// upgradable reports whether migrate_claim_paths rewrites a spelling.
func upgradable(r legacyclaims.Rewrite) bool { return r.Note == "" }

// upgradeConfig upgrades the claim spellings of doc, which holds the text
// of the configuration file src or the text gopkg.in/yaml.v2 decodes from
// it. convert leaves as written each spelling migrate_claim_paths leaves.
func upgradeConfig(ctx context.Context, file string, src []byte, doc *legacyclaims.Document, schemaPath func(string) string, convert bool) ([]byte, []legacyclaims.Rewrite, error) {
	cfg := &model.Cfg{}
	if _, err := decodeShared(file, src, cfg); err != nil {
		return nil, nil, err
	}
	shapes := credentialShapes{cfg: cfg, load: schemaLoader(ctx, cfg, schemaPath)}
	if err := legacyclaims.UpgradeConfig(doc, shapes, convert); err != nil {
		return nil, nil, err
	}
	text, err := doc.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return text, doc.Rewrites(), nil
}

// schemaLoader returns a loader of the schema of each credential, read
// once per credential.
func schemaLoader(ctx context.Context, cfg *model.Cfg, schemaPath func(string) string) func(string, *model.CredentialMetadata) error {
	loaded := make(map[string]error)
	return func(scope string, meta *model.CredentialMetadata) error {
		if err, done := loaded[scope]; done {
			return err
		}
		err := loadSchema(ctx, cfg, scope, meta, schemaPath)
		loaded[scope] = err
		return err
	}
}

// loadSchema loads the schema of the credential of scope.
func loadSchema(ctx context.Context, cfg *model.Cfg, scope string, meta *model.CredentialMetadata, schemaPath func(string) string) error {
	if schemaPath != nil {
		for _, path := range []*string{&meta.VCTMFilePath, &meta.MDDLFilePath} {
			if *path != "" {
				*path = schemaPath(*path)
			}
		}
	}
	var registry ts11client.Client
	if cfg.Common != nil {
		client, err := cfg.Common.CredentialRegistry.NewClient()
		if err != nil {
			return fmt.Errorf("failed to build credential registry client: %w", err)
		}
		registry = client
	}
	if err := meta.LoadCredentialSchema(ctx, scope, registry); err != nil {
		return fmt.Errorf("the claims of scope %q are read in its schema: %w", scope, err)
	}
	return nil
}

// DecodeFile decodes a configuration file the way the services decode it,
// with the claim spellings of earlier releases upgraded into
// cfg.Deprecations. It loads the schema of a credential only when a data
// source claim needs its document shape; schemaPath maps the schema file
// path of the credential metadata to the file to read, and nil reads each
// path as written. DecodeFile applies no defaults and no secrets.
func DecodeFile(ctx context.Context, file string, schemaPath func(string) string) (*model.Cfg, error) {
	src, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	return decodeConfig(ctx, file, src, schemaPath)
}

// decodeConfig decodes the text of a configuration file as DecodeFile
// decodes the file.
func decodeConfig(ctx context.Context, file string, src []byte, schemaPath func(string) string) (*model.Cfg, error) {
	doc, err := legacyclaims.Resolve(file, src, configType)
	if err != nil {
		return nil, err
	}
	text, rewrites, err := upgradeConfig(ctx, file, src, doc, schemaPath, false)
	if err != nil {
		return nil, err
	}
	cfg := &model.Cfg{}
	if err := yaml.Unmarshal(text, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", file, err)
	}
	cfg.Deprecations = rewrites
	return cfg, nil
}

// LoadFile reads the claims of a configuration file the way the apigw
// reads them: it upgrades the claim spellings of earlier releases into
// cfg.Deprecations, loads each credential schema, and checks each claim
// against the shape of its credential and each VCTM the issuer filters.
// schemaPath maps the schema file path of the credential metadata to the
// file to read, and nil reads each path as written. LoadFile applies no
// secrets and runs none of New's other checks.
func LoadFile(ctx context.Context, file string, schemaPath func(string) string) (*model.Cfg, error) {
	src, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	cfg := &model.Cfg{}
	if cfg.Deprecations, err = decodeShared(file, src, cfg); err != nil {
		return nil, err
	}
	if err := defaults.Set(cfg); err != nil {
		return nil, err
	}
	if cfg.Common == nil || len(cfg.Common.CredentialMetadata) == 0 {
		return nil, fmt.Errorf("%s: common.credential_metadata is required for the apigw service", file)
	}
	if err := checkCredentialMetadataEntries(cfg); err != nil {
		return nil, err
	}
	load := schemaLoader(ctx, cfg, schemaPath)
	for _, scope := range slices.Sorted(maps.Keys(cfg.Common.CredentialMetadata)) {
		if err := load(scope, cfg.Common.CredentialMetadata[scope]); err != nil {
			return nil, err
		}
	}
	if err := readDataSources(cfg, file, src); err != nil {
		return nil, err
	}
	if err := cfg.CheckClaimPaths(); err != nil {
		return nil, err
	}
	if err := checkFilterable(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
