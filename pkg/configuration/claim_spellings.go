package configuration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/SUNET/vc/pkg/legacyclaims"
	"github.com/SUNET/vc/pkg/model"

	ts11client "github.com/sirosfoundation/go-ts11client"
	"gopkg.in/yaml.v2"
)

// decodeShared decodes a configuration file into cfg. The claim spellings
// of earlier releases outside apigw.data_sources are upgraded, and
// apigw.data_sources is emptied: decodeDataSources reads it once the
// credential schemas are loaded.
func decodeShared(file string, src []byte, cfg *model.Cfg) ([]legacyclaims.Rewrite, error) {
	doc, err := legacyclaims.Parse(file, src)
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
	doc, err := legacyclaims.Parse(file, src)
	if err != nil {
		return model.DataSources{}, nil, err
	}
	if err := legacyclaims.UpgradeDataSources(doc, credentialShapes{cfg: cfg}); err != nil {
		return model.DataSources{}, nil, err
	}
	text, err := doc.Bytes()
	if err != nil {
		return model.DataSources{}, nil, err
	}
	var decoded struct {
		APIGW struct {
			DataSources model.DataSources `yaml:"data_sources"`
		} `yaml:"apigw"`
	}
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
// of a configuration file, keeping every comment. It loads the schema of a
// credential whose document shape a data source claim needs; schemaPath
// maps the schema file path of the credential metadata to the file to
// read, and nil reads each path as written.
func UpgradeFile(ctx context.Context, file string, src []byte, schemaPath func(string) string) ([]byte, []legacyclaims.Rewrite, error) {
	cfg := &model.Cfg{}
	if _, err := decodeShared(file, src, cfg); err != nil {
		return nil, nil, err
	}
	doc, err := legacyclaims.Parse(file, src)
	if err != nil {
		return nil, nil, err
	}
	shapes := credentialShapes{cfg: cfg, load: schemaLoader(ctx, cfg, schemaPath)}
	if err := legacyclaims.UpgradeConfig(doc, shapes); err != nil {
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

// LoadFile decodes a configuration file the way the services read it, with
// the claim spellings of earlier releases upgraded, and returns the
// upgraded spellings. It applies no defaults and no secrets.
func LoadFile(ctx context.Context, file string) (*model.Cfg, []legacyclaims.Rewrite, error) {
	src, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, nil, err
	}
	text, rewrites, err := UpgradeFile(ctx, file, src, nil)
	if err != nil {
		return nil, nil, err
	}
	cfg := &model.Cfg{}
	if err := yaml.Unmarshal(text, cfg); err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", file, err)
	}
	return cfg, rewrites, nil
}
