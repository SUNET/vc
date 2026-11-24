//go:build !bbsnative

package apiv1

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/SUNET/vc/pkg/bbs"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

func TestInitBBSKeysWithoutNativeBackend(t *testing.T) {
	t.Run("unconfigured BBS still starts", func(t *testing.T) {
		c := &Client{log: logger.NewSimple("test"), cfg: &model.Cfg{}}
		if err := c.initBBSKeys(); err != nil {
			t.Fatalf("an issuer that does not offer BBS must start: %v", err)
		}
		if c.bbsKeys != nil {
			t.Fatal("no keys should have been loaded")
		}
	})

	t.Run("configured BBS fails with ErrNotBuilt", func(t *testing.T) {
		enc := base64.RawURLEncoding
		c := &Client{
			log: logger.NewSimple("test"),
			cfg: &model.Cfg{Issuer: &model.Issuer{BBS: &model.BBSConfig{
				SecretKey: enc.EncodeToString(bytes.Repeat([]byte{7}, bbs.OctetSecretKeyLength)),
				PublicKey: enc.EncodeToString(bytes.Repeat([]byte{9}, bbs.OctetPublicKeyLength)),
			}}},
		}
		err := c.initBBSKeys()
		if !errors.Is(err, bbs.ErrNotBuilt) {
			t.Fatalf("err = %v, want ErrNotBuilt", err)
		}
		if c.bbsKeys != nil {
			t.Fatal("keys must stay unset when the backend is missing")
		}
	})
}
