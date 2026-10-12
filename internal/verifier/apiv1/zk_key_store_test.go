package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
)

// The bound reached the store from config, which is the whole of
// SUNET/vc#656's "make the bound configurable": 512MiB is a guess sized for
// a five-revision working set, and an operator facing more - or running
// many small pods on a shared disk - had no way to say so.
func TestConfigureVegaKeyStoreAppliesTheConfiguredBound(t *testing.T) {
	original := mdoc.VegaVerifierKeyCacheBytes()
	t.Cleanup(func() { mdoc.SetVegaVerifierKeyCacheBytes(original) })

	disabled := false
	c := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Verifier: &model.Verifier{
			ZkKeyCache: model.ZkKeyCacheConfig{
				MaxBytes: 128 << 20,
				// Off, so the test does not reach for a catalog. The warm
				// itself is covered under the zknative tag, where it can
				// actually do something.
				Prewarm: &disabled,
			},
		}},
	}

	c.configureVegaKeyStore()

	if got := mdoc.VegaVerifierKeyCacheBytes(); got != 128<<20 {
		t.Fatalf("bound = %d, want %d from config", got, 128<<20)
	}
}

// An unset max_bytes must leave the package default alone rather than
// setting the bound to zero, which would evict every key the moment it was
// written and turn every verification into a 100MB fetch.
func TestConfigureVegaKeyStoreLeavesAnUnsetBoundAlone(t *testing.T) {
	original := mdoc.VegaVerifierKeyCacheBytes()
	t.Cleanup(func() { mdoc.SetVegaVerifierKeyCacheBytes(original) })

	mdoc.SetVegaVerifierKeyCacheBytes(256 << 20)

	disabled := false
	c := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Verifier: &model.Verifier{
			ZkKeyCache: model.ZkKeyCacheConfig{Prewarm: &disabled},
		}},
	}

	c.configureVegaKeyStore()

	if got := mdoc.VegaVerifierKeyCacheBytes(); got != 256<<20 {
		t.Fatalf("bound = %d, want it unchanged at %d", got, 256<<20)
	}
}
