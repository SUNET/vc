// Package testsupport provides shared test-only infrastructure helpers
// (e.g. spinning up throwaway database containers) for use across the
// module's test files. It is a regular (non-_test.go) package so its
// helpers can be imported by tests in other packages.
package testsupport

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// IsDockerAvailable reports whether a working Docker daemon is reachable.
// Portable across platforms (Linux, macOS, Windows).
func IsDockerAvailable() bool {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, dockerPath, "version").Run() == nil // #nosec G204
}

// containerStartDeadline covers a container start on a heavily loaded machine.
const containerStartDeadline = 3 * time.Minute

// WithStartDeadline raises every deadline of the wait strategy already on the
// request. Pass it after the option that sets the strategy. It returns an error
// when the request holds no strategy or a strategy type it cannot raise.
//
// wait.ForLog and wait.ForListeningPort each apply their own 60-second default
// inside an enclosing deadline, so each leaf is set.
func WithStartDeadline() testcontainers.CustomizeRequestOption {
	return func(req *testcontainers.GenericContainerRequest) error {
		if req.WaitingFor == nil {
			return errors.New("testsupport.WithStartDeadline: no wait strategy on the request; pass it after the strategy")
		}
		return wait.Walk(&req.WaitingFor, raiseStartDeadline)
	}
}

func raiseStartDeadline(node wait.Strategy) error {
	switch s := node.(type) {
	case *wait.MultiStrategy:
		s.WithDeadline(containerStartDeadline)
	case *wait.LogStrategy:
		s.WithStartupTimeout(containerStartDeadline)
	case *wait.HostPortStrategy:
		s.WithStartupTimeout(containerStartDeadline)
	default:
		return fmt.Errorf("testsupport.WithStartDeadline: unsupported wait strategy %T", node)
	}
	return nil
}

// StartMongoContainer spins up a throwaway MongoDB via testcontainers and
// returns its connection URI, a connected *mongo.Client, and a cleanup
// function. Skips the calling test if Docker is not available.
func StartMongoContainer(t *testing.T) (uri string, client *mongo.Client, cleanup func()) {
	t.Helper()

	if !IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}

	ctx := t.Context()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Image:        "mongo:7",
		ExposedPorts: []string{"27017/tcp"},
		WaitingFor:   wait.ForLog("Waiting for connections").WithStartupTimeout(containerStartDeadline),
		Started:      true,
	})
	if err != nil {
		t.Fatalf("start mongo container: %v", err)
	}

	port, err := container.MappedPort(ctx, "27017")
	if err != nil {
		t.Fatalf("mapped port: %v", err)
	}
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}

	uri = fmt.Sprintf("mongodb://%s:%s", host, port.Port())
	t.Logf("MongoDB container started at %s", uri)

	client, err = mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo connect: %v", err)
	}

	cleanup = func() {
		// t.Context() is cancelled before t.Cleanup functions run.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		client.Disconnect(cleanupCtx)   // #nosec G104
		container.Terminate(cleanupCtx) // #nosec G104
	}

	return uri, client, cleanup
}
