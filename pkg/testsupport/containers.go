// Package testsupport provides shared test-only infrastructure helpers
// (e.g. spinning up throwaway database containers) for use across the
// module's test files. It is a regular (non-_test.go) package so its
// helpers can be imported by tests in other packages.
package testsupport

import (
	"context"
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

// StartMongoContainer spins up a throwaway MongoDB via testcontainers and
// returns its connection URI, a connected *mongo.Client, and a cleanup
// function. Skips the calling test if Docker is not available.
func StartMongoContainer(t *testing.T) (uri string, client *mongo.Client, cleanup func()) {
	t.Helper()

	if !IsDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "mongo:7",
			ExposedPorts: []string{"27017/tcp"},
			WaitingFor:   wait.ForLog("Waiting for connections"),
		},
		Started: true,
	})
	if err != nil {
		cancel()
		t.Fatalf("start mongo container: %v", err)
	}

	port, err := container.MappedPort(ctx, "27017")
	if err != nil {
		cancel()
		t.Fatalf("mapped port: %v", err)
	}
	host, err := container.Host(ctx)
	if err != nil {
		cancel()
		t.Fatalf("container host: %v", err)
	}

	uri = fmt.Sprintf("mongodb://%s:%s", host, port.Port())
	t.Logf("MongoDB container started at %s", uri)

	client, err = mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		cancel()
		t.Fatalf("mongo connect: %v", err)
	}

	cleanup = func() {
		// Use a fresh context for teardown: ctx's 120s setup deadline may
		// already have elapsed by the time cleanup runs (e.g. a slow test
		// body), which would otherwise make Disconnect/Terminate fail
		// immediately and leak the container.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		client.Disconnect(cleanupCtx)   // #nosec G104
		container.Terminate(cleanupCtx) // #nosec G104
		cancel()
	}

	return uri, client, cleanup
}
