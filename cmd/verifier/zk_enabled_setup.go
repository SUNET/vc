//go:build zk

package main

import (
	"fmt"
	"os"
	"proofs/server/v2/zk"
	"vc/pkg/model"
)

func setupZK(cfg *model.Cfg) error {
	if cfg.Verifier == nil || cfg.Verifier.ZK.CircuitsPath == "" || cfg.Verifier.ZK.CACertsPath == "" {
        return fmt.Errorf("ZK build requires circuits_path and cacerts_path in config")
    }
	zk.LoadCircuits(cfg.Verifier.ZK.CircuitsPath)
	pem, err := os.ReadFile(cfg.Verifier.ZK.CACertsPath)
	if err != nil {
		return fmt.Errorf("could not read ZK cacerts file: %w", err)
	}
	if err := zk.LoadIssuerRootCA(pem); err != nil {
		return fmt.Errorf("could not load issuer root CA: %w", err)
	}

	return nil
}