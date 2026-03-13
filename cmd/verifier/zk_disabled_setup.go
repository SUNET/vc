//go:build !zk

package main

import (
    "vc/pkg/model"
)

func setupZK(cfg *model.Cfg) error {
    return nil
}