//go:build !zknative

package apiv1

// circuitZkNativeBuilt reports whether this build can check a
// nym_auth proof. False here; see circuit_zk_native_built_cgo.go.
const circuitZkNativeBuilt = false
