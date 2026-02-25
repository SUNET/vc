//go:build didcomm && vc20

// Package discoverfeatures implements the DIDComm Discover Features Protocol 2.0.
//
// Discover Features is used to query another agent about the protocols
// and features it supports.
//
// Protocol URI: https://didcomm.org/discover-features/2.0
//
// # Message Types
//
//   - queries: Query supported features
//   - disclose: Response with supported features
//
// # Usage
//
//	// Create a query for all protocols
//	query := discoverfeatures.NewQuery(
//		"did:example:alice",
//		"did:example:bob",
//		discoverfeatures.QueryProtocols("*"),
//	)
//
//	// Handle a query and respond
//	disclose, _ := discoverfeatures.HandleQuery(query, supportedProtocols)
package discoverfeatures
