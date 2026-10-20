package model

// NymAuthVerifier configures verification of nym_auth pseudonym proofs.
//
// Separate from zk_circuits, which is the mdoc ZK path: that one
// resolves a circuit by the zkSystemId a presented document names,
// while this one selects a circuit by the pseudonym CONFIGURATION the
// verifier asked for. They are different questions and sharing one
// block would make the answer to each depend on the other.
type NymAuthVerifier struct {
	// Enable turns nym_auth verification on. Off by default: a
	// deployment that does not verify pseudonym proofs is unaffected
	// by any of this existing.
	Enable bool `yaml:"enable" doc_example:"true"`

	// VerifierID is the BARE verifier_id this Verifier is known by,
	// and SHA-256 of it is verifier_input - the value that scopes
	// every pseudonym to this Verifier.
	//
	// CONFIGURED, and never derived from client_id. verifier_id_type
	// is agreed out of band in the trust framework and is not on the
	// wire, so there is nothing in a request to derive it from; and
	// the prefixed Client Identifier is the form nym_auth_rulebook
	// PR #7 marks MUST NOT. Deriving it would produce a pseudonym no
	// other implementation reports, so a comparison would simply never
	// match and the subject would look innocent.
	//
	// For an x509_san_dns Verifier this is the dNSName with no prefix;
	// for a semantic one it is the whole "semantic_id:<identifier>"
	// value, which IS the identifier and not a prefix. See
	// pkg/nymauth.CheckVerifierID.
	VerifierID string `yaml:"verifier_id,omitempty" validate:"required_if=Enable true" doc_example:"\"verifier.example\""`

	// Circuits is where the circuit builds this Verifier will load
	// come from.
	Circuits NymAuthCircuits `yaml:"circuits,omitempty"`
}

// NymAuthCircuits configures which circuit builds may be loaded, and
// where their bytes come from.
type NymAuthCircuits struct {
	// Allow is the operator's allowlist. NOTHING outside it is ever
	// loaded.
	//
	// It is the only statement of which configuration a circuit
	// implements. The pseudonym's domain separator is baked into the
	// circuit build - it is a code constant in the prover, not a
	// parameter - so ssc and psc are different artifacts with
	// different ids, and nothing in the artifact itself tells this
	// Verifier which one it has. Until the native library exposes a
	// configuration accessor, the entry below is that statement, and
	// an entry naming the wrong configuration would verify proofs
	// against a pseudonym function nobody asked for.
	// No struct-tag validation on the entries: the validator recurses
	// into this subtree whether or not Enable is set, so a `required`
	// here would stop a deployment that has nym_auth switched OFF and
	// a half-written entry left behind. Every field is checked in
	// circuits.NewAllowlist instead, which runs only when enabled -
	// and checking in one place rather than two is what stops the two
	// from disagreeing.
	Allow []NymAuthCircuit `yaml:"allow,omitempty"`

	// Sources are zk-circuits catalog mirrors, used only by an
	// allowlist entry that names a catalog id instead of a local file.
	//
	// Optional, and empty is the ordinary case today: the published
	// catalog carries mdoc Longfellow entries only, with no nym_auth
	// descriptors and none of the four parameters this ABI needs. An
	// entry therefore supplies its own artifact.
	// No struct-tag validation, for the same reason the entries above
	// have none: the validator recurses into this subtree whether or
	// not Enable is set, so an `httpurl` tag here stops a deployment
	// that has nym_auth switched OFF and a half-written source left
	// behind. Checked in circuits.NewAllowlist instead, which runs
	// only when the feature is enabled.
	Sources []string `yaml:"sources,omitempty"`
}

// NymAuthCircuit is one allowed circuit build.
//
// Everything the native loader checks is here, because the loader
// checks the artifact against its own entry and refuses anything else
// before parsing it. An entry that does not match the artifact is a
// circuit that will not load, which is the right failure: the
// alternative is loading whatever was served.
type NymAuthCircuit struct {
	// Config is the pseudonym configuration this build implements -
	// "known-offender-matching-ssc" or "known-offender-matching-psc".
	//
	// First-class, because it is how a request selects a build. The
	// two produce DIFFERENT pseudonyms from the same inputs (the
	// domain separator is "nym_auth/v1/" + config), so verifying
	// against the wrong one yields a value that matches nothing and
	// reads as an innocent subject.
	Config string `yaml:"config" doc_example:"\"known-offender-matching-ssc\""`

	// HashCircuitID and SigCircuitID are the descriptor's circuit ids,
	// hex as the catalog writes them.
	HashCircuitID string `yaml:"hash_circuit_id" doc_example:"\"5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729\""`
	SigCircuitID  string `yaml:"sig_circuit_id" doc_example:"\"00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb\""`

	// BlockEncHash and BlockEncSig are the Ligero block_enc parameters
	// of the two circuits.
	BlockEncHash uint32 `yaml:"block_enc_hash" doc_example:"6983"`
	BlockEncSig  uint32 `yaml:"block_enc_sig" doc_example:"4679"`

	// ArtifactPath is a local file holding the DECOMPRESSED circuit
	// artifact. Mutually exclusive with ArtifactID.
	ArtifactPath string `yaml:"artifact_path,omitempty" doc_example:"\"/etc/vc/circuits/nym_auth-ssc.bin\""`

	// ArtifactID names a circuit in the configured catalog sources,
	// for a deployment whose catalog publishes nym_auth descriptors.
	// Mutually exclusive with ArtifactPath.
	ArtifactID string `yaml:"artifact_id,omitempty"`

	// ArtifactSHA256 and ArtifactBytes are over the DECOMPRESSED
	// artifact, which is what the native loader hashes.
	//
	// Both, not either. The length is not redundant: it is checked
	// before the bytes are read, so an artifact that is the wrong size
	// is refused without hashing however much of it was served.
	// The example values here are the REAL ones for the nym_auth
	// build, taken from zk-cred-longfellow's src/nymauth/profile.rs.
	// They are not decoration: gen_config_docs copies them verbatim
	// into docs/CONFIGURATION.md, and an operator configuring this
	// reads them there.
	//
	// This digest was previously a placeholder made by keeping the
	// real value's first eight and last four hex characters and
	// zeroing the middle, which made it survive exactly the check
	// someone would perform on it. Never write a plausible-looking
	// fake here; if a real value cannot be published, leave the
	// example out.
	ArtifactSHA256 string `yaml:"artifact_sha256" doc_example:"\"92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f\""`
	ArtifactBytes  int64  `yaml:"artifact_bytes" doc_example:"1062842"`
}
