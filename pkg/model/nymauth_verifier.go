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

	// VerifierID is the verifier_id this Verifier is known by, and
	// SHA-256 of it is verifier_input - the value that scopes every
	// pseudonym to this Verifier.
	//
	// CONFIGURED, and never derived from client_id. Rulebook v0.4
	// defines exactly two forms and the whole string is hashed,
	// prefix included:
	//
	//	x509_san_dns:<dns name>
	//	semantic_id:<identifier>
	//
	// Nothing is stripped and nothing is normalised, case included. A
	// value that is neither form is refused at startup: the BARE DNS
	// name was the correct value until 2026-10-20, so a configuration
	// written before then still carries one, and hashing it produces
	// a pseudonym no other implementation reports - a wrong answer
	// about a person rather than an error anyone sees.
	//
	// See pkg/nymauth.CheckVerifierID.
	VerifierID string `yaml:"verifier_id,omitempty" validate:"required_if=Enable true" doc_example:"\"x509_san_dns:verifier.example\""`

	// Circuits is where the circuit builds this Verifier will load
	// come from.
	Circuits NymAuthCircuits `yaml:"circuits,omitempty"`

	// ProofTimeSkewSeconds and ProofTimeMaxAgeSeconds bound how far a
	// presentation's proof_time may be from this verifier's clock.
	//
	// T is the PROVER'S: the circuit binds all 20 bytes of it into
	// its public inputs, so only the prover knows which second it
	// proved at. This window is what makes accepting its value safe -
	// without one a holder could replay a proof made long ago,
	// against a credential since revoked, or one made with a clock
	// set forward.
	//
	// Outside the window is REFUSED, never clamped: verifying against
	// a T the prover did not use cannot succeed, and would report the
	// wrong reason when it failed.
	//
	// Zero means the shared recommendation - 60 seconds of skew into
	// the future, 600 seconds of age. They are recommendations and
	// not protocol constants: the tolerance is this verifier's to
	// set, and a deployment that has not thought about it should
	// behave the way other implementations assume.
	ProofTimeSkewSeconds   int `yaml:"proof_time_skew_seconds,omitempty" doc_example:"60"`
	ProofTimeMaxAgeSeconds int `yaml:"proof_time_max_age_seconds,omitempty" doc_example:"600"`
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
	// SystemID is the proof system this build belongs to, named by
	// the catalog alias a presentation states in zkp_req's
	// "system_id" - "urn:circuits:longfellow:nym_auth:v1" or
	// "urn:circuits:vega:nym_auth:v1".
	//
	// First-class and REQUIRED, beside Config, because the two
	// together are what selects a build. One verifier may allow both
	// systems for the same pseudonym configuration - that is the
	// point of naming it - and an entry that did not say which system
	// it is would be an artifact handed to whichever circuit library
	// happened to be asked for it.
	//
	// It does not change the pseudonym. The domain separator is built
	// from Config alone ("nym_auth/v1/" + config), so the same subject
	// under the same configuration has the same pseudonym whichever
	// system proved it; the system decides only how the proof is
	// checked. That is what makes it safe for the holder to choose
	// between the systems a Verifier offers.
	SystemID string `yaml:"system_id" doc_example:"\"urn:circuits:longfellow:nym_auth:v1\""`

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
