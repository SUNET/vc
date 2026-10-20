-- One holder-supplied nym_auth commitment per subject, per issuer.
--
-- subject_key is SHA-256 over the ordered subject identifiers, hex. The
-- identifiers themselves are deliberately NOT stored: this table is a
-- list of who holds a nym_auth credential, and it does not need them to
-- do its job.
--
-- The issuer is implicit - it is this deployment's database - and
-- private_seed is derived per issuer, so a psc from elsewhere is a
-- different value anyway.
CREATE TABLE nymauth_psc (
    subject_key VARCHAR(64) PRIMARY KEY,
    psc         VARCHAR(64) NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL
);

-- The audit trail of operator-approved resets.
--
-- reset_of is SHA-256 of the PREVIOUS psc, never the psc itself: the
-- old pseudonyms stay derivable by whoever holds the old seed, and this
-- trail exists to show that a reset happened and who approved it, not
-- to keep a working key to a person's former identity.
--
-- (subject_key, evidence_ref) is the primary key, which is what makes a
-- reset idempotent for one piece of evidence: a retried request cannot
-- produce a second audit row, and so cannot discard a record the
-- subject has already re-established.
CREATE TABLE nymauth_psc_resets (
    subject_key  VARCHAR(64) NOT NULL,
    evidence_ref VARCHAR(255) NOT NULL,
    reset_of     VARCHAR(64) NOT NULL,
    approved_by  VARCHAR(255) NOT NULL,
    approved_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (subject_key, evidence_ref)
);
