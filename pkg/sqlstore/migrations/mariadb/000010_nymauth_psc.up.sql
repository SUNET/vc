-- One holder-supplied nym_auth commitment per subject, per issuer.
--
-- Every identifier column is utf8mb4_NOPAD_bin. MariaDB's default collation
-- is case-INSENSITIVE, and each of these is compared byte-exactly
-- somewhere: subject_key and acceptance decide which row a reset
-- removes, and evidence_ref is the idempotency key, where
-- "evidence-A" and "evidence-a" comparing equal would turn a second,
-- genuinely different approval into a replay that changes nothing.
-- NOPAD and not plain utf8mb4_bin: the _bin collations are still PAD
-- SPACE, so "evidence" and "evidence " compare equal under them. On an
-- opaque reference supplied by an operator those are two different
-- pieces of evidence, and the second one being read as a replay
-- reports a reset that did not happen.
--
-- Postgres and MongoDB compare these byte-exactly already; this is
-- what makes the three agree.
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
    subject_key VARCHAR(64) COLLATE utf8mb4_nopad_bin PRIMARY KEY,
    psc         VARCHAR(64) COLLATE utf8mb4_nopad_bin NOT NULL,
    -- Distinguishes ONE acceptance from the next, even when the next
    -- records the same commitment. A reset audits an acceptance, and
    -- a retry that completes an interrupted reset must remove the
    -- acceptance it audited and no other: without this, Accept(A),
    -- reset, Accept(A) again, replay-the-reset removes the second A,
    -- because the commitment alone cannot tell the two apart.
    acceptance  VARCHAR(36) COLLATE utf8mb4_nopad_bin NOT NULL,
    accepted_at TIMESTAMP NOT NULL
) ENGINE=InnoDB;

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
    subject_key  VARCHAR(64) COLLATE utf8mb4_nopad_bin NOT NULL,
    evidence_ref VARCHAR(255) COLLATE utf8mb4_nopad_bin NOT NULL,
    reset_of     VARCHAR(64) COLLATE utf8mb4_nopad_bin NOT NULL,
    -- The acceptance this reset removed; see nymauth_psc.acceptance.
    reset_acceptance VARCHAR(36) COLLATE utf8mb4_nopad_bin NOT NULL,
    approved_by  VARCHAR(255) NOT NULL,
    approved_at  TIMESTAMP NOT NULL,
    PRIMARY KEY (subject_key, evidence_ref)
) ENGINE=InnoDB;
