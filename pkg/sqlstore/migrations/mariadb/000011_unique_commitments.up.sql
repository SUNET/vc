-- One commitment per key value for each unique hash_commitment entry of
-- Credential Auxiliary Data. The primary key is what makes concurrent
-- issuances on different replicas agree on the first commitment stored.
CREATE TABLE unique_commitments (
    scope        VARCHAR(128) NOT NULL,
    path         VARCHAR(256) NOT NULL,
    key_hash     VARCHAR(64) NOT NULL,
    commitment   VARCHAR(128) NOT NULL,
    accepted_at  TIMESTAMP NOT NULL,
    PRIMARY KEY (scope, path, key_hash)
) ENGINE=InnoDB;

-- The audit trail of operator-approved resets.
CREATE TABLE unique_commitment_resets (
    scope                       VARCHAR(128) NOT NULL,
    path                        VARCHAR(256) NOT NULL,
    key_hash                    VARCHAR(64) NOT NULL,
    evidence_ref                VARCHAR(256) NOT NULL,
    previous_commitment_sha256  VARCHAR(64) NOT NULL,
    approved_by                 VARCHAR(256) NOT NULL,
    approved_at                 TIMESTAMP NOT NULL,
    PRIMARY KEY (scope, path, key_hash, evidence_ref)
) ENGINE=InnoDB;
