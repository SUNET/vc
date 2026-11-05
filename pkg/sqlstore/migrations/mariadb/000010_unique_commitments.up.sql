-- One commitment per key value for each unique hash_commitment entry of
-- Credential Auxiliary Data. The primary key is what makes concurrent
-- issuances on different replicas agree on the first commitment stored.
-- The identity and comparison columns compare byte for byte: scopes, JSON
-- paths, base64url values and evidence references are case-sensitive.
CREATE TABLE unique_commitments (
    scope        VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    path         VARCHAR(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    key_hash     VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    commitment   VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    accepted_at  TIMESTAMP NOT NULL,
    -- The Accept call that may remove the row, or empty once the row stays
    -- until a reset.
    releasable_by VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    PRIMARY KEY (scope, path, key_hash)
) ENGINE=InnoDB;

-- The audit trail of operator-approved resets.
CREATE TABLE unique_commitment_resets (
    scope                       VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    path                        VARCHAR(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    key_hash                    VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    evidence_ref                VARCHAR(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    previous_commitment_sha256  VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    approved_by                 VARCHAR(256) NOT NULL,
    approved_at                 TIMESTAMP NOT NULL,
    PRIMARY KEY (scope, path, key_hash, evidence_ref)
) ENGINE=InnoDB;
