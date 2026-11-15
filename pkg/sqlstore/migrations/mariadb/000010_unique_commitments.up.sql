-- One commitment per key value for each unique hash_commitment entry of
-- Credential Auxiliary Data. The primary key is what makes concurrent
-- issuances on different replicas agree on the first commitment stored.
-- Every string column compares byte for byte, trailing spaces included, as on
-- Postgres and MongoDB: scopes, JSON paths, base64url values and evidence
-- references are exact.
-- The times are DATETIME(6), written in UTC. A TIMESTAMP ends in 2038 before
-- MariaDB 11.5 and in 2106 after, follows the session time zone, and on a
-- server with explicit_defaults_for_timestamp off rewrites itself on an UPDATE
-- of the row.
--
-- The NO PAD binary collation is utf8mb4_nopad_bin on MariaDB and
-- utf8mb4_0900_bin on MySQL 8. utf8mb4_bin is PAD SPACE: 'A ' = 'A' holds under
-- it. A server with neither collation stops at the first PREPARE below with
-- "Unknown collation", naming the placeholder, before any table exists.
SET @exact_collation = COALESCE(
    (SELECT COLLATION_NAME FROM information_schema.COLLATIONS
     WHERE COLLATION_NAME IN ('utf8mb4_nopad_bin', 'utf8mb4_0900_bin')
     ORDER BY COLLATION_NAME = 'utf8mb4_nopad_bin' DESC LIMIT 1),
    'server_has_neither_utf8mb4_nopad_bin_nor_utf8mb4_0900_bin');
SET @exact_table = CONCAT(' ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE ', @exact_collation);

-- releasable_by is the Accept call that may remove the row, or empty once the
-- row stays until a reset.
SET @s = CONCAT('CREATE TABLE unique_commitments (
    scope         VARCHAR(128) NOT NULL,
    path          VARCHAR(256) NOT NULL,
    key_hash      VARCHAR(64) NOT NULL,
    commitment    VARCHAR(128) NOT NULL,
    accepted_at   DATETIME(6) NOT NULL,
    releasable_by VARCHAR(32) NOT NULL,
    PRIMARY KEY (scope, path, key_hash)
)', @exact_table);
PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;

-- The audit trail of operator-approved resets.
SET @s = CONCAT('CREATE TABLE unique_commitment_resets (
    scope                       VARCHAR(128) NOT NULL,
    path                        VARCHAR(256) NOT NULL,
    key_hash                    VARCHAR(64) NOT NULL,
    evidence_ref                VARCHAR(256) NOT NULL,
    previous_commitment_sha256  VARCHAR(64) NOT NULL,
    approved_by                 VARCHAR(256) NOT NULL,
    approved_at                 DATETIME(6) NOT NULL,
    PRIMARY KEY (scope, path, key_hash, evidence_ref)
)', @exact_table);
PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
