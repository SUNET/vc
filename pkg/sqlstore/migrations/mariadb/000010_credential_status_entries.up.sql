-- See the postgres copy of this migration for why the primary key is
-- (status_list_uri, idx, backend) and not (section, idx).
--
-- status_list_uri is part of the primary key, and InnoDB caps an index at
-- 3072 bytes, which utf8mb4 spends four per character - so 700 characters,
-- leaving room for the BIGINT and the backend alongside it (700*4 + 8 +
-- 32*4 = 2936). A status list URL longer than that is not a real deployment
-- shape, and a silently truncated one would collide entries belonging to
-- different lists.
--
-- backend is VARCHAR(32) rather than 64 because it is in the key now: the
-- longest value this build writes is "status_service", and the extra width
-- came within eight bytes of the InnoDB limit.
CREATE TABLE credential_status_entries (
    status_list_uri VARCHAR(700) NOT NULL,
    idx             BIGINT NOT NULL,
    identifier      VARCHAR(512) NOT NULL,
    section         BIGINT NOT NULL DEFAULT 0,
    backend         VARCHAR(32) NOT NULL,
    -- What authorization is decided against; see CredentialStatusEntry.
    authentic_source VARCHAR(256) NOT NULL DEFAULT '',
    scope           VARCHAR(256) NOT NULL DEFAULT '',
    issued_at       DATETIME(6) NOT NULL,
    PRIMARY KEY (status_list_uri, idx, backend)
) ENGINE=InnoDB;

CREATE INDEX credential_status_entries_identifier ON credential_status_entries (identifier);
