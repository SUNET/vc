-- See the postgres copy of this migration for why the primary key is
-- (status_list_uri, idx) and not (section, idx).
--
-- status_list_uri is part of the primary key, and InnoDB caps an index at
-- 3072 bytes, which utf8mb4 spends four per character - so 700 characters,
-- leaving room for the BIGINT alongside it. A status list URL longer than
-- that is not a real deployment shape, and a silently truncated one would
-- collide entries belonging to different lists.
CREATE TABLE credential_status_entries (
    status_list_uri VARCHAR(700) NOT NULL,
    idx             BIGINT NOT NULL,
    identifier      VARCHAR(512) NOT NULL,
    section         BIGINT NOT NULL DEFAULT 0,
    backend         VARCHAR(64) NOT NULL,
    scope           VARCHAR(256) NOT NULL DEFAULT '',
    issued_at       DATETIME(6) NOT NULL,
    PRIMARY KEY (status_list_uri, idx)
) ENGINE=InnoDB;

CREATE INDEX credential_status_entries_identifier ON credential_status_entries (identifier);
