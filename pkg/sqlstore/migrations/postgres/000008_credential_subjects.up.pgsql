CREATE TABLE credential_subjects (
    identifier  TEXT NOT NULL,
    section     BIGINT NOT NULL,
    idx         BIGINT NOT NULL,
    PRIMARY KEY (section, idx)
);

-- Non-unique: mirrors the non-unique Mongo index on identifier (an
-- identifier is not guaranteed to be 1:1 with a status-list slot).
CREATE INDEX credential_subjects_identifier ON credential_subjects (identifier);
