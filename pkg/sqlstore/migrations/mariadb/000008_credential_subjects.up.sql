CREATE TABLE credential_subjects (
    identifier  VARCHAR(512) NOT NULL,
    section     BIGINT NOT NULL,
    idx         BIGINT NOT NULL,
    PRIMARY KEY (section, idx)
) ENGINE=InnoDB;

-- Non-unique: mirrors the non-unique Mongo index on identifier (an
-- identifier is not guaranteed to be 1:1 with a status-list slot).
CREATE INDEX credential_subjects_identifier ON credential_subjects (identifier);
