CREATE TABLE datastore (
    authentic_source          VARCHAR(128) NOT NULL,
    scope                     VARCHAR(128) NOT NULL,
    document_id               VARCHAR(128) NOT NULL,
    document_data_validation  VARCHAR(128),
    document_data             JSONB NOT NULL,
    valid_not_after           TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (authentic_source, scope, document_id)
);

-- Normalized child table for identity_mapping_ids: gives real indexed joins
-- for AddIdentity/DeleteIdentity/GetByIdentity on both Postgres and MariaDB,
-- instead of JSON-array membership queries that only Postgres partially
-- supports well.
CREATE TABLE datastore_identity_mapping (
    authentic_source     VARCHAR(128) NOT NULL,
    scope                VARCHAR(128) NOT NULL,
    document_id          VARCHAR(128) NOT NULL,
    identity_mapping_id  VARCHAR(128) NOT NULL,
    PRIMARY KEY (authentic_source, scope, document_id, identity_mapping_id),
    FOREIGN KEY (authentic_source, scope, document_id)
        REFERENCES datastore (authentic_source, scope, document_id) ON DELETE CASCADE
);

CREATE INDEX datastore_identity_mapping_lookup
    ON datastore_identity_mapping (scope, identity_mapping_id, authentic_source);
