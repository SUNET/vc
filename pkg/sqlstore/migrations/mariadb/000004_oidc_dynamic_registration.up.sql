CREATE TABLE oidc_dynamic_registration (
    client_id                   VARCHAR(255) PRIMARY KEY,
    client_secret                TEXT NOT NULL,
    registration_access_token    TEXT,
    registration_client_uri      TEXT,
    client_secret_expires_at     BIGINT,
    registered_at                TIMESTAMP NOT NULL
) ENGINE=InnoDB;
