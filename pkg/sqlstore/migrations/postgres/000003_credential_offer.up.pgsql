CREATE TABLE credential_offer (
    uuid                          VARCHAR(64) PRIMARY KEY,
    credential_offer_parameters   JSONB NOT NULL
);
