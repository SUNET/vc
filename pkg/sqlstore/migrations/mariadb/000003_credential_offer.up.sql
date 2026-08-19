CREATE TABLE credential_offer (
    uuid                          VARCHAR(64) PRIMARY KEY,
    credential_offer_parameters   JSON NOT NULL
) ENGINE=InnoDB;
