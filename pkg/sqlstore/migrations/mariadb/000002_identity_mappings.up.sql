CREATE TABLE identity_mappings (
    authentic_source            VARCHAR(128) NOT NULL,
    authentic_source_person_id  VARCHAR(128) NOT NULL,
    attributes                  JSON NOT NULL,
    created_at                  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (authentic_source, authentic_source_person_id)
) ENGINE=InnoDB;

-- ResolveMapping's attributes.<key> = <value> conditions use
-- JSON_CONTAINS(attributes, JSON_OBJECT('key','value')) on MariaDB -- no
-- GIN-equivalent index exists here (see plan notes), a known perf tradeoff
-- vs Postgres for this table.
