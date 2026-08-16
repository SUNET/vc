CREATE TABLE identity_mappings (
    authentic_source            VARCHAR(128) NOT NULL,
    authentic_source_person_id  VARCHAR(128) NOT NULL,
    attributes                  JSONB NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (authentic_source, authentic_source_person_id)
);

-- Supports ResolveMapping's attributes.<key> = <value> AND-conditions via
-- JSONB containment (attributes @> '{"key":"value"}').
CREATE INDEX identity_mappings_attributes_gin ON identity_mappings USING GIN (attributes);
