-- One shared table across all named caches (DPoPJTI, VCINonce, JWKS, ...),
-- with cache_name as a discriminator -- avoids needing a migration per new
-- cache the way Mongo needs a new collection.
CREATE TABLE cache_entries (
    cache_name  VARCHAR(128) NOT NULL,
    key         VARCHAR(512) NOT NULL,
    json_value  JSONB NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cache_name, key)
);

-- Read-time correctness ("WHERE expires_at > now()") plus a periodic bounded
-- sweep for space reclamation both use this index.
CREATE INDEX cache_entries_expiry ON cache_entries (expires_at);
