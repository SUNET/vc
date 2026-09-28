-- The apigw's own record of which status-list entry belongs to which
-- credential subject. It is what a revocation request looks a credential up
-- by, and it lives here rather than only in the registry so that the local
-- registry can be left out of a deployment entirely.
--
-- The primary key is (status_list_uri, idx), NOT (section, idx): sections
-- are a concept internal to vc's own registry, and an external
-- draft-ietf-oauth-status-list service has none and reports section 0 for
-- every entry it issues. Keying on (section, idx) would collide across
-- different external lists on the very first pair of credentials.
-- 700 characters, matched to the MariaDB copy: there, status_list_uri is
-- part of the primary key and InnoDB caps an index at 3072 bytes, which
-- utf8mb4 spends four per character. Keeping both dialects the same width
-- means a URL that fits one fits the other.
CREATE TABLE credential_status_entries (
    status_list_uri VARCHAR(700) NOT NULL,
    idx             BIGINT NOT NULL,
    identifier      VARCHAR(512) NOT NULL,
    section         BIGINT NOT NULL DEFAULT 0,
    -- Which backend issued the entry ("registry" or "status_service").
    -- Recorded because the URI alone does not identify the backend, and
    -- guessing at revocation time writes the status into the wrong list.
    backend         VARCHAR(64) NOT NULL,
    scope           VARCHAR(256) NOT NULL DEFAULT '',
    issued_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (status_list_uri, idx)
);

-- Revocation looks entries up by subject; not unique, since one subject can
-- hold several credentials.
CREATE INDEX credential_status_entries_identifier ON credential_status_entries (identifier);
