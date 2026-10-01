-- The apigw's own record of which status-list entry belongs to which
-- credential subject. It is what a revocation request looks a credential up
-- by, and it lives here rather than only in the registry so that the local
-- registry can be left out of a deployment entirely.
--
-- The primary key is (status_list_uri, idx, backend), NOT (section, idx):
-- sections are a concept internal to vc's own registry, and an external
-- draft-ietf-oauth-status-list service has none and reports section 0 for
-- every entry it issues. Keying on (section, idx) would collide across
-- different external lists on the very first pair of credentials.
--
-- backend is in the key because it is the routing dimension: the table
-- records it precisely because the URI alone does not say who owns an
-- entry, so leaving it out of the key contradicts the reason the column
-- exists. Two backends reusing one URI and index - a reconfiguration that
-- points the registry at a URL an external service also serves - would
-- otherwise have the later upsert REPLACE the earlier mapping, and the
-- credential that mapping belonged to becomes unrevocable while its
-- revocation is routed to the wrong service.
--
-- It does not make lookups ambiguous: revocation reads by identifier and
-- narrows in memory, so a URI/index shared across backends yields two
-- entries and both are acted on, which is the right answer for two
-- distinct entries.
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
    backend         VARCHAR(32) NOT NULL,
    -- What authorization is decided against; see CredentialStatusEntry.
    authentic_source VARCHAR(256) NOT NULL DEFAULT '',
    scope           VARCHAR(256) NOT NULL DEFAULT '',
    issued_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (status_list_uri, idx, backend)
);

-- Revocation looks entries up by subject; not unique, since one subject can
-- hold several credentials.
CREATE INDEX credential_status_entries_identifier ON credential_status_entries (identifier);
