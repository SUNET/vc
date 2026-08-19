-- Column named "idx" rather than "index": INDEX is a reserved word in
-- MariaDB/MySQL grammar and would need backtick-quoting on every reference.
CREATE TABLE token_status_list (
    section  BIGINT NOT NULL,
    idx      BIGINT NOT NULL,
    status   SMALLINT NOT NULL,
    decoy    BOOLEAN NOT NULL,
    PRIMARY KEY (section, idx)
);

-- Supports the atomic "claim a decoy" pattern:
--   UPDATE token_status_list SET status=$1, decoy=false
--   WHERE section=$2 AND idx=$3 AND decoy=true
-- and CountDecoysInSectionWithLimit's (section, decoy) lookups.
CREATE INDEX token_status_list_decoy_lookup ON token_status_list (section, decoy);
