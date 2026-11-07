-- Restores the database's default character set and collation on string columns
-- and JSON's own collation on JSON columns. Every table is rebuilt.
--
-- The run fails in two cases. Fix the data first, because a failure leaves
-- schema_migrations dirty at this version with the foreign key dropped.
-- - The exact comparison lets rows exist side by side whose keys differ only in
--   case, accent or trailing spaces. The default collation folds them into one
--   key, which gives a duplicate-key error. Remove one of each such pair.
-- - A string column holds a character the default character set lacks, such as
--   Chinese on a latin1 database, which gives "Incorrect string value". Strict
--   mode turns the replacement of that character with "?" into this error.
SET SESSION sql_mode = CONCAT_WS(',', NULLIF(@@sql_mode, ''), 'STRICT_ALL_TABLES');

SET @restore = CONCAT(' CONVERT TO CHARACTER SET ', @@character_set_database, ' COLLATE ', @@collation_database);

ALTER TABLE datastore_identity_mapping DROP FOREIGN KEY datastore_identity_mapping_ibfk_1;

-- CONVERT TO transcodes MariaDB's JSON columns, which are LONGTEXT, and JSON holds
-- characters the default character set can lack. No conversion happens to or from
-- a BLOB, so each JSON column passes through LONGBLOB. It returns through LONGTEXT
-- because MySQL refuses a direct LONGBLOB to JSON change.
ALTER TABLE datastore MODIFY document_data LONGBLOB NOT NULL;
ALTER TABLE identity_mappings MODIFY attributes LONGBLOB NOT NULL;
ALTER TABLE credential_offer MODIFY credential_offer_parameters LONGBLOB NOT NULL;
ALTER TABLE clients
    MODIFY redirect_uris LONGBLOB NOT NULL,
    MODIFY grant_types LONGBLOB NOT NULL,
    MODIFY response_types LONGBLOB NOT NULL,
    MODIFY allowed_scopes LONGBLOB NOT NULL,
    MODIFY default_scopes LONGBLOB,
    MODIFY jwks LONGBLOB,
    MODIFY contacts LONGBLOB,
    MODIFY default_acr_values LONGBLOB,
    MODIFY request_uris LONGBLOB;
ALTER TABLE token_status_list_metadata MODIFY sections LONGBLOB NOT NULL;
ALTER TABLE cache_entries MODIFY json_value LONGBLOB NOT NULL;

SET @s = CONCAT('ALTER TABLE datastore', @restore); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE datastore_identity_mapping', @restore); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE identity_mappings', @restore); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE credential_offer', @restore); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE oidc_dynamic_registration', @restore); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE clients', @restore); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE token_status_list', @restore); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE token_status_list_metadata', @restore); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE credential_subjects', @restore); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE cache_entries', @restore); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;

ALTER TABLE datastore MODIFY document_data LONGTEXT CHARACTER SET utf8mb4 NOT NULL;
ALTER TABLE identity_mappings MODIFY attributes LONGTEXT CHARACTER SET utf8mb4 NOT NULL;
ALTER TABLE credential_offer MODIFY credential_offer_parameters LONGTEXT CHARACTER SET utf8mb4 NOT NULL;
ALTER TABLE clients
    MODIFY redirect_uris LONGTEXT CHARACTER SET utf8mb4 NOT NULL,
    MODIFY grant_types LONGTEXT CHARACTER SET utf8mb4 NOT NULL,
    MODIFY response_types LONGTEXT CHARACTER SET utf8mb4 NOT NULL,
    MODIFY allowed_scopes LONGTEXT CHARACTER SET utf8mb4 NOT NULL,
    MODIFY default_scopes LONGTEXT CHARACTER SET utf8mb4,
    MODIFY jwks LONGTEXT CHARACTER SET utf8mb4,
    MODIFY contacts LONGTEXT CHARACTER SET utf8mb4,
    MODIFY default_acr_values LONGTEXT CHARACTER SET utf8mb4,
    MODIFY request_uris LONGTEXT CHARACTER SET utf8mb4;
ALTER TABLE token_status_list_metadata MODIFY sections LONGTEXT CHARACTER SET utf8mb4 NOT NULL;
ALTER TABLE cache_entries MODIFY json_value LONGTEXT CHARACTER SET utf8mb4 NOT NULL;

-- Up widens TEXT to MEDIUMTEXT when it leaves a narrower character set, and CONVERT
-- TO keeps the wider type on the way back.
ALTER TABLE oidc_dynamic_registration
    MODIFY client_secret TEXT NOT NULL,
    MODIFY registration_access_token TEXT,
    MODIFY registration_client_uri TEXT;
ALTER TABLE clients
    MODIFY client_secret_hash TEXT,
    MODIFY jwks_uri TEXT,
    MODIFY client_name TEXT,
    MODIFY client_uri TEXT,
    MODIFY logo_uri TEXT,
    MODIFY tos_uri TEXT,
    MODIFY policy_uri TEXT,
    MODIFY software_id TEXT,
    MODIFY software_version TEXT,
    MODIFY application_type TEXT,
    MODIFY sector_identifier_uri TEXT,
    MODIFY id_token_signed_response_alg TEXT,
    MODIFY initiate_login_uri TEXT,
    MODIFY registration_access_token_hash TEXT;

ALTER TABLE datastore MODIFY document_data JSON NOT NULL;
ALTER TABLE identity_mappings MODIFY attributes JSON NOT NULL;
ALTER TABLE credential_offer MODIFY credential_offer_parameters JSON NOT NULL;
ALTER TABLE clients
    MODIFY redirect_uris JSON NOT NULL,
    MODIFY grant_types JSON NOT NULL,
    MODIFY response_types JSON NOT NULL,
    MODIFY allowed_scopes JSON NOT NULL,
    MODIFY default_scopes JSON,
    MODIFY jwks JSON,
    MODIFY contacts JSON,
    MODIFY default_acr_values JSON,
    MODIFY request_uris JSON;
ALTER TABLE token_status_list_metadata MODIFY sections JSON NOT NULL;
ALTER TABLE cache_entries MODIFY json_value JSON NOT NULL;

ALTER TABLE datastore_identity_mapping
    ADD CONSTRAINT datastore_identity_mapping_ibfk_1 FOREIGN KEY (authentic_source, scope, document_id)
        REFERENCES datastore (authentic_source, scope, document_id) ON DELETE CASCADE;
