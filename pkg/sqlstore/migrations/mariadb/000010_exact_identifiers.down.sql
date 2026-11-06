-- Restores the database's default collation on string columns and JSON's own
-- collation on JSON columns.
--
-- This can fail with a duplicate-key error: the exact comparison lets rows exist
-- side by side whose keys differ only in case, accent or trailing spaces, and the
-- default collation folds them into one key. Remove one of each such pair first.
-- A failure leaves schema_migrations dirty at this version.
SET @restore = CONCAT(' CONVERT TO CHARACTER SET ', @@character_set_database, ' COLLATE ', @@collation_database);

ALTER TABLE datastore_identity_mapping DROP FOREIGN KEY datastore_identity_mapping_ibfk_1;

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
