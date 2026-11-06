-- Every string column compares byte for byte, trailing spaces included, so a
-- stored identifier matches only its exact spelling, as on Postgres and MongoDB
-- and in the SPOCP authorization engine. Every table is rebuilt, so its default
-- collation also applies to columns added later.
--
-- The NO PAD binary collation is utf8mb4_nopad_bin on MariaDB and
-- utf8mb4_0900_bin on MySQL 8. utf8mb4_bin is PAD SPACE: 'A ' = 'A' holds under
-- it. A server with neither collation stops at the first PREPARE below with
-- "Unknown collation", naming the placeholder, before any row or table changes.
--
-- DDL is not transactional. A run that fails partway leaves schema_migrations
-- dirty at this version and the service refuses to start. Restore the backup, or
-- finish the remaining statements by hand and clear the dirty flag.
SET @exact_collation = COALESCE(
    (SELECT COLLATION_NAME FROM information_schema.COLLATIONS
     WHERE COLLATION_NAME IN ('utf8mb4_nopad_bin', 'utf8mb4_0900_bin')
     ORDER BY COLLATION_NAME = 'utf8mb4_nopad_bin' DESC LIMIT 1),
    'server_has_neither_utf8mb4_nopad_bin_nor_utf8mb4_0900_bin');
SET @convert = CONCAT(' CONVERT TO CHARACTER SET utf8mb4 COLLATE ', @exact_collation);

SET @s = CONCAT('DO _utf8mb4 ''x'' COLLATE ', @exact_collation); PREPARE s FROM @s; DEALLOCATE PREPARE s;

-- The foreign key accepted a child row spelt differently from its parent while
-- the columns folded, and AddIdentity and Replace wrote such rows. Each takes
-- its parent's spelling, which keeps it attached under the exact comparison.
-- The child primary key was unique under the folding, so no two rows collide.
UPDATE datastore_identity_mapping m
JOIN datastore d
    ON m.authentic_source = d.authentic_source AND m.scope = d.scope AND m.document_id = d.document_id
SET m.authentic_source = d.authentic_source, m.scope = d.scope, m.document_id = d.document_id;

-- MariaDB and MySQL both refuse to change the collation of a column in a foreign
-- key, with foreign_key_checks off as well. Adding the key back checks every
-- child row under the exact comparison.
ALTER TABLE datastore_identity_mapping DROP FOREIGN KEY datastore_identity_mapping_ibfk_1;

SET @s = CONCAT('ALTER TABLE datastore', @convert); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE datastore_identity_mapping', @convert); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE identity_mappings', @convert); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE credential_offer', @convert); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE oidc_dynamic_registration', @convert); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE clients', @convert); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE token_status_list', @convert); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE token_status_list_metadata', @convert); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE credential_subjects', @convert); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;
SET @s = CONCAT('ALTER TABLE cache_entries', @convert); PREPARE s FROM @s; EXECUTE s; DEALLOCATE PREPARE s;

ALTER TABLE datastore_identity_mapping
    ADD CONSTRAINT datastore_identity_mapping_ibfk_1 FOREIGN KEY (authentic_source, scope, document_id)
        REFERENCES datastore (authentic_source, scope, document_id) ON DELETE CASCADE;
