-- Singleton row, id fixed to 1 by the CHECK constraint (enforced by MariaDB
-- since 10.2). Startup does "INSERT IGNORE" with id=1 to initialize.
CREATE TABLE token_status_list_metadata (
    id              INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    current_section BIGINT NOT NULL,
    sections        JSON NOT NULL
) ENGINE=InnoDB;
