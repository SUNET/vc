-- Singleton row, id fixed to 1 by the CHECK constraint. Startup does
-- "INSERT ... ON CONFLICT (id) DO NOTHING" with id=1 to initialize.
CREATE TABLE token_status_list_metadata (
    id              INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    current_section BIGINT NOT NULL,
    sections        JSONB NOT NULL
);
