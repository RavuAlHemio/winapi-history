-- Windows symbols are identified in two ways:
-- 1. name (preferred), generally unique
-- 2. DLL name and ordinal, since ordinals are only unique per DLL
--
-- named symbols may also have ordinals within their DLL, but those are subject to change between
-- versions; such ordinals are stored in symbol_dll_os as a curiosity
CREATE TABLE symbols
( sym_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
, raw_name TEXT NULL
, dll_name TEXT NULL
, ordinal INTEGER NULL
, friendly_name TEXT NULL DEFAULT NULL
, UNIQUE (raw_name)
, UNIQUE (dll_name, ordinal)
, CHECK ( (raw_name IS NOT NULL AND dll_name IS NULL AND ordinal IS NULL)
          OR (raw_name IS NULL AND dll_name IS NOT NULL AND ordinal IS NOT NULL)
        )
);

CREATE TABLE operating_systems
( os_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
, short_name TEXT NOT NULL UNIQUE
, long_name TEXT NULL DEFAULT NULL
);

CREATE TABLE dlls
( dll_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
, path TEXT NOT NULL UNIQUE
, secondary_platform INTEGER NOT NULL CHECK(secondary_platform IN (0, 1))
);

CREATE TABLE symbol_dll_os
( sym_id INTEGER NOT NULL REFERENCES symbols (sym_id)
, dll_id INTEGER NOT NULL REFERENCES dlls (dll_id)
, os_id INTEGER NOT NULL REFERENCES operating_systems (os_id)
, ordinal INTEGER NULL
, PRIMARY KEY (sym_id, dll_id, os_id)
);

-- allow slicing and dicing symbol_dll_os from all sides:
-- (sym_id) prefix_of (sym_id, dll_id, os_id) PRIMARY KEY
-- (dll_id) prefix_of (dll_id, os_id) INDEX do
-- (os_id) is INDEX o
-- (sym_id, dll_id) prefix_of (sym_id, dll_id, os_id) PRIMARY KEY
-- (sym_id, os_id) is INDEX so
-- (dll_id, os_id) is INDEX do
-- (sym_id, dll_id, os_id) is PRIMARY KEY
CREATE INDEX idx_sdo_do ON symbol_dll_os (dll_id, os_id);
CREATE INDEX idx_sdo_so ON symbol_dll_os (sym_id, os_id);
CREATE INDEX idx_sdo_o ON symbol_dll_os (os_id);

-- schema version logic
CREATE TABLE schema_version
( ver INTEGER NOT NULL
);
INSERT INTO schema_version (ver) VALUES (1);
CREATE TRIGGER trig_schema_version_no_insert
    BEFORE INSERT ON schema_version
    BEGIN
        SELECT RAISE(ABORT, 'schema_version may only have exactly one row');
    END;
CREATE TRIGGER trig_schema_version_no_delete
    BEFORE DELETE ON schema_version
    BEGIN
        SELECT RAISE(ABORT, 'schema_version may only have exactly one row');
    END;
