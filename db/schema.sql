CREATE TABLE symbols
( sym_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
, raw_name TEXT NOT NULL UNIQUE
, friendly_name TEXT NULL DEFAULT NULL
);

CREATE TABLE operating_systems
( os_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
, short_name TEXT NOT NULL UNIQUE
, long_name TEXT NULL DEFAULT NULL
);

CREATE TABLE dlls
( dll_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
, path TEXT NOT NULL UNIQUE
);

CREATE TABLE symbol_dll_os
( sym_id INTEGER NOT NULL REFERENCES symbols (sym_id)
, dll_id INTEGER NOT NULL REFERENCES dlls (dll_id)
, os_id INTEGER NOT NULL REFERENCES operating_systems (os_id)
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
