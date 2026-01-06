ALTER TABLE symbols ADD is_meta_func INTEGER NOT NULL DEFAULT 0 CHECK(is_meta_func IN (0, 1));

UPDATE schema_version SET ver=3;
