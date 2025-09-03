ALTER TABLE operating_systems ADD has_icon INTEGER NOT NULL DEFAULT 0 CHECK(has_icon IN (0, 1));

UPDATE schema_version SET ver=2;
