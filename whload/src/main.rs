#[cfg(feature = "ms_cpp_filt")]
mod ms_cpp_filt;


use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;

use clap::Parser;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Params, Statement};


#[derive(Parser)]
enum Mode {
    /// Load symbols into the database.
    Load(LoadOpts),

    /// Demangle a Microsoft C++ symbol.
    #[cfg(feature = "ms_cpp_filt")]
    Demangle(DemangleOpts),
}

#[derive(Parser)]
struct LoadOpts {
    /// The path to the SQLite database in which to store the API information.
    pub database_path: PathBuf,

    /// The list of API calls.
    pub list_path: PathBuf,
}

#[cfg(feature = "ms_cpp_filt")]
#[derive(Parser)]
struct DemangleOpts {
    /// The name to demangle.
    pub name: String,
}

#[cfg(feature = "ms_cpp_filt")]
#[derive(Parser)]
struct DemangleDbOpts {
    /// The path to the SQLite database which to update with demangled names.
    pub database_path: PathBuf,
}


fn run_get_id_query<P: Params>(statement: &mut Statement, params: P) -> Option<i64> {
    statement
        .query_one(
            params,
            |row| {
                let entry_id: i64 = row
                    .get(0)
                    .expect("failed to obtain ID from column 0");
                Ok(entry_id)
            },
        )
        .optional()
        .expect("failed to run get-ID query")
}

fn run_insert_id_query<P: Params>(statement: &mut Statement, params: P) -> i64 {
    statement
        .query_one(
            params,
            |row| {
                let entry_id: i64 = row
                    .get(0)
                    .expect("failed to obtain ID from column 0");
                Ok(entry_id)
            },
        )
        .expect("failed to run insert-ID query")
}

fn main() {
    let mode = Mode::parse();

    match mode {
        Mode::Load(load_opts) => {
            do_load(load_opts);
        },

        #[cfg(feature = "ms_cpp_filt")]
        Mode::Demangle(demangle_opts) => {
            do_demangle(demangle_opts);
        },

    }
}

#[cfg(feature = "ms_cpp_filt")]
fn do_demangle(opts: DemangleOpts) {
    match crate::ms_cpp_filt::demangle_cpp_name(&opts.name) {
        Ok(d) => println!("ISOK {}", d),
        Err(e) => println!("FAIL {}", e),
    }
}

fn do_load(opts: LoadOpts) {
    // open the SQLite database
    let mut db = Connection::open_with_flags(
        &opts.database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_EXRESCODE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
    )
        .expect("failed to open SQLite database");

    // check schema
    let schema_version_exists = db.table_exists(None, "schema_version")
        .expect("failed to check if table schema_version exists");
    if !schema_version_exists {
        // populate
        db.execute_batch(include_str!("../../db/schema.sql"))
            .expect("failed to create initial database schema");
    }

    // migration-execution logic
    const MAX_SUPPORTED_SCHEMA: i64 = 2;
    let schema_version: i64 = db.query_one(
        "SELECT ver FROM schema_version",
        [],
        |r| r.get(0)
    )
        .expect("failed to query database for schema version");
    if schema_version <= 0 {
        panic!("database has invalid schema version {}", schema_version);
    }
    if schema_version == 1 {
        eprintln!("updating database to schema version 2");
        db.execute_batch(include_str!("../../db/migrations/r0001_to_r0002.sql"))
            .expect("failed to update database schema from version 1 to 2");
    }
    if schema_version > MAX_SUPPORTED_SCHEMA {
        eprintln!(
            "WARNING: schema version {} is greater than supported by this version ({})",
            schema_version, MAX_SUPPORTED_SCHEMA,
        );
        eprintln!("here's hoping nothing bad happens...");
    }

    // start a transaction
    let txn = db.transaction()
        .expect("failed to start transaction");

    {
        // prepare a few statements we will be using
        let mut query_os = txn
            .prepare("SELECT os_id FROM operating_systems WHERE short_name = ?1")
            .expect("failed to prepare query_os statement");
        let mut insert_os = txn
            .prepare("INSERT INTO operating_systems (short_name, long_name) VALUES (?1, NULL) RETURNING os_id")
            .expect("failed to prepare insert_os statement");
        let mut query_dll = txn
            .prepare("SELECT dll_id FROM dlls WHERE path = ?1")
            .expect("failed to prepare query_dll statement");
        let mut insert_dll = txn
            .prepare("INSERT INTO dlls (path, secondary_platform) VALUES (?1, ?2) RETURNING dll_id")
            .expect("failed to prepare insert_dll statement");
        let mut query_named_symbol = txn
            .prepare("SELECT sym_id FROM symbols WHERE raw_name = ?1")
            .expect("failed to prepare query_named_symbol statement");
        let mut insert_named_symbol = txn
            .prepare("INSERT INTO symbols (raw_name, dll_name, ordinal, friendly_name) VALUES (?1, NULL, NULL, ?2) RETURNING sym_id")
            .expect("failed to prepare query insert_named_symbol");
        let mut query_dll_ordinal_symbol = txn
            .prepare("SELECT sym_id FROM symbols WHERE dll_name = ?1 AND ordinal = ?2")
            .expect("failed to prepare query_dll_ordinal_symbol statement");
        let mut insert_dll_ordinal_symbol = txn
            .prepare("INSERT INTO symbols (raw_name, dll_name, ordinal, friendly_name) VALUES (NULL, ?1, ?2, NULL) RETURNING sym_id")
            .expect("failed to prepare query insert_dll_ordinal_symbol");
        let mut insert_relationship = txn
            .prepare("INSERT OR IGNORE INTO symbol_dll_os (sym_id, dll_id, os_id, ordinal) VALUES (?1, ?2, ?3, ?4)")
            .expect("failed to prepare query insert_relationship");

        // cache
        let mut op_sys_to_id: BTreeMap<String, i64> = BTreeMap::new();
        let mut dll_to_id: BTreeMap<String, i64> = BTreeMap::new();
        let mut symbol_name_to_id: BTreeMap<String, i64> = BTreeMap::new();
        let mut symbol_dll_to_ordinal_to_id: BTreeMap<String, BTreeMap<u64, i64>> = BTreeMap::new();

        // start crunching
        let list_file = File::open(&opts.list_path)
            .expect("failed to open list file");
        let mut list_reader = BufReader::new(list_file);

        let file_length = list_reader.seek(SeekFrom::End(0))
            .expect("failed to seek to the end of the input file");
        list_reader.seek(SeekFrom::Start(0))
            .expect("failed to seek to the start of the input file");

        let mut line = String::new();
        let mut last_file_percentage = 0;
        let mut file_bytes_read = 0;
        loop {
            line.clear();
            let bytes_read = list_reader.read_line(&mut line)
                .expect("failed to read line");
            if bytes_read == 0 {
                // EOF
                break;
            }

            // output progress
            file_bytes_read += u64::try_from(bytes_read).unwrap();
            let now_file_percentage = (file_bytes_read * 1000) / file_length;
            if last_file_percentage < now_file_percentage {
                last_file_percentage = now_file_percentage;
                eprintln!("{}\u{2030}", now_file_percentage);
            }

            // strip trailing newlines
            while line.ends_with(&['\r', '\n']) {
                line.pop();
            }
            if line.len() == 0 {
                continue;
            }

            let fields: Vec<&str> = line.split("\t").collect();
            if fields.len() != 3 {
                panic!("line {:?} does not have 3 fields", line);
            }

            let path_parts: Vec<String> = serde_json::from_str(&fields[0])
                .expect("failed to parse field 0 as JSON");
            if path_parts.len() != 1 {
                panic!("expected a single-part file path");
            }
            let dll_path = &path_parts[0];

            let symbol_name_opt = if fields[2].len() > 0 {
                Some(fields[2])
            } else {
                None
            };
            let ordinal_opt: Option<u64> = if fields[1].len() > 0 {
                Some(
                    fields[1]
                        .parse()
                        .expect("failed to parse ordinal")
                )
            } else {
                None
            };

            // decode the operating system from the path
            let dll_path_lower = dll_path
                .to_lowercase()
                .replace("/", "\\");
            let path_pieces: Vec<&str> = dll_path_lower
                .split("\\")
                .collect();
            if path_pieces.len() < 2 {
                panic!("expected at least two path pieces");
            }
            let operating_system = path_pieces[0];
            let dll_path = path_pieces[1..].join("\\");

            // find operating system ID
            let op_sys_id = if let Some(osi) = op_sys_to_id.get(operating_system) {
                *osi
            } else {
                let op_sys_id_opt = run_get_id_query(
                    &mut query_os,
                    [operating_system],
                );
                let op_sys_id = match op_sys_id_opt {
                    Some(osi) => osi,
                    None => {
                        run_insert_id_query(
                            &mut insert_os,
                            [operating_system],
                        )
                    },
                };
                op_sys_to_id.insert(
                    operating_system.to_owned(),
                    op_sys_id,
                );
                op_sys_id
            };

            // find DLL ID
            let dll_id = if let Some(di) = dll_to_id.get(&dll_path) {
                *di
            } else {
                let dll_id_opt = run_get_id_query(
                    &mut query_dll,
                    [dll_path.as_str()],
                );
                const NOT_A_SECONDARY_PLATFORM: bool = false;
                let dll_id = match dll_id_opt {
                    Some(di) => di,
                    None => {
                        run_insert_id_query(
                            &mut insert_dll,
                            (dll_path.as_str(), NOT_A_SECONDARY_PLATFORM),
                        )
                    },
                };
                dll_to_id.insert(dll_path.clone(), dll_id);
                dll_id
            };

            // find symbol ID
            let symbol_id = if let Some(symbol_name) = symbol_name_opt {
                // this is a named symbol
                if let Some(sid) = symbol_name_to_id.get(symbol_name) {
                    *sid
                } else {
                    let named_id_opt = run_get_id_query(
                        &mut query_named_symbol,
                        [symbol_name],
                    );
                    let sym_id = match named_id_opt {
                        Some(ni) => ni,
                        None => {
                            // we don't know this symbol yet
                            // try demangling it to obtain a friendly name
                            let friendly_name = try_demangle(symbol_name);

                            run_insert_id_query(
                                &mut insert_named_symbol,
                                (symbol_name, friendly_name),
                            )
                        },
                    };
                    symbol_name_to_id.insert(symbol_name.to_owned(), sym_id);
                    sym_id
                }
            } else if let Some(ordinal) = ordinal_opt {
                // this is an unnamed symbol with an ordinal within its DLL
                let final_dll_name = *path_pieces.last().unwrap();
                let sid_opt = symbol_dll_to_ordinal_to_id
                    .get(final_dll_name)
                    .and_then(|otoid| otoid.get(&ordinal));
                if let Some(sid) = sid_opt {
                    *sid
                } else {
                    let ordinal_id_opt = run_get_id_query(
                        &mut query_dll_ordinal_symbol,
                        (final_dll_name, ordinal),
                    );
                    let sid = match ordinal_id_opt {
                        Some(oi) => oi,
                        None => {
                            run_insert_id_query(
                                &mut insert_dll_ordinal_symbol,
                                (final_dll_name, ordinal),
                            )
                        }
                    };
                    symbol_dll_to_ordinal_to_id
                        .entry(final_dll_name.to_owned())
                        .or_insert_with(|| BTreeMap::new())
                        .insert(ordinal, sid);
                    sid
                }
            } else {
                panic!("symbol in {:?} with neither name nor ordinal", path_parts);
            };

            // now insert a new row that merges it all
            if let Err(e) = insert_relationship.execute((symbol_id, dll_id, op_sys_id, ordinal_opt)) {
                panic!("failed to add relationship: {:?}/{:?}#{:?}, {}, {}: {:?}", symbol_name_opt, path_parts, ordinal_opt, operating_system, dll_path, e);
            }
        }
    }

    // and we're done
    txn.commit()
        .expect("committing transaction failed");
}

#[cfg(feature = "ms_cpp_filt")]
fn try_demangle(symbol: &str) -> Option<String> {
    crate::ms_cpp_filt::demangle_cpp_name(symbol).ok()
}

#[cfg(not(feature = "ms_cpp_filt"))]
fn try_demangle(_symbol: &str) -> Option<String> {
    None
}
