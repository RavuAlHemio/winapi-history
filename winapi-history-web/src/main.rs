use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Cursor;

use askama::Template;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use rocket::{Request, Response};
use rocket::response::{Redirect, Responder};
use rocket::http::{ContentType, Status};
use rusqlite::{Connection, OpenFlags, Params, Row, Statement};
use tracing::error;


/// Characters not reserved for any special use in URLs.
///
/// Corresponds to the `unreserved` production in RFC3986.
///
/// `NON_ALPHANUMERIC` contains all characters that are not in `[0-9A-Za-z]`;
/// we derive our set by removing the unreserved punctuation characters.
const URL_UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-').remove(b'.').remove(b'_').remove(b'~');


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Template)]
#[template(path = "root.html")]
struct RootTemplate {
    pub operating_systems: Vec<OperatingSystemPart>,
    pub dll_start_chars: Vec<String>,
    pub func_start_chars: Vec<String>,
    pub ordinal_dll_start_chars: Vec<String>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Template)]
#[template(path = "os.html")]
struct OsTemplate {
    pub os: OperatingSystemPart,
    pub dlls: Vec<DllPart>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Template)]
#[template(path = "dll.html")]
struct DllTemplate {
    pub dll: DllPart,
    pub dll_operating_systems: Vec<OperatingSystemPart>,
    pub symbols_oses: Vec<(SymbolPart, Vec<OperatingSystemPart>)>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Template)]
#[template(path = "os-sym-list.html")]
struct OsSymbolListTemplate {
    pub os: OperatingSystemPart,
    pub symbols: Vec<OsSymbolPart>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Template)]
#[template(path = "os-dll-sym-list.html")]
struct OsDllSymbolListTemplate {
    pub os: OperatingSystemPart,
    pub dll: DllPart,
    pub symbols: Vec<SymbolPart>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Template)]
#[template(path = "symbol.html")]
struct SymbolTemplate {
    pub path_to_root: &'static str,
    pub symbol: SymbolPart,
    pub os_dlls: Vec<(OperatingSystemPart, Vec<DllPart>)>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Template)]
#[template(path = "alpha-dll-list.html")]
struct AlphabeticalDllListTemplate {
    pub dll_parts: Vec<DllOsesPart>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Template)]
#[template(path = "alpha-sym-list.html")]
struct AlphabeticalSymbolListTemplate {
    pub path_to_root: &'static str,
    pub symbols: Vec<SymbolPart>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Template)]
#[template(path = "compare-os.html")]
struct CompareOsTemplate {
    pub old_os: OperatingSystemPart,
    pub new_os: OperatingSystemPart,
    pub removed_dlls: Vec<String>,
    pub added_dlls: Vec<String>,
    pub removed_symbols: Vec<SymbolPart>,
    pub added_symbols: Vec<SymbolPart>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Template)]
#[template(path = "compare-os-dll.html")]
struct CompareOsDllTemplate {
    pub old_os: OperatingSystemPart,
    pub new_os: OperatingSystemPart,
    pub dll_path: String,
    pub removed_symbols: Vec<SymbolPart>,
    pub added_symbols: Vec<SymbolPart>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct OperatingSystemPart {
    pub short_name: String,
    pub long_name: String,
    pub has_icon: bool,
}
impl OperatingSystemPart {
    pub fn try_from_row(field_offset: usize, row: &Row<'_>) -> Result<Self, rusqlite::Error> {
        let short_name: String = row.get(field_offset + 0)?;
        let long_name_opt: Option<String> = row.get(field_offset + 1)?;
        let has_icon: bool = row.get(field_offset + 2)?;

        let long_name = if let Some(ln) = long_name_opt {
            ln
        } else {
            short_name.clone()
        };

        let os_part = Self {
            short_name,
            long_name,
            has_icon,
        };
        Ok(os_part)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct DllPart {
    pub path: String,
    pub secondary_platform: bool,
}
impl DllPart {
    pub fn try_from_row(field_offset: usize, row: &Row<'_>) -> Result<Self, rusqlite::Error> {
        let path: String = row.get(field_offset + 0)?;
        let secondary_platform: bool = row.get(field_offset + 1)?;
        let dll_part = Self {
            path,
            secondary_platform,
        };
        Ok(dll_part)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum SymbolPart {
    Named {
        raw_name: String,
        friendly_name: Option<String>,
        is_meta_func: bool,
    },
    DllOrdinal {
        dll_name: String,
        ordinal: u64,
        friendly_name: Option<String>, // `"<dll_name>#<ordinal>"` if not overridden
        is_meta_func: bool,
    },
}
impl SymbolPart {
    pub fn friendly_name(&self) -> Option<&str> {
        match self {
            Self::Named { friendly_name, .. }
                => friendly_name.as_deref(),
            Self::DllOrdinal { friendly_name, .. }
                => friendly_name.as_deref(),
        }
    }

    pub fn friendly_name_or_generate(&self) -> String {
        match self {
            Self::Named { friendly_name: Some(f), .. }
                => f.clone(),
            Self::Named { friendly_name: None, raw_name, .. }
                => raw_name.clone(),
            Self::DllOrdinal { friendly_name: Some(f), .. }
                => f.clone(),
            Self::DllOrdinal { friendly_name: None, dll_name, ordinal, .. }
                => format!("{}#{}", dll_name, ordinal),
        }
    }

    pub fn raw_name(&self) -> Option<&str> {
        match self {
            Self::Named { raw_name, .. }
                => Some(raw_name),
            Self::DllOrdinal { .. }
                => None,
        }
    }

    pub fn is_meta_func(&self) -> bool {
        match self {
            Self::Named { is_meta_func, .. }
                => *is_meta_func,
            Self::DllOrdinal { is_meta_func, .. }
                => *is_meta_func,
        }
    }

    pub fn dll_pair(&self) -> Option<(&str, u64)> {
        match self {
            Self::Named { .. }
                => None,
            Self::DllOrdinal { dll_name, ordinal, .. }
                => Some((dll_name.as_str(), *ordinal)),
        }
    }

    pub fn try_from_row(field_offset: usize, row: &Row<'_>) -> Result<Self, rusqlite::Error> {
        let raw_name: Option<String> = row.get(field_offset + 0)?;
        let friendly_name: Option<String> = row.get(field_offset + 1)?;
        let dll_name: Option<String> = row.get(field_offset + 2)?;
        let ordinal: Option<u64> = row.get(field_offset + 3)?;
        let is_meta_func: bool = row.get(field_offset + 4)?;

        let sym_part = if let Some(rn) = raw_name {
            SymbolPart::Named {
                raw_name: rn,
                friendly_name,
                is_meta_func,
            }
        } else if let Some(dn) = dll_name {
            SymbolPart::DllOrdinal {
                dll_name: dn,
                ordinal: ordinal.unwrap(),
                friendly_name,
                is_meta_func,
            }
        } else {
            panic!("symbol that is neither named nor ordinal");
        };
        Ok(sym_part)
    }

    pub fn try_named_from_row(field_offset: usize, row: &Row<'_>) -> Result<Self, rusqlite::Error> {
        let raw_name: String = row.get(field_offset + 0)?;
        let friendly_name: Option<String> = row.get(field_offset + 1)?;
        let is_meta_func: bool = row.get(field_offset + 2)?;
        Ok(SymbolPart::Named {
            raw_name,
            friendly_name,
            is_meta_func,
        })
    }

    pub fn try_ordinal_from_row(field_offset: usize, row: &Row<'_>) -> Result<Self, rusqlite::Error> {
        let dll_name: String = row.get(field_offset + 0)?;
        let ordinal: u64 = row.get(field_offset + 1)?;
        let friendly_name: Option<String> = row.get(field_offset + 2)?;
        let is_meta_func: bool = row.get(field_offset + 3)?;
        Ok(SymbolPart::DllOrdinal {
            dll_name,
            ordinal,
            friendly_name,
            is_meta_func,
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct OsSymbolPart {
    pub symbol: SymbolPart,
    pub dll: DllPart,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct DllOsesPart {
    pub dll: DllPart,
    pub oses: Vec<OperatingSystemPart>,
}


fn connect_to_database() -> Option<Connection> {
    let conn_res = Connection::open_with_flags(
        "winapi.sqlite3",
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_EXRESCODE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    );
    match conn_res {
        Ok(c) => {
            // we don't really care as long as the connection is read-only,
            // but should we ever implement writing features...
            c.pragma_update(None, "foreign_keys", true)
                .expect("failed to enable foreign-key enforcement");
            Some(c)
        },
        Err(e) => {
            error!("failed to connect to database: {}", e);
            None
        },
    }
}

fn prepare<'c>(db: &'c Connection, query: &str) -> Option<Statement<'c>> {
    match db.prepare(query) {
        Ok(s) => Some(s),
        Err(e) => {
            error!("failed to prepare statement for query {:?}: {}", query, e);
            None
        },
    }
}

fn query_database<
    T,
    P: Params,
    F: FnMut(&Row<'_>) -> Result<T, rusqlite::Error>,
>(statement: &mut Statement<'_>, params: P, transform_row: F) -> Option<Vec<T>> {
    let query_debug = format!("{:?}", statement);
    let rows = match statement.query_map(params, transform_row) {
        Ok(r) => r,
        Err(e) => {
            error!("failed to run query {}: {}", query_debug, e);
            return None;
        },
    };
    let mut finished_rows: Vec<T> = Vec::new();
    for row_res in rows {
        let row = match row_res {
            Ok(r) => r,
            Err(e) => {
                error!("failed to obtain row at index {}: {}", finished_rows.len(), e);
                return None;
            },
        };
        finished_rows.push(row);
    }
    Some(finished_rows)
}

fn prepare_and_query_database<
    T,
    P: Params,
    F: FnMut(&Row<'_>) -> Result<T, rusqlite::Error>,
>(db: &Connection, query: &str, params: P, transform_row: F) -> Option<Vec<T>> {
    let mut statement = prepare(db, query)?;
    query_database(&mut statement, params, transform_row)
}

fn check_database_existence<P: Params>(db: &Connection, query: &str, params: P) -> Option<bool> {
    let mut statement = match db.prepare(query) {
        Ok(s) => s,
        Err(e) => {
            error!("failed to prepare query {:?}: {}", query, e);
            return None;
        },
    };
    let rows = match statement.query_map(params, |_| Ok(())) {
        Ok(r) => r,
        Err(e) => {
            error!("failed to run query {:?}: {}", query, e);
            return None;
        },
    };
    let mut has_row = false;
    for row_res in rows {
        match row_res {
            Ok(_) => {
                has_row = true;
                break;
            },
            Err(e) => {
                error!("failed to obtain row: {}", e);
                return None;
            },
        }
    }
    Some(has_row)
}

fn response_500() -> Response<'static> {
    const BODY: &str = "internal server error";
    Response::build()
        .status(Status::InternalServerError)
        .header(ContentType::Text)
        .sized_body(BODY.len(), Cursor::new(BODY))
        .finalize()
}

enum TemplateResponder<T: Template + Debug> {
    Template(T),
    NotFound,
    Failure,
}
impl<'r, 'o : 'r, T: Template + Debug> Responder<'r, 'o> for TemplateResponder<T> {
    fn respond_to(self, _request: &'r Request<'_>) -> rocket::response::Result<'o> {
        match self {
            Self::Failure => Ok(response_500()),
            Self::NotFound => {
                const BODY: &str = "not found";
                let response = Response::build()
                    .status(Status::NotFound)
                    .header(ContentType::Text)
                    .sized_body(BODY.len(), Cursor::new(BODY))
                    .finalize();
                Ok(response)
            },
            Self::Template(template) => {
                let rendered = match template.render() {
                    Ok(r) => r,
                    Err(e) => {
                        error!("failed to render template {:?}: {}", template, e);
                        return Ok(response_500());
                    },
                };
                let response = Response::build()
                    .status(Status::Ok)
                    .header(ContentType::HTML)
                    .sized_body(rendered.len(), Cursor::new(rendered))
                    .finalize();
                Ok(response)
            },
        }
    }
}


#[rocket::get("/os/<os_name>")]
fn os_page(os_name: &str) -> TemplateResponder<OsTemplate> {
    let Some(db) = connect_to_database()
        else { return TemplateResponder::Failure };

    // does this operating system exist? what ID does it have?
    let os_info_rows_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                os_id, short_name, COALESCE(long_name, short_name), has_icon
            FROM
                operating_systems
            WHERE
                short_name = ?1
        ",
        [os_name],
        |row| {
            let os_id: i64 = row.get(0)?;
            let os_part = OperatingSystemPart::try_from_row(1, row)?;
            Ok((os_id, os_part))
        },
    );
    let (os_id, os_part) = match os_info_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(mut v) => v.swap_remove(0),
    };

    // find its DLLs
    let dlls_opt = prepare_and_query_database(
        &db,
        "
            SELECT DISTINCT
                d.path,
                d.secondary_platform
            FROM
                dlls d
            WHERE
                EXISTS (
                    SELECT 1
                    FROM symbol_dll_os sdo
                    WHERE sdo.dll_id = d.dll_id
                    AND sdo.os_id = ?1
                )
            ORDER BY
                1
        ",
        [os_id],
        |row| DllPart::try_from_row(0, row),
    );
    let Some(dlls) = dlls_opt
        else { return TemplateResponder::Failure };

    let template = OsTemplate {
        dlls,
        os: os_part,
    };
    TemplateResponder::Template(template)
}

#[rocket::get("/os/<os_name>/dll/<dll_name>")]
fn os_dll_page(os_name: &str, dll_name: &str) -> TemplateResponder<OsDllSymbolListTemplate> {
    let Some(db) = connect_to_database()
        else { return TemplateResponder::Failure };

    // does this operating system exist? what ID does it have?
    let os_info_rows_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                os_id, short_name, COALESCE(long_name, short_name), has_icon
            FROM
                operating_systems
            WHERE
                short_name = ?1
        ",
        [os_name],
        |row| {
            let os_id: i64 = row.get(0)?;
            let os_part = OperatingSystemPart::try_from_row(1, row)?;
            Ok((os_id, os_part))
        },
    );
    let (os_id, os_part) = match os_info_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(mut v) => v.swap_remove(0),
    };

    // does this DLL exist? what ID does it have?
    let dll_info_rows_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                dll_id, path, secondary_platform
            FROM
                dlls
            WHERE
                path = ?1
        ",
        [dll_name],
        |row| {
            let dll_id: i64 = row.get(0)?;
            let dll_part = DllPart::try_from_row(1, row)?;
            Ok((dll_id, dll_part))
        },
    );
    let (dll_id, dll_part) = match dll_info_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(mut v) => v.swap_remove(0),
    };

    // find the DLL's symbols in this OS, named and ordinal
    // including meta-functions
    let syms_opt = prepare_and_query_database(
        &db,
        "
            SELECT DISTINCT
                sym.raw_name,
                sym.friendly_name,
                sym.dll_name,
                sym.ordinal,
                sym.is_meta_func
            FROM
                dlls d
                INNER JOIN symbol_dll_os sdo
                    ON sdo.dll_id = d.dll_id
                INNER JOIN symbols sym
                    ON sym.sym_id = sdo.sym_id
            WHERE
                sdo.os_id = ?1
                AND d.dll_id = ?2
            ORDER BY
                1 ASC NULLS LAST,
                2 ASC NULLS LAST,
                3,
                4
        ",
        [os_id, dll_id],
        |row| SymbolPart::try_from_row(0, row),
    );
    let Some(symbols) = syms_opt
        else { return TemplateResponder::Failure };

    let template = OsDllSymbolListTemplate {
        symbols,
        os: os_part,
        dll: dll_part,
    };
    TemplateResponder::Template(template)
}

#[rocket::get("/os/<os_name>/all-symbols")]
fn all_os_symbols(os_name: &str) -> TemplateResponder<OsSymbolListTemplate> {
    let Some(db) = connect_to_database()
        else { return TemplateResponder::Failure };

    // does this operating system exist? what ID does it have?
    let os_info_rows_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                os_id,
                short_name,
                COALESCE(long_name, short_name),
                has_icon
            FROM
                operating_systems
            WHERE
                short_name = ?1
        ",
        [os_name],
        |row| {
            let os_id: i64 = row.get(0)?;
            let os_part = OperatingSystemPart::try_from_row(1, row)?;
            Ok((os_id, os_part))
        },
    );
    let (os_id, os) = match os_info_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(mut v) => v.swap_remove(0),
    };

    // find all symbols available in this OS, named and ordinal;
    // no meta-functions though
    let symbol_rows_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                sym.raw_name,
                sym.friendly_name,
                sym.dll_name,
                sym.ordinal,
                sym.is_meta_func,
                dll.path,
                dll.secondary_platform
            FROM
                symbols sym
                INNER JOIN symbol_dll_os sdo
                    ON sdo.sym_id = sym.sym_id
                INNER JOIN dlls dll
                    ON dll.dll_id = sdo.dll_id
            WHERE
                sdo.os_id = ?1
                AND sym.is_meta_func = 0
            ORDER BY
                1 ASC NULLS LAST,
                2 ASC NULLS LAST,
                3,
                4
        ",
        [os_id],
        |row| {
            let symbol_part = SymbolPart::try_from_row(0, row)?;
            let dll_part = DllPart::try_from_row(5, row)?;
            Ok(OsSymbolPart {
                dll: dll_part,
                symbol: symbol_part,
            })
        },
    );
    let symbol_rows = match symbol_rows_opt {
        None => return TemplateResponder::Failure,
        Some(sr) => sr,
    };

    let template = OsSymbolListTemplate {
        os,
        symbols: symbol_rows,
    };
    TemplateResponder::Template(template)
}

fn finish_dlls(db: &Connection, sym_id: i64, sym_part: SymbolPart, path_to_root: &'static str) -> TemplateResponder<SymbolTemplate> {
    let dll_rows_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                os.os_id,
                os.short_name,
                COALESCE(os.long_name, os.short_name),
                os.has_icon,
                dll.path,
                dll.secondary_platform
            FROM
                operating_systems os
                INNER JOIN symbol_dll_os sdo
                    ON sdo.os_id = os.os_id
                INNER JOIN dlls dll
                    ON dll.dll_id = sdo.dll_id
            WHERE
                sdo.sym_id = ?1
            ORDER BY
                os.release_date ASC NULLS LAST,
                3, 4
        ",
        [sym_id],
        |row| {
            let os_id: i64 = row.get(0)?;
            let os_part = OperatingSystemPart::try_from_row(1, row)?;
            let dll_part = DllPart::try_from_row(4, row)?;
            Ok((os_id, os_part, dll_part))
        },
    );
    let dll_rows = match dll_rows_opt {
        None => return TemplateResponder::Failure,
        Some(sr) => sr,
    };

    let mut id_to_os: BTreeMap<i64, OperatingSystemPart> = BTreeMap::new();
    let mut os_id_to_dlls: BTreeMap<i64, Vec<DllPart>> = BTreeMap::new();
    let mut os_id_ordered = Vec::new();
    for (os_id, os, dll) in dll_rows {
        id_to_os
            .entry(os_id)
            .or_insert_with(|| {
                // also append ID to ordering vec
                os_id_ordered.push(os_id);

                os
            });
        os_id_to_dlls
            .entry(os_id)
            .or_insert_with(|| Vec::with_capacity(1))
            .push(dll);
    }

    let mut os_dlls = Vec::with_capacity(id_to_os.len());
    for id in os_id_ordered {
        let os = id_to_os
            .remove(&id)
            .unwrap();
        let dlls = os_id_to_dlls
            .remove(&id)
            .unwrap();
        os_dlls.push((os, dlls));
    }

    let template = SymbolTemplate {
        path_to_root,
        symbol: sym_part,
        os_dlls,
    };
    TemplateResponder::Template(template)
}

#[rocket::get("/symbol/<sym_raw_name>")]
fn symbol_page(sym_raw_name: &str) -> TemplateResponder<SymbolTemplate> {
    let Some(db) = connect_to_database()
        else { return TemplateResponder::Failure };

    // does this symbol exist? what ID does it have?
    let sym_info_rows_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                sym_id,
                raw_name,
                friendly_name,
                is_meta_func
            FROM
                symbols
            WHERE
                raw_name = ?1
        ",
        [sym_raw_name],
        |row| {
            let sym_id: i64 = row.get(0)?;
            let sym_part = SymbolPart::try_named_from_row(1, row)?;
            Ok((sym_id, sym_part))
        },
    );
    let (sym_id, sym_part) = match sym_info_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(mut v) => v.swap_remove(0),
    };

    finish_dlls(&db, sym_id, sym_part, "../")
}

#[rocket::get("/symbol/dll/<dll_name>/ordinal/<ordinal>")]
fn dll_ordinal_symbol_page(dll_name: &str, ordinal: usize) -> TemplateResponder<SymbolTemplate> {
    let Some(db) = connect_to_database()
        else { return TemplateResponder::Failure };

    // does this symbol exist? what ID does it have?
    let sym_info_rows_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                sym_id,
                dll_name,
                ordinal,
                friendly_name,
                is_meta_func
            FROM
                symbols
            WHERE
                dll_name = ?1
                AND ordinal = ?2
        ",
        (dll_name, ordinal),
        |row| {
            let sym_id: i64 = row.get(0)?;
            let sym_part = SymbolPart::try_ordinal_from_row(1, row)?;
            Ok((sym_id, sym_part))
        },
    );
    let (sym_id, sym_part) = match sym_info_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(mut v) => v.swap_remove(0),
    };

    finish_dlls(&db, sym_id, sym_part, "../../../../")
}

#[rocket::get("/dll/<dll_name>")]
fn dll_page(dll_name: &str) -> TemplateResponder<DllTemplate> {
    let Some(db) = connect_to_database()
        else { return TemplateResponder::Failure };

    // does this DLL exist? what ID does it have?
    let dll_info_rows_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                dll_id, path, secondary_platform
            FROM
                dlls
            WHERE
                path = ?1
        ",
        [dll_name],
        |row| {
            let dll_id: i64 = row.get(0)?;
            let dll_part = DllPart::try_from_row(1, row)?;
            Ok((dll_id, dll_part))
        },
    );
    let (dll_id, dll_part) = match dll_info_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(mut v) => v.swap_remove(0),
    };

    // find the OSes that have this DLL
    let dll_oses_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                os.short_name,
                os.long_name,
                os.has_icon
            FROM
                operating_systems os
            WHERE
                EXISTS (
                    SELECT 1
                    FROM symbol_dll_os sdo
                    WHERE sdo.dll_id = ?1
                    AND sdo.os_id = os.os_id
                )
            ORDER BY
                os.release_date ASC NULLS LAST
        ",
        [dll_id],
        |row| OperatingSystemPart::try_from_row(0, row),
    );
    let dll_oses = match dll_oses_opt {
        Some(v) => v,
        None => return TemplateResponder::Failure,
    };

    // find the symbols in the DLL, named or ordinal;
    // meta-functions last
    let syms_opt = prepare_and_query_database(
        &db,
        "
            SELECT DISTINCT
                sym.sym_id,
                sym.raw_name,
                sym.friendly_name,
                sym.dll_name,
                sym.ordinal,
                sym.is_meta_func
            FROM
                dlls d
                INNER JOIN symbol_dll_os sdo
                    ON sdo.dll_id = d.dll_id
                INNER JOIN symbols sym
                    ON sym.sym_id = sdo.sym_id
            WHERE
                d.dll_id = ?1
            ORDER BY
                6,
                2 ASC NULLS LAST,
                3 ASC NULLS LAST,
                4,
                5
        ",
        [dll_id],
        |row| {
            let sym_id: i64 = row.get(0)?;
            let sym_part = SymbolPart::try_from_row(1, row)?;
            Ok((sym_id, sym_part))
        },
    );
    let Some(syms) = syms_opt
        else { return TemplateResponder::Failure };

    // find the operating systems per symbol
    const OS_QUERY: &'static str = "
        SELECT DISTINCT
            os.short_name,
            COALESCE(os.long_name, os.short_name),
            has_icon
        FROM
            operating_systems os
            INNER JOIN symbol_dll_os sdo
                ON sdo.os_id = os.os_id
        WHERE
            sdo.sym_id = ?1
        ORDER BY
            os.release_date ASC NULLS LAST
    ";
    let Some(mut os_statement) = prepare(&db, OS_QUERY)
        else { return TemplateResponder::Failure };

    let mut symbols_oses = Vec::with_capacity(syms.len());
    for (sym_id, sym_part) in syms {
        let oses_opt = query_database(
            &mut os_statement,
            [sym_id],
            |row| OperatingSystemPart::try_from_row(0, row),
        );
        let Some(oses) = oses_opt
            else { return TemplateResponder::Failure };
        symbols_oses.push((sym_part, oses));
    }

    let template = DllTemplate {
        dll: dll_part,
        dll_operating_systems: dll_oses,
        symbols_oses,
    };
    TemplateResponder::Template(template)
}

#[rocket::get("/dlls/<dll_prefix>")]
fn alpha_dll_page(dll_prefix: &str) -> TemplateResponder<AlphabeticalDllListTemplate> {
    let Some(db) = connect_to_database()
        else { return TemplateResponder::Failure };

    let prefix_len_chars = dll_prefix.chars().count();

    // find the DLLs with that prefix
    let dlls_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                dll_id,
                path,
                secondary_platform
            FROM
                dlls
            WHERE
                SUBSTR(path, 1, ?1) = ?2
            ORDER BY
                path
        ",
        (prefix_len_chars, dll_prefix),
        |row| {
            let dll_id: i64 = row.get(0)?;
            let dll = DllPart::try_from_row(1, row)?;
            let dll_oses_part = DllOsesPart {
                dll,
                oses: Vec::new(),
            };
            Ok((dll_id, dll_oses_part))
        },
    );
    let mut dlls = match dlls_opt {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(v) => v,
    };

    // enrich with operating system info
    const DLL_OS_QUERY: &str = "
        SELECT
            os.short_name,
            os.long_name,
            os.has_icon
        FROM
            operating_systems os
        WHERE
            EXISTS (
                SELECT 1
                FROM symbol_dll_os sdo
                WHERE sdo.os_id = os.os_id
                AND sdo.dll_id = ?1
            )
        ORDER BY
            os.release_date ASC NULLS LAST
    ";
    let Some(mut dll_os_query) = prepare(&db, DLL_OS_QUERY)
        else { return TemplateResponder::Failure };

    for (dll_id, dll_oses_part) in &mut dlls {
        let oses_opt = query_database(
            &mut dll_os_query,
            [*dll_id],
            |row| OperatingSystemPart::try_from_row(0, row),
        );
        let Some(oses) = oses_opt
            else { return TemplateResponder::Failure };
        dll_oses_part.oses = oses;
    }

    let dll_parts = dlls
        .into_iter()
        .map(|(_dll_id, dll_part)| dll_part)
        .collect();

    let template = AlphabeticalDllListTemplate {
        dll_parts,
    };
    TemplateResponder::Template(template)
}

#[rocket::get("/funcs/<sym_raw_prefix>")]
fn funcs_page(sym_raw_prefix: &str) -> TemplateResponder<AlphabeticalSymbolListTemplate> {
    let Some(db) = connect_to_database()
        else { return TemplateResponder::Failure };

    let prefix_len_chars = sym_raw_prefix.chars().count();

    // find the symbols with that raw-name prefix;
    // no meta-functions though
    let sym_info_rows_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                raw_name,
                friendly_name,
                is_meta_func
            FROM
                symbols
            WHERE
                raw_name IS NOT NULL
                AND (
                    SUBSTR(raw_name, 1, ?1) = ?2
                    OR SUBSTR(friendly_name, 1, ?1) = ?2
                )
                AND is_meta_func = 0
            ORDER BY
                raw_name
        ",
        (prefix_len_chars, sym_raw_prefix),
        |row| SymbolPart::try_named_from_row(0, row),
    );
    let symbols = match sym_info_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(v) => v,
    };

    let template = AlphabeticalSymbolListTemplate {
        path_to_root: "../",
        symbols,
    };
    TemplateResponder::Template(template)
}

#[rocket::get("/funcs/ordinal-only/<dll_path_prefix>")]
fn ordinal_only_funcs_page(dll_path_prefix: &str) -> TemplateResponder<AlphabeticalSymbolListTemplate> {
    let Some(db) = connect_to_database()
        else { return TemplateResponder::Failure };

    let dll_path_prefix_len = dll_path_prefix.chars().count();

    // find the ordinal-only symbols
    let sym_info_rows_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                dll_name,
                ordinal,
                friendly_name,
                is_meta_func
            FROM
                symbols
            WHERE
                dll_name IS NOT NULL
                AND SUBSTR(dll_name, 1, ?1) = ?2
                AND ordinal IS NOT NULL
            ORDER BY
                3 ASC NULLS LAST, 1, 2
        ",
        (dll_path_prefix_len, dll_path_prefix),
        |row| SymbolPart::try_ordinal_from_row(0, row),
    );
    let symbols = match sym_info_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(v) => v,
    };

    let template = AlphabeticalSymbolListTemplate {
        path_to_root: "../../",
        symbols,
    };
    TemplateResponder::Template(template)
}

#[rocket::get("/compare-os?<old>&<new>")]
fn compare_os_redirect(old: &str, new: &str) -> Redirect {
    // construct a permanent redirect to our preferred URL

    let old_percent: String = utf8_percent_encode(old, &URL_UNRESERVED).collect();
    let new_percent: String = utf8_percent_encode(new, &URL_UNRESERVED).collect();
    let new_url = format!("os/{}/compare/{}", old_percent, new_percent);

    Redirect::permanent(new_url)
}

#[rocket::get("/dll/<dll>/compare-os?<old>&<new>")]
fn compare_os_dll_redirect(old: &str, new: &str, dll: &str) -> Redirect {
    // construct a permanent redirect to our preferred URL

    let old_percent: String = utf8_percent_encode(old, &URL_UNRESERVED).collect();
    let new_percent: String = utf8_percent_encode(new, &URL_UNRESERVED).collect();
    let dll_percent: String = utf8_percent_encode(dll, &URL_UNRESERVED).collect();
    let new_url = format!("../../os/{}/compare/{}/dll/{}", old_percent, new_percent, dll_percent);

    Redirect::permanent(new_url)
}

#[rocket::get("/os/<old>/compare/<new>")]
fn compare_os(old: &str, new: &str) -> TemplateResponder<CompareOsTemplate> {
    let Some(db) = connect_to_database()
        else { return TemplateResponder::Failure };

    const FIND_OS_QUERY: &str = "
        SELECT
            os_id,
            short_name,
            COALESCE(long_name, short_name),
            has_icon
        FROM
            operating_systems
        WHERE
            short_name = ?1
    ";
    let Some(mut find_os_stmt) = prepare(&db, FIND_OS_QUERY)
        else { return TemplateResponder::Failure };

    let os_ify = |row: &Row<'_>| {
        let os_id: i64 = row.get(0)?;
        let os_part = OperatingSystemPart::try_from_row(1, row)?;
        Ok((os_id, os_part))
    };

    // find old OS
    let old_rows_res = query_database(
        &mut find_os_stmt,
        [old],
        os_ify,
    );
    let (old_os_id, old_os_part) = match old_rows_res {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(mut v) => v.swap_remove(0),
    };

    // find new OS
    let new_rows_res = query_database(
        &mut find_os_stmt,
        [new],
        os_ify,
    );
    let (new_os_id, new_os_part) = match new_rows_res {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(mut v) => v.swap_remove(0),
    };

    // prepare a DLL-difference query
    const DLL_DIFF_QUERY: &str = "
        SELECT
            dll.path
        FROM
            dlls dll
        WHERE
            EXISTS (
                SELECT 1
                FROM symbol_dll_os y_sdo
                WHERE y_sdo.os_id = ?1
                AND y_sdo.dll_id = dll.dll_id
            )
            AND NOT EXISTS (
                SELECT 1
                FROM symbol_dll_os n_sdo
                WHERE n_sdo.os_id = ?2
                AND n_sdo.dll_id = dll.dll_id
            )
        ORDER BY
            1
    ";
    let Some(mut dll_diff_stmt) = prepare(&db, DLL_DIFF_QUERY)
        else { return TemplateResponder::Failure };

    let dll_ify = |row: &Row<'_>| {
        let dll_path: String = row.get(0)?;
        Ok(dll_path)
    };

    // find DLLs which are in old but not in new
    let removed_dlls_opt = query_database(
        &mut dll_diff_stmt,
        [old_os_id, new_os_id],
        dll_ify,
    );
    let removed_dlls = match removed_dlls_opt {
        None => return TemplateResponder::Failure,
        Some(v) => v,
    };

    // find DLLs which are in new but not in old
    let added_dlls_opt = query_database(
        &mut dll_diff_stmt,
        [new_os_id, old_os_id],
        dll_ify,
    );
    let added_dlls = match added_dlls_opt {
        None => return TemplateResponder::Failure,
        Some(v) => v,
    };

    // prepare a symbol-difference query, for both named and ordinal symbols
    // but not for meta-functions
    const SYMBOL_DIFF_QUERY: &str = "
        SELECT
            sym.raw_name,
            sym.friendly_name,
            sym.dll_name,
            sym.ordinal,
            sym.is_meta_func
        FROM
            symbols sym
        WHERE
            sym.is_meta_func = 0
            AND EXISTS (
                SELECT 1
                FROM symbol_dll_os y_sdo
                WHERE y_sdo.os_id = ?1
                AND y_sdo.sym_id = sym.sym_id
            )
            AND NOT EXISTS (
                SELECT 1
                FROM symbol_dll_os n_sdo
                WHERE n_sdo.os_id = ?2
                AND n_sdo.sym_id = sym.sym_id
            )
        ORDER BY
            1 ASC NULLS LAST,
            2 ASC NULLS LAST,
            3,
            4
    ";
    let Some(mut symbol_diff_stmt) = prepare(&db, SYMBOL_DIFF_QUERY)
        else { return TemplateResponder::Failure };

    // find symbols which are in old but not in new
    let removed_symbol_rows_opt = query_database(
        &mut symbol_diff_stmt,
        [old_os_id, new_os_id],
        |row| SymbolPart::try_from_row(0, row),
    );
    let removed_symbols = match removed_symbol_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) => v,
    };

    // find symbols which are in new but not old
    let added_symbols_rows_opt = query_database(
        &mut symbol_diff_stmt,
        [new_os_id, old_os_id],
        |row| SymbolPart::try_from_row(0, row),
    );
    let added_symbols = match added_symbols_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) => v,
    };

    let template = CompareOsTemplate {
        old_os: old_os_part,
        new_os: new_os_part,
        added_dlls,
        removed_dlls,
        added_symbols,
        removed_symbols,
    };
    TemplateResponder::Template(template)
}

#[rocket::get("/os/<old_os>/compare/<new_os>/dll/<dll>")]
fn compare_os_dll(old_os: &str, new_os: &str, dll: &str) -> TemplateResponder<CompareOsDllTemplate> {
    let Some(db) = connect_to_database()
        else { return TemplateResponder::Failure };

    const FIND_OS_QUERY: &str = "
        SELECT
            os_id,
            short_name,
            COALESCE(long_name, short_name),
            has_icon
        FROM
            operating_systems
        WHERE
            short_name = ?1
    ";
    let Some(mut find_os_stmt) = prepare(&db, FIND_OS_QUERY)
        else { return TemplateResponder::Failure };

    let os_ify = |row: &Row<'_>| {
        let os_id: i64 = row.get(0)?;
        let os_part = OperatingSystemPart::try_from_row(1, row)?;
        Ok((os_id, os_part))
    };

    // find old OS
    let old_rows_res = query_database(
        &mut find_os_stmt,
        [old_os],
        os_ify,
    );
    let (old_os_id, old_os_part) = match old_rows_res {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(mut v) => v.swap_remove(0),
    };

    // find new OS
    let new_rows_res = query_database(
        &mut find_os_stmt,
        [new_os],
        os_ify,
    );
    let (new_os_id, new_os_part) = match new_rows_res {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(mut v) => v.swap_remove(0),
    };

    // find DLL
    const DLL_QUERY: &str = "
        SELECT
            dll.dll_id,
            dll.path
        FROM
            dlls dll
        WHERE
            dll.path = ?1
            AND EXISTS (
                SELECT 1
                FROM symbol_dll_os sdo_old
                WHERE sdo_old.os_id = ?2
                AND sdo_old.dll_id = dll.dll_id
            )
            AND EXISTS (
                SELECT 1
                FROM symbol_dll_os sdo_new
                WHERE sdo_new.os_id = ?3
                AND sdo_new.dll_id = dll.dll_id
            )
    ";
    let Some(mut dll_stmt) = prepare(&db, DLL_QUERY)
        else { return TemplateResponder::Failure };

    let dll_ify = |row: &Row<'_>| {
        let dll_id: i64 = row.get(0)?;
        let dll_path: String = row.get(1)?;
        Ok((dll_id, dll_path))
    };

    // find DLL
    let dll_res = query_database(
        &mut dll_stmt,
        (dll, old_os_id, new_os_id),
        dll_ify,
    );
    let (dll_id, dll_path) = match dll_res {
        None => return TemplateResponder::Failure,
        Some(v) if v.len() == 0 => return TemplateResponder::NotFound,
        Some(mut v) => v.swap_remove(0),
    };

    // prepare a symbol-difference query, for both named and ordinal symbols
    // but not meta-functions
    const SYMBOL_DIFF_QUERY: &str = "
        SELECT
            sym.raw_name,
            sym.friendly_name,
            sym.dll_name,
            sym.ordinal,
            sym.is_meta_func
        FROM
            symbols sym
        WHERE
            sym.is_meta_func = 0
            AND EXISTS (
                SELECT 1
                FROM symbol_dll_os y_sdo
                WHERE y_sdo.os_id = ?1
                AND y_sdo.dll_id = ?3
                AND y_sdo.sym_id = sym.sym_id
            )
            AND NOT EXISTS (
                SELECT 1
                FROM symbol_dll_os n_sdo
                WHERE n_sdo.os_id = ?2
                AND n_sdo.dll_id = ?3
                AND n_sdo.sym_id = sym.sym_id
            )
        ORDER BY
            1 ASC NULLS LAST,
            2 ASC NULLS LAST,
            3,
            4
    ";
    let Some(mut symbol_diff_stmt) = prepare(&db, SYMBOL_DIFF_QUERY)
        else { return TemplateResponder::Failure };

    // find symbols which are in old but not in new
    let removed_symbol_rows_opt = query_database(
        &mut symbol_diff_stmt,
        [old_os_id, new_os_id, dll_id],
        |row| SymbolPart::try_from_row(0, row),
    );
    let removed_symbols = match removed_symbol_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) => v,
    };

    // find symbols which are in new but not old
    let added_symbols_rows_opt = query_database(
        &mut symbol_diff_stmt,
        [new_os_id, old_os_id, dll_id],
        |row| SymbolPart::try_from_row(0, row),
    );
    let added_symbols = match added_symbols_rows_opt {
        None => return TemplateResponder::Failure,
        Some(v) => v,
    };

    let template = CompareOsDllTemplate {
        old_os: old_os_part,
        new_os: new_os_part,
        dll_path,
        added_symbols,
        removed_symbols,
    };
    TemplateResponder::Template(template)
}


#[rocket::get("/")]
fn root() -> TemplateResponder<RootTemplate> {
    let Some(db) = connect_to_database()
        else { return TemplateResponder::Failure };

    // obtain operating systems
    let operating_systems_opt = prepare_and_query_database(
        &db,
        "
            SELECT
                short_name,
                COALESCE(long_name, short_name),
                has_icon
            FROM operating_systems
            ORDER BY
                release_date ASC NULLS LAST,
                2
        ",
        [],
        |row| OperatingSystemPart::try_from_row(0, row),
    );
    let Some(operating_systems) = operating_systems_opt
        else { return TemplateResponder::Failure };

    // obtain first characters of DLL paths
    let dll_start_chars_opt = prepare_and_query_database(
        &db,
        "
            SELECT DISTINCT
                SUBSTR(path, 1, 1)
            FROM dlls
            ORDER BY
                1
        ",
        [],
        |row| {
            let letter: String = row.get(0)?;
            Ok(letter)
        },
    );
    let Some(dll_start_chars) = dll_start_chars_opt
        else { return TemplateResponder::Failure };

    // obtain first characters of function names
    // (raw names for named functions, friendly names for ordinal functions)
    // except "?", there's a lot of those due to C++ name mangling, take two characters in this case
    let func_start_chars_opt = prepare_and_query_database(
        &db,
        "
            WITH symbol_best_name(name) AS (
                SELECT
                    CASE
                        WHEN raw_name IS NOT NULL THEN raw_name
                        ELSE friendly_name
                    END name
                FROM
                    symbols
                WHERE
                    raw_name IS NOT NULL
                    OR friendly_name IS NOT NULL
            )
            SELECT DISTINCT
                CASE SUBSTR(name, 1, 1)
                    WHEN '?' THEN SUBSTR(name, 1, 2)
                    ELSE SUBSTR(name, 1, 1)
                END symbol_name
            FROM symbol_best_name
            ORDER BY
                1
        ",
        [],
        |row| {
            let letter: String = row.get(0)?;
            Ok(letter)
        },
    );
    let Some(func_start_chars) = func_start_chars_opt
        else { return TemplateResponder::Failure };

    // obtain first characters of DLLs with ordinal-only functions
    let ordinal_dll_start_chars_opt = prepare_and_query_database(
        &db,
        "
            SELECT DISTINCT
                SUBSTR(dll_name, 1, 1)
            FROM symbols
            WHERE
                dll_name IS NOT NULL
            ORDER BY
                1
        ",
        [],
        |row| {
            let letter: String = row.get(0)?;
            Ok(letter)
        },
    );
    let Some(ordinal_dll_start_chars) = ordinal_dll_start_chars_opt
        else { return TemplateResponder::Failure };

    let template = RootTemplate {
        operating_systems,
        dll_start_chars,
        func_start_chars,
        ordinal_dll_start_chars,
    };
    TemplateResponder::Template(template)
}


fn set_up_tracing() {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
}


#[rocket::launch]
fn rocket_launcher() -> _ {
    set_up_tracing();

    rocket::build().mount("/", rocket::routes![
        root,
        os_page,
        os_dll_page,
        all_os_symbols,
        symbol_page,
        dll_ordinal_symbol_page,
        funcs_page,
        ordinal_only_funcs_page,
        alpha_dll_page,
        dll_page,
        compare_os,
        compare_os_redirect,
        compare_os_dll,
        compare_os_dll_redirect,
    ])
}
