use std::path::PathBuf;

use clap::Parser;
use rusqlite::Connection;


#[derive(Parser)]
struct Opts {
    /// The path to the SQLite database in which to store the API information.
    pub database_path: PathBuf,

    /// The list of API calls.
    pub list_path: PathBuf,
}


fn main() {
    let opts = Opts::parse();

    // open the SQLite database
    let db = Connection::open(&opts.database_path)
        .expect("failed to open SQLite database");

    // check schema
    if !db.table_exists(None, "symbols") {
        
    }
}
