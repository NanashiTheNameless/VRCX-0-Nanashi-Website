pub mod account;
pub mod registry;

#[cfg(test)]
mod epoch_tests;

use std::path::Path;
use std::time::Duration;

use data_encoding::HEXLOWER;
use rusqlite::Connection;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database key does not open this file")]
    WrongKey,
    #[error("database schema {found} is newer than this server supports ({supported})")]
    TooNew { found: i64, supported: i64 },
    #[error("{0}")]
    Invalid(&'static str),
}

pub type DbResult<T> = Result<T, DbError>;

pub fn open_encrypted(path: &Path, key: &[u8; 32]) -> DbResult<Connection> {
    let conn = Connection::open(path)?;
    let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", HEXLOWER.encode(key)));
    conn.execute_batch(&pragma)?;
    if conn
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .is_err()
    {
        return Err(DbError::WrongKey);
    }
    conn.execute_batch(
        "PRAGMA secure_delete = ON;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    if page_count == 0 {
        conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")?;
    }
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    Ok(conn)
}

pub fn backup_connection(source: &Connection, destination: &Path, key: &[u8; 32]) -> DbResult<()> {
    if destination.exists() {
        return Err(DbError::Invalid("backup destination already exists"));
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| DbError::Invalid("cannot create backup directory"))?;
    }
    let mut target = open_encrypted(destination, key)?;
    let result = (|| {
        {
            let backup = rusqlite::backup::Backup::new(source, &mut target)?;
            backup.run_to_completion(16, Duration::from_millis(50), None)?;
        }
        target.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok::<_, DbError>(())
    })();
    drop(target);
    if result.is_err() {
        let _ = remove_files(destination);
    }
    result
}

pub fn migrate(conn: &mut Connection, migrations: &[&str]) -> DbResult<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL)")?;
    let current: i64 = conn
        .query_row("SELECT v FROM schema_version", [], |row| row.get(0))
        .unwrap_or(0);
    let supported = migrations.len() as i64;
    if current > supported {
        return Err(DbError::TooNew {
            found: current,
            supported,
        });
    }
    for (index, sql) in migrations.iter().enumerate().skip(current as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute("DELETE FROM schema_version", [])?;
        tx.execute(
            "INSERT INTO schema_version (v) VALUES (?1)",
            [index as i64 + 1],
        )?;
        tx.commit()?;
    }
    Ok(())
}

pub fn remove_files(path: &Path) -> std::io::Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        match std::fs::remove_file(&name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_file_needs_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        {
            let conn = open_encrypted(&path, &[7; 32]).unwrap();
            conn.execute_batch("CREATE TABLE t (x TEXT); INSERT INTO t VALUES ('plain marker');")
                .unwrap();
        }
        assert!(matches!(
            open_encrypted(&path, &[8; 32]),
            Err(DbError::WrongKey)
        ));
        let conn = open_encrypted(&path, &[7; 32]).unwrap();
        let x: String = conn.query_row("SELECT x FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(x, "plain marker");
        drop(conn);
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(12).any(|w| w == b"plain marker"));
        assert!(!raw.starts_with(b"SQLite format 3"));
    }

    #[test]
    fn online_backup_preserves_sqlcipher_encryption_and_contents() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("source.db");
        let backup_path = dir.path().join("backup.db");
        let source = open_encrypted(&source_path, &[4; 32]).unwrap();
        source
            .execute_batch(
                "CREATE TABLE value (v TEXT); INSERT INTO value VALUES ('backup marker');",
            )
            .unwrap();
        backup_connection(&source, &backup_path, &[4; 32]).unwrap();
        let backup = open_encrypted(&backup_path, &[4; 32]).unwrap();
        let marker: String = backup
            .query_row("SELECT v FROM value", [], |row| row.get(0))
            .unwrap();
        assert_eq!(marker, "backup marker");
        assert!(matches!(
            open_encrypted(&backup_path, &[5; 32]),
            Err(DbError::WrongKey)
        ));
        let raw = std::fs::read(&backup_path).unwrap();
        assert!(!raw.starts_with(b"SQLite format 3"));
    }

    #[test]
    fn migrations_run_once_and_refuse_newer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.db");
        let mut conn = open_encrypted(&path, &[1; 32]).unwrap();
        migrate(&mut conn, &["CREATE TABLE a (x)", "CREATE TABLE b (x)"]).unwrap();
        migrate(&mut conn, &["CREATE TABLE a (x)", "CREATE TABLE b (x)"]).unwrap();
        assert!(matches!(
            migrate(&mut conn, &["CREATE TABLE a (x)"]),
            Err(DbError::TooNew { .. })
        ));
    }

    #[test]
    fn remove_files_deletes_wal_and_shm() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.db");
        let conn = open_encrypted(&path, &[1; 32]).unwrap();
        conn.execute_batch("CREATE TABLE t (x)").unwrap();
        drop(conn);
        remove_files(&path).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
