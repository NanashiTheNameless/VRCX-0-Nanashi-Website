use super::*;
use rusqlite::types::Value;

fn tables(conn: &Connection) -> Vec<String> {
    conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name != 'schema_version' ORDER BY name").unwrap()
        .query_map([], |row| row.get(0)).unwrap().collect::<Result<_, _>>().unwrap()
}

fn columns(conn: &Connection, table: &str) -> Vec<String> {
    conn.prepare(&format!("PRAGMA table_info({table})"))
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn rows(conn: &Connection, table: &str) -> Vec<Vec<Value>> {
    let mut statement = conn
        .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
        .unwrap();
    let count = statement.column_count();
    statement
        .query_map([], |row| (0..count).map(|column| row.get(column)).collect())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn upgrade_copies(migrations: &[&str], fixture: &str) {
    let dir = tempfile::tempdir().unwrap();
    let mut source = open_encrypted(&dir.path().join("old.db"), &[7; 32]).unwrap();
    migrate(&mut source, &migrations[..1]).unwrap();
    source.execute_batch(fixture).unwrap();
    for (index, timestamp) in [
        None,
        Some(1784629815250_i64),
        Some(-1),
        Some(i64::MIN),
        Some(0),
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(timestamp) = timestamp {
            for table in tables(&source) {
                for column in columns(&source, &table) {
                    if column.ends_with("_ms") && column != "idle_timeout_ms" {
                        source
                            .execute(&format!("UPDATE {table} SET {column} = ?1"), [timestamp])
                            .unwrap();
                    }
                }
            }
        }
        let copy_path = dir.path().join(format!("copy-{index}.db"));
        backup_connection(&source, &copy_path, &[7; 32]).unwrap();
        let mut copy = open_encrypted(&copy_path, &[7; 32]).unwrap();
        migrate(&mut copy, migrations).unwrap();
        for table in tables(&source) {
            let old_columns = columns(&source, &table);
            let new_columns = columns(&copy, &table);
            let mut expected = rows(&source, &table);
            for (position, column) in old_columns.iter().enumerate() {
                let date = column.ends_with("_ms") && column != "idle_timeout_ms";
                assert_eq!(
                    new_columns[position],
                    if date {
                        column.trim_end_matches("_ms")
                    } else {
                        column
                    }
                );
                if date {
                    for row in &mut expected {
                        if let Value::Integer(value) = &mut row[position] {
                            *value = value.div_euclid(1000);
                        }
                    }
                }
            }
            assert_eq!(rows(&copy, &table), expected, "{table}");
            migrate(&mut copy, migrations).unwrap();
            assert_eq!(rows(&copy, &table), expected, "repeat {table}");
        }
        assert_eq!(
            copy.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        assert!(
            copy.prepare("PRAGMA foreign_key_check")
                .unwrap()
                .query([])
                .unwrap()
                .next()
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            open_encrypted(&copy_path, &[8; 32]),
            Err(DbError::WrongKey)
        ));
        assert_eq!(
            source
                .query_row("SELECT v FROM schema_version", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}

#[test]
fn account_upgrade_preserves_all_rows_and_opaque_bodies_in_encrypted_copy() {
    upgrade_copies(
        account::MIGRATIONS,
        r#"
INSERT INTO vaults VALUES ('vault', x'01', x'02', -1, 1, x'00ff0180', 1);
INSERT INTO chunks VALUES ('vault', 1, x'03', x'04', x'05', 100);
INSERT INTO envelopes VALUES ('envelope', '{"v":1,"createdAtMs":-1}', 30, -1);
INSERT INTO collections VALUES ('collection', '{"updated_at":1784629815}', 25, 1784629815250);
"#,
    );
}

#[test]
fn registry_upgrade_preserves_all_columns_durations_nulls_and_foreign_keys() {
    upgrade_copies(
        registry::MIGRATIONS,
        r#"
INSERT INTO settings VALUES ('retention', 'unchanged');
INSERT INTO accounts (account_id, email, state, created_at_ms) VALUES ('old', 'old@example.test', 'active', 1784629815250);
INSERT INTO recovery_codes VALUES ('old', x'01', NULL);
INSERT INTO tokens (token_id, account_id, kind, client_kind, secret_hmac, scopes, label, created_at_ms, idle_timeout_ms) VALUES ('token', 'old', 'session', 'desktop', x'01', '', '', -1, 43200000);
INSERT INTO client_ips VALUES ('token', 'old', '127.0.0.1', NULL, NULL, NULL, -1, 1784629815250);
INSERT INTO device_pairings VALUES (x'02', 'CODE', 'PC', 'sync', NULL, 'old', 'pending', 1784629815250, -1, 5);
INSERT INTO transfers VALUES ('transfer', 'old', x'03', x'04', -1);
INSERT INTO auth_tokens VALUES (x'05', 'old', 'login', -1, 2, 'opaque');
INSERT INTO email_codes VALUES ('old', 'login', x'06', -1, 1);
INSERT INTO collection_index VALUES ('collection', 'old', 1, 'title', NULL, -1);
INSERT INTO blob_deletions VALUES ('key', 'object', 2, -1);
INSERT INTO audit_log VALUES (1, 'actor', 'action', 'old', -1);
"#,
    );
}
