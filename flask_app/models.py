import sqlite3
import os
import json

DB_PATH = os.environ.get('DB_PATH', '/app/db/memsuite.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS cases (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            analyst     TEXT,
            description TEXT,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            status      TEXT DEFAULT 'OPEN'
        );

        CREATE TABLE IF NOT EXISTS dumps (
            id          TEXT PRIMARY KEY,
            case_id     TEXT REFERENCES cases(id),
            filename    TEXT NOT NULL,
            filepath    TEXT NOT NULL,
            sha256      TEXT NOT NULL,
            file_size   INTEGER,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            vol_version TEXT,
            status      TEXT DEFAULT 'QUEUED'
        );

        CREATE TABLE IF NOT EXISTS results (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            dump_id      TEXT REFERENCES dumps(id),
            plugin       TEXT NOT NULL,
            output_path  TEXT,
            executed_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            success      INTEGER DEFAULT 1,
            error_msg    TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            dump_id      TEXT REFERENCES dumps(id),
            finding_type TEXT NOT NULL,
            detail       TEXT,
            severity     TEXT,
            score        INTEGER,
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    conn.commit()

    # FIX #1 — migrate existing DBs that were created before error_msg column existed.
    # SQLite doesn't support IF NOT EXISTS on ALTER TABLE, so we probe first.
    cursor = conn.execute("PRAGMA table_info(results)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'error_msg' not in columns:
        conn.execute("ALTER TABLE results ADD COLUMN error_msg TEXT")
        conn.commit()

    conn.close()


def create_case(case_id, name, analyst, description):
    conn = get_db()
    conn.execute('INSERT INTO cases (id, name, analyst, description) VALUES (?,?,?,?)',
                 (case_id, name, analyst, description))
    conn.commit()
    conn.close()


def get_all_cases():
    conn = get_db()
    rows = conn.execute(
        'SELECT c.*, COUNT(d.id) as dump_count '
        'FROM cases c LEFT JOIN dumps d ON d.case_id=c.id '
        'GROUP BY c.id ORDER BY c.created_at DESC'
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_dump(dump_id, case_id, filename, filepath, sha256):
    conn = get_db()
    size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
    conn.execute(
        'INSERT INTO dumps (id, case_id, filename, filepath, sha256, file_size) VALUES (?,?,?,?,?,?)',
        (dump_id, case_id, filename, filepath, sha256, size)
    )
    conn.commit()
    conn.close()


def update_dump_status(dump_id, status, vol_version=None):
    conn = get_db()
    if vol_version:
        conn.execute('UPDATE dumps SET status=?, vol_version=? WHERE id=?',
                     (status, vol_version, dump_id))
    else:
        conn.execute('UPDATE dumps SET status=? WHERE id=?', (status, dump_id))
    conn.commit()
    conn.close()


def update_case_status(case_id, status):
    conn = get_db()
    conn.execute('UPDATE cases SET status=? WHERE id=?', (status, case_id))
    conn.commit()
    conn.close()


def get_case(case_id):
    conn = get_db()
    case = conn.execute('SELECT * FROM cases WHERE id=?', (case_id,)).fetchone()
    if not case:
        conn.close()
        return None
    dumps = conn.execute(
        'SELECT * FROM dumps WHERE case_id=? ORDER BY uploaded_at DESC', (case_id,)
    ).fetchall()
    conn.close()
    return {'case': dict(case), 'dumps': [dict(d) for d in dumps]}


def get_dump(dump_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM dumps WHERE id=?', (dump_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_findings(dump_id):
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM findings WHERE dump_id=? ORDER BY score DESC', (dump_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_findings(dump_id, findings_list, severity):
    conn = get_db()
    for f in findings_list:
        detail = f.get('detail', '')
        detail_str = json.dumps(detail) if isinstance(detail, dict) else str(detail)
        conn.execute(
            'INSERT INTO findings (dump_id, finding_type, detail, severity, score) VALUES (?,?,?,?,?)',
            (dump_id, f.get('type', 'unknown'), detail_str, severity, f.get('score', 0))
        )
    conn.commit()
    conn.close()


def log_result(dump_id, plugin, output_path, success=1, error_msg=None):
    conn = get_db()
    conn.execute(
        'INSERT INTO results (dump_id, plugin, output_path, success, error_msg) VALUES (?,?,?,?,?)',
        (dump_id, plugin, output_path, success, error_msg)
    )
    conn.commit()
    conn.close()


def get_results(dump_id):
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM results WHERE dump_id=? ORDER BY executed_at', (dump_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_dump_with_case(dump_id):
    conn = get_db()
    row = conn.execute('''
        SELECT d.*, c.name as case_name, c.analyst, c.description as case_description
        FROM dumps d LEFT JOIN cases c ON c.id = d.case_id
        WHERE d.id=?
    ''', (dump_id,)).fetchone()
    conn.close()
    return dict(row) if row else None
