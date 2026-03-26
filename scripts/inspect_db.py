import sqlite3
import json
from pathlib import Path

DB = Path(__file__).parent.parent / "backend" / "vapt_tool.db"

if not DB.exists():
    print(json.dumps({"error": f"Database not found at {DB}"}))
    exit(1)

conn = sqlite3.connect(str(DB))
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# List tables
cur.execute(
    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
)
tables = [r[0] for r in cur.fetchall()]

output = {"db_path": str(DB), "tables": {}}
for t in tables:
    try:
        # columns
        cur.execute(f"PRAGMA table_info('{t}');")
        cols = [c["name"] for c in cur.fetchall()]
        # sample rows
        cur.execute(f"SELECT * FROM '{t}' LIMIT 10;")
        rows = [dict(r) for r in cur.fetchall()]
        output["tables"][t] = {"columns": cols, "sample_rows": rows, "count": None}
        # count rows
        cur.execute(f"SELECT COUNT(1) as c FROM '{t}';")
        output["tables"][t]["count"] = cur.fetchone()["c"]
    except Exception as e:
        output["tables"][t] = {"error": str(e)}

print(json.dumps(output, indent=2, default=str))
conn.close()
