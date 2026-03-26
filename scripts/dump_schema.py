import sqlite3
from pathlib import Path

DB = Path(__file__).parent.parent / "backend" / "vapt_tool.db"
if not DB.exists():
    print("Database not found:", DB)
    raise SystemExit(1)
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute(
    "SELECT sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
)
rows = cur.fetchall()
schema_text = "\n\n".join(r[0] for r in rows if r[0])
out = Path(__file__).parent / "schema.sql"
out.write_text(schema_text)
print(schema_text)
conn.close()
