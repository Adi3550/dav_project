"""
seed_sample_data.py
Run this file to insert 15 sample student registrations into your udaanx.db
so you can test the analytics dashboard.

How to run:
    python seed_sample_data.py

Make sure you run this from the same folder as app.py
"""

import sqlite3
import uuid
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

# ── Find the database ─────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "udaanx.db")

if not os.path.exists(DB_PATH):
    print("❌ udaanx.db not found!")
    print("   Please run  python app.py  first to create the database,")
    print("   then run this script.")
    exit(1)

print(f"✅ Found database at: {DB_PATH}")

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
conn.execute("PRAGMA foreign_keys=ON")

# ── Helper ────────────────────────────────────────────────────
def reg_code():
    return "UDX-" + str(uuid.uuid4())[:8].upper()

def days_ago(n):
    return (datetime.utcnow() - timedelta(days=n)).isoformat()

# ── 15 Sample Students ────────────────────────────────────────
students = [
    # (student_id, full_name,            email,                    dept,    year, phone)
    ("UDX2025001", "Aditya Kumar",        "aditya@udaanx.edu",     "CSE",   "2",  "9876543210"),
    ("UDX2025002", "Priya Sharma",        "priya@udaanx.edu",      "ECE",   "3",  "9845123456"),
    ("UDX2025003", "Rohit Verma",         "rohit@udaanx.edu",      "MECH",  "1",  "9911223344"),
    ("UDX2025004", "Sneha Patel",         "sneha@udaanx.edu",      "CSE",   "4",  "9822334455"),
    ("UDX2025005", "Arjun Nair",          "arjun@udaanx.edu",      "MBA",   "PG", "9700112233"),
    ("UDX2025006", "Divya Reddy",         "divya@udaanx.edu",      "CSE",   "2",  "9988776655"),
    ("UDX2025007", "Karan Singh",         "karan@udaanx.edu",      "ECE",   "1",  "9865412378"),
    ("UDX2025008", "Ananya Menon",        "ananya@udaanx.edu",     "DESIGN","3",  "9754321098"),
    ("UDX2025009", "Vikram Yadav",        "vikram@udaanx.edu",     "CIVIL", "2",  "9641234567"),
    ("UDX2025010", "Pooja Joshi",         "pooja@udaanx.edu",      "MBA",   "PG", "9532109876"),
    ("UDX2025011", "Rahul Gupta",         "rahul@udaanx.edu",      "CSE",   "3",  "9423456789"),
    ("UDX2025012", "Meera Iyer",          "meera@udaanx.edu",      "ECE",   "4",  "9312345678"),
    ("UDX2025013", "Suresh Pillai",       "suresh@udaanx.edu",     "MECH",  "2",  "9201234567"),
    ("UDX2025014", "Lakshmi Nair",        "lakshmi@udaanx.edu",    "BCA",   "1",  "9190123456"),
    ("UDX2025015", "Amit Tiwari",         "amit@udaanx.edu",       "CSE",   "4",  "9089012345"),
]

# ── 15 Registrations — spread across events and dates ─────────
# Events seeded by app.py:
# 1 = Tech Fest 2025
# 2 = Cultural Night
# 3 = AI & ML Workshop
# 4 = Entrepreneurship Summit
# 5 = Sports Day 2025
# 6 = Design Sprint

registrations = [
    # (student_index, event_id, days_ago, on_waitlist)
    # Spread across different events and different days
    (0,  1, 12, 0),   # Aditya     → Tech Fest          12 days ago
    (1,  2, 11, 0),   # Priya      → Cultural Night      11 days ago
    (2,  5,  9, 0),   # Rohit      → Sports Day           9 days ago
    (3,  1,  8, 0),   # Sneha      → Tech Fest            8 days ago
    (4,  4,  7, 0),   # Arjun      → Entrepreneurship     7 days ago
    (5,  3,  6, 0),   # Divya      → AI & ML Workshop     6 days ago
    (6,  5,  5, 0),   # Karan      → Sports Day           5 days ago
    (7,  6,  4, 0),   # Ananya     → Design Sprint        4 days ago
    (8,  2,  4, 0),   # Vikram     → Cultural Night       4 days ago
    (9,  4,  3, 0),   # Pooja      → Entrepreneurship     3 days ago
    (10, 1,  3, 0),   # Rahul      → Tech Fest            3 days ago
    (11, 3,  2, 0),   # Meera      → AI & ML Workshop     2 days ago
    (12, 5,  2, 0),   # Suresh     → Sports Day           2 days ago
    (13, 2,  1, 0),   # Lakshmi    → Cultural Night       1 day ago
    (14, 1,  1, 0),   # Amit       → Tech Fest            1 day ago
]

# ── Insert Students ───────────────────────────────────────────
print("\n📥 Inserting students...")
student_db_ids = {}

for i, (sid, name, email, dept, year, phone) in enumerate(students):
    # Check if already exists
    existing = conn.execute(
        "SELECT id FROM students WHERE student_id=?", (sid,)
    ).fetchone()

    if existing:
        student_db_ids[i] = existing["id"]
        print(f"   ⚠️  {name} ({sid}) already exists — skipping")
    else:
        cursor = conn.execute(
            "INSERT INTO students(student_id, full_name, email, department, "
            "year_of_study, phone) VALUES(?,?,?,?,?,?)",
            (sid, name, email, dept, year, phone)
        )
        student_db_ids[i] = cursor.lastrowid
        print(f"   ✅ Inserted: {name} ({sid}) — {dept} Year {year}")

conn.commit()

# ── Insert Registrations ──────────────────────────────────────
print("\n📋 Inserting registrations...")

event_names = {
    1: "Tech Fest 2025",
    2: "Cultural Night",
    3: "AI & ML Workshop",
    4: "Entrepreneurship Summit",
    5: "Sports Day 2025",
    6: "Design Sprint",
}

inserted = 0
skipped  = 0

for stu_idx, event_id, d_ago, waitlist in registrations:
    stu_db_id  = student_db_ids[stu_idx]
    stu_name   = students[stu_idx][1]
    event_name = event_names[event_id]

    # Check if already registered for this event
    existing = conn.execute(
        "SELECT id FROM registrations WHERE student_id=? AND event_id=?",
        (stu_db_id, event_id)
    ).fetchone()

    if existing:
        print(f"   ⚠️  {stu_name} → {event_name} already exists — skipping")
        skipped += 1
        continue

    code = reg_code()
    timestamp = days_ago(d_ago)

    conn.execute(
        "INSERT INTO registrations(reg_code, student_id, event_id, "
        "registered_at, on_waitlist) VALUES(?,?,?,?,?)",
        (code, stu_db_id, event_id, timestamp, waitlist)
    )
    print(f"   ✅ {stu_name:20s} → {event_name:25s} | Code: {code} | {d_ago} day(s) ago")
    inserted += 1

conn.commit()

# ── Summary ───────────────────────────────────────────────────
print("\n" + "="*60)
print("  SEED COMPLETE!")
print("="*60)
print(f"  Students inserted  : {len(students) - skipped}")
print(f"  Registrations added: {inserted}")
print(f"  Skipped (duplicate): {skipped}")
print()

# Show current DB state
total_students = conn.execute("SELECT COUNT(*) FROM students").fetchone()[0]
total_events   = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
total_regs     = conn.execute("SELECT COUNT(*) FROM registrations").fetchone()[0]

print(f"  DB now has:")
print(f"    👤 Students     : {total_students}")
print(f"    📅 Events       : {total_events}")
print(f"    📋 Registrations: {total_regs}")
print()
print("  Now open your browser:")
print("  1. Go to  http://127.0.0.1:5000")
print("  2. Click  Admin Login")
print("  3. Login with  admin / Admin@12345")
print("  4. Click  Analytics  tab")
print("  5. You should now see all charts filled with data!")
print("="*60)

conn.close()
