"""
UdaanX University — College Event Portal  (FIXED v3)
Uses ONLY libraries confirmed available on your system:
  flask, sqlite3, werkzeug, pandas, matplotlib, PIL, stdlib

Run:  python app.py
Open: http://127.0.0.1:5000
"""

import os, io, uuid, hashlib, secrets, logging, re, time, base64, sqlite3
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from PIL import Image, ImageDraw

from flask import (Flask, jsonify, request, session,
                   send_from_directory, make_response, g)
from werkzeug.security import generate_password_hash, check_password_hash

# ── App ───────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.update(
    SECRET_KEY              = os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = "Lax",
    SESSION_COOKIE_SECURE   = False,
    PERMANENT_SESSION_LIFETIME = timedelta(hours=4),
    MAX_CONTENT_LENGTH      = 4 * 1024 * 1024,
)

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "udaanx.db")

# ── DB helpers ────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()

def query(sql, params=(), one=False, commit=False):
    db  = get_db()
    cur = db.execute(sql, params)
    if commit:
        db.commit()
        return cur.lastrowid
    return cur.fetchone() if one else cur.fetchall()

# ── Rate limiter (stdlib) ─────────────────────────────────────────────────────
_buckets: dict = defaultdict(list)

def rate_limit(max_calls: int, window: int = 60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip  = request.remote_addr or "unknown"
            key = f"{f.__name__}:{ip}"
            now = time.time()
            _buckets[key] = [t for t in _buckets[key] if now - t < window]
            if len(_buckets[key]) >= max_calls:
                return jsonify({"error": "Too many requests. Wait a moment."}), 429
            _buckets[key].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ── Sanitiser (replaces bleach) ───────────────────────────────────────────────
_TAGS = re.compile(r"<[^>]+>")

def clean(val) -> str:
    if val is None:
        return ""
    val = _TAGS.sub("", str(val).strip())
    return val[:500]

# ── Auth guard ────────────────────────────────────────────────────────────────
def require_admin(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return jsonify({"error": "Unauthorised"}), 401
        return f(*args, **kwargs)
    return wrapped

# ── Security headers ──────────────────────────────────────────────────────────
@app.after_request
def sec_headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"]        = "SAMEORIGIN"
    r.headers["X-XSS-Protection"]       = "1; mode=block"
    return r

# ── Audit log ─────────────────────────────────────────────────────────────────
def audit(action, details=""):
    ip = hashlib.md5((request.remote_addr or "").encode()).hexdigest()[:16]
    try:
        query("INSERT INTO audit_log(action,ip_hash,details) VALUES(?,?,?)",
              (action, ip, details), commit=True)
    except Exception:
        pass

# ── QR code via PIL ───────────────────────────────────────────────────────────
def make_qr(reg_code: str) -> str:
    SIZE, CELL, GRID, MARGIN = 200, 12, 13, 7
    NAVY, WHITE = (27, 42, 74), (255, 255, 255)
    img  = Image.new("RGB", (SIZE, SIZE), WHITE)
    draw = ImageDraw.Draw(img)
    draw.rectangle([3, 3, SIZE-4, SIZE-4], outline=NAVY, width=3)
    h = hashlib.sha256(reg_code.encode()).hexdigest()
    for row in range(GRID):
        for col in range(GRID):
            if int(h[(row * GRID + col) % len(h)], 16) % 2 == 0:
                x1 = MARGIN + col * CELL
                y1 = MARGIN + row * CELL
                draw.rectangle([x1, y1, x1+CELL-2, y1+CELL-2], fill=NAVY)
    for cx, cy in [(MARGIN, MARGIN),
                   (MARGIN+(GRID-7)*CELL, MARGIN),
                   (MARGIN, MARGIN+(GRID-7)*CELL)]:
        draw.rectangle([cx, cy, cx+7*CELL, cy+7*CELL],
                       outline=NAVY, width=3, fill=WHITE)
        draw.rectangle([cx+CELL, cy+CELL, cx+6*CELL, cy+6*CELL], fill=NAVY)
        draw.rectangle([cx+2*CELL, cy+2*CELL, cx+5*CELL, cy+5*CELL], fill=WHITE)
        draw.rectangle([cx+3*CELL, cy+3*CELL, cx+4*CELL, cy+4*CELL], fill=NAVY)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    return "data:image/png;base64," + base64.b64encode(buf.read()).decode()

# ── Event stats helper ────────────────────────────────────────────────────────
def event_stats(event_id: int) -> dict:
    confirmed = query(
        "SELECT COUNT(*) FROM registrations WHERE event_id=? AND on_waitlist=0",
        (event_id,), one=True)[0]
    waitlist  = query(
        "SELECT COUNT(*) FROM registrations WHERE event_id=? AND on_waitlist=1",
        (event_id,), one=True)[0]
    cap_row   = query("SELECT capacity FROM events WHERE id=?", (event_id,), one=True)
    capacity  = cap_row["capacity"] if cap_row else 100
    seats_left= max(0, capacity - confirmed)
    util      = round(min(100, confirmed / capacity * 100), 1) if capacity else 0
    status    = "full" if util >= 100 else "almost" if util >= 85 else "open"
    return dict(confirmed=confirmed, waitlist=waitlist,
                seats_left=seats_left, utilisation=util, status=status)

def row_to_event(row) -> dict:
    stats = event_stats(row["id"])
    return {
        "id": row["id"], "name": row["name"],
        "description": row["description"], "venue": row["venue"],
        "date": row["event_date"] or "TBD",
        "capacity": row["capacity"], "category": row["category"],
        **stats,
    }

# ── Chart helpers (matplotlib 3D enhanced → base64) ──────────────────────────
from mpl_toolkits.mplot3d import Axes3D

COLORS  = ["#2557D6","#D4913C","#059669","#7C3AED",
           "#DB2777","#0891B2","#D97706","#1B2A4A","#DC2626","#0D7A4E"]
COLORS2 = ["#3B6FEB","#EBA94E","#10B981","#8B5CF6",
           "#F472B6","#22D3EE","#FBBF24","#374151","#F87171","#34D399"]
NAVY_H  = "#1B2A4A"
BG      = "#F8FAFF"

def _to_b64(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight",
                facecolor=fig.get_facecolor(), dpi=130)
    buf.seek(0)
    data = base64.b64encode(buf.read()).decode()
    plt.close(fig)
    return "data:image/png;base64," + data

def _style_ax(ax):
    ax.set_facecolor(BG)
    ax.spines[["top","right"]].set_visible(False)
    ax.spines[["left","bottom"]].set_color("#D1D5DB")
    ax.tick_params(colors="#555", labelsize=8.5)
    ax.grid(axis="x", linestyle="--", alpha=0.4, color="#CBD5E1")

# ── 1. 3D Bar Chart (registrations per event) ─────────────────────────────────
def chart_3d_bar(labels, values, title):
    if not labels:
        return ""
    fig = plt.figure(figsize=(9, 5))
    fig.patch.set_facecolor("white")
    ax  = fig.add_subplot(111, projection="3d")
    n   = len(labels)
    xpos= np.arange(n)
    ypos= np.zeros(n)
    zpos= np.zeros(n)
    dx  = np.ones(n) * 0.6
    dy  = np.ones(n) * 0.4
    dz  = np.array(values, dtype=float)
    colors_hex = [COLORS[i % len(COLORS)] for i in range(n)]
    ax.bar3d(xpos, ypos, zpos, dx, dy, dz, color=colors_hex,
             alpha=0.88, shade=True, edgecolor="white", linewidth=0.5)
    ax.set_xticks(xpos + 0.3)
    short = [l[:12]+"…" if len(l)>12 else l for l in labels]
    ax.set_xticklabels(short, fontsize=7.5, rotation=20, ha="right", color="#333")
    ax.set_yticklabels([])
    ax.set_zlabel("Registrations", fontsize=8, color="#555")
    ax.set_title(title, fontsize=12, fontweight="bold", color=NAVY_H, pad=14)
    ax.set_facecolor("#EEF2FF")
    ax.xaxis.pane.fill = False
    ax.yaxis.pane.fill = False
    ax.zaxis.pane.fill = False
    ax.view_init(elev=22, azim=-55)
    for x, z, lbl in zip(xpos, dz, values):
        ax.text(x+0.3, 0.2, z+0.2, str(int(lbl)),
                ha="center", fontsize=8, fontweight="bold", color=NAVY_H)
    plt.tight_layout()
    return _to_b64(fig)

# ── 2. 3D Pie (department distribution) ──────────────────────────────────────
def chart_3d_pie(labels, values, title):
    if not labels:
        return ""
    fig, ax = plt.subplots(figsize=(7, 5), subplot_kw=dict(aspect="equal"))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    explode = [0.05] * len(labels)
    wedges, texts, autotexts = ax.pie(
        values, labels=None, autopct="%1.1f%%",
        colors=COLORS[:len(labels)], startangle=140,
        explode=explode, shadow=True,
        wedgeprops={"edgecolor":"white","linewidth":2.5},
        pctdistance=0.78, textprops={"fontsize":8})
    for at in autotexts:
        at.set_color("white"); at.set_fontweight("bold"); at.set_fontsize(8.5)
    # donut hole with gradient feel
    centre = plt.Circle((0,0), 0.50, fc="white",
                         linewidth=2, edgecolor="#E2E8F3")
    ax.add_patch(centre)
    ax.text(0, 0, f"{sum(values)}\nTotal", ha="center", va="center",
            fontsize=11, fontweight="bold", color=NAVY_H)
    ax.legend(wedges, [f"{l}  ({v})" for l,v in zip(labels,values)],
              loc="lower center", bbox_to_anchor=(0.5,-0.13),
              ncol=3, fontsize=8, frameon=False)
    ax.set_title(title, fontsize=12, fontweight="bold", color=NAVY_H, pad=10)
    plt.tight_layout()
    return _to_b64(fig)

# ── 3. Area + line trend chart ────────────────────────────────────────────────
def chart_area(dates, counts, title):
    if not dates:
        return ""
    fig, ax = plt.subplots(figsize=(9, 3.5))
    fig.patch.set_facecolor("white")
    x = np.arange(len(dates))
    ax.fill_between(x, counts, alpha=0.15, color="#2557D6")
    ax.fill_between(x, counts, alpha=0.08, color="#7C3AED")
    ax.plot(x, counts, color="#2557D6", linewidth=2.8,
            marker="o", markersize=6, markerfacecolor="white",
            markeredgewidth=2.2, markeredgecolor="#2557D6", zorder=5)
    # value labels on points
    for xi, yi in zip(x, counts):
        ax.annotate(str(yi), (xi, yi), textcoords="offset points",
                    xytext=(0,7), ha="center", fontsize=8,
                    fontweight="bold", color=NAVY_H)
    ax.set_xticks(x)
    ax.set_xticklabels(dates, rotation=30, ha="right", fontsize=8, color="#555")
    ax.set_title(title, fontsize=12, fontweight="bold", color=NAVY_H, pad=10)
    ax.set_ylabel("Registrations", fontsize=9, color="#555")
    _style_ax(ax)
    ax.grid(axis="y", linestyle="--", alpha=0.35, color="#CBD5E1")
    plt.tight_layout()
    return _to_b64(fig)

# ── 4. 3D Heatmap (dept × event) ─────────────────────────────────────────────
def chart_heatmap(depts, events, matrix):
    if not depts or not events:
        return ""
    arr = np.array(matrix, dtype=float)
    fig, ax = plt.subplots(figsize=(max(7, len(events)*1.4),
                                    max(3.5, len(depts)*0.85)))
    fig.patch.set_facecolor("white")
    im = ax.imshow(arr, cmap="YlOrRd", aspect="auto", vmin=0)
    ax.set_xticks(range(len(events)))
    ax.set_xticklabels([e[:14]+"…" if len(e)>14 else e for e in events],
                       rotation=35, ha="right", fontsize=8.5)
    ax.set_yticks(range(len(depts)))
    ax.set_yticklabels(depts, fontsize=9)
    mx = arr.max() or 1
    for i in range(len(depts)):
        for j in range(len(events)):
            v = int(arr[i,j])
            ax.text(j, i, str(v) if v else "–", ha="center", va="center",
                    fontsize=9, fontweight="bold" if v else "normal",
                    color="white" if v > mx*0.55 else "#1F2937")
    ax.set_title("🔥 Department × Event Heatmap", fontsize=12,
                 fontweight="bold", color=NAVY_H, pad=10)
    cbar = fig.colorbar(im, ax=ax, shrink=0.8, pad=0.02)
    cbar.ax.tick_params(labelsize=8)
    plt.tight_layout()
    return _to_b64(fig)

# ── 5. 3D Year-of-Study bar ───────────────────────────────────────────────────
def chart_3d_year(labels, values, title):
    if not labels:
        return ""
    fig = plt.figure(figsize=(8, 4.5))
    fig.patch.set_facecolor("white")
    ax  = fig.add_subplot(111, projection="3d")
    n   = len(labels)
    xp  = np.arange(n)
    ax.bar3d(xp, np.zeros(n), np.zeros(n),
             0.55, 0.35, np.array(values, dtype=float),
             color=[COLORS2[i%len(COLORS2)] for i in range(n)],
             alpha=0.9, shade=True, edgecolor="white", linewidth=0.4)
    ax.set_xticks(xp+0.27)
    ax.set_xticklabels([f"Year {l}" for l in labels],
                       fontsize=8, rotation=15, ha="right", color="#333")
    ax.set_yticklabels([])
    ax.set_zlabel("Students", fontsize=8, color="#555")
    ax.set_title(title, fontsize=12, fontweight="bold", color=NAVY_H, pad=14)
    ax.set_facecolor("#F0F4FF")
    ax.xaxis.pane.fill = False
    ax.yaxis.pane.fill = False
    ax.zaxis.pane.fill = False
    ax.view_init(elev=25, azim=-50)
    for x, z in zip(xp, values):
        ax.text(x+0.27, 0.18, z+0.15, str(z),
                ha="center", fontsize=8.5, fontweight="bold", color=NAVY_H)
    plt.tight_layout()
    return _to_b64(fig)

# ── 6. Most Active Students (horizontal bar with gradient) ────────────────────
def chart_active_students(names, counts, title):
    if not names:
        return ""
    n   = len(names)
    fig, ax = plt.subplots(figsize=(7, max(3, n*0.6)))
    fig.patch.set_facecolor("white")
    grad_colors = plt.cm.Blues(np.linspace(0.45, 0.85, n))[::-1]
    bars = ax.barh(names, counts, color=grad_colors, edgecolor="white",
                   height=0.62, linewidth=1.2)
    ax.set_title(title, fontsize=12, fontweight="bold", color=NAVY_H, pad=10)
    _style_ax(ax)
    ax.spines["left"].set_visible(False)
    ax.set_xlabel("Events Registered", fontsize=9, color="#555")
    for bar, val in zip(bars, counts):
        ax.text(bar.get_width()+0.05, bar.get_y()+bar.get_height()/2,
                f"  {val} events", va="center", fontsize=8.5,
                fontweight="bold", color=NAVY_H)
    # star badge for top
    if n > 0:
        ax.text(0.98, 0.97, "⭐ Top Participant",
                transform=ax.transAxes, ha="right", va="top",
                fontsize=8, color="#D4913C", fontweight="bold")
    plt.tight_layout()
    return _to_b64(fig)

# ── 7. Event Category 3D Pie ──────────────────────────────────────────────────
def chart_category_pie(labels, values, title):
    if not labels:
        return ""
    fig, ax = plt.subplots(figsize=(6.5, 4.5), subplot_kw=dict(aspect="equal"))
    fig.patch.set_facecolor("white")
    cat_colors = {"Tech":"#2557D6","Cultural":"#7C3AED","Workshop":"#0891B2",
                  "Business":"#D4913C","Sports":"#059669","Design":"#DB2777",
                  "General":"#1B2A4A"}
    colors_used = [cat_colors.get(l, COLORS[i%len(COLORS)]) for i,l in enumerate(labels)]
    wedges, _, autotexts = ax.pie(
        values, labels=None, autopct="%1.0f%%",
        colors=colors_used, startangle=90, shadow=True,
        explode=[0.04]*len(labels),
        wedgeprops={"edgecolor":"white","linewidth":2},
        pctdistance=0.80)
    for at in autotexts:
        at.set_color("white"); at.set_fontweight("bold"); at.set_fontsize(9)
    ax.legend(wedges, [f"{l} ({v} events)" for l,v in zip(labels,values)],
              loc="lower center", bbox_to_anchor=(0.5,-0.12),
              ncol=3, fontsize=8, frameon=False)
    ax.set_title(title, fontsize=12, fontweight="bold", color=NAVY_H, pad=10)
    plt.tight_layout()
    return _to_b64(fig)

# ── 8. Department Performance Score (stacked bar) ────────────────────────────
def chart_dept_score(depts, scores, title):
    if not depts:
        return ""
    n   = len(depts)
    fig, ax = plt.subplots(figsize=(8, max(3.5, n*0.65)))
    fig.patch.set_facecolor("white")
    sorted_data = sorted(zip(scores, depts), reverse=True)
    scores_s, depts_s = zip(*sorted_data) if sorted_data else ([], [])
    norm   = plt.Normalize(min(scores_s), max(scores_s))
    colors = plt.cm.RdYlGn(norm(list(scores_s)))
    bars   = ax.barh(list(depts_s), list(scores_s), color=colors,
                     edgecolor="white", height=0.6)
    ax.set_title(title, fontsize=12, fontweight="bold", color=NAVY_H, pad=10)
    ax.set_xlabel("Performance Score", fontsize=9, color="#555")
    _style_ax(ax)
    ax.spines["left"].set_visible(False)
    for bar, val in zip(bars, scores_s):
        ax.text(bar.get_width()+0.3, bar.get_y()+bar.get_height()/2,
                f"  {int(val)} pts", va="center", fontsize=8.5,
                fontweight="bold", color=NAVY_H)
    sm = plt.cm.ScalarMappable(cmap="RdYlGn", norm=norm)
    sm.set_array([])
    cbar = fig.colorbar(sm, ax=ax, shrink=0.7, pad=0.02)
    cbar.set_label("Score Level", fontsize=8)
    plt.tight_layout()
    return _to_b64(fig)

# ── 9. Seat Utilisation progress chart ───────────────────────────────────────
def chart_seat_util(event_names, util_pcts, title):
    if not event_names:
        return ""
    n   = len(event_names)
    fig, ax = plt.subplots(figsize=(8, max(3, n*0.7)))
    fig.patch.set_facecolor("white")
    ax.set_facecolor(BG)
    y_pos = np.arange(n)
    # background bars (100%)
    ax.barh(y_pos, [100]*n, color="#E5E7EB", height=0.55, edgecolor="white")
    # actual utilisation
    bar_colors = ["#DC2626" if p>=90 else "#D97706" if p>=70 else "#059669"
                  for p in util_pcts]
    ax.barh(y_pos, util_pcts, color=bar_colors, height=0.55,
            edgecolor="white", linewidth=0.5)
    ax.set_yticks(y_pos)
    ax.set_xticklabels([])
    short = [e[:16]+"…" if len(e)>16 else e for e in event_names]
    ax.set_yticklabels(short, fontsize=9, color="#333")
    ax.set_xlim(0, 115)
    ax.set_title(title, fontsize=12, fontweight="bold", color=NAVY_H, pad=10)
    ax.spines[["top","right","left","bottom"]].set_visible(False)
    ax.tick_params(axis="both", length=0)
    # percentage labels
    for i, (p, bc) in enumerate(zip(util_pcts, bar_colors)):
        emoji = "🔴" if p>=90 else "🟡" if p>=70 else "🟢"
        ax.text(p+1.5, i, f"{p:.0f}%  {emoji}", va="center",
                fontsize=9, fontweight="bold", color=bc)
    plt.tight_layout()
    return _to_b64(fig)


# ══════════════════════════════════════════════════════════════════════════════
# API ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/events")
def api_events():
    rows = query("SELECT * FROM events WHERE is_active=1 ORDER BY event_date")
    return jsonify([row_to_event(r) for r in rows])

@app.route("/api/student/<student_id>")
@rate_limit(30, 60)
def api_student(student_id):
    sid = clean(student_id).upper()
    row = query("SELECT * FROM students WHERE student_id=?", (sid,), one=True)
    if row:
        return jsonify({"found": True, "student_id": row["student_id"],
                        "full_name": row["full_name"], "email": row["email"],
                        "department": row["department"],
                        "year_of_study": row["year_of_study"],
                        "phone": row["phone"] or ""})
    return jsonify({"found": False})

@app.route("/api/register", methods=["POST"])
@rate_limit(5, 60)
def api_register():
    data = request.get_json(force=True, silent=True) or {}

    full_name     = clean(data.get("full_name", ""))
    student_id    = clean(data.get("student_id", "")).upper()
    email         = clean(data.get("email", "")).lower()
    department    = clean(data.get("department", ""))
    year_of_study = clean(data.get("year_of_study", ""))
    phone         = clean(data.get("phone", ""))
    event_id_raw  = data.get("event_id")

    # Validation
    if not full_name:
        return jsonify({"error": "Full name is required"}), 400
    if not student_id:
        return jsonify({"error": "Student ID is required"}), 400
    if not email or not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        return jsonify({"error": "Valid email is required"}), 400
    if not department:
        return jsonify({"error": "Department is required"}), 400
    if not year_of_study:
        return jsonify({"error": "Year of study is required"}), 400
    if not event_id_raw:
        return jsonify({"error": "Please select an event"}), 400

    try:
        event_id = int(event_id_raw)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid event"}), 400

    event = query("SELECT * FROM events WHERE id=? AND is_active=1",
                  (event_id,), one=True)
    if not event:
        return jsonify({"error": "Event not found"}), 404

    # Upsert student
    stu = query("SELECT * FROM students WHERE student_id=?", (student_id,), one=True)
    if stu:
        stu_id = stu["id"]
    else:
        stu_id = query(
            "INSERT INTO students(student_id,full_name,email,department,"
            "year_of_study,phone) VALUES(?,?,?,?,?,?)",
            (student_id, full_name, email, department,
             year_of_study, phone or None), commit=True)

    # Duplicate check
    if query("SELECT id FROM registrations WHERE student_id=? AND event_id=?",
             (stu_id, event_id), one=True):
        return jsonify({"error": f"You are already registered for {event['name']}!"}), 409

    # Waitlist check
    stats       = event_stats(event_id)
    on_waitlist = 1 if stats["confirmed"] >= event["capacity"] else 0
    reg_code    = "UDX-" + str(uuid.uuid4())[:8].upper()

    query("INSERT INTO registrations(reg_code,student_id,event_id,on_waitlist) "
          "VALUES(?,?,?,?)",
          (reg_code, stu_id, event_id, on_waitlist), commit=True)

    audit("REGISTER", f"student={student_id} event={event_id} waitlist={on_waitlist}")
    stats = event_stats(event_id)

    return jsonify({
        "success": True, "reg_code": reg_code,
        "on_waitlist": bool(on_waitlist), "qr_data": make_qr(reg_code),
        "student": {"student_id": student_id, "full_name": full_name,
                    "email": email, "department": department,
                    "year_of_study": year_of_study, "phone": phone},
        "event":   {"id": event["id"], "name": event["name"],
                    "venue": event["venue"], "date": event["event_date"] or "TBD",
                    "category": event["category"], **stats},
    })

# ── Admin auth ────────────────────────────────────────────────────────────────
@app.route("/api/admin/login", methods=["POST"])
@rate_limit(10, 60)
def api_admin_login():
    data     = request.get_json(force=True, silent=True) or {}
    username = clean(data.get("username", ""))
    password = data.get("password", "")

    user = query("SELECT * FROM admin_users WHERE username=?", (username,), one=True)
    if not user or not check_password_hash(user["password_hash"], password):
        audit("FAILED_LOGIN", f"user={username[:30]}")
        return jsonify({"error": "Invalid username or password"}), 401

    session.permanent = True
    session["admin_id"]   = user["id"]
    session["admin_name"] = user["username"]
    query("UPDATE admin_users SET last_login=? WHERE id=?",
          (datetime.utcnow().isoformat(), user["id"]), commit=True)
    audit("LOGIN", f"user={username}")
    return jsonify({"success": True, "username": user["username"]})

@app.route("/api/admin/logout", methods=["POST"])
def api_admin_logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/admin/me")
def api_admin_me():
    uid = session.get("admin_id")
    if not uid:
        return jsonify({"logged_in": False})
    user = query("SELECT username FROM admin_users WHERE id=?", (uid,), one=True)
    if not user:
        session.clear()
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, "username": user["username"]})

# ── Analytics ─────────────────────────────────────────────────────────────────
@app.route("/api/analytics")
@require_admin
def api_analytics():
    # ── Base join: registrations + students + events ──────────────────────────
    rows = query("""
        SELECT r.registered_at, r.on_waitlist,
               s.student_id, s.full_name, s.department, s.year_of_study,
               e.id AS event_id, e.name AS event_name,
               e.capacity, e.category
        FROM   registrations r
        JOIN   students s ON s.id = r.student_id
        JOIN   events   e ON e.id = r.event_id
    """)

    if not rows:
        return jsonify({"empty": True,
                        "totals": {"regs":0,"events":0,"depts":0,
                                   "waitlist":0,"capacity":0},
                        "charts": {}, "trending": [], "active_students": []})

    df = pd.DataFrame(
        [(r["registered_at"], r["on_waitlist"],
          r["student_id"],   r["full_name"],  r["department"],
          r["year_of_study"],r["event_id"],   r["event_name"],
          r["capacity"],     r["category"])
         for r in rows],
        columns=["registered_at","on_waitlist","student_id","full_name",
                 "department","year_of_study","event_id","event_name",
                 "capacity","category"])

    df["registered_at"] = pd.to_datetime(df["registered_at"])
    df["date_str"]      = df["registered_at"].dt.strftime("%d %b")

    # confirmed only for most charts
    dfc = df[df["on_waitlist"] == 0].copy()

    # ── Totals / KPIs ─────────────────────────────────────────────────────────
    total_regs      = len(dfc)
    total_waitlist  = int(df["on_waitlist"].sum())
    total_events    = dfc["event_name"].nunique()
    total_depts     = dfc["department"].nunique()

    # total capacity across active events
    all_events_rows = query("SELECT capacity FROM events WHERE is_active=1")
    total_capacity  = sum(r["capacity"] for r in all_events_rows)

    # ── Q1: Registrations per event (3D bar) ──────────────────────────────────
    ev = (dfc.groupby("event_name").size()
             .reset_index(name="count")
             .sort_values("count", ascending=False))

    # ── Q2: Students by Department (3D pie) ───────────────────────────────────
    dept = (dfc.groupby("department").size()
               .reset_index(name="count")
               .sort_values("count", ascending=False))

    # ── Q3: Registration Trend over time (area) ───────────────────────────────
    trend = (dfc.groupby("date_str").size()
                .reset_index(name="count"))

    # ── Q4: Year-of-Study breakdown (3D bar) ──────────────────────────────────
    year = (dfc.groupby("year_of_study").size()
               .reset_index(name="count")
               .sort_values("year_of_study"))

    # ── Q5: Dept × Event Heatmap ──────────────────────────────────────────────
    all_depts  = sorted(dfc["department"].unique().tolist())
    all_evs    = sorted(dfc["event_name"].unique().tolist())
    heat_df    = (dfc.groupby(["department","event_name"]).size()
                     .unstack(fill_value=0)
                     .reindex(index=all_depts, columns=all_evs, fill_value=0))

    # ── Q6: Most Active Students ──────────────────────────────────────────────
    # SQL: count how many events each student has joined
    active_rows = query("""
        SELECT s.full_name, s.department,
               COUNT(r.id) AS events_joined
        FROM   students s
        JOIN   registrations r ON r.student_id = s.id
        WHERE  r.on_waitlist = 0
        GROUP  BY s.id
        ORDER  BY events_joined DESC
        LIMIT  5
    """)
    active_names  = [r["full_name"] for r in active_rows]
    active_counts = [r["events_joined"] for r in active_rows]
    active_list   = [{"name": r["full_name"], "dept": r["department"],
                      "count": r["events_joined"]} for r in active_rows]

    # ── Q7: Event Category Distribution ──────────────────────────────────────
    # SQL: count events grouped by category
    cat_rows = query("""
        SELECT e.category, COUNT(DISTINCT e.id) AS total_events
        FROM   events e
        WHERE  e.is_active = 1
        GROUP  BY e.category
        ORDER  BY total_events DESC
    """)
    cat_labels = [r["category"] for r in cat_rows]
    cat_values = [r["total_events"] for r in cat_rows]

    # ── Q8: Department Performance Score ──────────────────────────────────────
    # Formula: (distinct events * 2) + (total registrations) = engagement score
    dept_score_rows = query("""
        SELECT s.department,
               COUNT(DISTINCT r.event_id) * 2 + COUNT(r.id) AS score,
               COUNT(r.id)              AS total_regs,
               COUNT(DISTINCT r.event_id) AS events_count
        FROM   students s
        JOIN   registrations r ON r.student_id = s.id
        WHERE  r.on_waitlist = 0
        GROUP  BY s.department
        ORDER  BY score DESC
    """)
    ds_depts  = [r["department"] for r in dept_score_rows]
    ds_scores = [r["score"] for r in dept_score_rows]
    dept_score_list = [{"dept": r["department"], "score": r["score"],
                        "regs": r["total_regs"],
                        "events": r["events_count"]} for r in dept_score_rows]

    # ── Q9: Seat Utilisation per event ────────────────────────────────────────
    util_rows = query("""
        SELECT e.name, e.capacity,
               COUNT(r.id) AS confirmed
        FROM   events e
        LEFT   JOIN registrations r
               ON e.id = r.event_id AND r.on_waitlist = 0
        WHERE  e.is_active = 1
        GROUP  BY e.id
        ORDER  BY confirmed DESC
    """)
    util_names = [r["name"] for r in util_rows]
    util_pcts  = [round(r["confirmed"]/r["capacity"]*100, 1)
                  if r["capacity"] else 0 for r in util_rows]
    util_list  = [{"event": r["name"], "capacity": r["capacity"],
                   "confirmed": r["confirmed"],
                   "pct": round(r["confirmed"]/r["capacity"]*100,1)
                   if r["capacity"] else 0} for r in util_rows]

    # ── Q10: Trending momentum score ──────────────────────────────────────────
    trows = query("""
        SELECT e.name, e.capacity,
               COUNT(r.id) AS regs,
               MIN(r.registered_at) AS first_reg
        FROM   events e
        JOIN   registrations r ON e.id = r.event_id
        WHERE  r.on_waitlist = 0
        GROUP  BY e.id
    """)
    trending = []
    for t in trows:
        first = datetime.fromisoformat(t["first_reg"])
        days  = max(1, (datetime.utcnow()-first).days+1)
        score = round(t["regs"]/days, 2)
        util  = round(t["regs"]/t["capacity"]*100, 1) if t["capacity"] else 0
        trending.append({"event": t["name"], "regs": t["regs"],
                         "score": score, "util": util})
    trending.sort(key=lambda x: x["score"], reverse=True)

    # ── Generate all charts ───────────────────────────────────────────────────
    charts = {
        # Chart 1 — 3D bar: registrations per event
        "bar": chart_3d_bar(
            ev["event_name"].tolist(), ev["count"].tolist(),
            "📊 Registrations per Event"),

        # Chart 2 — 3D pie: students by department
        "pie": chart_3d_pie(
            dept["department"].tolist(), dept["count"].tolist(),
            "🥧 Students by Department"),

        # Chart 3 — area: trend over time
        "trend": chart_area(
            trend["date_str"].tolist(), trend["count"].tolist(),
            "📈 Daily Registration Trend"),

        # Chart 4 — 3D bar: year of study
        "year": chart_3d_year(
            year["year_of_study"].tolist(), year["count"].tolist(),
            "🎓 Year-of-Study Breakdown"),

        # Chart 5 — heatmap: dept × event
        "heatmap": chart_heatmap(
            all_depts, all_evs, heat_df.values.tolist()),

        # Chart 6 — Most active students
        "active": chart_active_students(
            active_names, active_counts,
            "⭐ Top 5 Most Active Students"),

        # Chart 7 — event category distribution
        "category": chart_category_pie(
            cat_labels, cat_values,
            "🏷️ Event Category Distribution"),

        # Chart 8 — department performance score
        "dept_score": chart_dept_score(
            ds_depts, ds_scores,
            "🏆 Department Performance Score"),

        # Chart 9 — seat utilisation progress bars
        "seat_util": chart_seat_util(
            util_names, util_pcts,
            "💺 Seat Utilisation per Event"),
    }

    return jsonify({
        "empty": False,
        "totals": {
            "regs":      total_regs,
            "events":    total_events,
            "depts":     total_depts,
            "waitlist":  total_waitlist,
            "capacity":  total_capacity,
        },
        "trending":       trending,
        "active_students":active_list,
        "dept_scores":    dept_score_list,
        "util":           util_list,
        "charts":         charts,
    })

@app.route("/api/export-csv")
@require_admin
def api_export_csv():
    rows = query("""
        SELECT s.student_id, s.full_name, s.email, s.department, s.year_of_study,
               e.name AS event, e.event_date, r.reg_code, r.registered_at, r.on_waitlist
        FROM   registrations r
        JOIN   students s ON s.id=r.student_id
        JOIN   events   e ON e.id=r.event_id
        ORDER  BY r.registered_at DESC
    """)
    df = pd.DataFrame(
        [(r["student_id"],r["full_name"],r["email"],r["department"],r["year_of_study"],
          r["event"],r["event_date"],r["reg_code"],r["registered_at"],bool(r["on_waitlist"]))
         for r in rows],
        columns=["Student ID","Name","Email","Department","Year",
                 "Event","Event Date","Reg Code","Registered At","Waitlist"])
    buf = io.StringIO()
    df.to_csv(buf, index=False); buf.seek(0)
    audit("EXPORT_CSV")
    resp = make_response(buf.getvalue())
    resp.headers["Content-Disposition"] = "attachment; filename=registrations.csv"
    resp.headers["Content-Type"]        = "text/csv"
    return resp

@app.route("/api/admin/create-event", methods=["POST"])
@require_admin
def api_create_event():
    data     = request.get_json(force=True, silent=True) or {}
    name     = clean(data.get("name", ""))
    desc     = clean(data.get("description", ""))
    venue    = clean(data.get("venue", ""))
    date     = clean(data.get("event_date", ""))
    capacity = data.get("capacity", 100)
    category = clean(data.get("category", "General"))

    if not name:
        return jsonify({"error": "Event name is required"}), 400
    if not venue:
        return jsonify({"error": "Venue is required"}), 400
    try:
        capacity = int(capacity)
        if capacity < 1:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"error": "Capacity must be a positive number"}), 400

    # Validate date format if provided
    if date:
        try:
            datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

    event_id = query(
        "INSERT INTO events(name,description,venue,event_date,capacity,category,is_active)"
        " VALUES(?,?,?,?,?,?,1)",
        (name, desc, venue, date or None, capacity, category), commit=True
    )
    audit("CREATE_EVENT", f"name={name} capacity={capacity}")
    new_event = query("SELECT * FROM events WHERE id=?", (event_id,), one=True)
    return jsonify({"success": True, "event": row_to_event(new_event)})


@app.route("/api/admin/delete-event/<int:event_id>", methods=["POST"])
@require_admin
def api_delete_event(event_id):
    event = query("SELECT * FROM events WHERE id=?", (event_id,), one=True)
    if not event:
        return jsonify({"error": "Event not found"}), 404
    # Soft delete — just deactivate
    query("UPDATE events SET is_active=0 WHERE id=?", (event_id,), commit=True)
    audit("DELETE_EVENT", f"event_id={event_id} name={event['name']}")
    return jsonify({"success": True})



@app.route("/api/events-all")
@require_admin
def api_events_all():
    rows = query("SELECT * FROM events WHERE is_active=1 ORDER BY event_date")
    return jsonify([row_to_event(r) for r in rows])


@app.route("/api/registrations")
@require_admin
def api_registrations():

    rows = query("""
        SELECT s.student_id, s.full_name, s.email, s.department,
               e.name AS event_name, r.reg_code, r.registered_at, r.on_waitlist
        FROM   registrations r
        JOIN   students s ON s.id=r.student_id
        JOIN   events   e ON e.id=r.event_id
        ORDER  BY r.registered_at DESC LIMIT 200
    """)
    return jsonify([dict(r) for r in rows])

# ── SPA fallback ──────────────────────────────────────────────────────────────
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_spa(path):
    if path and os.path.exists(os.path.join(app.static_folder or "", path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.template_folder, "index.html")

@app.errorhandler(429)
def too_many(e):
    return jsonify({"error": "Too many requests. Wait a moment."}), 429

@app.errorhandler(500)
def server_err(e):
    log.exception("500")
    return jsonify({"error": "Internal server error"}), 500

# ── DB init ───────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            last_login TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, description TEXT DEFAULT '',
            venue TEXT DEFAULT 'TBD', event_date TEXT,
            capacity INTEGER DEFAULT 100, category TEXT DEFAULT 'General',
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL,
            email TEXT NOT NULL, department TEXT, year_of_study TEXT,
            phone TEXT, created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reg_code TEXT UNIQUE NOT NULL,
            student_id INTEGER NOT NULL REFERENCES students(id),
            event_id   INTEGER NOT NULL REFERENCES events(id),
            registered_at TEXT DEFAULT (datetime('now')),
            on_waitlist INTEGER DEFAULT 0,
            UNIQUE(student_id, event_id)
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT, ip_hash TEXT, details TEXT,
            timestamp TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS ix_reg_event ON registrations(event_id);
        CREATE INDEX IF NOT EXISTS ix_stu_id    ON students(student_id);
    """)

    # Admin user
    if not conn.execute("SELECT id FROM admin_users WHERE username='admin'").fetchone():
        conn.execute(
            "INSERT INTO admin_users(username,email,password_hash) VALUES(?,?,?)",
            ("admin", "admin@udaanx.edu", generate_password_hash("Admin@12345")))
        log.info("Admin user created")

    # Sample events
    if not conn.execute("SELECT id FROM events LIMIT 1").fetchone():
        conn.executemany(
            "INSERT INTO events(name,description,venue,event_date,capacity,category)"
            " VALUES(?,?,?,?,?,?)", [
            ("Tech Fest 2025","Annual hackathon, robotics & coding contests.",
             "Main Auditorium","2025-09-15",300,"Tech"),
            ("Cultural Night","Art, dance, music & drama from across India.",
             "Open Air Theatre","2025-09-20",500,"Cultural"),
            ("AI & ML Workshop","Hands-on neural networks and NLP from scratch.",
             "CS Lab Block A","2025-10-05",60,"Workshop"),
            ("Entrepreneurship Summit","Founders share unfiltered startup lessons.",
             "Conference Hall","2025-10-12",200,"Business"),
            ("Sports Day 2025","Inter-department cricket, football, badminton.",
             "Sports Ground","2025-11-01",400,"Sports"),
            ("Design Sprint","48-hour sprint solving real UX challenges.",
             "Design Studio","2025-11-15",40,"Design"),
        ])
        log.info("Sample events seeded")

    conn.commit(); conn.close()
    log.info("Database ready: %s", DB_PATH)

if __name__ == "__main__":
    init_db()
    print("\n" + "="*50)
    print("  UdaanX University Event Portal")
    print("  URL  : http://127.0.0.1:5000")
    print("  Admin: admin / Admin@12345")
    print("="*50 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
