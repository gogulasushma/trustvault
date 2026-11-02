import os
import secrets
import sqlite3
import uuid
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DATABASE = "trustvault.db"
UPLOAD_FOLDER = Path(__file__).parent / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)
ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg", "docx", "xlsx"}
CATEGORIES = ["Contract", "HR", "Finance", "Audit", "Other"]
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB limit


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def log_event(action, allowed, user_id=None, document_id=None, details=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (user_id, action, document_id, allowed, details) "
        "VALUES (?, ?, ?, ?, ?)",
        (user_id, action, document_id, 1 if allowed else 0, details),
    )
    db.commit()


def get_access(user, document_id):
    """THE permission check. Returns 'owner', 'edit', 'read' or None.
    Reads the database on every call, so a revoke works immediately."""
    db = get_db()
    doc = db.execute(
        "SELECT owner_id, deleted FROM documents WHERE id = ?", (document_id,)
    ).fetchone()
    if doc is None or doc["deleted"]:
        return None
    if doc["owner_id"] == user["id"]:
        return "owner"
    grant = db.execute(
        "SELECT level FROM permissions WHERE document_id = ? AND user_id = ?",
        (document_id, user["id"]),
    ).fetchone()
    return grant["level"] if grant else None


@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        g.user = get_db().execute(
            "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if g.user is None:
            session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            if g.user["role"] not in roles:
                log_event("forbidden_page", False, user_id=g.user["id"],
                          details=request.path)
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/")
def home():
    if g.user:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not (3 <= len(username) <= 30) or len(password) < 10:
            flash("Username must be 3-30 characters and password at least 10.")
            return render_template("register.html")
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) "
                "VALUES (?, ?, 'viewer')",
                (username, generate_password_hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("That username is taken.")
            return render_template("register.html")
        flash("Account created. Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user is not None and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            log_event("login", True, user_id=user["id"])
            return redirect(url_for("dashboard"))
        log_event("login", False, user_id=user["id"] if user else None,
                  details="username tried: " + username[:50])
        flash("Wrong username or password.")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event("logout", True, user_id=g.user["id"])
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/admin")
@role_required("admin")
def admin():
    db = get_db()
    logs = db.execute(
        "SELECT a.id, a.timestamp, u.username, a.action, a.document_id, "
        "a.allowed, a.details "
        "FROM audit_log a LEFT JOIN users u ON u.id = a.user_id "
        "ORDER BY a.id DESC LIMIT 100"
    ).fetchall()
    total = db.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()["n"]
    refused = db.execute(
        "SELECT COUNT(*) AS n FROM audit_log WHERE allowed = 0"
    ).fetchone()["n"]
    return render_template("admin.html", logs=logs, total=total, refused=refused)


@app.route("/upload", methods=["GET", "POST"])
@role_required("owner")
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        category = request.form.get("category", "")
        if file is None or file.filename == "":
            flash("Please choose a file.")
            return render_template("upload.html", categories=CATEGORIES)
        if category not in CATEGORIES:
            flash("Please choose a valid category.")
            return render_template("upload.html", categories=CATEGORIES)

        original_name = secure_filename(file.filename)
        extension = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
        if extension not in ALLOWED_EXTENSIONS:
            log_event("upload", False, user_id=g.user["id"],
                      details="blocked file type: " + extension[:10])
            flash("This file type is not allowed.")
            return render_template("upload.html", categories=CATEGORIES)

        stored_name = uuid.uuid4().hex + "." + extension
        path = UPLOAD_FOLDER / stored_name
        file.save(path)

        db = get_db()
        cursor = db.execute(
            "INSERT INTO documents (owner_id, original_name, stored_name, category, size_bytes) "
            "VALUES (?, ?, ?, ?, ?)",
            (g.user["id"], original_name, stored_name, category, path.stat().st_size),
        )
        db.commit()
        log_event("upload", True, user_id=g.user["id"], document_id=cursor.lastrowid)
        flash("Document uploaded.")
        return redirect(url_for("documents"))
    return render_template("upload.html", categories=CATEGORIES)


@app.route("/documents")
@login_required
def documents():
    uid = g.user["id"]
    docs = get_db().execute(
        "SELECT d.id, d.original_name, d.category, d.size_bytes, d.uploaded_at, "
        "u.username AS owner, "
        "CASE WHEN d.owner_id = ? THEN 'owner' ELSE p.level END AS access "
        "FROM documents d "
        "JOIN users u ON u.id = d.owner_id "
        "LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = ? "
        "WHERE d.deleted = 0 AND (d.owner_id = ? OR p.user_id IS NOT NULL) "
        "ORDER BY d.uploaded_at DESC",
        (uid, uid, uid),
    ).fetchall()
    return render_template("documents.html", docs=docs)


@app.route("/documents/<int:doc_id>/download")
@login_required
def download(doc_id):
    level = get_access(g.user, doc_id)
    if level is None:
        log_event("download", False, user_id=g.user["id"], document_id=doc_id)
        abort(404)
    doc = get_db().execute(
        "SELECT stored_name, original_name FROM documents WHERE id = ?", (doc_id,)
    ).fetchone()
    log_event("download", True, user_id=g.user["id"], document_id=doc_id)
    return send_from_directory(
        UPLOAD_FOLDER, doc["stored_name"],
        as_attachment=True, download_name=doc["original_name"],
    )


@app.route("/documents/<int:doc_id>/share", methods=["GET", "POST"])
@login_required
def share(doc_id):
    if get_access(g.user, doc_id) != "owner":
        log_event("share_page", False, user_id=g.user["id"], document_id=doc_id)
        abort(404)
    db = get_db()
    doc = db.execute(
        "SELECT id, original_name FROM documents WHERE id = ?", (doc_id,)
    ).fetchone()

    if request.method == "POST":
        action = request.form.get("action", "")
        username = request.form.get("username", "").strip()
        target = db.execute(
            "SELECT id, username FROM users WHERE username = ?", (username,)
        ).fetchone()
        if target is None or target["id"] == g.user["id"]:
            flash("Choose another existing user.")
        elif action == "grant":
            level = request.form.get("level", "")
            if level not in ("read", "edit"):
                flash("Invalid access level.")
            else:
                db.execute(
                    "INSERT INTO permissions (document_id, user_id, level, granted_by) "
                    "VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(document_id, user_id) DO UPDATE SET "
                    "level = excluded.level, granted_by = excluded.granted_by, "
                    "granted_at = CURRENT_TIMESTAMP",
                    (doc_id, target["id"], level, g.user["id"]),
                )
                db.commit()
                log_event("grant", True, user_id=g.user["id"], document_id=doc_id,
                          details=target["username"] + ":" + level)
                flash("Access granted.")
        elif action == "revoke":
            db.execute(
                "DELETE FROM permissions WHERE document_id = ? AND user_id = ?",
                (doc_id, target["id"]),
            )
            db.commit()
            log_event("revoke", True, user_id=g.user["id"], document_id=doc_id,
                      details=target["username"])
            flash("Access revoked.")
        return redirect(url_for("share", doc_id=doc_id))

    grants = db.execute(
        "SELECT u.username, p.level FROM permissions p "
        "JOIN users u ON u.id = p.user_id WHERE p.document_id = ?",
        (doc_id,),
    ).fetchall()
    return render_template("share.html", doc=doc, grants=grants)


if __name__ == "__main__":
    app.run(debug=True)