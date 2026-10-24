import json
import os
import uuid
import boto3
import click
from botocore.client import Config
from botocore.exceptions import BotoCoreError, ClientError
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps
from urllib.parse import urlparse
from flask import Flask, Response, abort, request, redirect, url_for, render_template_string, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.permanent_session_lifetime = timedelta(hours=12)
db_url = os.environ.get("DATABASE_URL", "sqlite:///local.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
db = SQLAlchemy(app)

class PurchaseOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # sequential PO number
    vendor = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now())
    created_by_id = db.Column(db.Integer, db.ForeignKey("app_user.id"), nullable=True)
    # Attachment rows are removed with the PO (bucket objects are removed in delete_po).
    attachments = db.relationship(
        "PurchaseOrderAttachment", backref="po", cascade="all, delete-orphan",
        order_by="PurchaseOrderAttachment.id",
    )

class PurchaseOrderAttachment(db.Model):
    __tablename__ = "po_attachment"
    id = db.Column(db.Integer, primary_key=True)
    po_id = db.Column(db.Integer, db.ForeignKey("purchase_order.id"), nullable=False, index=True)
    storage_key = db.Column(db.String(255), nullable=False, unique=True)
    original_filename = db.Column(db.String(255))
    content_type = db.Column(db.String(100))
    size_bytes = db.Column(db.Integer)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("app_user.id"), nullable=True)
    created_at = db.Column(db.DateTime, server_default=func.now())

class User(db.Model):
    __tablename__ = "app_user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), nullable=False, default="member")

class LoginAttempt(db.Model):
    """Failed-login counter for one throttle key ("user:<name>" or "ip:<addr>")."""
    __tablename__ = "login_attempt"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), unique=True, index=True, nullable=False)
    failed_count = db.Column(db.Integer, nullable=False, default=0)
    window_start = db.Column(db.DateTime, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

VALID_ROLES = ("admin", "member")

with app.app_context():
    db.create_all()
    # Idempotent migration: add the role column to pre-existing app_user tables.
    _dialect = db.engine.dialect.name
    if _dialect == "postgresql":
        db.session.execute(text(
            "ALTER TABLE app_user ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'member'"
        ))
        db.session.commit()
    elif _dialect == "sqlite":
        _cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(app_user)")).fetchall()]
        if "role" not in _cols:
            db.session.execute(text(
                "ALTER TABLE app_user ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'member'"
            ))
            db.session.commit()
    # Idempotent migration: add the created_by_id column to pre-existing purchase_order tables.
    if _dialect == "postgresql":
        db.session.execute(text(
            "ALTER TABLE purchase_order ADD COLUMN IF NOT EXISTS created_by_id INTEGER REFERENCES app_user(id)"
        ))
        db.session.commit()
    elif _dialect == "sqlite":
        _po_cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(purchase_order)")).fetchall()]
        if "created_by_id" not in _po_cols:
            db.session.execute(text(
                "ALTER TABLE purchase_order ADD COLUMN created_by_id INTEGER REFERENCES app_user(id)"
            ))
            db.session.commit()
    # Bootstrap the first admin from the environment when no users exist yet.
    _admin_username = os.environ.get("ADMIN_USERNAME", "").strip()
    _admin_password = os.environ.get("ADMIN_PASSWORD", "")
    # One-time promotion: only when no admin exists, so a demotion persists across restarts.
    if _admin_username:
        _admin_count = db.session.execute(
            text("SELECT COUNT(*) FROM app_user WHERE role = 'admin'")
        ).scalar()
        if not _admin_count:
            db.session.execute(
                text("UPDATE app_user SET role = 'admin' WHERE username = :u"),
                {"u": _admin_username},
            )
            db.session.commit()
    if _admin_username and _admin_password and User.query.first() is None:
        try:
            db.session.add(User(
                username=_admin_username,
                password_hash=generate_password_hash(_admin_password),
                is_active=True,
                role="admin",
            ))
            db.session.commit()
        except IntegrityError:
            # Another worker created the user first.
            db.session.rollback()

# Used to equalize timing when the username does not exist.
_DUMMY_HASH = generate_password_hash("not-a-real-password")

BASE = """
<!doctype html><html><head><meta charset="utf-8"><title>PO Tracker</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#1f6feb">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="PO Tracker">
<link rel="manifest" href="{{ url_for('manifest') }}">
<link rel="apple-touch-icon" href="{{ url_for('icon') }}">
<style>body{font-family:sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:.4rem;text-align:left}
.flash{color:#b00}.total{font-size:1.4rem;font-weight:bold}input,textarea{width:100%;padding:.4rem;margin:.2rem 0 .8rem}
button,a.btn{padding:.5rem 1rem;text-decoration:none}
.site-header{display:flex;align-items:center;gap:1rem;margin-bottom:1rem}
.site-header .logo-link{display:inline-flex;flex:0 0 auto;max-width:40%}
.site-header img{height:48px;width:auto;max-width:100%}
.site-header h1{margin:0}</style></head><body>
<header class="site-header"><a class="logo-link" href="{{ url_for('index') }}"><img src="{{ url_for('logo') }}" alt="Church logo"></a>
<h1>PO Tracker</h1></header>
<p><a class="btn" href="{{ url_for('index') }}">Dashboard</a> <a class="btn" href="{{ url_for('new_po') }}">New PO</a>{% if show_users_link %} <a class="btn" href="{{ url_for('admin_users') }}">Users</a>{% endif %}{% if session.get('user_id') %} <a class="btn" href="{{ url_for('logout') }}">Log out</a>{% endif %}</p>
{% for m in get_flashed_messages() %}<p class="flash">{{ m }}</p>{% endfor %}
{{ body|safe }}
<script>if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');</script>
</body></html>
"""

INDEX = """
<p class="total">Total: ${{ "{:,.2f}".format(total) }} ({{ count }} POs)</p>
<table><tr><th>PO #</th><th>Vendor</th><th>Description</th><th>Amount</th><th>Created</th><th>Created by</th>{% if is_admin %}<th></th>{% endif %}</tr>
{% for po in pos %}<tr><td><a href="{{ url_for('po_detail', po_id=po.id) }}">PO-{{ po.id }}</a></td><td>{{ po.vendor }}</td><td>{{ po.description }}</td>
<td>${{ "{:,.2f}".format(po.amount) }}</td><td>{{ po.created_at.strftime('%Y-%m-%d') if po.created_at else '' }}</td>
<td>{{ creators.get(po.created_by_id, '-') if po.created_by_id else '-' }}</td>
{% if is_admin %}<td><a class="btn" href="{{ url_for('edit_po', po_id=po.id) }}">Edit</a>
<form method="post" action="{{ url_for('delete_po', po_id=po.id) }}" style="display:inline" onsubmit="return confirm('Delete PO-{{ po.id }}? This cannot be undone.');">
<button type="submit">Delete</button></form></td>{% endif %}</tr>
{% else %}<tr><td colspan="{{ 7 if is_admin else 6 }}">No purchase orders yet.</td></tr>{% endfor %}</table>
"""

PO_DETAIL = """
<h2>PO-{{ po.id }}</h2>
<p><strong>Vendor:</strong> {{ po.vendor }}<br>
<strong>Description:</strong> {{ po.description }}<br>
<strong>Amount:</strong> ${{ "{:,.2f}".format(po.amount) }}<br>
<strong>Created:</strong> {{ po.created_at.strftime('%Y-%m-%d') if po.created_at else '' }}<br>
<strong>Created by:</strong> {{ creator or '-' }}</p>
<h3>Attachments</h3>
<table><tr><th>File</th><th>Size</th><th>Uploaded</th>{% if is_admin %}<th></th>{% endif %}</tr>
{% for a in po.attachments %}<tr><td><a href="{{ url_for('view_attachment', attachment_id=a.id) }}" target="_blank" rel="noopener">{{ a.original_filename or 'attachment' }}</a></td>
<td>{{ "{:,.1f}".format((a.size_bytes or 0) / 1024) }} KB</td>
<td>{{ a.created_at.strftime('%Y-%m-%d') if a.created_at else '' }}</td>
{% if is_admin %}<td><form method="post" action="{{ url_for('delete_attachment', attachment_id=a.id) }}" style="display:inline" onsubmit="return confirm('Delete this attachment? This cannot be undone.');">
<button type="submit">Delete</button></form></td>{% endif %}</tr>
{% else %}<tr><td colspan="{{ 4 if is_admin else 3 }}">No attachments yet.</td></tr>{% endfor %}</table>
<form method="post" action="{{ url_for('upload_attachment', po_id=po.id) }}" enctype="multipart/form-data">
<label>Attach invoice (PDF, JPG, PNG or HEIC, max 10 MB)<input type="file" name="file" required accept=".pdf,.jpg,.jpeg,.png,.heic,.heif"></label>
<button type="submit">Upload</button>
</form>
"""

FORM = """
<form method="post">
<label>Vendor<input name="vendor" required maxlength="200" value="{{ vendor or '' }}"></label>
<label>Description<textarea name="description" rows="3">{{ description or '' }}</textarea></label>
<label>Amount (USD)<input name="amount" required inputmode="decimal" placeholder="0.00" value="{{ amount or '' }}"></label>
<button type="submit">{{ submit_label or 'Create PO' }}</button>
</form>
"""

LOGIN = """
<form method="post">
<input type="hidden" name="next" value="{{ next_url }}">
<label>Username<input name="username" required autofocus maxlength="80" autocomplete="username"></label>
<label>Password<input type="password" name="password" required autocomplete="current-password"></label>
<button type="submit">Sign in</button>
</form>
"""

ADMIN_USERS = """
<h2>Users</h2>
<table><tr><th>Username</th><th>Role</th><th>Status</th><th>Reset password</th><th></th><th></th><th>Lock</th><th>Delete</th></tr>
{% for u in users %}<tr><td>{{ u.username }}</td><td>{{ u.role }}</td><td>{{ 'Active' if u.is_active else 'Disabled' }}</td>
{% if u.id == bootstrap_id and u.id != current_id %}<td colspan="3">Protected</td>{% else %}
<td><form method="post" action="{{ url_for('admin_reset_password', user_id=u.id) }}">
<input type="password" name="password" required minlength="8" autocomplete="new-password" placeholder="New password (min 8)">
<button type="submit">Reset</button></form></td>
<td>{% if u.id != current_id %}<form method="post" action="{{ url_for('admin_toggle_user', user_id=u.id) }}">
<button type="submit">{{ 'Disable' if u.is_active else 'Enable' }}</button></form>{% endif %}</td>
<td>{% if u.id != current_id %}<form method="post" action="{{ url_for('admin_set_role', user_id=u.id) }}">
<button type="submit">{{ 'Make member' if u.role == 'admin' else 'Make admin' }}</button></form>{% endif %}</td>{% endif %}
<td>{% if u.username.strip().lower() in locked_usernames %}<strong>Locked</strong> <form method="post" action="{{ url_for('admin_unlock_user', user_id=u.id) }}" style="display:inline"><button type="submit">Unlock</button></form>{% endif %}</td>
<td>{% if u.id != current_id and u.id != bootstrap_id %}<form method="post" action="{{ url_for('admin_delete_user', user_id=u.id) }}" style="display:inline" onsubmit="return confirm('Delete user {{ u.username }}? Their POs are kept but show no creator. This cannot be undone.');">
<button type="submit">Delete</button></form>{% endif %}</td></tr>
{% endfor %}</table>
<h2>Create user</h2>
<form method="post" action="{{ url_for('admin_users') }}">
<label>Username<input name="username" required maxlength="80" autocomplete="off"></label>
<label>Password (at least 8 characters)<input type="password" name="password" required minlength="8" autocomplete="new-password"></label>
<label>Role<select name="role">
<option value="member" selected>member</option>
<option value="admin">admin</option>
</select></label>
<button type="submit">Create user</button>
</form>
"""

def render(template, **ctx):
    return render_template_string(BASE, body=render_template_string(template, **ctx))

PUBLIC_ENDPOINTS = {"login", "logout", "healthz", "manifest", "icon", "sw", "static", "logo"}

def safe_next(target):
    """Only allow same-site relative redirects."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return url_for("index")
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return url_for("index")
    return target

@app.before_request
def require_login():
    if request.endpoint is None or request.endpoint in PUBLIC_ENDPOINTS:
        return None
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if user is not None and user.is_active:
        return None
    session.clear()
    next_url = request.full_path.rstrip("?") if request.method == "GET" else None
    return redirect(url_for("login", next=next_url) if next_url else url_for("login"))

# Login throttling: 5 failed attempts within a 15-minute window for the same
# username locks that username for 15 minutes, measured from the most recent
# failure. There is no per-IP limit, because behind a shared proxy one client
# address could lock out every user. While a username is locked the password
# is not checked. Counts live in the login_attempt table so they survive
# redeploys. Unknown usernames are counted exactly like known ones so
# responses never reveal whether an account exists. A successful login clears
# the username's failures, and an admin can unlock a username from the Users
# page or with the "flask unlock-user" command.
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW = timedelta(minutes=15)
LOGIN_LOCKOUT = timedelta(minutes=15)

def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def _throttle_keys(username):
    name = username.strip().lower()[:100]
    if not name:
        return []
    return ["user:" + name]

def _login_locked(keys):
    if not keys:
        return False
    now = _utcnow()
    return db.session.query(LoginAttempt.id).filter(
        LoginAttempt.key.in_(keys), LoginAttempt.locked_until > now
    ).first() is not None

def _record_login_failure(keys):
    if not keys:
        return
    for attempt in range(2):
        now = _utcnow()
        rows = {r.key: r for r in LoginAttempt.query.filter(LoginAttempt.key.in_(keys)).all()}
        for key in keys:
            row = rows.get(key)
            if row is None:
                row = LoginAttempt(key=key, failed_count=0, window_start=now)
                db.session.add(row)
            if now - row.window_start > LOGIN_WINDOW:
                row.failed_count = 0
                row.window_start = now
                row.locked_until = None
            row.failed_count += 1
            if row.failed_count >= LOGIN_MAX_FAILURES:
                row.locked_until = now + LOGIN_LOCKOUT
        try:
            db.session.commit()
            return
        except IntegrityError:
            # A concurrent request created the same key; retry once against its row.
            db.session.rollback()

def _clear_login_failures(keys):
    if not keys:
        return
    LoginAttempt.query.filter(LoginAttempt.key.in_(keys)).delete(synchronize_session=False)
    db.session.commit()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        throttle_keys = _throttle_keys(username)
        if _login_locked(throttle_keys):
            flash("Too many failed attempts. Try again in a few minutes.")
            return render(LOGIN, next_url=request.form.get("next", "")), 429
        user = User.query.filter_by(username=username).first() if username else None
        if user is not None:
            password_ok = check_password_hash(user.password_hash, password)
        else:
            check_password_hash(_DUMMY_HASH, password)
            password_ok = False
        if user is not None and user.is_active and password_ok:
            _clear_login_failures(throttle_keys)
            session.clear()
            session.permanent = True
            session["user_id"] = user.id
            return redirect(safe_next(request.form.get("next", "")))
        _record_login_failure(throttle_keys)
        flash("Invalid username or password.")
        return render(LOGIN, next_url=request.form.get("next", "")), 401
    return render(LOGIN, next_url=request.args.get("next", ""))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

def current_user():
    """Return the active User for the session, or None."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = db.session.get(User, user_id)
    if user is not None and user.is_active:
        return user
    return None

def is_admin(user):
    """Admin means the user has the "admin" role."""
    return user is not None and user.role == "admin"

def is_bootstrap_admin(user):
    """True if user is the account named by the ADMIN_USERNAME env var."""
    name = os.environ.get("ADMIN_USERNAME", "").strip()
    return user is not None and bool(name) and user.username == name

def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_admin(current_user()):
            abort(403)
        return view(*args, **kwargs)
    return wrapper

@app.context_processor
def inject_nav():
    return {"show_users_link": is_admin(current_user())}

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "member")
        if not username:
            flash("Username is required.")
        elif len(username) > 80:
            flash("Username must be 80 characters or fewer.")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.")
        elif role not in VALID_ROLES:
            flash("Invalid role.")
        elif User.query.filter_by(username=username).first() is not None:
            flash("That username is already taken.")
        else:
            try:
                db.session.add(User(
                    username=username,
                    password_hash=generate_password_hash(password),
                    is_active=True,
                    role=role,
                ))
                db.session.commit()
                flash(f"Created user {username}.")
            except IntegrityError:
                db.session.rollback()
                flash("That username is already taken.")
        return redirect(url_for("admin_users"))
    users = User.query.order_by(User.username).all()
    bootstrap_id = next((u.id for u in users if is_bootstrap_admin(u)), None)
    locked_keys = db.session.query(LoginAttempt.key).filter(
        LoginAttempt.key.like("user:%"), LoginAttempt.locked_until > _utcnow()
    ).all()
    locked_usernames = {k[len("user:"):] for (k,) in locked_keys}
    return render(ADMIN_USERS, users=users, current_id=current_user().id, bootstrap_id=bootstrap_id,
                  locked_usernames=locked_usernames)

@app.route("/admin/users/<int:user_id>/unlock", methods=["POST"])
@admin_required
def admin_unlock_user(user_id):
    target = db.session.get(User, user_id)
    if target is None:
        abort(404)
    LoginAttempt.query.filter(
        LoginAttempt.key == "user:" + target.username.strip().lower()
    ).delete(synchronize_session=False)
    db.session.commit()
    flash(f"Unlocked {target.username}.")
    return redirect(url_for("admin_users"))

@app.cli.command("unlock-user")
@click.argument("username")
def unlock_user_command(username):
    """Clear login throttling for USERNAME."""
    LoginAttempt.query.filter(
        LoginAttempt.key == "user:" + username.strip().lower()
    ).delete(synchronize_session=False)
    db.session.commit()
    click.echo(f"Unlocked {username}.")

@app.route("/admin/users/<int:user_id>/password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if is_bootstrap_admin(user) and user.id != current_user().id:
        flash("The bootstrap admin account is protected.")
        return redirect(url_for("admin_users"))
    password = request.form.get("password", "")
    if len(password) < 8:
        flash("Password must be at least 8 characters.")
    else:
        user.password_hash = generate_password_hash(password)
        db.session.commit()
        flash(f"Password reset for {user.username}.")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_user(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if is_bootstrap_admin(user) and user.id != current_user().id:
        flash("The bootstrap admin account is protected.")
        return redirect(url_for("admin_users"))
    if user.id == current_user().id:
        flash("You cannot disable your own account.")
    else:
        user.is_active = not user.is_active
        db.session.commit()
        flash(f"{user.username} is now {'active' if user.is_active else 'disabled'}.")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def admin_set_role(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if is_bootstrap_admin(user):
        flash("The bootstrap admin account is protected.")
        return redirect(url_for("admin_users"))
    if user.id == current_user().id:
        flash("You cannot change your own role.")
    else:
        user.role = "member" if user.role == "admin" else "admin"
        db.session.commit()
        flash(f"{user.username} is now {user.role}.")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if is_bootstrap_admin(user):
        flash("The bootstrap admin account is protected.")
        return redirect(url_for("admin_users"))
    if user.id == current_user().id:
        flash("You cannot delete your own account.")
        return redirect(url_for("admin_users"))
    username = user.username
    try:
        PurchaseOrder.query.filter(PurchaseOrder.created_by_id == user.id).update(
            {PurchaseOrder.created_by_id: None}, synchronize_session=False
        )
        LoginAttempt.query.filter(
            LoginAttempt.key == "user:" + username.strip().lower()
        ).delete(synchronize_session=False)
        db.session.delete(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Could not delete user.")
        return redirect(url_for("admin_users"))
    flash(f"Deleted user {username}.")
    return redirect(url_for("admin_users"))

@app.route("/")
def index():
    pos = PurchaseOrder.query.order_by(PurchaseOrder.id.desc()).all()
    total = sum((po.amount for po in pos), Decimal("0"))
    creator_ids = {po.created_by_id for po in pos if po.created_by_id}
    creators = {}
    if creator_ids:
        creators = {
            uid: name for uid, name in
            db.session.query(User.id, User.username).filter(User.id.in_(creator_ids)).all()
        }
    return render(INDEX, pos=pos, total=total, count=len(pos), creators=creators,
                  is_admin=is_admin(current_user()))

@app.route("/new", methods=["GET", "POST"])
def new_po():
    if request.method == "POST":
        vendor = request.form.get("vendor", "").strip()
        description = request.form.get("description", "").strip()
        try:
            amount = Decimal(request.form.get("amount", "").strip()).quantize(Decimal("0.01"))
        except (InvalidOperation, ValueError):
            amount = None
        if not vendor:
            flash("Vendor is required.")
        elif amount is None or amount <= 0:
            flash("Enter a valid amount greater than zero.")
        else:
            po = PurchaseOrder(
                vendor=vendor,
                description=description,
                amount=amount,
                created_by_id=current_user().id,
            )
            db.session.add(po)
            db.session.commit()
            flash(f"Created PO-{po.id}.")
            return redirect(url_for("index"))
    return render(FORM)

@app.route("/pos/<int:po_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_po(po_id):
    po = db.session.get(PurchaseOrder, po_id)
    if po is None:
        abort(404)
    if request.method == "POST":
        vendor = request.form.get("vendor", "").strip()
        description = request.form.get("description", "").strip()
        raw_amount = request.form.get("amount", "").strip()
        try:
            amount = Decimal(raw_amount).quantize(Decimal("0.01"))
        except (InvalidOperation, ValueError):
            amount = None
        if not vendor:
            flash("Vendor is required.")
        elif amount is None or amount <= 0:
            flash("Enter a valid amount greater than zero.")
        else:
            # Only vendor, description and amount change; creator and created date are preserved.
            po.vendor = vendor
            po.description = description
            po.amount = amount
            db.session.commit()
            flash(f"Updated PO-{po.id}.")
            return redirect(url_for("index"))
        return render(FORM, vendor=vendor, description=description, amount=raw_amount,
                      submit_label="Save changes")
    return render(FORM, vendor=po.vendor, description=po.description,
                  amount="{:.2f}".format(po.amount), submit_label="Save changes")

@app.route("/pos/<int:po_id>/delete", methods=["POST"])
@admin_required
def delete_po(po_id):
    po = db.session.get(PurchaseOrder, po_id)
    if po is None:
        abort(404)
    # Attachment rows cascade with the PO; remove their bucket objects after the commit.
    keys = [a.storage_key for a in po.attachments]
    db.session.delete(po)
    db.session.commit()
    for key in keys:
        try:
            _s3_delete(key)
        except (ClientError, BotoCoreError, RuntimeError):
            app.logger.warning("Could not delete attachment object %s", key)
    flash(f"Deleted PO-{po_id}.")
    return redirect(url_for("index"))

# Attachments live in a private Railway Bucket (S3-compatible); the DB stores only metadata.
HEIC_BRANDS = {b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"}

def detect_file_type(data):
    """Return (content_type, extension) from magic bytes, or None if not allowed."""
    if data.startswith(b"%PDF-"):
        return "application/pdf", "pdf"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", "jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "png"
    if data[4:8] == b"ftyp" and data[8:12] in HEIC_BRANDS:
        return ("image/heif", "heif") if data[8:12] in (b"mif1", b"msf1") else ("image/heic", "heic")
    return None

def _bucket_name():
    name = os.environ.get("BUCKET_NAME", "")
    if not name:
        raise RuntimeError("Attachment storage is not configured.")
    return name

def _s3_client():
    return boto3.client(
        "s3",
        endpoint_url=os.environ.get("BUCKET_ENDPOINT"),
        region_name=os.environ.get("BUCKET_REGION"),
        aws_access_key_id=os.environ.get("BUCKET_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("BUCKET_SECRET_ACCESS_KEY"),
        config=Config(signature_version="s3v4"),
    )

def _s3_delete(key):
    """Delete one object; a missing object is not an error."""
    try:
        _s3_client().delete_object(Bucket=_bucket_name(), Key=key)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("NoSuchKey", "404", "NotFound"):
            raise

@app.errorhandler(RequestEntityTooLarge)
def file_too_large(_exc):
    flash("File is too large (max 10 MB).")
    po_id = (request.view_args or {}).get("po_id")
    return redirect(url_for("po_detail", po_id=po_id) if po_id else url_for("index"))

@app.route("/pos/<int:po_id>")
def po_detail(po_id):
    po = db.session.get(PurchaseOrder, po_id)
    if po is None:
        abort(404)
    creator_user = db.session.get(User, po.created_by_id) if po.created_by_id else None
    creator = creator_user.username if creator_user else None
    return render(PO_DETAIL, po=po, creator=creator, is_admin=is_admin(current_user()))

@app.route("/pos/<int:po_id>/attachments", methods=["POST"])
def upload_attachment(po_id):
    po = db.session.get(PurchaseOrder, po_id)
    if po is None:
        abort(404)
    back = redirect(url_for("po_detail", po_id=po_id))
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        flash("Choose a file to upload.")
        return back
    data = upload.stream.read(MAX_ATTACHMENT_BYTES + 1)
    if len(data) > MAX_ATTACHMENT_BYTES:
        flash("File is too large (max 10 MB).")
        return back
    if not data:
        flash("The file is empty.")
        return back
    detected = detect_file_type(data)
    if detected is None:
        flash("Unsupported file type. Upload a PDF, JPEG, PNG or HEIC file.")
        return back
    content_type, ext = detected
    key = f"attachments/{po_id}/{uuid.uuid4()}.{ext}"
    try:
        _s3_client().put_object(Bucket=_bucket_name(), Key=key, Body=data, ContentType=content_type)
    except (ClientError, BotoCoreError, RuntimeError):
        app.logger.exception("Attachment upload failed for PO-%s", po_id)
        flash("Could not store the attachment. Please try again.")
        return back
    try:
        db.session.add(PurchaseOrderAttachment(
            po_id=po_id,
            storage_key=key,
            original_filename=secure_filename(upload.filename)[:255] or "attachment",
            content_type=content_type,
            size_bytes=len(data),
            uploaded_by_id=current_user().id,
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Attachment row insert failed for PO-%s", po_id)
        try:
            _s3_delete(key)
        except (ClientError, BotoCoreError, RuntimeError):
            app.logger.warning("Could not clean up uploaded object %s", key)
        flash("Could not save the attachment. Please try again.")
        return back
    flash("Attachment uploaded.")
    return back

@app.route("/attachments/<int:attachment_id>")
def view_attachment(attachment_id):
    att = db.session.get(PurchaseOrderAttachment, attachment_id)
    if att is None:
        abort(404)
    try:
        url = _s3_client().generate_presigned_url(
            "get_object",
            Params={"Bucket": _bucket_name(), "Key": att.storage_key},
            ExpiresIn=300,
        )
    except (ClientError, BotoCoreError, RuntimeError):
        app.logger.exception("Could not presign attachment %s", attachment_id)
        flash("Could not open the attachment.")
        return redirect(url_for("po_detail", po_id=att.po_id))
    return redirect(url)

@app.route("/attachments/<int:attachment_id>/delete", methods=["POST"])
@admin_required
def delete_attachment(attachment_id):
    att = db.session.get(PurchaseOrderAttachment, attachment_id)
    if att is None:
        abort(404)
    po_id = att.po_id
    try:
        _s3_delete(att.storage_key)
    except (ClientError, BotoCoreError, RuntimeError):
        app.logger.exception("Could not delete attachment object %s", attachment_id)
        flash("Could not delete the attachment from storage.")
        return redirect(url_for("po_detail", po_id=po_id))
    db.session.delete(att)
    db.session.commit()
    flash("Attachment deleted.")
    return redirect(url_for("po_detail", po_id=po_id))

@app.route("/logo.png")
def logo():
    return send_from_directory(
        os.path.dirname(os.path.abspath(__file__)),
        "SScolor 03.jpg",
        mimetype="image/jpeg",
        max_age=86400,
    )

@app.route("/manifest.webmanifest")
def manifest():
    data = {
        "name": "PO Tracker",
        "short_name": "POs",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#1f6feb",
        "icons": [
            {"src": url_for("icon"), "sizes": "any", "type": "image/svg+xml"},
        ],
    }
    return Response(json.dumps(data), mimetype="application/manifest+json")

ICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">'
    '<rect width="512" height="512" rx="96" fill="#1f6feb"/>'
    '<text x="256" y="340" font-family="sans-serif" font-size="240" '
    'font-weight="bold" text-anchor="middle" fill="#fff">PO</text></svg>'
)

@app.route("/icon.svg")
def icon():
    return Response(ICON_SVG, mimetype="image/svg+xml")

SW_JS = """
self.addEventListener('install', function (event) { self.skipWaiting(); });
self.addEventListener('activate', function (event) { event.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', function (event) { event.respondWith(fetch(event.request)); });
"""

@app.route("/sw.js")
def sw():
    return Response(SW_JS, mimetype="application/javascript")

@app.route("/healthz")
def healthz():
    return "ok", 200
