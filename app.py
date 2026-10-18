import json
import os
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from urllib.parse import urlparse
from flask import Flask, Response, abort, request, redirect, url_for, render_template_string, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

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
db = SQLAlchemy(app)

class PurchaseOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # sequential PO number
    vendor = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now())

class User(db.Model):
    __tablename__ = "app_user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), nullable=False, default="member")

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
button,a.btn{padding:.5rem 1rem;text-decoration:none}</style></head><body>
<h1>PO Tracker</h1>
<p><a class="btn" href="{{ url_for('index') }}">Dashboard</a> <a class="btn" href="{{ url_for('new_po') }}">New PO</a>{% if show_users_link %} <a class="btn" href="{{ url_for('admin_users') }}">Users</a>{% endif %}{% if session.get('user_id') %} <a class="btn" href="{{ url_for('logout') }}">Log out</a>{% endif %}</p>
{% for m in get_flashed_messages() %}<p class="flash">{{ m }}</p>{% endfor %}
{{ body|safe }}
<script>if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');</script>
</body></html>
"""

INDEX = """
<p class="total">Total: ${{ "{:,.2f}".format(total) }} ({{ count }} POs)</p>
<table><tr><th>PO #</th><th>Vendor</th><th>Description</th><th>Amount</th><th>Created</th></tr>
{% for po in pos %}<tr><td>PO-{{ po.id }}</td><td>{{ po.vendor }}</td><td>{{ po.description }}</td>
<td>${{ "{:,.2f}".format(po.amount) }}</td><td>{{ po.created_at.strftime('%Y-%m-%d') if po.created_at else '' }}</td></tr>
{% else %}<tr><td colspan="5">No purchase orders yet.</td></tr>{% endfor %}</table>
"""

FORM = """
<form method="post">
<label>Vendor<input name="vendor" required maxlength="200"></label>
<label>Description<textarea name="description" rows="3"></textarea></label>
<label>Amount (USD)<input name="amount" required inputmode="decimal" placeholder="0.00"></label>
<button type="submit">Create PO</button>
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
<table><tr><th>Username</th><th>Role</th><th>Status</th><th>Reset password</th><th></th><th></th></tr>
{% for u in users %}<tr><td>{{ u.username }}</td><td>{{ u.role }}</td><td>{{ 'Active' if u.is_active else 'Disabled' }}</td>
{% if u.id == bootstrap_id and u.id != current_id %}<td colspan="3">Protected</td>{% else %}
<td><form method="post" action="{{ url_for('admin_reset_password', user_id=u.id) }}">
<input type="password" name="password" required minlength="8" autocomplete="new-password" placeholder="New password (min 8)">
<button type="submit">Reset</button></form></td>
<td>{% if u.id != current_id %}<form method="post" action="{{ url_for('admin_toggle_user', user_id=u.id) }}">
<button type="submit">{{ 'Disable' if u.is_active else 'Enable' }}</button></form>{% endif %}</td>
<td>{% if u.id != current_id %}<form method="post" action="{{ url_for('admin_set_role', user_id=u.id) }}">
<button type="submit">{{ 'Make member' if u.role == 'admin' else 'Make admin' }}</button></form>{% endif %}</td>{% endif %}</tr>
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

PUBLIC_ENDPOINTS = {"login", "logout", "healthz", "manifest", "icon", "sw", "static"}

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

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first() if username else None
        if user is not None:
            password_ok = check_password_hash(user.password_hash, password)
        else:
            check_password_hash(_DUMMY_HASH, password)
            password_ok = False
        if user is not None and user.is_active and password_ok:
            session.clear()
            session.permanent = True
            session["user_id"] = user.id
            return redirect(safe_next(request.form.get("next", "")))
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
    return render(ADMIN_USERS, users=users, current_id=current_user().id, bootstrap_id=bootstrap_id)

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

@app.route("/")
def index():
    pos = PurchaseOrder.query.order_by(PurchaseOrder.id.desc()).all()
    total = sum((po.amount for po in pos), Decimal("0"))
    return render(INDEX, pos=pos, total=total, count=len(pos))

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
            po = PurchaseOrder(vendor=vendor, description=description, amount=amount)
            db.session.add(po)
            db.session.commit()
            flash(f"Created PO-{po.id}.")
            return redirect(url_for("index"))
    return render(FORM)

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
